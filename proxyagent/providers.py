"""Upstream forwarding + scope enforcement.

The proxy receives a request authed by a machine token, swaps in the REAL provider
key, and forwards it upstream — streaming straight through. The machine never sees
the real key; the proxy logs usage for every call.
"""

from __future__ import annotations

import fnmatch
import json
import time

import httpx

from . import pricing, redact, signers
from .config import Config, PROVIDERS
from .store import Store, now_ms

FAILOVER_STATUS = {429, 500, 502, 503, 504, 529}


def _headers_for(provider, secret: str, kind: str) -> dict:
    if kind != "api_key":  # oauth / bearer
        return {"Authorization": f"Bearer {secret}", **provider.extra_headers}
    if provider.auth_style == "x-api-key":
        return {"x-api-key": secret, **provider.extra_headers}
    return {"Authorization": f"Bearer {secret}", **provider.extra_headers}


def resolve_candidates(provider, store: Store | None) -> list[dict]:
    """Every usable auth header-set for a provider, in rotation order: the stored pool
    (api_key then oauth creds), then the env key as a last resort. The forwarder tries
    them in turn, rotating past any that 429/5xx — that's the failover."""
    out: list[dict] = []
    if store:
        for c in store.get_credentials(provider.name, kind="api_key"):
            out.append(_headers_for(provider, c["secret"], "api_key"))
        for c in store.get_credentials(provider.name, kind="oauth"):
            out.append(_headers_for(provider, c["secret"], "oauth"))
    if provider.key:
        out.append(provider.auth_headers())
    return out


def resolve_auth(provider, store: Store | None) -> tuple[dict, bool]:
    cands = resolve_candidates(provider, store)
    return (cands[0], True) if cands else ({}, False)


def plan_for_credential(provider, c: dict, body: dict, *, store: Store | None = None) -> tuple | None:
    """Map ONE credential to a concrete (url, headers, body_bytes), per its auth kind:
    api_key/oauth → the provider endpoint; azure → a custom deployment URL; bedrock →
    SigV4-signed Claude-on-Bedrock; vertex → SA-token Claude-on-Vertex. Returns None if the
    credential can't produce a plan (e.g. azure with no endpoint, malformed bedrock/vertex)."""
    raw = json.dumps(body).encode("utf-8")
    JSON = {"content-type": "application/json"}
    kind, meta = c["kind"], (c.get("meta") or {})
    if kind == "api_key":
        return (provider.endpoint, {**JSON, **_headers_for(provider, c["secret"], "api_key")}, raw)
    if kind == "oauth":
        secret = c["secret"]
        exp = meta.get("expires_ms")
        # refresh the access token if it's expired (or within 60s) and refreshable
        if (store and exp and exp < int(time.time() * 1000) + 60_000
                and meta.get("refresh_token") and meta.get("token_url")):
            try:
                res = signers.oauth_refresh(c)
                if res:
                    secret, ttl = res
                    store.refresh_credential(c["id"], secret,
                                             expires_ms=int(time.time() * 1000) + ttl * 1000)
            except Exception:  # noqa: BLE001 — fall back to the existing token
                pass
        return (provider.endpoint, {**JSON, "Authorization": f"Bearer {secret}", **provider.extra_headers}, raw)
    if kind == "azure":
        ep = (meta.get("endpoint") or "").rstrip("/")
        return (ep, {**JSON, "api-key": c["secret"]}, raw) if ep else None
    if kind == "bedrock":
        try:
            return signers.bedrock_plan(c, body)
        except Exception:  # noqa: BLE001 — malformed bedrock cred
            return None
    if kind == "vertex":
        try:
            return signers.vertex_plan(c, body)
        except Exception:  # noqa: BLE001 — SA invalid / token fetch fails
            return None
    return None


def build_plans(provider, store: Store | None, body: dict) -> list[tuple]:
    """Every way to fulfil this request, in rotation order, as (url, headers, body_bytes).
    The forwarder tries them in turn, rotating past any that 429/5xx — that's the failover."""
    plans: list[tuple] = []
    if store:
        for c in store.get_credentials(provider.name):
            plan = plan_for_credential(provider, c, body, store=store)
            if plan:
                plans.append(plan)
    if provider.key:
        plans.append((provider.endpoint, {"content-type": "application/json", **provider.auth_headers()},
                      json.dumps(body).encode("utf-8")))
    return plans


def scope_allows(scope: list[str], provider: str, model: str) -> bool:
    """A scope entry is a glob over 'provider:model', e.g. 'anthropic:claude-*', or '*'."""
    target = f"{provider}:{model or '*'}"
    for entry in scope:
        if entry == "*" or fnmatch.fnmatch(target, entry) or fnmatch.fnmatch(provider, entry):
            return True
    return False


def _extract_usage(provider: str, payload: dict) -> tuple[int | None, int | None]:
    u = payload.get("usage") or {}
    if provider == "anthropic":
        return u.get("input_tokens"), u.get("output_tokens")
    return u.get("prompt_tokens"), u.get("completion_tokens")


async def forward(
    config: Config, provider_name: str, body: dict,
    *, streaming: bool, token: dict, store: Store, tools_used: list[str] | None = None,
):
    """Forward a request upstream. Returns (status, headers, body_iter_or_dict, log_after)."""
    provider = PROVIDERS[provider_name]
    model = body.get("model", "")
    t0 = now_ms()

    # Offline mock — exercise the full pipeline (auth, scope, log, cost) with NO real
    # key. Use model "mock" (or "mock-…") anywhere a real model would go.
    if model.startswith("mock"):
        payload, (ptok, ctok) = _mock_payload(provider.shape, body)
        store.log_request(
            token_id=token["id"], token_label=token.get("label"), provider=provider_name,
            model=model, status=200, prompt_tokens=ptok, completion_tokens=ctok,
            latency_ms=now_ms() - t0, streamed=1 if streaming else 0,
            tools_used=json.dumps(tools_used or []), cost_usd=pricing.cost_usd(model, ptok, ctok),
            error=None)
        if streaming:
            return 200, {"content-type": "text/event-stream"}, _mock_stream(provider.shape, payload), None
        return 200, {"content-type": "application/json"}, payload, None

    plans = build_plans(provider, store, body)
    if not plans:
        return 502, {}, {"error": f"provider '{provider_name}' not configured on the proxy "
                                  f"(set {provider.key_env} or `proxyagent provider add {provider_name}`)"}, None

    def _log(status, ptok, ctok, err=None):
        store.log_request(
            token_id=token["id"], token_label=token.get("label"), provider=provider_name,
            model=model, status=status, prompt_tokens=ptok, completion_tokens=ctok,
            latency_ms=now_ms() - t0, streamed=1 if streaming else 0,
            tools_used=json.dumps(tools_used or []), cost_usd=pricing.cost_usd(model, ptok, ctok),
            error=err,
        )

    if streaming:
        async def _gen():
            ptok = ctok = None
            status = 200
            try:
                async with httpx.AsyncClient(timeout=config.request_timeout) as client:
                    for i, (url, headers, raw) in enumerate(plans):
                        async with client.stream("POST", url, headers=headers, content=raw) as resp:
                            status = resp.status_code
                            if status in FAILOVER_STATUS and i < len(plans) - 1:
                                await resp.aread()  # drain + rotate to the next credential
                                continue
                            async for chunk in resp.aiter_raw():
                                text = chunk.decode("utf-8", "ignore")
                                if '"output_tokens"' in text or '"completion_tokens"' in text:
                                    try:
                                        for line in text.splitlines():
                                            if line.startswith("data:"):
                                                d = json.loads(line[5:].strip())
                                                usage = d.get("usage") or (d.get("message") or {}).get("usage") or {}
                                                ptok = usage.get("input_tokens") or usage.get("prompt_tokens") or ptok
                                                ctok = usage.get("output_tokens") or usage.get("completion_tokens") or ctok
                                    except Exception:
                                        pass
                                yield chunk
                            break
            finally:
                _log(status, ptok, ctok)
        return 200, {"content-type": "text/event-stream"}, _gen(), None

    # Non-streaming, with credential failover across the pool.
    last_status, last_payload = 502, {"error": "all credentials failed"}
    async with httpx.AsyncClient(timeout=config.request_timeout) as client:
        for i, (url, headers, raw) in enumerate(plans):
            resp = await client.post(url, headers=headers, content=raw)
            if resp.status_code in FAILOVER_STATUS and i < len(plans) - 1:
                last_status = resp.status_code
                continue
            try:
                payload = resp.json()
            except Exception:
                payload = {"error": resp.text}
            ptok, ctok = _extract_usage(provider.shape, payload if isinstance(payload, dict) else {})
            _log(resp.status_code, ptok, ctok,
                 None if resp.is_success else redact.redact(str(payload)[:300]))
            return resp.status_code, {"content-type": "application/json"}, payload, None
    _log(last_status, None, None, "all credentials failed")
    return last_status, {"content-type": "application/json"}, last_payload, None


def _extract_tool_calls(shape: str, payload: dict) -> list[dict]:
    """Normalise a response's tool requests to [{id, name, args}] across both shapes."""
    out: list[dict] = []
    if shape == "anthropic":
        for blk in payload.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                out.append({"id": blk.get("id"), "name": blk.get("name"), "args": blk.get("input") or {}})
    else:
        msg = ((payload.get("choices") or [{}])[0]).get("message") or {}
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except Exception:  # noqa: BLE001 — model emitted bad JSON args
                args = {}
            out.append({"id": tc.get("id"), "name": fn.get("name"), "args": args})
    return out


def _append_tool_turn(shape: str, body: dict, payload: dict, results: list[tuple]) -> None:
    """Append the model's tool-call turn + our tool_result turn back onto the conversation."""
    msgs = body.setdefault("messages", [])
    if shape == "anthropic":
        msgs.append({"role": "assistant", "content": payload.get("content", [])})
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": c["id"], "content": out} for c, out in results]})
    else:
        msgs.append(((payload.get("choices") or [{}])[0]).get("message") or {})
        for c, out in results:
            msgs.append({"role": "tool", "tool_call_id": c["id"], "content": out})


async def forward_agentic(config: Config, provider_name: str, body: dict, *, token: dict,
                          store: Store, tools, max_steps: int = 6):
    """Non-streaming agentic loop: forward, and while the model asks to use a tool the proxy
    MANAGES, execute it server-side, append the result, and re-call — until a final answer or
    max_steps. The machine never holds the tool's credentials. Returns (status, payload, steps)."""
    shape = PROVIDERS[provider_name].shape
    steps = 0
    while True:
        status, _h, payload, _ = await forward(config, provider_name, body, streaming=False,
                                               token=token, store=store, tools_used=tools.names())
        if status != 200 or not isinstance(payload, dict):
            return status, payload, steps
        calls = _extract_tool_calls(shape, payload)
        managed = [c for c in calls if c.get("name") and tools.manages(c["name"])]
        if not managed or steps >= max_steps:
            return status, payload, steps
        steps += 1
        results = [(c, await tools.execute(c["name"], c["args"])) for c in managed]
        _append_tool_turn(shape, body, payload, results)


def _ping_body(provider, model: str | None) -> dict:
    """A minimal, cheap request to validate a credential reaches + authenticates upstream."""
    from .config import CATALOG
    model = model or (CATALOG.get(provider.name, {}).get("models") or ["claude-3-5-haiku"])[0]
    body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]}
    if provider.shape == "anthropic":
        body["anthropic_version"] = "2023-06-01"
    return body


async def test_credential(config, provider_name: str, cred: dict, *, model: str | None = None) -> dict:
    """Ping the real upstream with ONE stored credential and report whether it works.
    A 2xx/4xx means the endpoint is reachable; 200 = the credential authenticates. Network
    errors mean unreachable. Never returns secret material."""
    provider = PROVIDERS[provider_name]
    body = _ping_body(provider, model)
    plan = plan_for_credential(provider, cred, body)
    if not plan:
        return {"ok": False, "reachable": False, "kind": cred.get("kind"),
                "detail": f"could not build a request for a '{cred.get('kind')}' credential "
                          f"(missing config — e.g. azure endpoint or region)"}
    url, headers, raw = plan
    t0 = now_ms()
    try:
        async with httpx.AsyncClient(timeout=min(config.request_timeout, 20)) as client:
            resp = await client.post(url, headers=headers, content=raw)
    except Exception as e:  # noqa: BLE001 — DNS/connect/timeout → unreachable
        return {"ok": False, "reachable": False, "kind": cred.get("kind"),
                "latency_ms": now_ms() - t0, "detail": redact.redact(f"{type(e).__name__}: {e}")[:200]}
    ok = resp.is_success
    auth_fail = resp.status_code in (401, 403)
    detail = ("authenticated" if ok else
              "authentication failed — bad credential" if auth_fail else
              f"reachable, upstream returned {resp.status_code}")
    return {"ok": ok, "reachable": True, "status": resp.status_code, "kind": cred.get("kind"),
            "auth_ok": not auth_fail, "latency_ms": now_ms() - t0, "detail": detail}


# ------------------------------------------------------------------ #
# Offline mock — provider-shaped canned responses for local testing.
# ------------------------------------------------------------------ #

def _last_user_text(body: dict) -> str:
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            if isinstance(c, list):
                return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def _has_tool_result(body: dict) -> bool:
    """True once the conversation already carries a tool_result — i.e. we're on the
    second leg of an agentic loop and the mock should now answer instead of re-calling."""
    for m in body.get("messages", []):
        if m.get("role") == "tool":
            return True
        c = m.get("content")
        if isinstance(c, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
            return True
    return False


def _last_tool_result_text(body: dict) -> str:
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "tool" and isinstance(m.get("content"), str):
            return m["content"]
        c = m.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    out = b.get("content")
                    return out if isinstance(out, str) else json.dumps(out)
    return ""


def _mock_payload(provider: str, body: dict):
    prompt = _last_user_text(body)[:200]
    tools = body.get("tools") or []
    ptok = max(1, len(prompt) // 4)

    # Agentic-loop mock: if tools are offered and we haven't run one yet, ask to call the
    # first tool — so the full server-side tool loop runs end-to-end with no real key.
    if tools and not _has_tool_result(body):
        first = tools[0]
        name = first.get("name") if provider == "anthropic" else (first.get("function") or {}).get("name")
        args = {"query": prompt or "proxyagent"}
        if provider == "anthropic":
            return ({
                "id": "msg_mock", "type": "message", "role": "assistant", "model": body.get("model"),
                "content": [{"type": "tool_use", "id": "toolu_mock", "name": name, "input": args}],
                "stop_reason": "tool_use", "usage": {"input_tokens": ptok, "output_tokens": 2},
            }, (ptok, 2))
        return ({
            "id": "chatcmpl-mock", "object": "chat.completion", "model": body.get("model"),
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [{
                    "id": "call_mock", "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args)}}]}}],
            "usage": {"prompt_tokens": ptok, "completion_tokens": 2, "total_tokens": ptok + 2},
        }, (ptok, 2))

    tr = _last_tool_result_text(body)
    text = (f"[proxyagent mock] received: {prompt!r}. "
            + (f"tool returned: {tr[:200]}" if tr else "No real key used — the pipeline works."))
    ctok = max(1, len(text) // 4)
    if provider == "anthropic":
        return ({
            "id": "msg_mock", "type": "message", "role": "assistant", "model": body.get("model"),
            "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
            "usage": {"input_tokens": ptok, "output_tokens": ctok},
        }, (ptok, ctok))
    return ({
        "id": "chatcmpl-mock", "object": "chat.completion", "model": body.get("model"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": ptok, "completion_tokens": ctok, "total_tokens": ptok + ctok},
    }, (ptok, ctok))


async def _mock_stream(provider: str, payload: dict):
    import json as _j
    if provider == "anthropic":
        text = payload["content"][0]["text"]
        yield f"event: message_start\ndata: {_j.dumps({'type':'message_start','message':payload})}\n\n".encode()
        yield (f"event: content_block_delta\ndata: "
               f"{_j.dumps({'type':'content_block_delta','delta':{'type':'text_delta','text':text}})}\n\n").encode()
        yield b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
    else:
        text = payload["choices"][0]["message"]["content"]
        chunk = {"choices": [{"delta": {"content": text}, "index": 0}]}
        yield f"data: {_j.dumps(chunk)}\n\n".encode()
        yield b"data: [DONE]\n\n"
