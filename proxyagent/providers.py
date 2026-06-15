"""Upstream forwarding + scope enforcement.

The proxy receives a request authed by a machine token, swaps in the REAL provider
key, and forwards it upstream — streaming straight through. The machine never sees
the real key; the proxy logs usage for every call.
"""

from __future__ import annotations

import fnmatch
import json

import httpx

from . import pricing
from .config import Config, PROVIDERS
from .store import Store, now_ms

def resolve_auth(provider, store: Store | None) -> tuple[dict, bool]:
    """Auth headers for an upstream call. A stored credential (proxy_agent_keys) wins
    over the env key; returns ({}, False) when nothing is configured."""
    cred = store.get_credential(provider.name) if store else None
    if cred:
        secret, kind = cred["secret"], cred["kind"]
        if kind == "oauth":
            return {"Authorization": f"Bearer {secret}", **provider.extra_headers}, True
        if provider.auth_style == "x-api-key":
            return {"x-api-key": secret, **provider.extra_headers}, True
        return {"Authorization": f"Bearer {secret}", **provider.extra_headers}, True
    headers = provider.auth_headers()
    return headers, bool(headers)


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

    auth, ok = resolve_auth(provider, store)
    if not ok:
        return 502, {}, {"error": f"provider '{provider_name}' not configured on the proxy "
                                  f"(set {provider.key_env} or `proxyagent provider add {provider_name}`)"}, None

    url = provider.endpoint
    headers = {"content-type": "application/json", **auth}

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
                    async with client.stream("POST", url, headers=headers, json=body) as resp:
                        status = resp.status_code
                        async for chunk in resp.aiter_raw():
                            # Best-effort usage capture from the final SSE event.
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
            finally:
                _log(status, ptok, ctok)
        return 200, {"content-type": "text/event-stream"}, _gen(), None

    # Non-streaming.
    async with httpx.AsyncClient(timeout=config.request_timeout) as client:
        resp = await client.post(url, headers=headers, json=body)
    try:
        payload = resp.json()
    except Exception:
        payload = {"error": resp.text}
    ptok, ctok = _extract_usage(provider.shape, payload if isinstance(payload, dict) else {})
    _log(resp.status_code, ptok, ctok, None if resp.is_success else str(payload)[:300])
    return resp.status_code, {"content-type": "application/json"}, payload, None


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


def _mock_payload(provider: str, body: dict):
    prompt = _last_user_text(body)[:200]
    text = f"[proxyagent mock] received: {prompt!r}. No real key used — the pipeline works."
    ptok, ctok = max(1, len(prompt) // 4), max(1, len(text) // 4)
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
