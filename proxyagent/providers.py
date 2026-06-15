"""Upstream forwarding + scope enforcement.

The proxy receives a request authed by a machine token, swaps in the REAL provider
key, and forwards it upstream — streaming straight through. The machine never sees
the real key; the proxy logs usage for every call.
"""

from __future__ import annotations

import fnmatch
import json

import httpx

from .config import Config, PROVIDERS
from .store import Store, now_ms

# Map our public path → (provider, upstream path).
ROUTES = {
    "anthropic": ("anthropic", "/v1/messages"),
    "openai": ("openai", "/v1/chat/completions"),
}


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
    config: Config, provider_name: str, upstream_path: str, body: dict,
    *, streaming: bool, token: dict, store: Store, tools_used: list[str] | None = None,
):
    """Forward a request upstream. Returns (status, headers, body_iter_or_dict, log_after)."""
    provider = PROVIDERS[provider_name]
    if not provider.key:
        return 502, {}, {"error": f"provider '{provider_name}' not configured on the proxy"}, None

    url = provider.base_url + upstream_path
    headers = {"content-type": "application/json", **provider.auth_headers()}
    model = body.get("model", "")
    t0 = now_ms()

    def _log(status, ptok, ctok, err=None):
        store.log_request(
            token_id=token["id"], token_label=token.get("label"), provider=provider_name,
            model=model, status=status, prompt_tokens=ptok, completion_tokens=ctok,
            latency_ms=now_ms() - t0, streamed=1 if streaming else 0,
            tools_used=json.dumps(tools_used or []), error=err,
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
    ptok, ctok = _extract_usage(provider_name, payload if isinstance(payload, dict) else {})
    _log(resp.status_code, ptok, ctok, None if resp.is_success else str(payload)[:300])
    return resp.status_code, {"content-type": "application/json"}, payload, None
