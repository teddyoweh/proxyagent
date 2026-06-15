"""The proxy server — FastAPI.

Public (machine-token) endpoints mirror the provider APIs so harnesses just point
their base URL here. Admin endpoints (admin-token) manage tokens, view usage/logs,
and list tools. The static dashboard is served at /.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .config import Config, PROVIDERS
from .providers import ROUTES, forward, scope_allows
from .security import token_matches
from .store import Store, now_ms
from .tools import ToolRegistry

UI_DIR = Path(__file__).resolve().parent / "ui"


class TokenBody(BaseModel):
    label: str = "machine"
    scope: list[str] = ["*"]
    ttl_seconds: int | None = None
    rate_limit: int = 0


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.load()
    store = Store(config.db_path)
    tools = ToolRegistry(config)
    app = FastAPI(title="proxyagent", version="0.1.0")
    app.state.store = store

    # ------------------------------------------------------------------ #
    # Auth helpers
    # ------------------------------------------------------------------ #
    def _bearer(authorization: str | None, x_api_key: str | None) -> str | None:
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return x_api_key

    def auth_machine(authorization, x_api_key) -> dict:
        from .security import hash_token
        tok = _bearer(authorization, x_api_key)
        if not tok:
            raise HTTPException(401, "missing token")
        row = store.get_token_by_hash(hash_token(tok))
        if not row or row["revoked"]:
            raise HTTPException(401, "invalid or revoked token")
        if row["expires_ms"] and row["expires_ms"] < now_ms():
            raise HTTPException(401, "token expired")
        if row["rate_limit"] and store.recent_request_count(row["id"]) >= row["rate_limit"]:
            raise HTTPException(429, "rate limit exceeded")
        store.touch_token(row["id"])
        return row

    def require_admin(authorization, x_admin_token) -> None:
        tok = None
        if authorization and authorization.lower().startswith("bearer "):
            tok = authorization[7:].strip()
        tok = tok or x_admin_token
        if not tok or not token_matches(tok, config.admin_token_hash):
            raise HTTPException(401, "admin auth required")

    import json as _json
    from .store import Store as _S  # noqa

    # ------------------------------------------------------------------ #
    # Provider proxy endpoints
    # ------------------------------------------------------------------ #
    async def _proxy(provider_key: str, request: Request, authorization, x_api_key):
        token = auth_machine(authorization, x_api_key)
        provider_name, upstream_path = ROUTES[provider_key]
        body = await request.json()
        model = body.get("model", "")
        scope = _json.loads(token["scope_json"])
        if not scope_allows(scope, provider_name, model):
            raise HTTPException(403, f"token scope does not allow {provider_name}:{model}")

        used_tools: list[str] = []
        if request.headers.get("x-proxyagent-tools", "").lower() in ("1", "on", "true"):
            body = tools.inject(body, provider_name)
            used_tools = tools.names()

        streaming = bool(body.get("stream"))
        status, headers, payload, _ = await forward(
            config, provider_name, upstream_path, body,
            streaming=streaming, token=token, store=store, tools_used=used_tools,
        )
        if streaming:
            return StreamingResponse(payload, media_type="text/event-stream")
        return JSONResponse(payload, status_code=status)

    @app.post("/anthropic/v1/messages")
    async def anthropic(request: Request, authorization: str | None = Header(None),
                        x_api_key: str | None = Header(None)):
        return await _proxy("anthropic", request, authorization, x_api_key)

    @app.post("/openai/v1/chat/completions")
    async def openai(request: Request, authorization: str | None = Header(None),
                     x_api_key: str | None = Header(None)):
        return await _proxy("openai", request, authorization, x_api_key)

    # ------------------------------------------------------------------ #
    # Tools — execute a proxied tool (creds stay here)
    # ------------------------------------------------------------------ #
    @app.get("/v1/tools")
    async def list_tools(authorization: str | None = Header(None),
                         x_api_key: str | None = Header(None)):
        auth_machine(authorization, x_api_key)
        return {"tools": tools.list()}

    @app.post("/v1/tools/{name}/execute")
    async def exec_tool(name: str, request: Request, authorization: str | None = Header(None),
                        x_api_key: str | None = Header(None)):
        auth_machine(authorization, x_api_key)
        args = await request.json()
        if not tools.manages(name):
            raise HTTPException(404, f"unknown tool '{name}'")
        return {"result": await tools.execute(name, args)}

    # ------------------------------------------------------------------ #
    # Admin API
    # ------------------------------------------------------------------ #
    @app.post("/admin/tokens")
    async def create_token(body: TokenBody, authorization: str | None = Header(None),
                           x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        plain, row = store.create_token(body.label, body.scope,
                                        ttl_seconds=body.ttl_seconds, rate_limit=body.rate_limit)
        return {"token": plain, "id": row["id"], "label": row["label"],
                "scope": body.scope, "note": "shown once — store it now"}

    @app.get("/admin/tokens")
    async def list_tokens_ep(authorization: str | None = Header(None),
                             x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        out = []
        for t in store.list_tokens():
            out.append({"id": t["id"], "label": t["label"], "masked": t["masked"],
                        "scope": _json.loads(t["scope_json"]), "revoked": bool(t["revoked"]),
                        "rate_limit": t["rate_limit"], "expires_ms": t["expires_ms"],
                        "last_used_ms": t["last_used_ms"]})
        return {"tokens": out}

    @app.delete("/admin/tokens/{tid}")
    async def revoke_token_ep(tid: str, authorization: str | None = Header(None),
                              x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        if not store.revoke_token(tid):
            raise HTTPException(404, "no such token")
        return {"ok": True}

    @app.get("/admin/logs")
    async def logs_ep(limit: int = 200, authorization: str | None = Header(None),
                      x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"logs": store.list_logs(limit)}

    @app.get("/admin/usage")
    async def usage_ep(authorization: str | None = Header(None),
                       x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"usage": store.usage_summary(),
                "providers": config.configured_providers(),
                "tools": tools.list()}

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "providers": config.configured_providers(), "tools": tools.names()}

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    async def ui():
        idx = UI_DIR / "index.html"
        return HTMLResponse(idx.read_text() if idx.exists() else "<h1>proxyagent</h1>")

    return app
