"""The proxy server — FastAPI.

Public (machine-token) endpoints mirror the provider APIs so harnesses just point
their base URL here. Admin endpoints (admin-token) manage tokens, view usage/logs,
and list tools. The static dashboard is served at /.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from . import aliases, cache, crypto
from .config import (AUTH_LABELS, AUTH_READY, CATALOG, HARNESSES, Config, PROVIDERS,
                     provider_budget, provider_rate_limit)
from .providers import forward, forward_agentic, scope_allows, test_credential
from .security import token_matches
from .store import Store, now_ms
from .tools import ToolRegistry

UI_DIR = Path(__file__).resolve().parent / "ui"


class TokenBody(BaseModel):
    label: str = "machine"
    scope: list[str] = ["*"]
    ttl_seconds: int | None = None
    rate_limit: int = 0
    budget_usd: float | None = None


class TokenPatch(BaseModel):
    scope: list[str] | None = None
    rate_limit: int | None = None
    budget_usd: float | None = None


class ProviderBody(BaseModel):
    provider: str
    secret: str
    kind: str = "api_key"            # api_key | oauth | bedrock | azure | vertex
    label: str | None = None
    refresh: str | None = None
    meta: dict | None = None         # bedrock: {access_key, region}; azure: {endpoint}


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.load()
    store = Store(config.db_path)
    tools = ToolRegistry(config)
    app = FastAPI(title="proxyagent", version="0.1.0")
    app.state.store = store
    app.state.tools = tools
    started_at = time.time()

    # Audit-log retention — trim call traces older than PROXYAGENT_LOG_RETENTION_DAYS
    # on startup so an always-on proxy never grows the log table without bound.
    import os as _os
    _ret = int(_os.environ.get("PROXYAGENT_LOG_RETENTION_DAYS", "0") or 0)
    if _ret > 0:
        try:
            store.trim_logs(now_ms() - _ret * 86_400_000)
        except Exception:  # noqa: BLE001 — retention is best-effort, never block boot
            pass

    # ------------------------------------------------------------------ #
    # Budget alerting — POST a webhook when a token/provider crosses its cap.
    # Deduped per (kind,id) with a cooldown so a blocked-but-retrying client
    # doesn't spam the hook.
    # ------------------------------------------------------------------ #
    alerted: dict = {}

    def _budget_alert(kind: str, name: str, cap: float, spend: float) -> None:
        url = os.environ.get("PROXYAGENT_BUDGET_WEBHOOK")
        if not url:
            return
        cooldown = int(os.environ.get("PROXYAGENT_BUDGET_WEBHOOK_COOLDOWN", "300") or 300)
        key = (kind, name)
        nowt = time.time()
        if nowt - alerted.get(key, 0) < cooldown:
            return
        alerted[key] = nowt
        try:
            httpx.post(url, json={"event": "budget_exhausted", "type": kind, "id": name,
                                  "cap_usd": cap, "spend_usd": round(spend, 6)}, timeout=5)
        except Exception:  # noqa: BLE001 — alerting is best-effort, never block the request
            pass

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
        budget = row.get("budget_usd")
        if budget is not None:
            spend = store.token_spend(row["id"])
            if spend >= budget:
                _budget_alert("token", row["id"], budget, spend)
                raise HTTPException(402, f"token budget of ${budget:.4f} exhausted")
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
    async def _proxy(provider: str, request: Request, authorization, x_api_key):
        token = auth_machine(authorization, x_api_key)
        if provider not in PROVIDERS:
            raise HTTPException(404, f"unknown provider '{provider}' (known: {list(PROVIDERS)})")
        # Request id for tracing — honour an inbound one, else mint. Echoed on the response
        # and stored on the call trace so a client log line ties to a proxy_agent_calls row.
        import uuid as _uuid
        rid = (request.headers.get("x-proxyagent-request-id") or "")[:128] or "req_" + _uuid.uuid4().hex[:16]
        body = await request.json()
        # model remap — may rename the model and/or reroute to another provider
        provider, model = aliases.remap(provider, body.get("model", ""))
        if provider not in PROVIDERS:
            raise HTTPException(400, f"alias target provider '{provider}' is unknown")
        body["model"] = model
        scope = _json.loads(token["scope_json"])
        if not scope_allows(scope, provider, model):
            raise HTTPException(403, f"token scope does not allow {provider}:{model}")

        rl = provider_rate_limit(provider)
        if rl and store.recent_provider_count(provider) >= rl:
            raise HTTPException(429, f"rate limit for provider '{provider}' exceeded ({rl}/min)")

        pb = provider_budget(provider)
        if pb:
            pspend = store.provider_spend(provider)
            if pspend >= pb:
                _budget_alert("provider", provider, pb, pspend)
                raise HTTPException(402, f"provider '{provider}' budget of ${pb:g} exhausted")

        tools_on = request.headers.get("x-proxyagent-tools", "").lower() in ("1", "on", "true")
        used_tools: list[str] = []
        if tools_on:
            body = tools.inject(body, PROVIDERS[provider].shape)
            used_tools = tools.names()

        streaming = bool(body.get("stream"))

        # Server-side agentic tool loop: the proxy executes managed tools (keys stay here)
        # and re-calls the model until it returns a final answer. Non-streaming only.
        # Step budget: env default, overridable per-request (0 = return the tool request
        # without executing — handy for clients that want to run tools themselves).
        if tools_on and not streaming:
            max_steps = int(os.environ.get("PROXYAGENT_MAX_TOOL_STEPS", "6") or 6)
            hdr = request.headers.get("x-proxyagent-tool-steps-max")
            if hdr is not None:
                try:
                    max_steps = max(0, min(20, int(hdr)))
                except ValueError:
                    pass
            status, payload, steps = await forward_agentic(
                config, provider, body, token=token, store=store, tools=tools,
                max_steps=max_steps, request_id=rid)
            return JSONResponse(payload, status_code=status,
                                headers={"x-proxyagent-tool-steps": str(steps),
                                         "x-proxyagent-tool-steps-max": str(max_steps),
                                         "x-proxyagent-request-id": rid})

        # Response cache (non-streaming only): serve identical requests from memory.
        ck = None
        if not streaming and cache.enabled() and request.headers.get("x-proxyagent-cache", "").lower() != "no":
            ck = cache.key(provider, body)
            hit = cache.get(ck)
            if hit is not None:
                store.log_request(token_id=token["id"], token_label=token.get("label"),
                                  provider=provider, model=model, status=200, cost_usd=0.0,
                                  tools_used='["cache-hit"]', request_id=rid)
                return JSONResponse(hit, status_code=200,
                                    headers={"x-proxyagent-cache": "hit", "x-proxyagent-request-id": rid})

        status, headers, payload, _ = await forward(
            config, provider, body, streaming=streaming, token=token, store=store,
            tools_used=used_tools, request_id=rid)
        if streaming:
            return StreamingResponse(payload, media_type="text/event-stream",
                                     headers={"x-proxyagent-request-id": rid})
        if ck is not None and status == 200 and isinstance(payload, dict):
            cache.put(ck, payload)
        return JSONResponse(payload, status_code=status, headers={"x-proxyagent-request-id": rid})

    # OpenAI-compatible providers hit /<provider>/v1/chat/completions; Anthropic-style
    # hit /<provider>/v1/messages. The provider segment selects the upstream.
    @app.post("/{provider}/v1/chat/completions")
    async def chat(provider: str, request: Request, authorization: str | None = Header(None),
                   x_api_key: str | None = Header(None)):
        return await _proxy(provider, request, authorization, x_api_key)

    @app.post("/{provider}/v1/messages")
    async def messages(provider: str, request: Request, authorization: str | None = Header(None),
                       x_api_key: str | None = Header(None)):
        return await _proxy(provider, request, authorization, x_api_key)

    # ------------------------------------------------------------------ #
    # Model listing — OpenAI-shaped {object:"list", data:[…]} so harnesses that
    # probe /v1/models for available models get an answer (no upstream call).
    # ------------------------------------------------------------------ #
    def _models_list(provider_name: str | None = None) -> dict:
        names = [provider_name] if provider_name else list(PROVIDERS)
        data = [{"id": mid, "object": "model", "owned_by": n}
                for n in names for mid in (CATALOG.get(n, {}).get("models") or [])]
        data.append({"id": "mock", "object": "model", "owned_by": "proxyagent"})
        return {"object": "list", "data": data}

    @app.get("/v1/models")
    async def list_models_all(authorization: str | None = Header(None),
                              x_api_key: str | None = Header(None)):
        auth_machine(authorization, x_api_key)
        return _models_list()

    @app.get("/{provider}/v1/models")
    async def list_models_provider(provider: str, authorization: str | None = Header(None),
                                   x_api_key: str | None = Header(None)):
        auth_machine(authorization, x_api_key)
        if provider not in PROVIDERS:
            raise HTTPException(404, f"unknown provider '{provider}'")
        return _models_list(provider)

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
        plain, row = store.create_token(body.label, body.scope, ttl_seconds=body.ttl_seconds,
                                        rate_limit=body.rate_limit, budget_usd=body.budget_usd)
        return {"token": plain, "id": row["id"], "label": row["label"],
                "scope": body.scope, "budget_usd": body.budget_usd, "note": "shown once — store it now"}

    @app.get("/admin/tokens")
    async def list_tokens_ep(authorization: str | None = Header(None),
                             x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        out = []
        for t in store.list_tokens():
            out.append({"id": t["id"], "label": t["label"], "masked": t["masked"],
                        "scope": _json.loads(t["scope_json"]), "revoked": bool(t["revoked"]),
                        "rate_limit": t["rate_limit"], "expires_ms": t["expires_ms"],
                        "last_used_ms": t["last_used_ms"], "budget_usd": t.get("budget_usd"),
                        "spent_usd": round(store.token_spend(t["id"]), 6)})
        return {"tokens": out}

    @app.delete("/admin/tokens/{tid}")
    async def revoke_token_ep(tid: str, authorization: str | None = Header(None),
                              x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        if not store.revoke_token(tid):
            raise HTTPException(404, "no such token")
        return {"ok": True}

    @app.patch("/admin/tokens/{tid}")
    async def patch_token_ep(tid: str, body: TokenPatch, authorization: str | None = Header(None),
                             x_admin_token: str | None = Header(None)):
        """Retune a token's scope / rate limit / budget without re-minting it."""
        require_admin(authorization, x_admin_token)
        if not store.get_token(tid):
            raise HTTPException(404, "no such token")
        if not store.update_token(tid, scope=body.scope, rate_limit=body.rate_limit,
                                  budget_usd=body.budget_usd):
            raise HTTPException(400, "nothing to update")
        t = store.get_token(tid)
        return {"id": tid, "scope": _json.loads(t["scope_json"]),
                "rate_limit": t["rate_limit"], "budget_usd": t.get("budget_usd")}

    @app.get("/admin/logs")
    async def logs_ep(limit: int = 200, authorization: str | None = Header(None),
                      x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"logs": store.list_logs(limit)}

    @app.post("/admin/logs/trim")
    async def trim_logs_ep(days: int = 30, authorization: str | None = Header(None),
                           x_admin_token: str | None = Header(None)):
        """Delete call traces older than `days`. The audit-log retention knob, on demand."""
        require_admin(authorization, x_admin_token)
        if days < 0:
            raise HTTPException(400, "days must be >= 0")
        deleted = store.trim_logs(now_ms() - days * 86_400_000)
        return {"deleted": deleted, "kept_days": days}

    @app.get("/admin/logs/export", response_class=PlainTextResponse)
    async def export_logs_ep(limit: int = 100_000, authorization: str | None = Header(None),
                             x_admin_token: str | None = Header(None)):
        """Export the audit trail as CSV (for SIEM ingest / compliance / archival)."""
        require_admin(authorization, x_admin_token)
        import csv
        import io
        cols = ["ts_ms", "request_id", "token_id", "token_label", "provider", "model", "status",
                "prompt_tokens", "completion_tokens", "cost_usd", "latency_ms",
                "streamed", "tools_used", "error"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in store.list_logs(limit):
            w.writerow([r.get(c) for c in cols])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                 headers={"content-disposition": "attachment; filename=proxyagent-audit.csv"})

    def _configured() -> list[str]:
        env = set(config.configured_providers())
        db = {c["provider"] for c in store.list_credentials() if c["active"]}
        return sorted(env | db)

    @app.get("/admin/usage")
    async def usage_ep(authorization: str | None = Header(None),
                       x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"usage": store.usage_summary(), "providers": _configured(),
                "tools": tools.list(), "backend": store.backend,
                "encryption": crypto.encryption_available()}

    @app.get("/admin/stats")
    async def stats_ep(authorization: str | None = Header(None),
                       x_admin_token: str | None = Header(None)):
        """One-shot operational summary: version, uptime, cache, counts, spend."""
        require_admin(authorization, x_admin_token)
        from . import __version__
        m = store.metrics()
        cs = cache.stats()
        toks = store.list_tokens()
        return {
            "version": __version__, "uptime_s": round(time.time() - started_at),
            "backend": store.backend, "encryption": crypto.encryption_available(),
            "cache": {"enabled": cache.enabled(), "ttl_s": cs["ttl"], "hits": cs["hits"], "size": cs["size"]},
            "latency_ms": store.latency_percentiles(),
            "tokens": {"active": sum(1 for t in toks if not t["revoked"]), "total": len(toks)},
            "credentials": m["credentials"], "providers": _configured(),
            "requests": m["total"]["requests"], "cost_usd": round(m["total"]["cost_usd"] or 0, 6),
        }

    @app.get("/admin/usage-by-day")
    async def usage_by_day_ep(days: int = 14, authorization: str | None = Header(None),
                              x_admin_token: str | None = Header(None)):
        """Daily usage timeseries — requests, tokens, cost per UTC day."""
        require_admin(authorization, x_admin_token)
        return {"days": store.usage_by_day(max(1, min(365, days)))}

    @app.get("/admin/usage-by-model")
    async def usage_by_model_ep(authorization: str | None = Header(None),
                                x_admin_token: str | None = Header(None)):
        """Per-model usage breakdown — which model is driving requests + spend."""
        require_admin(authorization, x_admin_token)
        rows = [{"provider": r["provider"], "model": r["model"], "requests": r["requests"],
                 "prompt_tokens": r["prompt_tokens"], "completion_tokens": r["completion_tokens"],
                 "cost_usd": round(float(r.get("cost_usd") or 0), 6)}
                for r in store.usage_by_model()]
        return {"models": rows}

    @app.get("/admin/usage-by-token")
    async def usage_by_token_ep(authorization: str | None = Header(None),
                                x_admin_token: str | None = Header(None)):
        """Per-token spend breakdown — which machine token is costing what."""
        require_admin(authorization, x_admin_token)
        rows = []
        for r in store.usage_by_token():
            budget = r.get("budget_usd")
            cost = round(float(r.get("cost_usd") or 0), 6)
            rows.append({
                "id": r["id"], "label": r["label"], "masked": r.get("masked"),
                "revoked": bool(r["revoked"]), "requests": r["requests"],
                "prompt_tokens": r["prompt_tokens"], "completion_tokens": r["completion_tokens"],
                "cost_usd": cost, "budget_usd": budget,
                "budget_pct": round(cost / budget * 100, 1) if budget else None,
                "last_call_ms": r.get("last_call_ms"), "last_used_ms": r.get("last_used_ms"),
            })
        return {"tokens": rows}

    # -- provider credentials (proxy_agent_keys) -------------------------- #
    @app.post("/admin/providers")
    async def add_provider(body: ProviderBody, authorization: str | None = Header(None),
                           x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        if body.provider not in PROVIDERS:
            raise HTTPException(400, f"unknown provider; known: {list(PROVIDERS)}")
        cid = store.add_credential(body.provider, body.secret, kind=body.kind,
                                   label=body.label, refresh=body.refresh, meta=body.meta)
        return {"id": cid, "provider": body.provider, "kind": body.kind,
                "stored": "encrypted" if crypto.encryption_available() else "plaintext"}

    @app.get("/admin/providers")
    async def list_providers(authorization: str | None = Header(None),
                             x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"credentials": store.list_credentials(), "configured": _configured(),
                "encryption": crypto.encryption_available()}

    @app.delete("/admin/providers/{cid}")
    async def del_provider(cid: str, authorization: str | None = Header(None),
                           x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        if not store.remove_credential(cid):
            raise HTTPException(404, "no such credential")
        return {"ok": True}

    @app.post("/admin/providers/{cid}/toggle")
    async def toggle_provider(cid: str, authorization: str | None = Header(None),
                              x_admin_token: str | None = Header(None)):
        """Enable/disable a stored credential (pause it without deleting)."""
        require_admin(authorization, x_admin_token)
        cred = store.get_credential_by_id(cid)
        if not cred:
            raise HTTPException(404, "no such credential")
        new_active = not bool(cred["active"])
        store.set_credential_active(cid, new_active)
        return {"id": cid, "active": new_active}

    @app.post("/admin/providers/{cid}/test")
    async def test_provider(cid: str, authorization: str | None = Header(None),
                            x_admin_token: str | None = Header(None)):
        """Ping the upstream with this stored credential and report ok / fail."""
        require_admin(authorization, x_admin_token)
        cred = store.get_credential_by_id(cid)
        if not cred:
            raise HTTPException(404, "no such credential")
        return await test_credential(config, cred["provider"], cred)

    @app.get("/admin/harnesses")
    async def harnesses(authorization: str | None = Header(None),
                        x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        kinds_by_prov: dict[str, set] = {}
        for c in store.list_credentials():
            if c["active"]:
                kinds_by_prov.setdefault(c["provider"], set()).add(c["kind"])
        out = []
        for name, h in HARNESSES.items():
            prov = PROVIDERS.get(h["provider"])
            have = kinds_by_prov.get(h["provider"], set())
            env_key = bool(prov and prov.key)

            def _conn(m):
                if m == "api_key":
                    return env_key or "api_key" in have
                return m in have

            out.append({
                "name": name, "label": h["label"], "provider": h["provider"],
                "color": h["color"], "install": h["install"],
                "auth": [{"mode": m, "label": AUTH_LABELS.get(m, m),
                          "ready": m in AUTH_READY, "connected": _conn(m)}
                         for m in h["auth"]],
                "configured": env_key or bool(have),
            })
        return {"harnesses": out}

    @app.get("/admin/catalog")
    async def catalog(authorization: str | None = Header(None),
                      x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        pool: dict[str, list] = {}
        for c in store.list_credentials():   # include disabled creds so they can be re-enabled
            pool.setdefault(c["provider"], []).append(c)
        out = []
        for name, prov in PROVIDERS.items():
            meta = CATALOG.get(name, {})
            creds = pool.get(name, [])
            out.append({
                "name": name, "label": meta.get("label", name.title()),
                "kinds": meta.get("kinds", ["api_key"]), "color": meta.get("color", "#888"),
                "models": meta.get("models", []), "shape": prov.shape,
                "via_env": bool(prov.key), "via_store": any(c["active"] for c in creds),
                "creds": [{"id": c["id"], "kind": c["kind"], "masked": c.get("masked"),
                           "label": c.get("label"), "active": bool(c["active"])} for c in creds],
                "endpoint": prov.endpoint,
            })
        return {"providers": out, "encryption": crypto.encryption_available()}

    # -- model aliases / remap -------------------------------------------- #
    @app.get("/admin/aliases")
    async def get_aliases(authorization: str | None = Header(None),
                          x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        return {"map": aliases.get_map()}

    @app.put("/admin/aliases")
    async def set_aliases(request: Request, authorization: str | None = Header(None),
                          x_admin_token: str | None = Header(None)):
        require_admin(authorization, x_admin_token)
        body = await request.json()
        aliases.set_map(body.get("map", body))
        return {"map": aliases.get_map()}

    @app.get("/healthz")
    async def healthz():
        from . import __version__
        return {"ok": True, "version": __version__, "uptime_s": round(time.time() - started_at),
                "providers": _configured(), "available": sorted(PROVIDERS),
                "tools": tools.names(), "backend": store.backend,
                "aliases": len(aliases.get_map())}

    @app.get("/readyz")
    async def readyz():
        """Readiness probe — pings the backing store. 503 if the DB is unreachable, so a
        load balancer / k8s readiness check can pull a broken instance out of rotation."""
        try:
            store.ping()
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"ready": False, "backend": store.backend, "error": str(e)[:200]},
                                status_code=503)
        return {"ready": True, "backend": store.backend}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics(authorization: str | None = Header(None),
                      x_admin_token: str | None = Header(None)):
        """Prometheus metrics. Admin-gated unless PROXYAGENT_METRICS_PUBLIC=1."""
        import os as _os
        if _os.environ.get("PROXYAGENT_METRICS_PUBLIC") != "1":
            require_admin(authorization, x_admin_token)
        m = store.metrics()
        t = m["total"]
        L = ["# HELP proxyagent_requests_total Proxied requests",
             "# TYPE proxyagent_requests_total counter",
             f"proxyagent_requests_total {t['requests']}"]
        for r in m["by_provider"]:
            L.append(f'proxyagent_requests_total{{provider="{r["provider"]}"}} {r["n"]}')
        for r in m["by_status"]:
            L.append(f'proxyagent_responses_total{{status="{r["status"]}"}} {r["n"]}')
        L += ["# HELP proxyagent_tokens_total Tokens processed", "# TYPE proxyagent_tokens_total counter",
              f'proxyagent_tokens_total{{direction="input"}} {t["prompt_tokens"]}',
              f'proxyagent_tokens_total{{direction="output"}} {t["completion_tokens"]}',
              "# HELP proxyagent_cost_usd_total Spend in USD", "# TYPE proxyagent_cost_usd_total counter",
              f"proxyagent_cost_usd_total {t['cost_usd']}"]
        for r in m["by_provider"]:
            L.append(f'proxyagent_cost_usd_total{{provider="{r["provider"]}"}} {r["c"]}')
        cs = cache.stats()
        L += ["# TYPE proxyagent_active_tokens gauge", f"proxyagent_active_tokens {m['active_tokens']}",
              "# TYPE proxyagent_credentials gauge", f"proxyagent_credentials {m['credentials']}",
              "# TYPE proxyagent_cache_hits_total counter", f"proxyagent_cache_hits_total {cs['hits']}",
              "# TYPE proxyagent_cache_size gauge", f"proxyagent_cache_size {cs['size']}"]
        return "\n".join(L) + "\n"

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    async def ui():
        idx = UI_DIR / "index.html"
        return HTMLResponse(idx.read_text() if idx.exists() else "<h1>proxyagent</h1>")

    return app
