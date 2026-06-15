"""proxyagent — run any agent (Claude, Codex, custom) on any machine, with no API
key on the machine. A secure, self-hosted proxy for models *and* tools.

    # on the proxy host (holds the real keys):
    import proxyagent
    proxyagent.serve()                       # or: $ proxyagent serve

    # on any remote machine (holds only a throwaway token):
    proxyagent.run("claude-code", goal="build the app",
                   proxy="https://proxy.you.com", token="pa_…")
"""

from __future__ import annotations

from typing import Optional

from .harness import run  # noqa: F401  (the headline SDK call)

__version__ = "0.6.0"
__all__ = ["run", "serve", "create_app", "Config", "Admin", "__version__"]


def create_app(config=None):
    """The ASGI app, for embedding behind your own server."""
    from .server import create_app as _c
    return _c(config)


def serve(host: str = "127.0.0.1", port: int = 8080, config=None):
    """Run the proxy + dashboard."""
    import uvicorn
    from .config import Config
    cfg = config or Config.load()
    uvicorn.run(create_app(cfg), host=host, port=port, log_level="warning")


def Config():  # noqa: N802 — convenience re-export
    from .config import Config as _C
    return _C.load()


class Admin:
    """Programmatic admin client — mint/list/revoke tokens against a running proxy."""

    def __init__(self, proxy: str, admin_token: str):
        import httpx
        self._c = httpx.Client(base_url=proxy.rstrip("/"),
                               headers={"x-admin-token": admin_token}, timeout=30)

    def mint(self, label: str = "machine", scope: Optional[list] = None,
             ttl_seconds: Optional[int] = None, rate_limit: int = 0) -> str:
        r = self._c.post("/admin/tokens", json={
            "label": label, "scope": scope or ["*"], "ttl_seconds": ttl_seconds,
            "rate_limit": rate_limit})
        r.raise_for_status()
        return r.json()["token"]

    def tokens(self) -> list:
        return self._c.get("/admin/tokens").json()["tokens"]

    def revoke(self, token_id: str) -> None:
        self._c.delete(f"/admin/tokens/{token_id}").raise_for_status()

    def add_provider(self, provider: str, secret: str, kind: str = "api_key",
                     label: Optional[str] = None) -> str:
        r = self._c.post("/admin/providers", json={
            "provider": provider, "secret": secret, "kind": kind, "label": label})
        r.raise_for_status()
        return r.json()["id"]

    def providers(self) -> dict:
        return self._c.get("/admin/providers").json()

    def remove_provider(self, cred_id: str) -> None:
        self._c.delete(f"/admin/providers/{cred_id}").raise_for_status()

    def logs(self, limit: int = 100) -> list:
        return self._c.get("/admin/logs", params={"limit": limit}).json()["logs"]

    def usage(self) -> dict:
        return self._c.get("/admin/usage").json()
