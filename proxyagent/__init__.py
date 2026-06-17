"""proxyagent — run any agent (Claude, Codex, custom) on any machine, with no API
key on the machine. A secure, self-hosted proxy for models *and* tools.

    # on the proxy host (holds the real keys):
    import proxyagent
    proxyagent.serve()                       # or: $ proxyagent serve

    # on any remote machine (holds only a throwaway token) — token + prompt, it just runs:
    import proxyagent
    proxyagent.run("build the app", token="pa_…", proxy="https://proxy.you.com")
"""

from __future__ import annotations

import os
from typing import Optional

__version__ = "0.61.0"
__all__ = ["run", "serve", "create_app", "Config", "Admin", "__version__"]


def run(goal: str, *, harness: str = "claude-code", token: Optional[str] = None,
        proxy: Optional[str] = None, command: Optional[str] = None,
        cwd: Optional[str] = None, extra_env: Optional[dict] = None) -> int:
    """Run a real agent on THIS machine against `goal` — with no API key here, just the
    proxy token. The headline SDK call:

        import proxyagent
        proxyagent.run("build a SwiftUI todo app",
                       token="pa_…", proxy="https://proxy.you.com")

    Launches Claude Code (default; or harness="codex", or any command="my-agent {goal}")
    with its *_BASE_URL pointed at the proxy and the machine token as its key. The real
    provider key never touches this machine. Returns the process exit code.
    """
    from .harness import run as _run_harness
    token = token or os.environ.get("PROXYAGENT_TOKEN")
    if not token:
        raise ValueError("proxyagent.run needs a machine token (token='pa_…' or PROXYAGENT_TOKEN env)")
    proxy = proxy or os.environ.get("PROXYAGENT_PROXY") or "http://127.0.0.1:8080"
    return _run_harness(harness, goal, proxy_url=proxy, token=token,
                        command=command, cwd=cwd, extra_env=extra_env)


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

    def stats(self) -> dict:
        """One-shot operational summary: version, uptime, cache, counts, spend."""
        return self._c.get("/admin/stats").json()

    def summary(self) -> str:
        """A shareable Markdown status report (totals, top providers/models)."""
        r = self._c.get("/admin/summary")
        r.raise_for_status()
        return r.text

    def usage_by_token(self) -> list:
        """Per-token spend breakdown — which machine token is costing what."""
        return self._c.get("/admin/usage-by-token").json()["tokens"]

    def usage_by_model(self) -> list:
        """Per-model usage breakdown — which model is driving requests + spend."""
        return self._c.get("/admin/usage-by-model").json()["models"]

    def usage_by_day(self, days: int = 14) -> list:
        """Daily usage timeseries — requests, tokens, cost per UTC day."""
        return self._c.get("/admin/usage-by-day", params={"days": days}).json()["days"]

    def export_logs(self, limit: int = 100_000) -> str:
        """The audit trail as CSV text (for SIEM / archival)."""
        r = self._c.get("/admin/logs/export", params={"limit": limit})
        r.raise_for_status()
        return r.text

    def trim_logs(self, days: int = 30) -> int:
        """Delete call traces older than `days`; returns the number removed."""
        r = self._c.post("/admin/logs/trim", params={"days": days})
        r.raise_for_status()
        return r.json()["deleted"]

    def test_credential(self, cred_id: str) -> dict:
        """Ping the upstream with a stored credential; reports ok / reachable / auth."""
        r = self._c.post(f"/admin/providers/{cred_id}/test")
        r.raise_for_status()
        return r.json()

    def test_all_credentials(self) -> dict:
        """Health-sweep every stored credential concurrently; {results, ok, total}."""
        r = self._c.post("/admin/providers/test-all")
        r.raise_for_status()
        return r.json()
