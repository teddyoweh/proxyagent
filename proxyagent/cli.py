"""proxyagent CLI — serve the proxy, mint tokens, run harnesses, watch usage."""

from __future__ import annotations

import os
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Run any agent on any machine — with no API key on the machine.", no_args_is_help=True)
console = Console()
err = Console(stderr=True)


DEFAULT_PROXY = "http://127.0.0.1:8080"


def _admin_client(proxy: str, admin: Optional[str]) -> httpx.Client:
    admin = admin or os.environ.get("PROXYAGENT_ADMIN_TOKEN")
    if not admin:
        err.print("[red]Need an admin token[/red] (--admin or PROXYAGENT_ADMIN_TOKEN). "
                  "It's printed when you run [bold]proxyagent serve[/bold].")
        raise typer.Exit(1)
    return httpx.Client(base_url=proxy.rstrip("/"), headers={"x-admin-token": admin}, timeout=30)


def _is_remote(proxy: str, admin: Optional[str]) -> bool:
    """Manage a REMOTE proxy (via admin API) only if an admin token is given or the
    proxy isn't localhost. Otherwise operate on the LOCAL store directly — no admin
    token needed, you already have filesystem access."""
    from urllib.parse import urlparse
    if admin or os.environ.get("PROXYAGENT_ADMIN_TOKEN"):
        return True
    return urlparse(proxy).hostname not in (None, "127.0.0.1", "localhost", "0.0.0.0")


def _local_store():
    from .config import Config
    from .store import Store
    return Store(Config.load().db_path)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8080):
    """Run the proxy server + dashboard."""
    import uvicorn

    from .config import Config
    from .server import create_app

    config = Config.load()
    if config.admin_token_plain:
        console.print(Panel.fit(
            f"[green]✓ proxyagent[/green]\n\n[bold]Admin token[/bold] (for the dashboard)\n"
            f"  [yellow]{config.admin_token_plain}[/yellow]\n\n"
            f"[dim]Reveal anytime: [bold]proxyagent admin-token[/bold][/dim]",
            border_style="green"))
    console.print(f"[dim]Dashboard:[/dim] http://{host}:{port}   "
                  f"[dim]providers:[/dim] {', '.join(config.configured_providers()) or 'none — `proxyagent provider add anthropic --key …`'}")
    console.print("[dim]Mint a machine token in another terminal:[/dim] [bold]proxyagent token new[/bold] [dim](works locally, no admin token needed)[/dim]")
    uvicorn.run(create_app(config), host=host, port=port, log_level="warning")


@app.command("admin-token")
def admin_token():
    """Print this machine's admin token (for the dashboard)."""
    from .config import Config
    cfg = Config.load()
    if cfg.admin_token_plain:
        console.print(cfg.admin_token_plain)
    else:
        err.print("[yellow]Admin token is set via PROXYAGENT_ADMIN_TOKEN (not stored here).[/yellow]")


@app.command("run")
def run_harness(
    harness: str = typer.Argument(..., help="claude-code | codex | <custom>"),
    goal: str = typer.Option(..., "--goal", "-g", help="What the agent should do."),
    proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
    token: Optional[str] = typer.Option(None, "--token", help="Machine token (or PROXYAGENT_TOKEN)."),
    command: Optional[str] = typer.Option(None, "--command", help="Custom harness command template."),
    cwd: Optional[str] = typer.Option(None, "--cwd"),
):
    """Run a harness on THIS machine, pointed at the proxy (no real key needed here)."""
    from . import harness as H

    tok = token or os.environ.get("PROXYAGENT_TOKEN")
    if not tok:
        err.print("[red]Need a machine token[/red] (--token or PROXYAGENT_TOKEN).")
        raise typer.Exit(1)
    console.print(f"[dim]→ {harness} via {proxy} (no key on this machine)[/dim]")
    code = H.run(harness, goal, proxy_url=proxy, token=tok, cwd=cwd, command=command)
    raise typer.Exit(code)


token_app = typer.Typer(help="Mint / list / revoke machine tokens.")
app.add_typer(token_app, name="token")
provider_app = typer.Typer(help="Add / list / remove provider credentials (stored, encrypted).")
app.add_typer(provider_app, name="provider")
alias_app = typer.Typer(help="Model remap — rename or reroute models (e.g. force everything to mock).")
app.add_typer(alias_app, name="alias")


@alias_app.command("ls")
def alias_ls(proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
             admin: str = typer.Option(None, "--admin")):
    """Show the current model map."""
    with _admin_client(proxy, admin) as c:
        m = c.get("/admin/aliases").json()["map"]
    if not m:
        console.print("[dim]No aliases. e.g. `proxyagent alias set '*' mock`[/dim]"); return
    t = Table(title="Model aliases")
    t.add_column("Match"); t.add_column("→ Target")
    for k, v in m.items():
        t.add_row(k, v)
    console.print(t)


@alias_app.command("set")
def alias_set(match: str, target: str,
              proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
              admin: str = typer.Option(None, "--admin")):
    """Map a model → a model (rename) or 'provider:model' (reroute). Use '*' to catch all."""
    with _admin_client(proxy, admin) as c:
        m = c.get("/admin/aliases").json()["map"]
        m[match] = target
        c.put("/admin/aliases", json={"map": m})
    console.print(f"[green]✓[/green] [cyan]{match}[/cyan] → {target}")


@alias_app.command("rm")
def alias_rm(match: str, proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
             admin: str = typer.Option(None, "--admin")):
    """Remove an alias."""
    with _admin_client(proxy, admin) as c:
        m = c.get("/admin/aliases").json()["map"]
        m.pop(match, None)
        c.put("/admin/aliases", json={"map": m})
    console.print(f"[green]✓[/green] removed {match}")


@provider_app.command("add")
def provider_add(
    provider: str = typer.Argument(..., help="anthropic | openai"),
    key: str = typer.Option(..., "--key", "--secret", help="API key, or OAuth access token with --kind oauth."),
    kind: str = typer.Option("api_key", "--kind", help="api_key | oauth"),
    label: str = typer.Option(None, "--label"),
    proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
    admin: str = typer.Option(None, "--admin"),
):
    """Store a provider credential (encrypted if PROXYAGENT_SECRET_KEY is set)."""
    from .config import PROVIDERS
    if provider not in PROVIDERS:
        err.print(f"[red]✗[/red] unknown provider; known: {', '.join(PROVIDERS)}"); raise typer.Exit(1)
    if not _is_remote(proxy, admin):
        from . import crypto
        _local_store().add_credential(provider, key, kind=kind, label=label)
        stored = "encrypted" if crypto.encryption_available() else "plaintext"
    else:
        with _admin_client(proxy, admin) as c:
            r = c.post("/admin/providers", json={"provider": provider, "secret": key,
                                                 "kind": kind, "label": label})
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
        stored = r.json()["stored"]
    note = "[green]encrypted[/green]" if stored == "encrypted" else "[yellow]plaintext — set PROXYAGENT_SECRET_KEY[/yellow]"
    console.print(f"[green]✓[/green] stored [cyan]{provider}[/cyan] ({kind}) · {note}")


@provider_app.command("ls")
def provider_ls(proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
                admin: str = typer.Option(None, "--admin")):
    """List stored provider credentials (secrets never shown)."""
    if not _is_remote(proxy, admin):
        from . import crypto
        from .config import PROVIDERS
        creds = _local_store().list_credentials()
        configured = sorted({n for n, p in PROVIDERS.items() if p.key}
                            | {c["provider"] for c in creds if c["active"]})
        d = {"credentials": creds, "configured": configured, "encryption": crypto.encryption_available()}
    else:
        with _admin_client(proxy, admin) as c:
            r = c.get("/admin/providers")
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
        d = r.json()
    t = Table(title=f"Provider credentials  ·  encryption {'on' if d['encryption'] else 'OFF'}")
    for col in ("ID", "Provider", "Kind", "Label", "Active"):
        t.add_column(col)
    for k in d["credentials"]:
        t.add_row(k["id"], k["provider"], k["kind"], k.get("label") or "",
                  "[green]yes[/green]" if k["active"] else "no")
    console.print(t)
    console.print(f"[dim]configured (env+stored): {', '.join(d['configured']) or 'none'}[/dim]")


@provider_app.command("rm")
def provider_rm(cred_id: str, proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
                admin: str = typer.Option(None, "--admin")):
    """Remove a stored credential."""
    if not _is_remote(proxy, admin):
        if not _local_store().remove_credential(cred_id):
            err.print(f"[red]✗[/red] no such credential"); raise typer.Exit(1)
    else:
        with _admin_client(proxy, admin) as c:
            r = c.delete(f"/admin/providers/{cred_id}")
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
    console.print(f"[green]✓[/green] removed {cred_id}")


@token_app.command("new")
def token_new(
    label: str = typer.Argument("machine"),
    scope: list[str] = typer.Option(["*"], "--scope", help="Allowed provider:model globs, e.g. anthropic:claude-*"),
    ttl: Optional[int] = typer.Option(None, "--ttl", help="Seconds until expiry."),
    rate: int = typer.Option(0, "--rate", help="Max requests/min (0 = unlimited)."),
    budget: Optional[float] = typer.Option(None, "--budget", help="Max $ this token may spend."),
    proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
    admin: Optional[str] = typer.Option(None, "--admin"),
):
    """Mint a machine token — give it to a remote machine; it holds no real key."""
    if not _is_remote(proxy, admin):
        plain, _ = _local_store().create_token(label, list(scope), ttl_seconds=ttl,
                                               rate_limit=rate, budget_usd=budget)
    else:
        with _admin_client(proxy, admin) as c:
            r = c.post("/admin/tokens", json={"label": label, "scope": list(scope),
                                              "ttl_seconds": ttl, "rate_limit": rate,
                                              "budget_usd": budget})
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
        plain = r.json()["token"]
    console.print(Panel.fit(
        f"[green]✓ machine token[/green] [dim]({label})[/dim]\n\n  [yellow]{plain}[/yellow]\n\n"
        f"[dim]scope: {', '.join(scope)} · shown once[/dim]", border_style="green"))


@token_app.command("ls")
def token_ls(proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
             admin: Optional[str] = typer.Option(None, "--admin")):
    """List machine tokens."""
    if not _is_remote(proxy, admin):
        import json as _json
        rows = [{"id": t["id"], "label": t["label"], "masked": t["masked"],
                 "scope": _json.loads(t["scope_json"]), "revoked": t["revoked"]}
                for t in _local_store().list_tokens()]
    else:
        with _admin_client(proxy, admin) as c:
            r = c.get("/admin/tokens")
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
        rows = r.json()["tokens"]
    if not rows:
        console.print("[dim]No tokens.[/dim]"); return
    t = Table(title="Machine tokens")
    for col in ("ID", "Label", "Token", "Scope", "Status"):
        t.add_column(col)
    for k in rows:
        t.add_row(k["id"], k["label"], k["masked"], ", ".join(k["scope"]),
                  "[red]revoked[/red]" if k["revoked"] else "[green]active[/green]")
    console.print(t)


@token_app.command("revoke")
def token_revoke(token_id: str, proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
                 admin: Optional[str] = typer.Option(None, "--admin")):
    """Revoke a token by id."""
    if not _is_remote(proxy, admin):
        if not _local_store().revoke_token(token_id):
            err.print(f"[red]✗[/red] no such token"); raise typer.Exit(1)
    else:
        with _admin_client(proxy, admin) as c:
            r = c.delete(f"/admin/tokens/{token_id}")
        if r.status_code >= 400:
            err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
    console.print(f"[green]✓[/green] revoked {token_id}")


@app.command()
def logs(limit: int = 50, proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
         admin: Optional[str] = typer.Option(None, "--admin")):
    """Recent proxied requests (audit log)."""
    with _admin_client(proxy, admin) as c:
        r = c.get("/admin/logs", params={"limit": limit})
    if r.status_code >= 400:
        err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
    rows = r.json()["logs"]
    t = Table(title="Requests")
    for col in ("Token", "Provider", "Model", "Status", "In", "Out", "Cost", "ms"):
        t.add_column(col)
    for g in rows:
        cost = g.get("cost_usd")
        t.add_row(g.get("token_label") or "", g.get("provider") or "", (g.get("model") or "")[:28],
                  str(g.get("status") or ""), str(g.get("prompt_tokens") or "-"),
                  str(g.get("completion_tokens") or "-"),
                  f"${cost:.4f}" if cost else "-", str(g.get("latency_ms") or ""))
    console.print(t)


@app.command()
def usage(proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
          admin: str = typer.Option(None, "--admin")):
    """Totals: requests, tokens, and cost across all proxied calls."""
    with _admin_client(proxy, admin) as c:
        r = c.get("/admin/usage")
    if r.status_code >= 400:
        err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
    d = r.json()
    u = d["usage"]
    console.print(Panel.fit(
        f"[bold]{u['requests']}[/bold] requests   "
        f"[bold]{u['prompt_tokens']:,}[/bold] in · [bold]{u['completion_tokens']:,}[/bold] out   "
        f"[green]${u.get('cost_usd', 0):.4f}[/green]\n"
        f"[dim]backend: {d.get('backend')} · providers: {', '.join(d['providers']) or 'none'} · "
        f"encryption: {'on' if d.get('encryption') else 'off'}[/dim]",
        title="usage", border_style="green"))


if __name__ == "__main__":
    app()
