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


def _admin_client(proxy: str, admin: Optional[str]) -> httpx.Client:
    admin = admin or os.environ.get("PROXYAGENT_ADMIN_TOKEN")
    if not admin:
        err.print("[red]Need an admin token[/red] (--admin or PROXYAGENT_ADMIN_TOKEN). "
                  "It's printed when you run [bold]proxyagent serve[/bold].")
        raise typer.Exit(1)
    return httpx.Client(base_url=proxy.rstrip("/"), headers={"x-admin-token": admin}, timeout=30)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8080):
    """Run the proxy server + dashboard."""
    import uvicorn

    from .config import Config
    from .server import create_app

    config = Config.load()
    if config.admin_token_plain:
        console.print(Panel.fit(
            f"[green]✓ proxyagent[/green]\n\n[bold]Admin token[/bold] (shown once)\n"
            f"  [yellow]{config.admin_token_plain}[/yellow]\n\n"
            f"[dim]Save it — you need it for the dashboard + `proxyagent token`.[/dim]",
            border_style="green"))
    console.print(f"[dim]Dashboard:[/dim] http://{host}:{port}   "
                  f"[dim]providers:[/dim] {', '.join(config.configured_providers()) or 'none — set ANTHROPIC_API_KEY / OPENAI_API_KEY'}")
    uvicorn.run(create_app(config), host=host, port=port, log_level="warning")


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


@token_app.command("new")
def token_new(
    label: str = typer.Argument("machine"),
    scope: list[str] = typer.Option(["*"], "--scope", help="Allowed provider:model globs, e.g. anthropic:claude-*"),
    ttl: Optional[int] = typer.Option(None, "--ttl", help="Seconds until expiry."),
    rate: int = typer.Option(0, "--rate", help="Max requests/min (0 = unlimited)."),
    proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
    admin: Optional[str] = typer.Option(None, "--admin"),
):
    """Mint a machine token — give it to a remote machine; it holds no real key."""
    with _admin_client(proxy, admin) as c:
        r = c.post("/admin/tokens", json={"label": label, "scope": list(scope),
                                          "ttl_seconds": ttl, "rate_limit": rate})
    if r.status_code >= 400:
        err.print(f"[red]✗[/red] {r.text}"); raise typer.Exit(1)
    d = r.json()
    console.print(Panel.fit(
        f"[green]✓ machine token[/green] [dim]({label})[/dim]\n\n  [yellow]{d['token']}[/yellow]\n\n"
        f"[dim]scope: {', '.join(scope)} · shown once[/dim]", border_style="green"))


@token_app.command("ls")
def token_ls(proxy: str = typer.Option("http://127.0.0.1:8080", "--proxy"),
             admin: Optional[str] = typer.Option(None, "--admin")):
    """List machine tokens."""
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
    for col in ("Token", "Provider", "Model", "Status", "In", "Out", "ms"):
        t.add_column(col)
    for g in rows:
        t.add_row(g.get("token_label") or "", g.get("provider") or "", (g.get("model") or "")[:28],
                  str(g.get("status") or ""), str(g.get("prompt_tokens") or "-"),
                  str(g.get("completion_tokens") or "-"), str(g.get("latency_ms") or ""))
    console.print(t)


if __name__ == "__main__":
    app()
