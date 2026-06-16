"""Run an agent harness on a machine, pointed at the proxy — so the machine holds
only the throwaway proxy token, never a real key.

Almost every harness honours `*_BASE_URL`, so the shim is tiny: set the base URL to
the proxy, set the "api key" to the machine token, and launch the harness unmodified.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Harness:
    name: str
    # build argv from (goal, proxy_base) — the base is the proxy root, no trailing slash
    launch: Callable[[str, str], list[str]]
    check: list[str] = field(default_factory=list)     # how to detect it's installed
    install_hint: str = ""

    def env(self, proxy_url: str, token: str) -> dict:
        base = proxy_url.rstrip("/")
        return {
            "ANTHROPIC_BASE_URL": f"{base}/anthropic",
            "ANTHROPIC_API_KEY": token,
            "ANTHROPIC_AUTH_TOKEN": token,
            "OPENAI_BASE_URL": f"{base}/openai/v1",
            "OPENAI_API_BASE": f"{base}/openai/v1",
            "OPENAI_API_KEY": token,
        }


def _codex_launch(goal: str, base: str) -> list[str]:
    """Codex ignores OPENAI_BASE_URL/OPENAI_API_KEY (it defaults to ChatGPT OAuth), so we
    define a one-off model provider pointing at the proxy in API-key mode + the chat wire
    API (which the proxy speaks). The key is read from OPENAI_API_KEY (set in env())."""
    return [
        "codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
        "-c", "model_provider=proxyagent",
        "-c", "model_providers.proxyagent.name=proxyagent",
        "-c", f"model_providers.proxyagent.base_url={base}/openai/v1",
        "-c", "model_providers.proxyagent.env_key=OPENAI_API_KEY",
        "-c", "model_providers.proxyagent.wire_api=chat",
        goal,
    ]


HARNESSES: dict[str, Harness] = {
    # Claude Code honours ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY (set in env()).
    "claude-code": Harness(
        name="claude-code",
        launch=lambda goal, base: ["claude", "-p", goal, "--permission-mode", "bypassPermissions"],
        check=["claude", "--version"],
        install_hint="npm i -g @anthropic-ai/claude-code",
    ),
    "codex": Harness(
        name="codex",
        launch=_codex_launch,
        check=["codex", "--version"],
        install_hint="npm i -g @openai/codex   (or: brew install codex)",
    ),
}


def register_custom(name: str, command: str) -> Harness:
    """A custom harness: `command` is a template; {goal} and {proxy} are substituted."""
    def _launch(goal: str, base: str) -> list[str]:
        cmd = command.replace("{proxy}", base)
        return shlex.split(cmd.replace("{goal}", goal)) if "{goal}" in cmd \
            else shlex.split(cmd) + [goal]
    h = Harness(name=name, launch=_launch)
    HARNESSES[name] = h
    return h


def run(harness: str, goal: str, *, proxy_url: str, token: str,
        cwd: str | None = None, extra_env: dict | None = None,
        command: str | None = None) -> int:
    """Run a harness against a goal, pointed at the proxy. Streams to stdout.
    Returns the exit code."""
    h = HARNESSES.get(harness) or (register_custom(harness, command) if command else None)
    if h is None:
        raise ValueError(f"unknown harness {harness!r} (pass command=... for a custom one)")
    base = proxy_url.rstrip("/")
    env = {**os.environ, **h.env(proxy_url, token), **(extra_env or {})}
    argv = h.launch(goal, base)
    proc = subprocess.run(argv, cwd=cwd, env=env)
    return proc.returncode
