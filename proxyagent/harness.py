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
    # build argv from a goal (headless / non-interactive invocation)
    launch: Callable[[str], list[str]]
    check: list[str] = field(default_factory=list)     # how to detect it's installed
    install_hint: str = ""

    def env(self, proxy_url: str, token: str) -> dict:
        base = proxy_url.rstrip("/")
        return {
            "ANTHROPIC_BASE_URL": f"{base}/anthropic",
            "ANTHROPIC_API_KEY": token,
            "OPENAI_BASE_URL": f"{base}/openai/v1",
            "OPENAI_API_BASE": f"{base}/openai/v1",
            "OPENAI_API_KEY": token,
        }


HARNESSES: dict[str, Harness] = {
    "claude-code": Harness(
        name="claude-code",
        launch=lambda goal: ["claude", "-p", goal, "--permission-mode", "bypassPermissions"],
        check=["claude", "--version"],
        install_hint="npm i -g @anthropic-ai/claude-code",
    ),
    "codex": Harness(
        name="codex",
        launch=lambda goal: ["codex", "exec", goal],
        check=["codex", "--version"],
        install_hint="npm i -g @openai/codex",
    ),
}


def register_custom(name: str, command: str) -> Harness:
    """A custom harness: `command` is a template; {goal} is substituted."""
    def _launch(goal: str) -> list[str]:
        return shlex.split(command.replace("{goal}", goal)) if "{goal}" in command \
            else shlex.split(command) + [goal]
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
    env = {**os.environ, **h.env(proxy_url, token), **(extra_env or {})}
    argv = h.launch(goal)
    proc = subprocess.run(argv, cwd=cwd, env=env)
    return proc.returncode
