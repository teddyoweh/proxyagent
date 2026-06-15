"""Configuration — provider upstreams, real credentials (env only), paths, admin auth.

Real keys are read from the environment and never persisted. The proxy is the ONLY
place they live.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .security import hash_token, new_token, ADMIN_PREFIX

HOME = Path(os.environ.get("PROXYAGENT_HOME", Path.home() / ".proxyagent"))


@dataclass
class Provider:
    name: str
    endpoint: str          # full upstream URL (e.g. …/v1/chat/completions)
    key_env: str           # env var holding the REAL key
    auth_style: str        # "bearer" | "x-api-key"
    shape: str             # "openai" | "anthropic" (request + usage format)
    extra_headers: dict = field(default_factory=dict)

    @property
    def key(self) -> str | None:
        return os.environ.get(self.key_env)

    def auth_headers(self) -> dict:
        key = self.key
        if not key:
            return {}
        if self.auth_style == "x-api-key":
            return {"x-api-key": key, **self.extra_headers}
        return {"Authorization": f"Bearer {key}", **self.extra_headers}


def _p(name, endpoint, key_env, *, shape="openai", style="bearer", extra=None) -> Provider:
    endpoint = os.environ.get(f"PROXYAGENT_{name.upper()}_ENDPOINT", endpoint)
    return Provider(name, endpoint, key_env, style, shape, extra or {})


# Built-in upstreams. Anthropic uses its Messages API; the rest are OpenAI-compatible.
# Add your own / override endpoints via PROXYAGENT_<NAME>_ENDPOINT.
PROVIDERS: dict[str, Provider] = {
    "anthropic":  _p("anthropic", "https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY",
                     shape="anthropic", style="x-api-key",
                     extra={"anthropic-version": os.environ.get("ANTHROPIC_VERSION", "2023-06-01")}),
    "openai":     _p("openai", "https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "gemini":     _p("gemini", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "GEMINI_API_KEY"),
    "groq":       _p("groq", "https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY"),
    "openrouter": _p("openrouter", "https://openrouter.ai/api/v1/chat/completions", "OPENROUTER_API_KEY"),
    "mistral":    _p("mistral", "https://api.mistral.ai/v1/chat/completions", "MISTRAL_API_KEY"),
    "deepseek":   _p("deepseek", "https://api.deepseek.com/v1/chat/completions", "DEEPSEEK_API_KEY"),
    "xai":        _p("xai", "https://api.x.ai/v1/chat/completions", "XAI_API_KEY"),
    "together":   _p("together", "https://api.together.xyz/v1/chat/completions", "TOGETHER_API_KEY"),
}


@dataclass
class Config:
    home: Path = HOME
    db_path: str = ""
    admin_token_hash: str = ""
    admin_token_plain: str | None = None   # only set when freshly generated
    request_timeout: float = 600.0

    @classmethod
    def load(cls) -> "Config":
        HOME.mkdir(parents=True, exist_ok=True)
        cfg = cls(db_path=str(HOME / "proxyagent.db"))
        # Admin token: from env, or a persisted one, or freshly generated (shown once).
        env_admin = os.environ.get("PROXYAGENT_ADMIN_TOKEN")
        admin_file = HOME / "admin_token"
        if env_admin:
            cfg.admin_token_hash = hash_token(env_admin)
        elif admin_file.exists():
            cfg.admin_token_hash = admin_file.read_text().strip()
        else:
            plain = new_token(ADMIN_PREFIX)
            cfg.admin_token_hash = hash_token(plain)
            admin_file.write_text(cfg.admin_token_hash)
            admin_file.chmod(0o600)
            cfg.admin_token_plain = plain
        return cfg

    def configured_providers(self) -> list[str]:
        return [n for n, p in PROVIDERS.items() if p.key]
