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
    base_url: str          # upstream API root
    key_env: str           # env var holding the REAL key
    auth_style: str        # "bearer" (OpenAI) | "x-api-key" (Anthropic)
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


# Built-in upstreams. base_url overridable via env (e.g. Azure, self-hosted, gateways).
def _provider(name, default_base, key_env, style, extra=None) -> Provider:
    base = os.environ.get(f"PROXYAGENT_{name.upper()}_BASE_URL", default_base)
    return Provider(name, base.rstrip("/"), key_env, style, extra or {})


PROVIDERS: dict[str, Provider] = {
    "anthropic": _provider(
        "anthropic", "https://api.anthropic.com", "ANTHROPIC_API_KEY", "x-api-key",
        {"anthropic-version": os.environ.get("ANTHROPIC_VERSION", "2023-06-01")},
    ),
    "openai": _provider("openai", "https://api.openai.com", "OPENAI_API_KEY", "bearer"),
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
