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


# Display metadata for the dashboard: label, the auth kinds each provider supports,
# a brand accent colour, and example models.
CATALOG: dict[str, dict] = {
    "anthropic":  {"label": "Anthropic",   "kinds": ["api_key", "oauth"], "color": "#D97757",
                   "models": ["claude-opus-4", "claude-sonnet-4-5", "claude-haiku-4"]},
    "openai":     {"label": "OpenAI",       "kinds": ["api_key", "oauth"], "color": "#10A37F",
                   "models": ["gpt-5", "gpt-4.1", "gpt-4o", "o3"]},
    "gemini":     {"label": "Google Gemini","kinds": ["api_key"],          "color": "#4285F4",
                   "models": ["gemini-2.5-pro", "gemini-2.5-flash"]},
    "groq":       {"label": "Groq",         "kinds": ["api_key"],          "color": "#F55036",
                   "models": ["llama-3.3-70b", "deepseek-r1-distill"]},
    "openrouter": {"label": "OpenRouter",   "kinds": ["api_key"],          "color": "#7C7CFF",
                   "models": ["anthropic/claude-sonnet-4.5", "openai/gpt-5"]},
    "mistral":    {"label": "Mistral",      "kinds": ["api_key"],          "color": "#FF7000",
                   "models": ["mistral-large", "codestral"]},
    "deepseek":   {"label": "DeepSeek",     "kinds": ["api_key"],          "color": "#4D6BFE",
                   "models": ["deepseek-chat", "deepseek-reasoner"]},
    "xai":        {"label": "xAI",          "kinds": ["api_key"],          "color": "#111111",
                   "models": ["grok-4", "grok-3-mini"]},
    "together":   {"label": "Together",     "kinds": ["api_key"],          "color": "#0F6FFF",
                   "models": ["llama-3.3-70b", "qwen-2.5-72b"]},
}


# Agent harnesses (what you actually RUN) and the auth modes each supports. The model
# providers above are the *backends*; these are the agents. Auth mode availability is
# what makes the proxy valuable — it can centralise all of them so the machine holds none.
HARNESSES: dict[str, dict] = {
    "claude-code": {"label": "Claude Code", "provider": "anthropic", "color": "#D97757",
                    "install": "npm i -g @anthropic-ai/claude-code",
                    "auth": ["api_key", "oauth", "bedrock", "vertex"]},
    "codex":       {"label": "Codex", "provider": "openai", "color": "#10A37F",
                    "install": "npm i -g @openai/codex",
                    "auth": ["api_key", "oauth", "azure"]},
    "gemini-cli":  {"label": "Gemini CLI", "provider": "gemini", "color": "#4285F4",
                    "install": "npm i -g @google/gemini-cli",
                    "auth": ["api_key", "oauth", "vertex"]},
}
AUTH_LABELS = {"api_key": "API key", "oauth": "OAuth", "bedrock": "AWS Bedrock",
               "vertex": "Google Vertex", "azure": "Azure"}
# Auth modes that are fully wired today (just a key swap). Others are surfaced in the
# UI as "available" and built out (Bedrock SigV4 / Vertex token / OAuth refresh).
AUTH_READY = {"api_key"}


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
        existing = admin_file.read_text().strip() if admin_file.exists() else ""
        if env_admin:
            # Production: trust the env token, persist nothing.
            cfg.admin_token_hash = hash_token(env_admin)
        elif existing.startswith(ADMIN_PREFIX):
            # Local: the plaintext is stored (0600) so the dashboard stays reachable.
            cfg.admin_token_plain = existing
            cfg.admin_token_hash = hash_token(existing)
        else:
            # Fresh (or migrating an old hash-only file we can't recover): regenerate.
            plain = new_token(ADMIN_PREFIX)
            admin_file.write_text(plain)
            admin_file.chmod(0o600)
            cfg.admin_token_plain = plain
            cfg.admin_token_hash = hash_token(plain)
        return cfg

    def configured_providers(self) -> list[str]:
        return [n for n, p in PROVIDERS.items() if p.key]
