"""Model remapping — rewrite the requested model (and optionally re-route to another
provider) before forwarding.

A map entry's value is either a model name (rename) or "provider:model" (reroute):

    PROXYAGENT_MODEL_MAP='{"*": "mock"}'                       # force everything offline
    PROXYAGENT_MODEL_MAP='{"gpt-4o": "anthropic:claude-sonnet-4-5"}'   # reroute to Claude

Lookup order: exact "provider:model" → exact "model" → wildcard "*".
Runtime overrides (set via the admin API) win over the env map.
"""

from __future__ import annotations

import json
import os

_RUNTIME: dict[str, str] = {}


def _env_map() -> dict[str, str]:
    raw = os.environ.get("PROXYAGENT_MODEL_MAP")
    if not raw:
        return {}
    try:
        return {str(k): str(v) for k, v in json.loads(raw).items()}
    except Exception:
        return {}


def get_map() -> dict[str, str]:
    return {**_env_map(), **_RUNTIME}


def set_map(m: dict) -> None:
    _RUNTIME.clear()
    _RUNTIME.update({str(k): str(v) for k, v in (m or {}).items()})


def remap(provider: str, model: str) -> tuple[str, str]:
    """Return the (provider, model) to actually use."""
    m = get_map()
    target = m.get(f"{provider}:{model}") or m.get(model) or m.get("*")
    if not target:
        return provider, model
    if ":" in target:
        p, mm = target.split(":", 1)
        return p, mm
    return provider, target
