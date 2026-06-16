"""Optional response cache — identical (provider, body) requests are served from memory,
saving upstream cost + latency.

Off by default. Enable with `PROXYAGENT_CACHE_TTL=<seconds>`. Per-request bypass with the
header `x-proxyagent-cache: no`. Non-streaming JSON responses only.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

_CACHE: dict[str, tuple[dict, int]] = {}   # key -> (payload, expiry_ms)
_HITS = 0


def ttl_seconds() -> int:
    try:
        return int(os.environ.get("PROXYAGENT_CACHE_TTL", "0") or 0)
    except ValueError:
        return 0


def enabled() -> bool:
    return ttl_seconds() > 0


def key(provider: str, body: dict) -> str:
    blob = provider + "|" + json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def get(k: str):
    global _HITS
    v = _CACHE.get(k)
    if not v:
        return None
    if v[1] < int(time.time() * 1000):
        _CACHE.pop(k, None)
        return None
    _HITS += 1
    return v[0]


def put(k: str, payload: dict) -> None:
    _CACHE[k] = (payload, int(time.time() * 1000) + ttl_seconds() * 1000)


def stats() -> dict:
    return {"size": len(_CACHE), "hits": _HITS, "ttl": ttl_seconds()}
