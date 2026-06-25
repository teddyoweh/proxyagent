"""Redaction — a safety net so secret-shaped strings never land in the audit log.

Upstream error bodies (the only place we persist response text) are passed through this
before they reach `proxy_agent_calls.error`. Always on; cheap; defensive.
"""

from __future__ import annotations

import json
import re

CAPTURE_LIMIT = 16_384  # max chars stored per captured request/response body

_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{12,}"), "sk-***"),                 # OpenAI / Anthropic api keys
    (re.compile(r"pa_[A-Za-z0-9_\-]{12,}"), "pa_***"),                 # proxyagent tokens
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer ***"),  # bearer tokens
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***"),                      # AWS access key id
    (re.compile(r"ASIA[0-9A-Z]{16}"), "ASIA***"),                      # AWS temp key id
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "AIza***"),               # Google api keys
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "xox***"),          # Slack tokens
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "gh***"),              # GitHub tokens
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[private key redacted]"),
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "***@***"),  # emails
]


def redact(text: str | None) -> str | None:
    if not text:
        return text
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def capture(obj, limit: int = CAPTURE_LIMIT) -> str | None:
    """Serialize a request/response body for the audit log: JSON-encode, redact
    secret-shaped strings, and size-cap. Used for the prompt/output inspector when
    body capture is enabled. Returns None for empty input."""
    if obj is None:
        return None
    try:
        text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        text = str(obj)
    text = redact(text) or ""
    if len(text) > limit:
        text = text[:limit] + f"…[truncated {len(text) - limit} chars]"
    return text
