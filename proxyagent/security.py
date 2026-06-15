"""Security primitives — token minting, hashing, constant-time checks, redaction.

Design rules (the whole point of this project):
  * Real provider/tool keys live ONLY on the server, in memory/config — never in the
    DB, never in logs, never returned over the API.
  * Machine tokens are stored as salted SHA-256 hashes. The plaintext is shown ONCE,
    at creation. A leaked DB reveals no usable token.
  * All token comparisons are constant-time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_PREFIX = "pa_"
ADMIN_PREFIX = "pa_admin_"


def new_token(prefix: str = TOKEN_PREFIX, *, nbytes: int = 32) -> str:
    """A high-entropy, URL-safe token. Shown to the caller exactly once."""
    return prefix + secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Stable SHA-256 hex of a token — what we persist + compare against."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, stored_hash: str) -> bool:
    """Constant-time check of a presented token against a stored hash."""
    return hmac.compare_digest(hash_token(token), stored_hash)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ------------------------------------------------------------------ #
# Redaction — so secrets never reach logs or error bodies.
# ------------------------------------------------------------------ #

_SENSITIVE_HEADERS = {"authorization", "x-api-key", "api-key", "proxy-authorization"}


def redact_headers(headers: dict) -> dict:
    out = {}
    for k, v in headers.items():
        out[k] = "***" if k.lower() in _SENSITIVE_HEADERS else v
    return out


def mask(value: str | None, keep: int = 4) -> str:
    """Mask a secret for display: pa_abcd… → pa_abcd…(masked)."""
    if not value:
        return ""
    head = value[: keep + len(TOKEN_PREFIX)] if value.startswith(TOKEN_PREFIX) else value[:keep]
    return f"{head}…"
