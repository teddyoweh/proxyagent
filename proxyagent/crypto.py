"""At-rest encryption for stored provider credentials.

If `PROXYAGENT_SECRET_KEY` is set (and `cryptography` is installed), provider secrets
are encrypted with Fernet before they touch the database. Without a key, secrets are
stored as-is and we warn loudly — fine for a laptop, not for a shared Postgres.
"""

from __future__ import annotations

import base64
import hashlib
import os

_PREFIX = "enc:"


def _fernet():
    key = os.environ.get("PROXYAGENT_SECRET_KEY")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    derived = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
    return Fernet(derived)


def encryption_available() -> bool:
    return _fernet() is not None


def encrypt(value: str) -> str:
    f = _fernet()
    return _PREFIX + f.encrypt(value.encode()).decode() if f else value


def decrypt(value: str) -> str:
    if value and value.startswith(_PREFIX):
        f = _fernet()
        if not f:
            raise RuntimeError("PROXYAGENT_SECRET_KEY required to decrypt a stored credential")
        return f.decrypt(value[len(_PREFIX):].encode()).decode()
    return value
