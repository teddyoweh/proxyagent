"""Persistence — machine tokens (hashed) + a full request/usage audit log.

SQLite, guarded by a lock so it's safe across the server's worker threads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .security import hash_token, new_token, mask

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id          TEXT PRIMARY KEY,
    hash        TEXT NOT NULL UNIQUE,
    label       TEXT,
    scope_json  TEXT NOT NULL DEFAULT '["*"]',   -- allowed "provider:model" globs
    rate_limit  INTEGER NOT NULL DEFAULT 0,       -- max requests/min (0 = unlimited)
    created_ms  INTEGER,
    expires_ms  INTEGER,                          -- NULL = never
    revoked     INTEGER NOT NULL DEFAULT 0,
    last_used_ms INTEGER,
    masked      TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id           TEXT PRIMARY KEY,
    ts_ms        INTEGER,
    token_id     TEXT,
    token_label  TEXT,
    provider     TEXT,
    model        TEXT,
    status       INTEGER,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    latency_ms   INTEGER,
    streamed     INTEGER,
    tools_used   TEXT,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts_ms DESC);
CREATE INDEX IF NOT EXISTS idx_logs_token ON logs (token_id);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- tokens ------------------------------------------------------------ #

    def create_token(self, label: str, scope: list[str], *, ttl_seconds: int | None = None,
                     rate_limit: int = 0) -> tuple[str, dict]:
        """Mint a token. Returns (plaintext_once, row). Plaintext is never stored."""
        plain = new_token()
        tid = "tok_" + uuid.uuid4().hex[:12]
        expires = now_ms() + ttl_seconds * 1000 if ttl_seconds else None
        with self._lock:
            self._conn.execute(
                """INSERT INTO tokens (id, hash, label, scope_json, rate_limit, created_ms,
                                       expires_ms, masked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (tid, hash_token(plain), label, json.dumps(scope), rate_limit, now_ms(),
                 expires, mask(plain)),
            )
            self._conn.commit()
        return plain, self.get_token(tid)

    def get_token(self, tid: str) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM tokens WHERE id=?", (tid,)).fetchone()
        return dict(r) if r else None

    def get_token_by_hash(self, h: str) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM tokens WHERE hash=?", (h,)).fetchone()
        return dict(r) if r else None

    def list_tokens(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM tokens ORDER BY created_ms DESC").fetchall()
        return [dict(r) for r in rows]

    def revoke_token(self, tid: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE tokens SET revoked=1 WHERE id=?", (tid,))
            self._conn.commit()
        return cur.rowcount > 0

    def touch_token(self, tid: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE tokens SET last_used_ms=? WHERE id=?", (now_ms(), tid))
            self._conn.commit()

    def recent_request_count(self, tid: str, window_ms: int = 60_000) -> int:
        with self._lock:
            r = self._conn.execute(
                "SELECT COUNT(*) c FROM logs WHERE token_id=? AND ts_ms>=?",
                (tid, now_ms() - window_ms),
            ).fetchone()
        return r["c"]

    # -- logs / usage ------------------------------------------------------ #

    def log_request(self, **kw) -> None:
        kw.setdefault("id", "log_" + uuid.uuid4().hex[:12])
        kw.setdefault("ts_ms", now_ms())
        cols = ["id", "ts_ms", "token_id", "token_label", "provider", "model", "status",
                "prompt_tokens", "completion_tokens", "latency_ms", "streamed", "tools_used", "error"]
        vals = [kw.get(c) for c in cols]
        with self._lock:
            self._conn.execute(
                f"INSERT INTO logs ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals
            )
            self._conn.commit()

    def list_logs(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM logs ORDER BY ts_ms DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def usage_summary(self) -> dict:
        with self._lock:
            r = self._conn.execute(
                """SELECT COUNT(*) requests,
                          COALESCE(SUM(prompt_tokens),0) prompt_tokens,
                          COALESCE(SUM(completion_tokens),0) completion_tokens
                   FROM logs"""
            ).fetchone()
        return dict(r)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
