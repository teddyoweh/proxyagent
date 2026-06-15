"""Storage backend — SQLite by default (local), or Postgres when a URL is given.

Set `PROXYAGENT_DATABASE_URL=postgresql://…` (or pass `database_url=`) and everything
lands in Postgres; otherwise it's a local SQLite file. Tables are prefixed
`proxy_agent_` so they sit cleanly in a shared database.
"""

from __future__ import annotations

import os
import sqlite3
import threading


def database_url() -> str | None:
    return os.environ.get("PROXYAGENT_DATABASE_URL") or os.environ.get("DATABASE_URL")


def is_postgres(url: str | None) -> bool:
    return bool(url) and url.startswith(("postgres://", "postgresql://"))


class DB:
    """Tiny cross-backend wrapper. Use `?` placeholders everywhere; we translate for
    Postgres. Thread-safe via a lock (fine for a proxy's scale)."""

    def __init__(self, sqlite_path: str = ":memory:", url: str | None = None):
        self._lock = threading.RLock()
        self.url = url if url is not None else database_url()
        self.pg = is_postgres(self.url)
        if self.pg:
            import psycopg  # type: ignore
            self._conn = psycopg.connect(self.url, autocommit=True)
        else:
            self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def execute(self, sql: str, params: tuple = ()):  # returns rowcount-ish handle
        with self._lock:
            if self.pg:
                cur = self._conn.cursor()
                cur.execute(self._q(sql), params)
                return cur
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        with self._lock:
            if self.pg:
                cur = self._conn.cursor()
                cur.execute(self._q(sql), params)
                row = cur.fetchone()
                if not row:
                    return None
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))
            r = self._conn.execute(sql, params).fetchone()
            return dict(r) if r else None

    def fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            if self.pg:
                cur = self._conn.cursor()
                cur.execute(self._q(sql), params)
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, r)) for r in rows]
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def executescript(self, script: str) -> None:
        with self._lock:
            if self.pg:
                cur = self._conn.cursor()
                for stmt in [s for s in script.split(";") if s.strip()]:
                    cur.execute(stmt)
            else:
                self._conn.executescript(script)
                self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
