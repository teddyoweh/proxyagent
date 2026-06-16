"""Persistence — machine tokens, stored provider credentials, and call traces+cost.

Backend is SQLite (local) or Postgres (via URL) — see db.py. Tables:
  * proxy_agent_tokens  — machine tokens (hashed)
  * proxy_agent_keys    — provider credentials you add (api_key / oauth), encrypted
  * proxy_agent_calls   — every proxied request: usage, latency, cost, tools, errors
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from . import crypto
from .db import DB
from .security import hash_token, new_token, mask

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proxy_agent_tokens (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, label TEXT,
    scope_json TEXT NOT NULL DEFAULT '["*"]', rate_limit INTEGER NOT NULL DEFAULT 0,
    created_ms BIGINT, expires_ms BIGINT, revoked INTEGER NOT NULL DEFAULT 0,
    last_used_ms BIGINT, masked TEXT, budget_usd DOUBLE PRECISION
);
CREATE TABLE IF NOT EXISTS proxy_agent_keys (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'api_key',
    secret TEXT NOT NULL, refresh TEXT, expires_ms BIGINT, label TEXT,
    created_ms BIGINT, meta_json TEXT, active INTEGER NOT NULL DEFAULT 1, masked TEXT
);
CREATE TABLE IF NOT EXISTS proxy_agent_calls (
    id TEXT PRIMARY KEY, ts_ms BIGINT, token_id TEXT, token_label TEXT,
    provider TEXT, model TEXT, status INTEGER,
    prompt_tokens INTEGER, completion_tokens INTEGER, latency_ms INTEGER,
    streamed INTEGER, tools_used TEXT, cost_usd DOUBLE PRECISION, error TEXT
);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


class Store:
    def __init__(self, path: str | Path = ":memory:", url: str | None = None):
        self.db = DB(str(path), url=url)
        self.db.executescript(_SCHEMA)
        self.backend = "postgres" if self.db.pg else "sqlite"
        # migrate older DBs created before budget_usd existed
        for stmt in ("ALTER TABLE proxy_agent_tokens ADD COLUMN budget_usd DOUBLE PRECISION",
                     "ALTER TABLE proxy_agent_keys ADD COLUMN masked TEXT"):
            try:
                self.db.execute(stmt)
            except Exception:
                pass

    # -- machine tokens ---------------------------------------------------- #

    def create_token(self, label, scope, *, ttl_seconds=None, rate_limit=0, budget_usd=None):
        plain = new_token()
        tid = "tok_" + uuid.uuid4().hex[:12]
        expires = now_ms() + ttl_seconds * 1000 if ttl_seconds else None
        self.db.execute(
            """INSERT INTO proxy_agent_tokens
               (id, hash, label, scope_json, rate_limit, created_ms, expires_ms, masked, budget_usd)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tid, hash_token(plain), label, json.dumps(scope), rate_limit, now_ms(),
             expires, mask(plain), budget_usd),
        )
        return plain, self.get_token(tid)

    def token_spend(self, token_id: str) -> float:
        r = self.db.fetchone(
            "SELECT COALESCE(SUM(cost_usd),0) s FROM proxy_agent_calls WHERE token_id=?", (token_id,))
        return float((r or {}).get("s", 0) or 0)

    def get_token(self, tid):
        return self.db.fetchone("SELECT * FROM proxy_agent_tokens WHERE id=?", (tid,))

    def get_token_by_hash(self, h):
        return self.db.fetchone("SELECT * FROM proxy_agent_tokens WHERE hash=?", (h,))

    def list_tokens(self):
        return self.db.fetchall("SELECT * FROM proxy_agent_tokens ORDER BY created_ms DESC")

    def revoke_token(self, tid):
        cur = self.db.execute("UPDATE proxy_agent_tokens SET revoked=1 WHERE id=?", (tid,))
        return cur.rowcount > 0

    def touch_token(self, tid):
        self.db.execute("UPDATE proxy_agent_tokens SET last_used_ms=? WHERE id=?", (now_ms(), tid))

    def recent_request_count(self, tid, window_ms=60_000):
        r = self.db.fetchone(
            "SELECT COUNT(*) c FROM proxy_agent_calls WHERE token_id=? AND ts_ms>=?",
            (tid, now_ms() - window_ms))
        return (r or {}).get("c", 0)

    def recent_provider_count(self, provider, window_ms=60_000):
        r = self.db.fetchone(
            "SELECT COUNT(*) c FROM proxy_agent_calls WHERE provider=? AND ts_ms>=?",
            (provider, now_ms() - window_ms))
        return (r or {}).get("c", 0)

    # -- provider credentials (proxy_agent_keys) --------------------------- #

    def add_credential(self, provider, secret, *, kind="api_key", refresh=None,
                       expires_ms=None, label=None, meta=None, replace=False):
        """Add a credential to a provider's POOL. A provider can hold many credentials
        across auth types (several api_keys, oauth tokens, bedrock, vertex…). replace=True
        swaps out other creds of the SAME kind; default keeps them (for failover/rotation)."""
        cid = "key_" + uuid.uuid4().hex[:12]
        if replace:
            self.db.execute("UPDATE proxy_agent_keys SET active=0 WHERE provider=? AND kind=?",
                            (provider, kind))
        self.db.execute(
            """INSERT INTO proxy_agent_keys
               (id, provider, kind, secret, refresh, expires_ms, label, created_ms, meta_json, active, masked)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (cid, provider, kind, crypto.encrypt(secret),
             crypto.encrypt(refresh) if refresh else None, expires_ms, label, now_ms(),
             json.dumps(meta or {}), mask(secret)),
        )
        return cid

    def _decrypt_row(self, r):
        r = dict(r)
        r["secret"] = crypto.decrypt(r["secret"])
        if r.get("refresh"):
            r["refresh"] = crypto.decrypt(r["refresh"])
        if r.get("meta_json"):
            try:
                r["meta"] = json.loads(r["meta_json"])
            except Exception:
                r["meta"] = {}
        return r

    def get_credential(self, provider, kind=None):
        """Most-recent active credential (optionally of a kind), decrypted."""
        creds = self.get_credentials(provider, kind=kind)
        return creds[-1] if creds else None

    def get_credentials(self, provider, kind=None):
        """The provider's whole active pool, decrypted, oldest→newest (rotation order)."""
        q = "SELECT * FROM proxy_agent_keys WHERE provider=? AND active=1"
        args = [provider]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        return [self._decrypt_row(r) for r in self.db.fetchall(q + " ORDER BY created_ms", tuple(args))]

    def get_credential_by_id(self, cid):
        """A single credential by its id, decrypted — for connection-testing."""
        r = self.db.fetchone("SELECT * FROM proxy_agent_keys WHERE id=?", (cid,))
        return self._decrypt_row(r) if r else None

    def list_credentials(self):
        rows = self.db.fetchall("SELECT * FROM proxy_agent_keys ORDER BY created_ms DESC")
        # never return the secret material
        return [{"id": r["id"], "provider": r["provider"], "kind": r["kind"],
                 "label": r["label"], "active": bool(r["active"]), "masked": r.get("masked"),
                 "created_ms": r["created_ms"]} for r in rows]

    def remove_credential(self, cid):
        cur = self.db.execute("DELETE FROM proxy_agent_keys WHERE id=?", (cid,))
        return cur.rowcount > 0

    def refresh_credential(self, cid, new_secret, *, expires_ms=None):
        """Persist a refreshed access token (+ new expiry in meta) for an OAuth cred."""
        r = self.db.fetchone("SELECT meta_json FROM proxy_agent_keys WHERE id=?", (cid,))
        meta = json.loads(r["meta_json"]) if r and r.get("meta_json") else {}
        if expires_ms is not None:
            meta["expires_ms"] = expires_ms
        self.db.execute("UPDATE proxy_agent_keys SET secret=?, meta_json=?, masked=? WHERE id=?",
                        (crypto.encrypt(new_secret), json.dumps(meta), mask(new_secret), cid))

    # -- call traces (proxy_agent_calls) ----------------------------------- #

    def log_request(self, **kw):
        kw.setdefault("id", "call_" + uuid.uuid4().hex[:12])
        kw.setdefault("ts_ms", now_ms())
        cols = ["id", "ts_ms", "token_id", "token_label", "provider", "model", "status",
                "prompt_tokens", "completion_tokens", "latency_ms", "streamed",
                "tools_used", "cost_usd", "error"]
        self.db.execute(
            f"INSERT INTO proxy_agent_calls ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            tuple(kw.get(c) for c in cols))

    def list_logs(self, limit=200):
        return self.db.fetchall("SELECT * FROM proxy_agent_calls ORDER BY ts_ms DESC LIMIT ?", (limit,))

    def trim_logs(self, older_than_ms: int) -> int:
        cur = self.db.execute("DELETE FROM proxy_agent_calls WHERE ts_ms < ?", (older_than_ms,))
        return cur.rowcount

    def usage_by_token(self):
        """Per-token spend breakdown — requests, tokens, cost, last-used — joined to the
        token label/masked id so the dashboard can show who is spending what."""
        rows = self.db.fetchall(
            """SELECT t.id, t.label, t.masked, t.revoked, t.budget_usd, t.last_used_ms,
                      COUNT(c.id) requests,
                      COALESCE(SUM(c.prompt_tokens),0) prompt_tokens,
                      COALESCE(SUM(c.completion_tokens),0) completion_tokens,
                      COALESCE(SUM(c.cost_usd),0) cost_usd,
                      MAX(c.ts_ms) last_call_ms
               FROM proxy_agent_tokens t
               LEFT JOIN proxy_agent_calls c ON c.token_id = t.id
               GROUP BY t.id, t.label, t.masked, t.revoked, t.budget_usd, t.last_used_ms
               ORDER BY cost_usd DESC""")
        return [dict(r) for r in rows]

    def usage_summary(self):
        r = self.db.fetchone(
            """SELECT COUNT(*) requests,
                      COALESCE(SUM(prompt_tokens),0) prompt_tokens,
                      COALESCE(SUM(completion_tokens),0) completion_tokens,
                      COALESCE(SUM(cost_usd),0) cost_usd
               FROM proxy_agent_calls""")
        return r or {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0}

    def metrics(self) -> dict:
        total = self.usage_summary()
        by_provider = self.db.fetchall(
            "SELECT provider, COUNT(*) n, COALESCE(SUM(cost_usd),0) c FROM proxy_agent_calls "
            "WHERE provider IS NOT NULL GROUP BY provider")
        by_status = self.db.fetchall(
            "SELECT status, COUNT(*) n FROM proxy_agent_calls WHERE status IS NOT NULL GROUP BY status")
        active_tokens = sum(1 for t in self.list_tokens() if not t["revoked"])
        credentials = sum(1 for c in self.list_credentials() if c["active"])
        return {"total": total, "by_provider": by_provider, "by_status": by_status,
                "active_tokens": active_tokens, "credentials": credentials}

    def close(self):
        self.db.close()
