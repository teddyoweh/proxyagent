"""Core security + proxy plumbing tests (no real provider keys needed)."""

import os

os.environ.setdefault("PROXYAGENT_HOME", "/tmp/proxyagent_test_home")
os.environ["PROXYAGENT_ADMIN_TOKEN"] = "pa_admin_test"

from fastapi.testclient import TestClient  # noqa: E402

from proxyagent.config import Config  # noqa: E402
from proxyagent.providers import scope_allows  # noqa: E402
from proxyagent.security import hash_token, token_matches, new_token  # noqa: E402
from proxyagent.server import create_app  # noqa: E402
from proxyagent.store import Store  # noqa: E402

ADMIN = {"x-admin-token": "pa_admin_test"}


def _client():
    cfg = Config.load()
    cfg.db_path = ":memory:"
    return TestClient(create_app(cfg))


def test_token_hash_roundtrip():
    t = new_token()
    assert token_matches(t, hash_token(t))
    assert not token_matches("pa_wrong", hash_token(t))


def test_scope_globs():
    assert scope_allows(["*"], "anthropic", "claude-sonnet-4")
    assert scope_allows(["anthropic:claude-*"], "anthropic", "claude-opus-4")
    assert not scope_allows(["anthropic:claude-*"], "openai", "gpt-4")
    assert not scope_allows(["anthropic:claude-opus-*"], "anthropic", "claude-sonnet-4")


def test_store_token_lifecycle():
    s = Store(":memory:")
    plain, row = s.create_token("m1", ["anthropic:*"])
    assert plain.startswith("pa_")
    assert s.get_token_by_hash(hash_token(plain))["id"] == row["id"]
    assert s.revoke_token(row["id"])
    assert s.get_token_by_hash(hash_token(plain))["revoked"] == 1


def test_admin_requires_auth():
    c = _client()
    assert c.get("/admin/tokens").status_code == 401
    assert c.get("/admin/tokens", headers=ADMIN).status_code == 200


def test_mint_and_use_scope_enforcement():
    c = _client()
    r = c.post("/admin/tokens", headers=ADMIN, json={"label": "m", "scope": ["anthropic:claude-*"]})
    tok = r.json()["token"]
    # wrong provider/model → 403 (scope), proving auth+scope run before any upstream call
    r2 = c.post("/openai/v1/chat/completions", headers={"authorization": f"Bearer {tok}"},
                json={"model": "gpt-4o", "messages": []})
    assert r2.status_code == 403
    # revoked → 401
    tid = r.json()["id"]
    c.delete(f"/admin/tokens/{tid}", headers=ADMIN)
    r3 = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
                json={"model": "claude-sonnet-4", "messages": []})
    assert r3.status_code == 401


def test_healthz_and_ui():
    c = _client()
    assert c.get("/healthz").json()["ok"] is True
    assert "proxyagent" in c.get("/").text
