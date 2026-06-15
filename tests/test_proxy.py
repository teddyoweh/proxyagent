"""Core security + proxy plumbing tests (no real provider keys needed)."""

import os

os.environ.setdefault("PROXYAGENT_HOME", "/tmp/proxyagent_test_home")
os.environ["PROXYAGENT_ADMIN_TOKEN"] = "pa_admin_test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from proxyagent import aliases as _aliases  # noqa: E402
from proxyagent.config import Config, PROVIDERS  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_aliases():
    _aliases.set_map({})
    yield
    _aliases.set_map({})
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


def test_pricing():
    from proxyagent.pricing import cost_usd
    # 1M in @ $3, 1M out @ $15 for sonnet
    assert cost_usd("claude-sonnet-4-5", 1_000_000, 1_000_000) == 18.0
    assert cost_usd("gpt-4o-mini", 1_000_000, 0) == 0.15
    assert cost_usd("unknown-model", 100, 100) is None


def test_credential_storage_and_resolution():
    from proxyagent.config import PROVIDERS
    from proxyagent.providers import resolve_auth
    s = Store(":memory:")
    # env fallback when nothing stored
    headers, ok = resolve_auth(PROVIDERS["openai"], s)
    cid = s.add_credential("openai", "sk-real-key", kind="api_key", label="prod")
    cred = s.get_credential("openai")
    assert cred["secret"] == "sk-real-key"               # decrypted roundtrip
    # list never leaks the secret
    listed = s.list_credentials()
    assert listed[0]["provider"] == "openai" and "secret" not in listed[0]
    # resolve_auth now uses the stored credential
    headers, ok = resolve_auth(PROVIDERS["openai"], s)
    assert ok and headers["Authorization"] == "Bearer sk-real-key"
    assert s.remove_credential(cid)


def test_mock_provider_offline():
    """Full pipeline with no real key: mint → call model 'mock' → response + usage + log."""
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"label": "m", "scope": ["*"]}).json()["token"]
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 50, "messages": [{"role": "user", "content": "hello"}]})
    assert r.status_code == 200
    body = r.json()
    assert body["content"][0]["text"].startswith("[proxyagent mock]")
    assert body["usage"]["input_tokens"] >= 1
    # it was logged (with $0 cost)
    logs = c.get("/admin/logs", headers=ADMIN).json()["logs"]
    assert logs[0]["model"] == "mock" and logs[0]["status"] == 200
    # openai shape too
    r2 = c.post("/openai/v1/chat/completions", headers={"authorization": f"Bearer {tok}"},
                json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]})
    assert r2.json()["choices"][0]["message"]["content"].startswith("[proxyagent mock]")


def test_provider_admin_endpoints():
    c = _client()
    r = c.post("/admin/providers", headers=ADMIN, json={"provider": "anthropic", "secret": "sk-ant-x"})
    assert r.status_code == 200 and r.json()["provider"] == "anthropic"
    listed = c.get("/admin/providers", headers=ADMIN).json()
    assert "anthropic" in listed["configured"]
    # unknown provider rejected
    assert c.post("/admin/providers", headers=ADMIN,
                  json={"provider": "nope", "secret": "x"}).status_code == 400


def test_more_providers_route():
    # new providers are routable; mock works on any of them with no key
    assert "groq" in PROVIDERS and "gemini" in PROVIDERS and "openrouter" in PROVIDERS
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r = c.post("/groq/v1/chat/completions", headers={"authorization": f"Bearer {tok}"},
               json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200 and r.json()["choices"][0]["message"]["content"].startswith("[proxyagent mock]")
    # unknown provider → 404
    assert c.post("/nope/v1/chat/completions", headers={"authorization": f"Bearer {tok}"},
                  json={"model": "mock", "messages": []}).status_code == 404


def test_model_remap_forces_mock_offline():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # map everything to mock → a "real" model call runs offline, no key
    c.put("/admin/aliases", headers=ADMIN, json={"map": {"*": "mock"}})
    r = c.post("/openai/v1/chat/completions", headers={"authorization": f"Bearer {tok}"},
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200 and "[proxyagent mock]" in r.json()["choices"][0]["message"]["content"]


def test_model_remap_reroutes_provider():
    from proxyagent.aliases import remap
    _aliases.set_map({"gpt-4o": "anthropic:mock"})
    assert remap("openai", "gpt-4o") == ("anthropic", "mock")
    assert remap("openai", "gpt-4o-mini") == ("openai", "gpt-4o-mini")  # no match


def test_budget_exhaustion_returns_402():
    c = _client()
    r = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "budget_usd": 0.001})
    tok, tid = r.json()["token"], r.json()["id"]
    # under budget (mock costs $0) → ok
    assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
                  json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]}).status_code == 200
    # record spend over the cap, then the next call is blocked
    c.app.state.store.log_request(token_id=tid, provider="anthropic", model="x", status=200, cost_usd=0.05)
    assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
                  json={"model": "mock", "messages": []}).status_code == 402


def test_harness_catalog():
    c = _client()
    h = c.get("/admin/harnesses", headers=ADMIN).json()["harnesses"]
    names = {x["name"] for x in h}
    assert {"claude-code", "codex", "gemini-cli"} <= names
    cc = next(x for x in h if x["name"] == "claude-code")
    assert {a["mode"] for a in cc["auth"]} == {"api_key", "oauth", "bedrock", "vertex"}
    assert any(a["mode"] == "api_key" and a["ready"] for a in cc["auth"])
