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


def test_max_concurrency_503(monkeypatch):
    monkeypatch.setenv("PROXYAGENT_MAX_CONCURRENCY", "1")
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    body = {"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
    # normally fine
    assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body).status_code == 200
    # simulate a request already in flight → next one is rejected with 503
    c.app.state.inflight["n"] = 1
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body)
    assert r.status_code == 503 and "capacity" in r.json()["detail"]
    # counter restored after the rejected request (it never incremented past the cap)
    c.app.state.inflight["n"] = 0
    assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body).status_code == 200
    assert c.app.state.inflight["n"] == 0   # decremented cleanly


def test_token_clone():
    c = _client()
    src = c.post("/admin/tokens", headers=ADMIN,
                 json={"scope": ["anthropic:*"], "label": "prod", "budget_usd": 9.0,
                       "rate_limit": 30, "note": "primary"}).json()
    cl = c.post(f"/admin/tokens/{src['id']}/clone", headers=ADMIN).json()
    assert cl["token"].startswith("pa_") and cl["token"] != src["token"]
    assert cl["scope"] == ["anthropic:*"]
    # the clone carried over the config (new id, copied scope/budget/rate/note)
    toks = {t["id"]: t for t in c.get("/admin/tokens", headers=ADMIN).json()["tokens"]}
    new = toks[cl["id"]]
    assert new["budget_usd"] == 9.0 and new["rate_limit"] == 30 and new["note"] == "primary"
    assert new["label"] == "prod-copy" and new["id"] != src["id"]
    assert c.post("/admin/tokens/key_nope/clone", headers=ADMIN).status_code == 404


def test_revoke_expired_and_note():
    from proxyagent.store import now_ms
    c = _client()
    store = c.app.state.store
    # an already-expired token (force expiry into the past) + a live one
    _, old = store.create_token("old", ["*"], ttl_seconds=60, note="temp key")
    store.db.execute("UPDATE proxy_agent_tokens SET expires_ms=? WHERE id=?",
                     (now_ms() - 1000, old["id"]))
    _, live = store.create_token("live", ["*"])
    r = c.post("/admin/tokens/revoke-expired", headers=ADMIN).json()
    assert r["revoked"] == 1
    toks = {t["id"]: t for t in c.get("/admin/tokens", headers=ADMIN).json()["tokens"]}
    assert toks[old["id"]]["revoked"] is True and toks[live["id"]]["revoked"] is False
    assert toks[old["id"]]["note"] == "temp key"   # note round-trips
    # second sweep finds nothing
    assert c.post("/admin/tokens/revoke-expired", headers=ADMIN).json()["revoked"] == 0
    assert c.post("/admin/tokens/revoke-expired").status_code == 401


def test_token_ip_allowlist():
    """A token restricted to a CIDR rejects requests from outside it (via X-Forwarded-For)."""
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN,
                 json={"scope": ["*"], "allowed_ips": ["10.0.0.0/8"]}).json()["token"]
    body = {"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
    # in-range → allowed
    ok = c.post("/anthropic/v1/messages",
                headers={"x-api-key": tok, "x-forwarded-for": "10.1.2.3"}, json=body)
    assert ok.status_code == 200
    # out-of-range → 403
    no = c.post("/anthropic/v1/messages",
                headers={"x-api-key": tok, "x-forwarded-for": "203.0.113.5"}, json=body)
    assert no.status_code == 403 and "not allowed" in no.json()["detail"]
    # a token WITHOUT an allow-list is unrestricted
    free = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    assert c.post("/anthropic/v1/messages",
                  headers={"x-api-key": free, "x-forwarded-for": "203.0.113.5"}, json=body).status_code == 200
    # the allow-list shows up in the token listing
    listed = c.get("/admin/tokens", headers=ADMIN).json()["tokens"]
    assert any(t.get("allowed_ips") == ["10.0.0.0/8"] for t in listed)


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


def test_cors_preflight_and_headers(monkeypatch):
    monkeypatch.setenv("PROXYAGENT_CORS_ORIGINS", "https://app.example.com")
    c = _client()
    # OPTIONS preflight is answered with the allow-origin
    pre = c.options("/anthropic/v1/messages",
                    headers={"Origin": "https://app.example.com",
                             "Access-Control-Request-Method": "POST"})
    assert pre.headers.get("access-control-allow-origin") == "https://app.example.com"
    # an actual request echoes the allow-origin + exposes the proxy headers
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r = c.post("/anthropic/v1/messages",
               headers={"x-api-key": tok, "Origin": "https://app.example.com"},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    assert r.headers.get("access-control-allow-origin") == "https://app.example.com"
    assert "x-proxyagent-request-id" in r.headers.get("access-control-expose-headers", "")


def test_gzip_middleware_installed():
    c = _client()
    assert any("GZip" in str(m.cls) for m in c.app.user_middleware)
    # a large response is still correct end-to-end with gzip negotiation
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r = c.get("/v1/models", headers={"x-api-key": tok, "accept-encoding": "gzip"})
    assert r.status_code == 200 and len(r.json()["data"]) > 1


def test_cors_off_by_default():
    c = _client()
    r = c.get("/healthz", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in r.headers


def test_ui_hide_class_wins():
    """Regression: `.hide` must override #app{display:flex} and .modal{display:grid} —
    otherwise the app + create-key modal render permanently (stacked over the gate)."""
    from pathlib import Path
    import proxyagent
    html = (Path(proxyagent.__file__).parent / "ui" / "index.html").read_text()
    assert ".hide{display:none!important}" in html


def test_docs_page():
    c = _client()
    r = c.get("/docs")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    body = r.text
    assert "Run any agent on any machine" in body
    assert "ANTHROPIC_BASE_URL" in body and "proxyagent serve" in body and "proxyagent token new" in body
    # the dashboard links to it
    assert "/docs" in c.get("/").text


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


def test_credential_pool_and_failover_order():
    from proxyagent.providers import resolve_candidates
    s = Store(":memory:")
    s.add_credential("openai", "sk-1", kind="api_key")     # additive by default →
    s.add_credential("openai", "sk-2", kind="api_key")     # a pool of two keys
    creds = s.get_credentials("openai", kind="api_key")
    assert [c["secret"] for c in creds] == ["sk-1", "sk-2"]   # oldest→newest rotation order
    cands = resolve_candidates(PROVIDERS["openai"], s)
    assert cands[0]["Authorization"] == "Bearer sk-1"
    assert cands[1]["Authorization"] == "Bearer sk-2"        # failover tries #2 next
    listed = s.list_credentials()
    assert len(listed) == 2 and all("secret" not in c and c["masked"] for c in listed)


def test_sigv4_structure_and_determinism():
    import datetime, re
    from proxyagent.signers import sigv4_headers
    now = datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.timezone.utc)
    kw = dict(method="POST", host="bedrock-runtime.us-east-1.amazonaws.com", path="/model/x/invoke",
              region="us-east-1", service="bedrock", access_key="AKIDEXAMPLE",
              secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", body=b'{"a":1}', now=now)
    h1, h2 = sigv4_headers(**kw), sigv4_headers(**kw)
    assert h1 == h2                                  # deterministic at a fixed time
    a = h1["Authorization"]
    assert a.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request")
    assert "SignedHeaders=content-type;host;x-amz-date" in a
    assert re.search(r"Signature=[0-9a-f]{64}$", a) and h1["x-amz-date"] == "20150830T123600Z"


def test_bedrock_plan_and_build_plans():
    from proxyagent.signers import bedrock_plan
    from proxyagent.providers import build_plans
    url, headers, raw = bedrock_plan(
        {"secret": "sk", "meta": {"access_key": "AKID", "region": "us-west-2"}},
        {"model": "claude-sonnet-4-5", "max_tokens": 10, "messages": []})
    assert url.startswith("https://bedrock-runtime.us-west-2.amazonaws.com/model/") and url.endswith("/invoke")
    import json
    b = json.loads(raw)
    assert b["anthropic_version"] == "bedrock-2023-05-31" and "model" not in b
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256")
    # a provider can mix api_key + bedrock in its pool; both become plans
    s = Store(":memory:")
    s.add_credential("anthropic", "sk-1", kind="api_key")
    s.add_credential("anthropic", "awssecret", kind="bedrock", meta={"access_key": "AKID", "region": "us-east-1"})
    plans = build_plans(PROVIDERS["anthropic"], s, {"model": "claude-sonnet-4-5", "messages": []})
    assert len(plans) == 2 and plans[0][0].endswith("/v1/messages") and "bedrock-runtime" in plans[1][0]


def test_vertex_assertion_and_url():
    import base64, json
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from proxyagent.signers import vertex_signed_assertion, vertex_url
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    sa = {"client_email": "svc@proj.iam.gserviceaccount.com", "private_key": pem,
          "token_uri": "https://oauth2.googleapis.com/token"}
    jwt = vertex_signed_assertion(sa, now=1700000000)
    parts = jwt.split(".")
    assert len(parts) == 3
    b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    header, claims = json.loads(b64d(parts[0])), json.loads(b64d(parts[1]))
    assert header["alg"] == "RS256" and claims["iss"] == sa["client_email"]
    assert claims["scope"].endswith("cloud-platform")
    # signature must verify against the public key (raises on tamper)
    key.public_key().verify(b64d(parts[2]), (parts[0] + "." + parts[1]).encode(),
                            padding.PKCS1v15(), hashes.SHA256())
    assert vertex_url("myproj", "us-east5", "claude-sonnet-4-5") == (
        "https://us-east5-aiplatform.googleapis.com/v1/projects/myproj/locations/us-east5"
        "/publishers/anthropic/models/claude-sonnet-4-5:rawPredict")


def test_metrics_latency_histogram():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    for _ in range(3):
        c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    m = c.get("/metrics", headers=ADMIN).text
    assert "proxyagent_request_duration_ms histogram" in m
    assert 'proxyagent_request_duration_ms_bucket{le="+Inf"} 3' in m
    assert "proxyagent_request_duration_ms_count 3" in m


def test_metrics_prometheus():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
           json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]})
    assert c.get("/metrics").status_code == 401                  # admin-gated by default
    r = c.get("/metrics", headers=ADMIN)
    assert r.status_code == 200 and "text/plain" in r.headers["content-type"]
    body = r.text
    assert "proxyagent_requests_total" in body and "proxyagent_cost_usd_total" in body
    assert 'proxyagent_responses_total{status="200"}' in body and "proxyagent_credentials" in body


def test_response_cache():
    import os
    os.environ["PROXYAGENT_CACHE_TTL"] = "60"
    try:
        c = _client()
        tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
        body = {"model": "mock", "messages": [{"role": "user", "content": "cache me"}]}
        r1 = c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body)
        assert r1.status_code == 200 and r1.headers.get("x-proxyagent-cache") is None   # miss → forwarded
        r2 = c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body)
        assert r2.headers.get("x-proxyagent-cache") == "hit" and r1.json() == r2.json()  # served from cache
        r3 = c.post("/anthropic/v1/messages", headers={"x-api-key": tok, "x-proxyagent-cache": "no"}, json=body)
        assert r3.headers.get("x-proxyagent-cache") is None                              # bypass forces a miss
    finally:
        os.environ.pop("PROXYAGENT_CACHE_TTL", None)


def test_provider_rate_limit():
    import os
    os.environ["PROXYAGENT_PROVIDER_RATE_LIMITS"] = '{"anthropic": 1}'
    try:
        c = _client()
        tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
        body = {"model": "mock", "messages": [{"role": "user", "content": "hi"}]}
        assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body).status_code == 200
        assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=body).status_code == 429
        # a different provider is unaffected
        assert c.post("/openai/v1/chat/completions", headers={"x-api-key": tok}, json=body).status_code == 200
    finally:
        os.environ.pop("PROXYAGENT_PROVIDER_RATE_LIMITS", None)


def test_redact_secrets():
    from proxyagent.redact import redact
    s = redact("boom: sk-abcdefghij1234567890 user a@b.com Bearer abc123xyz789token AKIA0123456789ABCDEF")
    assert "sk-abcdefghij" not in s and "sk-***" in s
    assert "a@b.com" not in s and "***@***" in s
    assert "Bearer ***" in s and "AKIA***" in s
    assert redact(None) is None and redact("") == ""


def test_oauth_refresh_helpers():
    from proxyagent.signers import oauth_refresh
    assert oauth_refresh({"meta": {}}) is None            # not refreshable → None
    assert oauth_refresh({"secret": "x"}) is None
    # store.refresh_credential swaps the access token + updates expiry in meta
    s = Store(":memory:")
    cid = s.add_credential("anthropic", "old-tok", kind="oauth",
                           meta={"refresh_token": "r", "token_url": "https://x/t", "expires_ms": 1})
    s.refresh_credential(cid, "new-tok", expires_ms=999999999999)
    c = s.get_credentials("anthropic", kind="oauth")[0]
    assert c["secret"] == "new-tok" and (c["meta"] or {}).get("expires_ms") == 999999999999


def test_credential_toggle_active():
    c = _client()
    cid = c.post("/admin/providers", headers=ADMIN,
                 json={"provider": "anthropic", "secret": "sk-x", "label": "p"}).json()["id"]
    store = c.app.state.store
    assert len(store.get_credentials("anthropic")) == 1   # active → in the pool
    # disable → drops out of the active pool, but still listed (for re-enable)
    r = c.post(f"/admin/providers/{cid}/toggle", headers=ADMIN).json()
    assert r["active"] is False
    assert store.get_credentials("anthropic") == []
    cat = c.get("/admin/catalog", headers=ADMIN).json()["providers"]
    anth = next(p for p in cat if p["name"] == "anthropic")
    assert anth["via_store"] is False and any(cc["active"] is False for cc in anth["creds"])
    # re-enable → back in the pool
    assert c.post(f"/admin/providers/{cid}/toggle", headers=ADMIN).json()["active"] is True
    assert len(store.get_credentials("anthropic")) == 1
    assert c.post(f"/admin/providers/{cid}/toggle").status_code == 401
    assert c.post("/admin/providers/key_nope/toggle", headers=ADMIN).status_code == 404


def test_token_search_filter():
    c = _client()
    c.post("/admin/tokens", headers=ADMIN, json={"label": "macbook-pro", "scope": ["anthropic:*"]})
    c.post("/admin/tokens", headers=ADMIN, json={"label": "ci-runner", "scope": ["openai:*"]})
    assert len(c.get("/admin/tokens", headers=ADMIN).json()["tokens"]) >= 2
    # filter by label substring
    mac = c.get("/admin/tokens", headers=ADMIN, params={"q": "macbook"}).json()["tokens"]
    assert len(mac) == 1 and mac[0]["label"] == "macbook-pro"
    # filter by scope substring
    oa = c.get("/admin/tokens", headers=ADMIN, params={"q": "openai"}).json()["tokens"]
    assert len(oa) == 1 and oa[0]["label"] == "ci-runner"
    # no matches → empty
    assert c.get("/admin/tokens", headers=ADMIN, params={"q": "zzz-nope"}).json()["tokens"] == []


def test_patch_token_note_and_summary():
    c = _client()
    tid = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "n"}).json()["id"]
    # edit just the note via PATCH
    assert c.patch("/admin/tokens/" + tid, headers=ADMIN, json={"note": "rotated 2026-06"}).status_code == 200
    listed = {t["id"]: t for t in c.get("/admin/tokens", headers=ADMIN).json()["tokens"]}
    assert listed[tid]["note"] == "rotated 2026-06"
    # drive a request, then the Markdown summary reflects it
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
           json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    md = c.get("/admin/summary", headers=ADMIN).text
    assert md.startswith("# proxyagent") and "**requests**" in md and "By provider" in md and "anthropic" in md
    assert c.get("/admin/summary").status_code == 401


def test_patch_token_retune():
    c = _client()
    mk = c.post("/admin/tokens", headers=ADMIN,
                json={"scope": ["anthropic:*"], "rate_limit": 0}).json()
    tok, tid = mk["token"], mk["id"]
    # initially scoped to anthropic only → openai is forbidden
    assert c.post("/openai/v1/chat/completions", headers={"x-api-key": tok},
                  json={"model": "mock", "messages": []}).status_code == 403
    # widen the scope + set a budget via PATCH (no re-mint)
    r = c.patch("/admin/tokens/" + tid, headers=ADMIN,
                json={"scope": ["*"], "rate_limit": 5, "budget_usd": 2.5})
    assert r.status_code == 200 and r.json()["scope"] == ["*"] and r.json()["rate_limit"] == 5
    # now openai works
    assert c.post("/openai/v1/chat/completions", headers={"x-api-key": tok},
                  json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]}).status_code == 200
    listed = {t["id"]: t for t in c.get("/admin/tokens", headers=ADMIN).json()["tokens"]}
    assert listed[tid]["budget_usd"] == 2.5 and listed[tid]["scope"] == ["*"]
    assert c.patch("/admin/tokens/key_nope", headers=ADMIN, json={"scope": ["*"]}).status_code == 404
    assert c.patch("/admin/tokens/" + tid, json={"scope": ["*"]}).status_code == 401


def test_models_listing_endpoint():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # needs a machine token
    assert c.get("/v1/models").status_code == 401
    allm = c.get("/v1/models", headers={"x-api-key": tok}).json()
    assert allm["object"] == "list" and any(m["id"] == "mock" for m in allm["data"])
    ids = {m["id"] for m in allm["data"]}
    assert len(ids) > 1  # multiple providers' catalogs aggregated
    # per-provider listing is scoped to that provider (+ mock)
    one = c.get("/anthropic/v1/models", headers={"x-api-key": tok}).json()
    owners = {m["owned_by"] for m in one["data"]}
    assert owners <= {"anthropic", "proxyagent"}
    assert c.get("/nope/v1/models", headers={"x-api-key": tok}).status_code == 404


def test_usage_by_day_and_latency():
    from proxyagent.store import now_ms
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    store = c.app.state.store
    _, trow = store.create_token("seed", ["*"])
    # two calls today + one 3 days ago (explicit ts + latency)
    store.log_request(token_id=trow["id"], provider="anthropic", model="mock", status=200,
                      cost_usd=0.0, latency_ms=10)
    store.log_request(token_id=trow["id"], provider="anthropic", model="mock", status=200,
                      cost_usd=0.0, latency_ms=30)
    store.log_request(token_id=trow["id"], provider="anthropic", model="mock", status=200,
                      cost_usd=0.0, latency_ms=20, ts_ms=now_ms() - 3 * 86_400_000)
    days = c.get("/admin/usage-by-day", headers=ADMIN, params={"days": 14}).json()["days"]
    assert len(days) == 2 and all("date" in d and d["requests"] >= 1 for d in days)
    assert sum(d["requests"] for d in days) == 3
    # latency percentiles show up in /admin/stats
    lat = c.get("/admin/stats", headers=ADMIN).json()["latency_ms"]
    assert lat["count"] == 3 and lat["p50"] in (10, 20, 30) and lat["p95"] == 30
    assert c.get("/admin/usage-by-day").status_code == 401


def test_tool_execution_counts():
    """Executing a managed tool bumps a per-tool counter surfaced in /admin/stats."""
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # web_search is registered by default; empty query returns early (no network) but still counts
    for _ in range(2):
        r = c.post("/v1/tools/web_search/execute", headers={"x-api-key": tok}, json={})
        assert r.status_code == 200
    stats = c.get("/admin/stats", headers=ADMIN).json()
    assert stats["tool_calls"].get("web_search") == 2
    # unknown tool → 404, not counted
    assert c.post("/v1/tools/nope/execute", headers={"x-api-key": tok}, json={}).status_code == 404


def test_admin_stats_summary():
    import proxyagent
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "ttl_seconds": 3600}).json()["token"]
    c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
           json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    s = c.get("/admin/stats", headers=ADMIN).json()
    assert s["version"] == proxyagent.__version__ and s["uptime_s"] >= 0
    assert s["requests"] >= 1 and s["tokens"]["active"] >= 1
    assert set(s["cache"]) == {"enabled", "ttl_s", "hits", "size"}
    assert c.get("/admin/stats").status_code == 401
    # the TTL token carries expires_ms for the UI countdown
    t = c.get("/admin/tokens", headers=ADMIN).json()["tokens"][0]
    assert t["expires_ms"] and t["expires_ms"] > 0


def test_healthz_version_uptime():
    import proxyagent
    c = _client()
    h = c.get("/healthz").json()
    assert h["ok"] is True and h["version"] == proxyagent.__version__
    assert isinstance(h["uptime_s"], int) and h["uptime_s"] >= 0


def test_stats_by_status_breakdown():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    for _ in range(3):
        c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    by_status = c.get("/admin/stats", headers=ADMIN).json()["by_status"]
    assert by_status.get("200") == 3


def test_usage_by_model_breakdown():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    for m in ("mock-a", "mock-a", "mock-b"):
        c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": m, "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    rows = {r["model"]: r for r in c.get("/admin/usage-by-model", headers=ADMIN).json()["models"]}
    assert rows["mock-a"]["requests"] == 2 and rows["mock-b"]["requests"] == 1
    assert rows["mock-a"]["provider"] == "anthropic"
    assert c.get("/admin/usage-by-model").status_code == 401


def test_request_id_echo_and_logged():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # inbound request id is honoured + echoed + stored on the trace
    r = c.post("/anthropic/v1/messages",
               headers={"x-api-key": tok, "x-proxyagent-request-id": "trace-abc-123"},
               json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    assert r.headers.get("x-proxyagent-request-id") == "trace-abc-123"
    logs = c.get("/admin/logs", headers=ADMIN).json()["logs"]
    assert logs[0]["request_id"] == "trace-abc-123"
    # with no inbound id, the proxy mints one (req_…) and still echoes it
    r2 = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
                json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "yo"}]})
    rid = r2.headers.get("x-proxyagent-request-id")
    assert rid and rid.startswith("req_")
    # request id rides through to the CSV export
    csv = c.get("/admin/logs/export", headers=ADMIN).text
    assert "request_id" in csv.splitlines()[0] and "trace-abc-123" in csv


def test_traceparent_passthrough(monkeypatch):
    """W3C trace headers from the client are forwarded onto the upstream request."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import proxyagent.providers as P
    seen = {}

    class _Resp:
        status_code = 200
        is_success = True
        text = "{}"
        def json(self): return {"id": "x", "usage": {"input_tokens": 1, "output_tokens": 1}}

    class _CaptureClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, *, headers, content):
            seen.update(headers)
            return _Resp()

    monkeypatch.setattr(P.httpx, "AsyncClient", _CaptureClient)
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    r = c.post("/anthropic/v1/messages",
               headers={"x-api-key": tok, "traceparent": tp, "tracestate": "vendor=1"},
               json={"model": "claude-3-5-haiku", "max_tokens": 5,
                     "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert seen.get("traceparent") == tp and seen.get("tracestate") == "vendor=1"


def test_upstream_timeout_returns_504(monkeypatch):
    """A real upstream timeout surfaces as a clean 504 (not a raw 500)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")   # gives build_plans a real plan
    import proxyagent.providers as P

    class _TimeoutClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): raise P.httpx.TimeoutException("timed out")

    monkeypatch.setattr(P.httpx, "AsyncClient", _TimeoutClient)
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "claude-3-5-haiku", "max_tokens": 5,
                     "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 504 and "timeout" in r.json()["error"].lower()
    # it's logged as a 504
    assert c.get("/admin/logs", headers=ADMIN).json()["logs"][0]["status"] == 504


def test_event_webhook_token_lifecycle(monkeypatch):
    """Creating + revoking a token POSTs lifecycle events to PROXYAGENT_EVENT_WEBHOOK."""
    import proxyagent.server as srv
    sent = []

    class _Resp:
        status_code = 200

    import json as _j
    monkeypatch.setattr(srv.httpx, "post",
                        lambda url, **kw: (sent.append(_j.loads(kw["content"])), _Resp())[1])
    monkeypatch.setenv("PROXYAGENT_EVENT_WEBHOOK", "https://hook.test/events")
    c = _client()
    mk = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "ci"}).json()
    c.delete("/admin/tokens/" + mk["id"], headers=ADMIN)
    events = {e["event"]: e for e in sent}
    assert "token_created" in events and "token_revoked" in events
    assert events["token_created"]["id"] == mk["id"] and events["token_created"]["label"] == "ci"
    assert events["token_revoked"]["id"] == mk["id"]


def test_webhook_hmac_signature(monkeypatch):
    """When PROXYAGENT_WEBHOOK_SECRET is set, webhook payloads carry a valid HMAC signature."""
    import hashlib
    import hmac
    import json as _j
    import proxyagent.server as srv
    cap = {}

    class _Resp:
        status_code = 200

    def _post(url, **kw):
        cap["content"] = kw["content"]
        cap["headers"] = kw["headers"]
        return _Resp()

    monkeypatch.setattr(srv.httpx, "post", _post)
    monkeypatch.setenv("PROXYAGENT_EVENT_WEBHOOK", "https://hook.test/x")
    monkeypatch.setenv("PROXYAGENT_WEBHOOK_SECRET", "s3cret")
    c = _client()
    c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "ci"})
    sig = cap["headers"].get("X-Proxyagent-Signature", "")
    expected = "sha256=" + hmac.new(b"s3cret", cap["content"], hashlib.sha256).hexdigest()
    assert sig == expected
    assert _j.loads(cap["content"])["event"] == "token_created"


def test_token_request_count():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "rc"}).json()["token"]
    for _ in range(3):
        c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    rc = next(t for t in c.get("/admin/tokens", headers=ADMIN).json()["tokens"] if t["label"] == "rc")
    assert rc["requests"] == 3


def test_healthz_cache_field():
    c = _client()
    h = c.get("/healthz").json()
    assert "cache" in h and set(h["cache"]) == {"enabled", "size"}


def test_budget_webhook_fires(monkeypatch):
    """When a token crosses its budget, the proxy POSTs an alert to the configured webhook
    (deduped) before returning 402."""
    import proxyagent.server as srv
    sent = []

    class _Resp:  # minimal stand-in
        status_code = 200

    def _fake_post(url, **kw):
        import json as _j
        sent.append({"url": url, "json": _j.loads(kw["content"]), "headers": kw.get("headers", {})})
        return _Resp()

    monkeypatch.setattr(srv.httpx, "post", _fake_post)
    monkeypatch.setenv("PROXYAGENT_BUDGET_WEBHOOK", "https://hook.test/alert")
    c = _client()
    mk = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "budget_usd": 0.001})
    tok, tid = mk.json()["token"], mk.json()["id"]
    # seed spend over the cap, then a call trips the budget + the webhook
    c.app.state.store.log_request(token_id=tid, provider="anthropic", model="x", status=200, cost_usd=0.01)
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 402
    assert len(sent) == 1
    body = sent[0]["json"]
    assert body["event"] == "budget_exhausted" and body["type"] == "token" and body["id"] == tid
    assert body["cap_usd"] == 0.001 and body["spend_usd"] >= 0.001
    # second blocked call within cooldown does NOT re-fire
    c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
           json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    assert len(sent) == 1


def test_provider_budget_402(monkeypatch):
    """A provider-wide cost ceiling returns 402 once the provider's total spend crosses it,
    regardless of which token calls."""
    from proxyagent.store import now_ms
    monkeypatch.setenv("PROXYAGENT_PROVIDER_BUDGETS", '{"anthropic": 0.001}')
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # seed spend above the ceiling via a logged call, then the next request is blocked
    store = c.app.state.store
    _, trow = store.create_token("seed", ["*"])
    store.log_request(token_id=trow["id"], provider="anthropic", model="x", status=200, cost_usd=0.01)
    assert store.provider_spend("anthropic") >= 0.001
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
               json={"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 402 and "budget" in r.json()["detail"]
    # a different, un-capped provider still works
    r2 = c.post("/openai/v1/chat/completions", headers={"x-api-key": tok},
                json={"model": "mock", "messages": [{"role": "user", "content": "hi"}]})
    assert r2.status_code == 200


def test_credential_label_stored():
    c = _client()
    r = c.post("/admin/providers", headers=ADMIN,
               json={"provider": "anthropic", "secret": "sk-x", "label": "prod-pool"})
    assert r.status_code == 200
    creds = c.get("/admin/providers", headers=ADMIN).json()["credentials"]
    assert any(k["label"] == "prod-pool" for k in creds)


def test_readyz_require_provider(monkeypatch):
    monkeypatch.setenv("PROXYAGENT_REQUIRE_PROVIDER", "1")
    c = _client()
    # no provider configured → not ready
    r = c.get("/readyz")
    assert r.status_code == 503 and "no provider" in r.json()["error"]
    # add a credential → ready
    c.post("/admin/providers", headers=ADMIN, json={"provider": "anthropic", "secret": "sk-x"})
    r2 = c.get("/readyz")
    assert r2.status_code == 200 and r2.json()["ready"] is True and "anthropic" in r2.json()["providers"]


def test_token_last_error_surfaced(monkeypatch):
    from proxyagent.store import now_ms
    c = _client()
    mk = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "e"}).json()
    store = c.app.state.store
    store.log_request(token_id=mk["id"], provider="anthropic", model="x", status=401,
                      error="authentication failed", ts_ms=now_ms())
    t = next(x for x in c.get("/admin/tokens", headers=ADMIN).json()["tokens"] if x["id"] == mk["id"])
    assert t["last_error"] and t["last_error"]["status"] == 401
    assert "authentication failed" in t["last_error"]["error"]
    # a token with no errors reports null
    ok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "ok"}).json()
    t2 = next(x for x in c.get("/admin/tokens", headers=ADMIN).json()["tokens"] if x["id"] == ok["id"])
    assert t2["last_error"] is None


def test_readyz_and_ping():
    c = _client()
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["ready"] is True and r.json()["backend"] == "sqlite"
    assert Store(":memory:").ping() is True
    # broken store → 503 (monkeypatch the store the route closes over)
    c.app.state.store.ping = lambda: (_ for _ in ()).throw(RuntimeError("db gone"))
    rr = c.get("/readyz")
    assert rr.status_code == 503 and rr.json()["ready"] is False and "db gone" in rr.json()["error"]


def test_py_typed_marker_packaged():
    import proxyagent
    import os.path as _p
    assert _p.exists(_p.join(_p.dirname(proxyagent.__file__), "py.typed"))


def test_server_side_tool_loop(monkeypatch):
    """Full agentic loop offline: mock asks to call a tool → proxy executes it server-side
    → appends tool_result → re-calls → mock returns a final answer citing the tool output."""
    import json as _j
    monkeypatch.setenv("PROXYAGENT_DISABLE_WEB_SEARCH", "1")  # only our local echo tool is offered
    c = _client()
    from proxyagent.tools import Tool

    async def _echo(args):
        return f"ECHO[{args.get('query', '')}]"
    c.app.state.tools.register(Tool(
        "echo", "echo back the query",
        {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, _echo))

    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    # Anthropic shape
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok, "x-proxyagent-tools": "on"},
               json={"model": "mock", "max_tokens": 50, "messages": [{"role": "user", "content": "ping"}]})
    assert r.status_code == 200
    assert r.headers.get("x-proxyagent-tool-steps") == "1"   # exactly one tool round-trip
    body = r.json()
    assert body["stop_reason"] == "end_turn"                 # ended with a final answer, not tool_use
    assert "ECHO[ping]" in _j.dumps(body)                    # the tool actually ran server-side
    # OpenAI shape too
    r2 = c.post("/openai/v1/chat/completions", headers={"authorization": f"Bearer {tok}", "x-proxyagent-tools": "on"},
                json={"model": "mock", "messages": [{"role": "user", "content": "hey"}]})
    assert r2.headers.get("x-proxyagent-tool-steps") == "1"
    assert "ECHO[hey]" in _j.dumps(r2.json())
    assert r2.json()["choices"][0]["finish_reason"] == "stop"


def test_agentic_max_steps_zero_returns_tool_request(monkeypatch):
    """max-steps=0 returns the model's tool request WITHOUT executing it — so a client can
    run the tool itself. Verifies the per-request header overrides the loop budget."""
    import json as _j
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r = c.post("/anthropic/v1/messages",
               headers={"x-api-key": tok, "x-proxyagent-tools": "on", "x-proxyagent-tool-steps-max": "0"},
               json={"model": "mock", "max_tokens": 50, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert r.headers.get("x-proxyagent-tool-steps") == "0"
    assert r.headers.get("x-proxyagent-tool-steps-max") == "0"
    body = r.json()
    assert body["stop_reason"] == "tool_use"                 # not executed → still asking
    assert any(b.get("type") == "tool_use" for b in body["content"])
    # env default still runs the full loop when no header is sent
    monkeypatch.setenv("PROXYAGENT_DISABLE_WEB_SEARCH", "1")
    c2 = _client()
    from proxyagent.tools import Tool

    async def _echo(args):
        return f"ECHO[{args.get('query', '')}]"
    c2.app.state.tools.register(Tool("echo", "e", {"type": "object", "properties": {
        "query": {"type": "string"}}, "required": ["query"]}, _echo))
    tok2 = c2.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    r2 = c2.post("/anthropic/v1/messages", headers={"x-api-key": tok2, "x-proxyagent-tools": "on"},
                 json={"model": "mock", "max_tokens": 50, "messages": [{"role": "user", "content": "go"}]})
    assert r2.headers.get("x-proxyagent-tool-steps") == "1" and "ECHO[go]" in _j.dumps(r2.json())


def test_plan_for_credential_per_kind():
    from proxyagent.providers import plan_for_credential
    from proxyagent.config import PROVIDERS
    body = {"model": "claude-3-5-haiku", "max_tokens": 1, "messages": []}
    # api_key → provider endpoint + x-api-key header
    url, hdrs, raw = plan_for_credential(PROVIDERS["anthropic"], {"kind": "api_key", "secret": "sk-x"}, body)
    assert url == PROVIDERS["anthropic"].endpoint and hdrs["x-api-key"] == "sk-x"
    # oauth → Bearer
    _, h2, _ = plan_for_credential(PROVIDERS["openai"], {"kind": "oauth", "secret": "tok"}, body)
    assert h2["Authorization"] == "Bearer tok"
    # azure with no endpoint → None (can't build a plan)
    assert plan_for_credential(PROVIDERS["openai"], {"kind": "azure", "secret": "k", "meta": {}}, body) is None
    # azure with endpoint → that URL + api-key header
    u3, h3, _ = plan_for_credential(PROVIDERS["openai"],
                                    {"kind": "azure", "secret": "k", "meta": {"endpoint": "https://az/x"}}, body)
    assert u3 == "https://az/x" and h3["api-key"] == "k"


def test_test_all_credentials(monkeypatch):
    import proxyagent.server as srv

    async def _fake(config, provider, cred, **kw):
        # 'anthropic' reports healthy, everything else auth-failed
        return ({"ok": True, "reachable": True, "status": 200, "latency_ms": 5, "detail": "authenticated"}
                if provider == "anthropic"
                else {"ok": False, "reachable": True, "status": 401, "detail": "bad credential"})

    monkeypatch.setattr(srv, "test_credential", _fake)
    c = _client()
    c.post("/admin/providers", headers=ADMIN, json={"provider": "anthropic", "secret": "sk-a"})
    c.post("/admin/providers", headers=ADMIN, json={"provider": "openai", "secret": "sk-b"})
    r = c.post("/admin/providers/test-all", headers=ADMIN).json()
    assert r["total"] == 2 and r["ok"] == 1
    by_prov = {x["provider"]: x for x in r["results"]}
    assert by_prov["anthropic"]["ok"] is True and by_prov["openai"]["ok"] is False
    assert all("id" in x and "kind" in x for x in r["results"])
    assert c.post("/admin/providers/test-all").status_code == 401


def test_body_size_guard_413(monkeypatch):
    monkeypatch.setenv("PROXYAGENT_MAX_BODY_BYTES", "200")
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"]}).json()["token"]
    big = {"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "x" * 5000}]}
    r = c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=big)
    assert r.status_code == 413 and "too large" in r.json()["detail"]
    # a small request still works
    small = {"model": "mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
    assert c.post("/anthropic/v1/messages", headers={"x-api-key": tok}, json=small).status_code == 200


def test_credential_test_endpoint_404():
    c = _client()
    # unknown credential id → 404, no network
    assert c.post("/admin/providers/key_nope/test", headers=ADMIN).status_code == 404
    # admin-gated
    assert c.post("/admin/providers/key_nope/test").status_code == 401


def test_test_credential_unreachable(monkeypatch):
    """A credential pointed at a dead host reports reachable=False (network error caught)."""
    import asyncio
    from proxyagent.providers import test_credential
    from proxyagent.config import Config
    cfg = Config.load()
    cred = {"provider": "anthropic", "kind": "api_key", "secret": "sk-x",
            "meta": {}, "id": "key_x"}

    class _BoomClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): raise ConnectionError("no route to host")

    monkeypatch.setattr("proxyagent.providers.httpx.AsyncClient", _BoomClient)
    res = asyncio.new_event_loop().run_until_complete(test_credential(cfg, "anthropic", cred))
    assert res["ok"] is False and res["reachable"] is False
    assert "ConnectionError" in res["detail"]


def test_log_retention_trim():
    from proxyagent.store import now_ms
    s = Store(":memory:")
    _, tok = s.create_token("m", ["*"])
    # one old call (10 days ago) + one fresh call
    s.log_request(token_id=tok["id"], provider="anthropic", model="mock", status=200,
                  ts_ms=now_ms() - 10 * 86_400_000, cost_usd=0.01)
    s.log_request(token_id=tok["id"], provider="anthropic", model="mock", status=200, cost_usd=0.02)
    assert len(s.list_logs()) == 2
    deleted = s.trim_logs(now_ms() - 7 * 86_400_000)   # keep last 7 days
    assert deleted == 1
    rows = s.list_logs()
    assert len(rows) == 1 and rows[0]["model"] == "mock"


def test_log_trim_and_export_endpoints():
    c = _client()
    tok = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "ci"}).json()["token"]
    c.post("/anthropic/v1/messages", headers={"x-api-key": tok},
           json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    # CSV export carries the header row + the call
    exp = c.get("/admin/logs/export", headers=ADMIN)
    assert exp.status_code == 200 and exp.headers["content-type"].startswith("text/csv")
    lines = exp.text.strip().splitlines()
    assert lines[0].startswith("ts_ms,request_id,token_id,token_label,provider,model")
    assert any("mock" in ln for ln in lines[1:])
    # trim with days=0 wipes everything; bad input rejected
    assert c.post("/admin/logs/trim", headers=ADMIN, params={"days": -1}).status_code == 400
    trimmed = c.post("/admin/logs/trim", headers=ADMIN, params={"days": 0}).json()
    assert trimmed["deleted"] >= 1 and c.get("/admin/logs", headers=ADMIN).json()["logs"] == []
    # admin-gated
    assert c.get("/admin/logs/export").status_code == 401


def test_usage_by_token_breakdown():
    c = _client()
    a = c.post("/admin/tokens", headers=ADMIN, json={"scope": ["*"], "label": "alpha"}).json()["token"]
    b = c.post("/admin/tokens", headers=ADMIN,
               json={"scope": ["*"], "label": "beta", "budget_usd": 5.0}).json()["token"]
    for _ in range(2):
        c.post("/anthropic/v1/messages", headers={"x-api-key": a},
               json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    c.post("/anthropic/v1/messages", headers={"x-api-key": b},
           json={"model": "mock", "max_tokens": 10, "messages": [{"role": "user", "content": "yo"}]})
    rows = {t["label"]: t for t in c.get("/admin/usage-by-token", headers=ADMIN).json()["tokens"]}
    assert rows["alpha"]["requests"] == 2 and rows["beta"]["requests"] == 1
    assert rows["beta"]["budget_usd"] == 5.0 and rows["beta"]["budget_pct"] is not None
    assert rows["alpha"]["budget_pct"] is None
    assert c.get("/admin/usage-by-token").status_code == 401
