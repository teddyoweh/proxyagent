"""Request signers for the cloud auth modes — so the proxy holds the cloud credentials
and the machine running the harness holds none.

  * AWS SigV4 (Bedrock) — full signature, no boto3 dependency.
  * Azure OpenAI — api-key header to a custom deployment endpoint.

Vertex (GCP service-account → access token) lands next.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import time
from urllib.parse import quote


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(*, method: str, host: str, path: str, region: str, service: str,
                  access_key: str, secret_key: str, body: bytes,
                  session_token: str | None = None,
                  content_type: str = "application/json", now: datetime.datetime | None = None) -> dict:
    """AWS Signature Version 4 headers for a request. `path` must already be URI-encoded."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()

    hdrs = {"content-type": content_type, "host": host, "x-amz-date": amzdate}
    if session_token:
        hdrs["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    canonical_request = f"{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n"
                      f"{hashlib.sha256(canonical_request.encode()).hexdigest()}")
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    out = {"Authorization": auth, "x-amz-date": amzdate, "content-type": content_type}
    if session_token:
        out["x-amz-security-token"] = session_token
    return out


# Map a few common Anthropic model ids → their Bedrock ids (best-effort; pass a bedrock id directly to skip).
def bedrock_model_id(model: str) -> str:
    if model.startswith("anthropic.") or ":" in model:
        return model
    table = {
        "claude-opus-4": "anthropic.claude-opus-4-20250514-v1:0",
        "claude-sonnet-4-5": "anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4": "anthropic.claude-sonnet-4-20250514-v1:0",
        "claude-3-5-sonnet": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "claude-3-5-haiku": "anthropic.claude-3-5-haiku-20241022-v1:0",
    }
    for prefix, bid in table.items():
        if model.startswith(prefix):
            return bid
    return model


def bedrock_plan(cred: dict, body: dict):
    """(url, headers, body_bytes) for a Claude-on-Bedrock invoke, SigV4-signed here."""
    meta = cred.get("meta") or {}
    region = meta.get("region", "us-east-1")
    model_id = bedrock_model_id(body.get("model", ""))
    payload = {k: v for k, v in body.items() if k != "model"}
    payload["anthropic_version"] = "bedrock-2023-05-31"
    raw = json.dumps(payload).encode("utf-8")
    host = f"bedrock-runtime.{region}.amazonaws.com"
    path = f"/model/{quote(model_id, safe='')}/invoke"
    headers = sigv4_headers(
        method="POST", host=host, path=path, region=region, service="bedrock",
        access_key=meta.get("access_key", ""), secret_key=cred.get("secret", ""),
        body=raw, session_token=meta.get("session_token"))
    return f"https://{host}{path}", headers, raw


# ------------------------------------------------------------------ #
# Google Vertex AI — service account → OAuth2 access token → Claude-on-Vertex.
# The proxy holds the service-account key; the machine holds none.
# ------------------------------------------------------------------ #

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_VERTEX_TOKEN_CACHE: dict[str, tuple[str, int]] = {}   # client_email -> (token, expiry_ms)


def vertex_signed_assertion(sa: dict, *, now: int | None = None) -> str:
    """A signed RS256 JWT bearer assertion for the service account (no network)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    iat = int(now if now is not None else time.time())
    token_uri = sa.get("token_uri", "https://oauth2.googleapis.com/token")
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": sa["client_email"], "scope": "https://www.googleapis.com/auth/cloud-platform",
              "aud": token_uri, "iat": iat, "exp": iat + 3600}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(sig)}"


def vertex_access_token(sa: dict) -> str:
    """Exchange the SA assertion for a short-lived access token (cached ~1h)."""
    import httpx
    email = sa["client_email"]
    nowms = int(time.time() * 1000)
    cached = _VERTEX_TOKEN_CACHE.get(email)
    if cached and cached[1] - 60_000 > nowms:
        return cached[0]
    token_uri = sa.get("token_uri", "https://oauth2.googleapis.com/token")
    r = httpx.post(token_uri, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": vertex_signed_assertion(sa)}, timeout=20)
    r.raise_for_status()
    body = r.json()
    tok, ttl = body["access_token"], body.get("expires_in", 3600)
    _VERTEX_TOKEN_CACHE[email] = (tok, nowms + ttl * 1000)
    return tok


def vertex_url(project: str, region: str, model: str) -> str:
    return (f"https://{region}-aiplatform.googleapis.com/v1/projects/{project}"
            f"/locations/{region}/publishers/anthropic/models/{quote(model, safe='')}:rawPredict")


def vertex_plan(cred: dict, body: dict):
    """(url, headers, body_bytes) for a Claude-on-Vertex rawPredict call."""
    sa = json.loads(cred["secret"])                      # the full service-account JSON
    meta = cred.get("meta") or {}
    region = meta.get("region") or sa.get("region") or "us-east5"
    project = meta.get("project_id") or sa.get("project_id")
    payload = {k: v for k, v in body.items() if k != "model"}
    payload["anthropic_version"] = "vertex-2023-10-16"
    raw = json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json", "Authorization": f"Bearer {vertex_access_token(sa)}"}
    return vertex_url(project, region, body.get("model", "")), headers, raw
