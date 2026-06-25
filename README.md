<div align="center">

# proxyagent

**Run any agent — Claude, Codex, custom — on any machine, with _no API key on the machine._**

A secure, self-hosted proxy for models **and** tools. Your keys live in one hardened place; every machine holds only a scoped, revocable token.

</div>

---

Agents need model access (and tool access) to do anything. Today that means scattering
real API keys across every machine an agent runs on — a security nightmare. `proxyagent`
fixes it: stand up **one** proxy that holds the real credentials, and point every agent at
it. The machine gets a throwaway token; the real key never leaves the proxy.

```
   remote machine                     proxy (you host)            upstream
 ┌────────────────┐  token only   ┌──────────────────┐  real key  ┌───────────┐
 │ claude / codex │ ───────────►  │  proxyagent serve │ ─────────► │ Anthropic │
 │  (no real key) │ ◄───────────  │  scope·log·tools  │ ◄───────── │  OpenAI   │
 └────────────────┘   stream      └──────────────────┘            └───────────┘
```

## How it works
Every harness honours `*_BASE_URL`, so the shim is trivial: point the base URL at the
proxy and use the **machine token** as the "api key." The proxy authenticates the token,
checks its scope, **swaps in the real key**, forwards upstream, and logs the call. The
machine never sees a real credential.

## Try it with zero keys (local)
```bash
pip install proxyagent && proxyagent serve        # prints an admin token
proxyagent token new local        # works locally, no admin token needed     # mint a token
# call the built-in `mock` model — full pipeline (auth, scope, usage, cost, log), no real key:
curl -s localhost:8080/anthropic/v1/messages -H "x-api-key: pa_…" \
  -d '{"model":"mock","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
```

## Quickstart

**1. Run the proxy** (on a box you control — it holds the real keys):
```bash
pip install proxyagent
export ANTHROPIC_API_KEY=sk-ant-…      # and/or OPENAI_API_KEY=sk-…
proxyagent serve                        # prints an admin token + a dashboard at :8080
```

**2. Mint a machine token** (scoped + revocable):
```bash
proxyagent token new macbook-01 --scope "anthropic:claude-*"   # local: no admin token needed
```

**3. Run a real agent on any machine — no real key there.** Token + prompt, it just runs the
actual Claude Code / Codex CLI locally, routing every model call through the proxy:
```python
import proxyagent
proxyagent.run("build a SwiftUI todo app and run the tests",
               token="pa_…", proxy="https://proxy.you.com")   # harness="codex" for Codex
```
```bash
# same from the CLI:
PROXYAGENT_TOKEN=pa_… proxyagent run codex --goal "fix the failing tests" --proxy https://proxy.you.com
```
Install the agent CLI you want first: `npm i -g @anthropic-ai/claude-code` or `npm i -g @openai/codex`.
proxyagent wires each one to the proxy automatically (Claude Code via `ANTHROPIC_BASE_URL`; Codex via a
one-off model provider). Both are verified end-to-end — every call lands on the proxy, keyless.

## The dashboard & docs
`proxyagent serve` ships a dashboard at `/` and a full **"how to run it" docs page at `/docs`**
(install → serve → add a key → mint a token → point any agent/SDK/curl at the proxy, with
copy-paste snippets pre-filled with your host). Reveal the admin token with
`proxyagent admin-token`. The dashboard:

- **Access keys** — the credentials you create. Each is a provider + an auth type
  (Anthropic · API key, Anthropic · Bedrock, OpenAI · Azure, …); pick the type, enter the
  key/fields, done. Listed with provider logo · auth type · masked key · **test** · **disable** ·
  remove. **Test** pings the real upstream and shows ok / auth-failed / unreachable — catch a
  bad key the moment you add it. **Disable** pauses a credential (it drops out of the failover
  pool) without deleting it, so you can re-enable later.
- **Machine tokens** — mint (scoped / TTL / budget / note / IP allow-list), **search** (by
  label/id/scope), **edit** (retune in place, no re-mint), **clone** (duplicate config, new
  secret), revoke, and **revoke-expired** (one-click cleanup). Minting shows a sample curl + copy-`.env`.
  **Click any machine** to open its **drill-down page** — that machine's requests, spend, budget,
  and an inspectable log of every prompt it sent and the model's output.
- **Model routing** — add/remove model remaps (e.g. `* → mock` for offline).
- **Activity** — **spend-by-token** breakdown (requests · tokens · cost · budget %), a live
  request log with usage + cost, plus **Export CSV** and **Trim** of the audit trail. **Click a
  request** to inspect the exact prompt (system + messages) and the output it returned.

### Prompt & output capture
The proxy records each call's request/response bodies so the dashboard can show what actually
went through — the per-machine page and the Activity feed both expand to a side-by-side
**Prompt → Output** inspector. Bodies are **redacted** (secret-shaped strings → `sk-***`) and
**size-capped** (~16 KB each) before they're stored. On by default; turn it off to keep only
metadata (tokens/cost/status):

```bash
export PROXYAGENT_CAPTURE_BODIES=0     # store metadata only — never persist prompts/outputs
```

## Proxied tools — the same trick, for tools
The proxy can also hold your **tool** keys and hand agents governed tools — so an agent gets
web search (and custom tools) without ever holding the tool's credential.

```bash
export TAVILY_API_KEY=tvly-…                                   # web_search uses this; agents never see it
export PROXYAGENT_TOOLS='[{"name":"crm","url":"https://hooks.you.com/crm","headers":{"Authorization":"Bearer …"}}]'
# then send requests with header  x-proxyagent-tools: on  → tool defs are injected;
# the proxy executes calls to managed tools server-side (keys stay here).
```

**Server-side agentic loop.** With `x-proxyagent-tools: on` (non-streaming), the proxy runs
the *whole* tool loop for you: model asks to use a tool → proxy **executes it server-side**
(its credentials never leave the proxy) → appends the `tool_result` → re-calls the model →
repeats until a final answer (capped at 6 steps). The agent just sends one request and gets
the finished answer back; the response carries `x-proxyagent-tool-steps: <n>`. Works on both
Anthropic (`tool_use`) and OpenAI (`tool_calls`) shapes. Try it offline with `model: "mock"` —
the mock emits a real `tool_use`, so the loop runs end-to-end with no keys.

The step budget defaults to 6 (`PROXYAGENT_MAX_TOOL_STEPS`) and is overridable per-request with
`x-proxyagent-tool-steps-max: <n>`. Set it to **0** to get the model's tool request back
*without* executing it — for clients that want to run the tool themselves.

## Credentials, storage & cost

By default provider keys come from the **environment** and stay local. Or **add** them
once and they're stored **encrypted** (`proxy_agent_keys`) — locally in SQLite, or in
**Postgres** if you point at one. Either way the machine never sees them.

```bash
export PROXYAGENT_SECRET_KEY=…                 # enables at-rest encryption (Fernet)
proxyagent provider add anthropic --key sk-ant-…          # stored, encrypted
proxyagent provider add openai --key sk-…  --kind api_key
# OAuth: store an access token (+ refresh_token/token_url in meta → auto-refreshed before expiry)
proxyagent provider ls
proxyagent provider test <cred-id>     # ping the upstream: ok / auth-failed / unreachable

# Postgres-backed (shared, multi-instance): tables proxy_agent_keys / _tokens / _calls
export PROXYAGENT_DATABASE_URL=postgresql://user:pass@host/db    # pip install 'proxyagent[postgres]'
```

Every call is traced in `proxy_agent_calls` with **token usage, latency, and computed
cost** (per-model pricing, override via `PROXYAGENT_PRICING`). See it live:

```bash
proxyagent doctor             # diagnose setup: providers · encryption · db · admin token
proxyagent usage              # totals: requests · tokens · $ cost
proxyagent logs               # per-request trace incl. cost
proxyagent usage-by-token     # per-token spend breakdown (who's costing what)
proxyagent logs-export -o audit.csv    # dump the audit trail to CSV
proxyagent logs-trim 30       # delete traces older than 30 days
```

**Per-token & per-model spend.** See exactly which machine token *and* which model is costing
what (`GET /admin/usage-by-token`, `GET /admin/usage-by-model`, both surfaced side-by-side in the
dashboard's Activity tab). Keep the audit table bounded and exportable:

```bash
export PROXYAGENT_LOG_RETENTION_DAYS=30        # trim traces older than 30d on startup
curl -XPOST localhost:8080/admin/logs/trim?days=30  -H "x-admin-token: pa_admin_…"   # trim on demand
curl localhost:8080/admin/logs/export -H "x-admin-token: pa_admin_…" -o audit.csv     # CSV for SIEM/archival
```

## Deploy
```bash
docker compose up -d                 # proxy at :8080; reveal admin token via `docker compose logs`
# or with shared Postgres:
docker compose --profile postgres up -d
```
A `Dockerfile` (with a `/healthz` HEALTHCHECK) and `docker-compose.yml` (proxy + optional Postgres,
persistent volume) ship in the repo. Bring keys via a `.env` file. Verified: container builds,
`/healthz` green, mock call + dashboard serve. `GET /readyz` is a **readiness** probe that pings the
backing store and returns **503** if the DB is unreachable — wire it to your load balancer / k8s
readiness check so a broken instance is pulled from rotation. Set `PROXYAGENT_REQUIRE_PROVIDER=1`
to also fail readiness until at least one provider is configured (keeps a fresh/misconfigured
instance out of rotation). Each token's most recent error is surfaced in `/admin/tokens` + the dashboard.

## Rate limits
Per-token limits (mint with `--rate`) and **per-provider** limits protect your upstreams:
```bash
export PROXYAGENT_PROVIDER_RATE_LIMITS='{"anthropic": 600, "openai": 1000}'   # requests/min
export PROXYAGENT_RATE_LIMIT_DEFAULT=300                                        # fallback for the rest
```
Over the limit → `429`.

## Response cache
Off by default. Set `PROXYAGENT_CACHE_TTL=<seconds>` and identical (provider + body) non-streaming
requests are served from memory — saving upstream cost + latency. Cache hits return
`x-proxyagent-cache: hit`; bypass per-request with header `x-proxyagent-cache: no`. Hits/size are
in `/metrics`.

## Request tracing
W3C trace context (`traceparent` / `tracestate` / `baggage`) sent by the client is **forwarded
to the upstream**, so a distributed trace spans the proxy hop. Every proxied response also carries
`x-proxyagent-request-id`. Send your own
(`x-proxyagent-request-id: <id>`) and the proxy honours + echoes it; omit it and the proxy mints
one (`req_…`). The id is stored on the call trace (`proxy_agent_calls.request_id`, in `logs` and
the CSV export), so a client log line ties straight to a row in the audit trail.

## Operational summary
`GET /admin/stats` (or `proxyagent.Admin(...).stats()`) returns a one-shot snapshot — version,
uptime, cache (enabled/ttl/hits/size), **latency p50/p95**, active+total tokens, credentials,
configured providers, **per-tool execution counts**, total requests and spend. `GET /admin/summary`
(or `Admin.summary()`) returns a shareable **Markdown** status report (totals + top providers/models).
`GET /admin/usage-by-day?days=14` returns a daily timeseries (requests/tokens/cost per UTC day). The
dashboard's Activity tab shows the stat strip, a **14-day requests chart**, and each token's
**expiry countdown**, and **auto-refreshes** when you focus the tab.

## Observability — Prometheus
`GET /metrics` exposes `proxyagent_requests_total`, `proxyagent_responses_total{status}`,
`proxyagent_tokens_total{direction}`, `proxyagent_cost_usd_total{provider}`,
`proxyagent_active_tokens`, `proxyagent_credentials`, and a
`proxyagent_request_duration_ms` **histogram** (latency buckets + sum/count). Admin-gated by default; set
`PROXYAGENT_METRICS_PUBLIC=1` for unauthenticated scraping on an internal network.

## Resilience
On a network fault the proxy fails over to the next credential in the pool; if they're all
exhausted it returns a **clean `504`** (upstream timeout) or `502` (connection error) with a
descriptive body — never a raw 500. Tune the upstream timeout with `PROXYAGENT_REQUEST_TIMEOUT`.
Cap request size with `PROXYAGENT_MAX_BODY_BYTES` (over → `413`; 0 = unlimited). Cap in-flight
proxied requests with `PROXYAGENT_MAX_CONCURRENCY` (over → `503`; 0 = unlimited) to shield upstreams. The dashboard's
**Test all** button (and `Admin.test_all_credentials()`) health-sweeps every stored credential
concurrently and reports ok / auth-failed / unreachable per credential. Responses are **gzip**-
compressed when the client accepts it (e.g. model lists / audit logs shrink ~75%), and the
dashboard has a **light/dark theme** toggle (persisted).

## Browser clients (CORS)
Off by default. Set `PROXYAGENT_CORS_ORIGINS` to a comma-separated allowlist (or `*`) and the
proxy answers OPTIONS preflight + echoes `Access-Control-Allow-Origin`, exposing the
`x-proxyagent-*` headers — so a browser-based agent or dashboard can call it directly.
```bash
export PROXYAGENT_CORS_ORIGINS="https://app.you.com,https://staging.you.com"
```

## Security model
- **Real keys never leave the proxy** — read from env, never persisted, never logged, never returned.
- **Machine tokens are stored hashed** (SHA-256); plaintext shown once. A stolen DB yields nothing usable.
- **Scoped** (`provider:model` globs), **expiring** (TTL), **revocable**, **rate-limited**, and
  optionally **IP-locked** (mint with `allowed_ips` CIDRs; off-list clients get `403`, honouring
  `X-Forwarded-For` behind a proxy).
- **Constant-time** token comparison; sensitive headers redacted from logs, and upstream error
  bodies passed through a **secret redactor** (api keys, bearer tokens, AWS/Google keys, emails) before they touch the audit log.
- Admin API + dashboard gated by a separate admin token. Run it behind TLS.

## SDK — token + prompt, it just runs
The headline call: hand it a **token** and a **prompt**, and it runs a real agent (Claude Code
by default) on this machine against that prompt — **no API key here**, the proxy holds the key.
```python
import proxyagent
proxyagent.run("build a SwiftUI todo app and run the tests",
               token="pa_…", proxy="https://proxy.you.com")
# harness="codex" for Codex, command="my-agent {goal}" for any custom agent.
# token also reads PROXYAGENT_TOKEN; proxy reads PROXYAGENT_PROXY.
```
Manage the proxy programmatically too — mint tokens, manage credentials, host it:
```python
import proxyagent
app   = proxyagent.create_app()            # ASGI app — embed in your own service
admin = proxyagent.Admin("https://proxy.you.com", "pa_admin_…")
token = admin.mint("laptop", scope=["anthropic:claude-*"], ttl_seconds=3600)
proxyagent.run("build the app", token=token, proxy="https://proxy.you.com")   # ← run an agent with it
```

## Harnesses & auth modes
Two things are separate: **which agent CLI you run** on the machine, and **how the proxy
authenticates upstream**. The machine only ever holds a `pa_` token; the proxy holds the real
credential in whatever auth mode you configure.

Built-in harnesses (run the real CLI locally, keyless): **`claude-code`**, **`codex`**, and any
**custom** command (`--command "my-agent {goal}"`) — anything that respects `*_BASE_URL`, e.g. aider/Cline.

On the proxy side, a provider credential can be any of these auth modes — all wired:

| Auth mode | How the proxy uses it |
|---|---|
| **API key** | `x-api-key` / `Authorization: Bearer` to the provider endpoint |
| **OAuth** | stored access token, auto-refreshed via refresh_token before expiry |
| **AWS Bedrock** | the proxy SigV4-signs the Claude-on-Bedrock request itself (no boto3) |
| **Azure** | api-key header to your Azure deployment URL |
| **Google Vertex** | service-account JSON → JWT → access token → Claude-on-Vertex |

For Bedrock/Vertex the proxy holds the AWS/GCP credentials and signs upstream, so the machine needs
no cloud creds at all. Add any of them in the dashboard's **Access keys** tab or via `proxyagent provider add … --kind`.

```bash
# the cloud-credential paths — the machine that runs the harness holds none of these:
proxyagent provider add anthropic --kind bedrock --key <AWS_SECRET>   # + meta: access_key, region
proxyagent provider add openai    --kind azure   --key <AZURE_KEY>    # + meta: endpoint
proxyagent provider add anthropic --kind oauth    --key <OAUTH_TOKEN>
proxyagent provider add anthropic --kind vertex  --key "$(cat sa.json)"   # + meta: region
```

## Credential pools & failover
A provider isn't one key — it's a **pool**. Add as many credentials as you want, across
auth types (several API keys, OAuth tokens, …); each is managed individually in the
dashboard. The proxy rotates through the pool, **failing over** to the next credential on
any `429` / `5xx` — so a rate-limited or dead key never takes you down.

```bash
proxyagent provider add anthropic --key sk-ant-aaa        # additive — builds the pool
proxyagent provider add anthropic --key sk-ant-bbb
proxyagent provider add anthropic --key <oauth> --kind oauth
```

## Budgets — per-token and per-provider
Cap what any token can spend; once its summed cost crosses the cap, the proxy returns **402**.
```bash
proxyagent token new ci --budget 5.00      # this token may spend at most $5
```
Or cap a whole **provider** — a spend ceiling across *all* tokens, so one runaway agent can't
blow your bill no matter which token it holds:
```bash
export PROXYAGENT_PROVIDER_BUDGETS='{"anthropic": 200, "openai": 50}'   # $ ceilings; over → 402
```
Get **alerted** when any cap is crossed — the proxy POSTs a webhook (deduped per token/provider
with a cooldown) right before the 402:
```bash
export PROXYAGENT_BUDGET_WEBHOOK=https://hooks.slack.com/…   # {event,type,id,cap_usd,spend_usd}
export PROXYAGENT_BUDGET_WEBHOOK_COOLDOWN=300                # seconds between repeat alerts (default 300)
export PROXYAGENT_EVENT_WEBHOOK=https://hooks.you.com/…      # token_created / token_revoked lifecycle events
export PROXYAGENT_WEBHOOK_SECRET=…                           # sign all webhooks: X-Proxyagent-Signature: sha256=HMAC(body)
```

## Supported providers
`anthropic` · `openai` · `gemini` · `groq` · `openrouter` · `mistral` · `deepseek` ·
`xai` · `together` — Anthropic uses its Messages API; the rest are OpenAI-compatible.
Point a harness/agent at `https://proxy.you.com/<provider>/v1` and it routes there.
Add or override any endpoint with `PROXYAGENT_<NAME>_ENDPOINT`. A `GET /v1/models` (and
`/<provider>/v1/models`) returns the routable catalog in OpenAI list shape, so harnesses that
probe for available models just work.

## Model remap — rename or reroute models
Rewrite the requested model before forwarding — rename it, or reroute it to a totally
different provider:

```bash
proxyagent alias set gpt-4o anthropic:claude-sonnet-4-5   # send "gpt-4o" calls to Claude
proxyagent alias set '*' mock                             # force EVERYTHING offline (no keys)
proxyagent alias ls
```

The `'*' → mock` trick is the **offline harness** unlock: point `claude-code` at the
proxy, map everything to `mock`, and it runs end-to-end with zero keys and zero spend —
perfect for local dev, demos, and CI.

## Supported harnesses
`claude-code`, `codex`, and any **custom** command (`--command "my-agent {goal}"`). Adding one
is a few lines — it just needs to respect `*_BASE_URL`.

## License
Apache-2.0
