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

**3. Run any agent on any machine — no real key there:**
```bash
PROXYAGENT_TOKEN=pa_… proxyagent run claude-code \
  --goal "build a SwiftUI todo app" --proxy https://proxy.you.com
# or:  proxyagent run codex --goal "fix the failing tests" --token pa_…
```

Or use any harness directly — just set the env and the proxy does the rest:
```bash
export ANTHROPIC_BASE_URL=https://proxy.you.com/anthropic
export ANTHROPIC_API_KEY=pa_…          # the machine token, not the real key
claude -p "ship it"
```

## The dashboard
`proxyagent serve` ships a dashboard at `/` (reveal the admin token with
`proxyagent admin-token`):

- **Access keys** — the credentials you create. Each is a provider + an auth type
  (Anthropic · API key, Anthropic · Bedrock, OpenAI · Azure, …); pick the type, enter the
  key/fields, done. Listed with provider logo · auth type · masked key · remove.
- **Machine tokens** — mint (scoped / TTL / budget), list, revoke.
- **Model routing** — add/remove model remaps (e.g. `* → mock` for offline).
- **Activity** — live request log with usage + cost, and headline stats.

## Proxied tools — the same trick, for tools
The proxy can also hold your **tool** keys and hand agents governed tools — so an agent gets
web search (and custom tools) without ever holding the tool's credential.

```bash
export TAVILY_API_KEY=tvly-…                                   # web_search uses this; agents never see it
export PROXYAGENT_TOOLS='[{"name":"crm","url":"https://hooks.you.com/crm","headers":{"Authorization":"Bearer …"}}]'
# then send requests with header  x-proxyagent-tools: on  → tool defs are injected;
# the proxy executes calls to managed tools server-side (keys stay here).
```

## Credentials, storage & cost

By default provider keys come from the **environment** and stay local. Or **add** them
once and they're stored **encrypted** (`proxy_agent_keys`) — locally in SQLite, or in
**Postgres** if you point at one. Either way the machine never sees them.

```bash
export PROXYAGENT_SECRET_KEY=…                 # enables at-rest encryption (Fernet)
proxyagent provider add anthropic --key sk-ant-…          # stored, encrypted
proxyagent provider add openai --key sk-…  --kind api_key
# OAuth: store an access token →  proxyagent provider add anthropic --key <oauth-token> --kind oauth
proxyagent provider ls

# Postgres-backed (shared, multi-instance): tables proxy_agent_keys / _tokens / _calls
export PROXYAGENT_DATABASE_URL=postgresql://user:pass@host/db    # pip install 'proxyagent[postgres]'
```

Every call is traced in `proxy_agent_calls` with **token usage, latency, and computed
cost** (per-model pricing, override via `PROXYAGENT_PRICING`). See it live:

```bash
proxyagent usage          # totals: requests · tokens · $ cost
proxyagent logs           # per-request trace incl. cost
```

## Deploy
```bash
docker compose up -d                 # proxy at :8080; reveal admin token via `docker compose logs`
# or with shared Postgres:
docker compose --profile postgres up -d
```
A `Dockerfile` (with a `/healthz` HEALTHCHECK) and `docker-compose.yml` (proxy + optional Postgres,
persistent volume) ship in the repo. Bring keys via a `.env` file. Verified: container builds,
`/healthz` green, mock call + dashboard serve.

## Observability — Prometheus
`GET /metrics` exposes `proxyagent_requests_total`, `proxyagent_responses_total{status}`,
`proxyagent_tokens_total{direction}`, `proxyagent_cost_usd_total{provider}`,
`proxyagent_active_tokens`, `proxyagent_credentials`. Admin-gated by default; set
`PROXYAGENT_METRICS_PUBLIC=1` for unauthenticated scraping on an internal network.

## Security model
- **Real keys never leave the proxy** — read from env, never persisted, never logged, never returned.
- **Machine tokens are stored hashed** (SHA-256); plaintext shown once. A stolen DB yields nothing usable.
- **Scoped** (`provider:model` globs), **expiring** (TTL), **revocable**, **rate-limited**.
- **Constant-time** token comparison; sensitive headers redacted from logs.
- Admin API + dashboard gated by a separate admin token. Run it behind TLS.

## SDK
```python
import proxyagent

# host the proxy (embed in your own service):
app = proxyagent.create_app()              # ASGI app

# mint tokens programmatically:
admin = proxyagent.Admin("https://proxy.you.com", "pa_admin_…")
token = admin.mint("ci-runner", scope=["anthropic:claude-*"], ttl_seconds=3600)

# run a harness on this machine, no key here:
proxyagent.run("claude-code", goal="build the app",
               proxy="https://proxy.you.com", token=token)
```

## Harnesses & auth modes
You run an **agent harness**, and each one can authenticate several ways. The proxy's job
is to centralise *all* of them so the machine running the harness holds only a `pa_` token:

| Harness | Provider | Auth modes |
|---|---|---|
| **Claude Code** | Anthropic | API key · OAuth (subscription) · AWS Bedrock · Google Vertex |
| **Codex** | OpenAI | API key · OAuth (ChatGPT) · Azure |
| **Gemini CLI** | Google | API key · OAuth · Vertex |

Connect each mode in the dashboard's **Harnesses** tab (or `proxyagent provider add … --kind`).
**Every auth mode is wired**: API key, OAuth, AWS Bedrock (the proxy SigV4-signs the Claude-on-Bedrock
request itself), Azure, and Google Vertex (service-account JSON → access token → Claude-on-Vertex).
For Bedrock/Vertex the proxy holds the AWS/GCP credentials and signs upstream, so the machine needs no cloud creds at all. The model providers below are the *backends* for model-agnostic
harnesses (aider, Cline…).

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

## Per-token budgets
Cap what any token can spend; once its summed cost crosses the cap, the proxy returns **402**.
```bash
proxyagent token new ci --budget 5.00      # this token may spend at most $5
```

## Supported providers
`anthropic` · `openai` · `gemini` · `groq` · `openrouter` · `mistral` · `deepseek` ·
`xai` · `together` — Anthropic uses its Messages API; the rest are OpenAI-compatible.
Point a harness/agent at `https://proxy.you.com/<provider>/v1` and it routes there.
Add or override any endpoint with `PROXYAGENT_<NAME>_ENDPOINT`.

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
