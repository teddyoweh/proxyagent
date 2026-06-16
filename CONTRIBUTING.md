# Contributing

```bash
git clone https://github.com/teddyoweh/proxyagent && cd proxyagent
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,secure]"
pytest -q
```

- Tests run on every push/PR (GitHub Actions, Python 3.10 + 3.12). Add a test with your change.
- No real API keys needed — the built-in `mock` model exercises the full pipeline offline
  (`PROXYAGENT_CACHE_TTL`, `PROXYAGENT_PROVIDER_RATE_LIMITS`, etc. toggle features).
- This is a security tool: keep secrets out of git, never log credentials, and prefer
  scoped/revocable access. Small, focused PRs are easiest to review.
