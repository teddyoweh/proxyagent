"""Cost tracking — turn token usage into dollars.

Prices are USD per 1M tokens (input, output). Matched by a prefix of the model name,
so "claude-sonnet-4-5-2025…" picks up "claude-sonnet". Override / extend via
`PROXYAGENT_PRICING` (JSON: {"model-prefix": [in_per_mtok, out_per_mtok]}).
"""

from __future__ import annotations

import json
import os

# Indicative list prices (USD / 1M tokens). Tune freely.
DEFAULT_PRICES: dict[str, tuple[float, float]] = {
    # Anthropic
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-5-haiku": (0.80, 4.0),
    # OpenAI
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.0, 8.0),
    "o3-mini": (1.10, 4.40),
    "o3": (2.0, 8.0),
    "gpt-5": (1.25, 10.0),
    # offline test provider — free
    "mock": (0.0, 0.0),
}


def _prices() -> dict[str, tuple[float, float]]:
    prices = dict(DEFAULT_PRICES)
    raw = os.environ.get("PROXYAGENT_PRICING")
    if raw:
        try:
            for k, v in json.loads(raw).items():
                prices[k] = (float(v[0]), float(v[1]))
        except Exception:
            pass
    return prices


def price_for(model: str) -> tuple[float, float] | None:
    if not model:
        return None
    prices = _prices()
    # longest matching prefix wins (so gpt-4o-mini beats gpt-4o)
    best = None
    for prefix, p in prices.items():
        if model.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, p)
    return best[1] if best else None


def cost_usd(model: str, input_tokens: int | None, output_tokens: int | None) -> float | None:
    p = price_for(model or "")
    if p is None:
        return None
    cin, cout = p
    return round((input_tokens or 0) / 1e6 * cin + (output_tokens or 0) / 1e6 * cout, 6)
