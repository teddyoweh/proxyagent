"""Proxied tools — give agents governed tools (web search, custom HTTP tools) whose
credentials live ONLY on the proxy.

The proxy can:
  * inject tool definitions into a model request (so the agent can call them), and
  * execute the tool server-side when the model asks for it — so the agent never
    holds the tool's API key (same security model as the model keys).

Built-in: `web_search`. Custom tools are registered as HTTP webhooks in config; their
auth headers stay on the proxy.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict                       # JSON Schema for the tool input
    executor: Callable[[dict], Awaitable[str]]

    def anthropic_def(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}

    def openai_def(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.input_schema}}


# ------------------------------------------------------------------ #
# Built-in: web search (Tavily if configured, else DuckDuckGo fallback).
# The search key lives on the proxy — agents never see it.
# ------------------------------------------------------------------ #

async def _web_search(args: dict) -> str:
    query = str(args.get("query", "")).strip()
    if not query:
        return "error: empty query"
    tavily = os.environ.get("TAVILY_API_KEY")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            if tavily:
                r = await client.post("https://api.tavily.com/search", json={
                    "api_key": tavily, "query": query, "max_results": 5})
                data = r.json()
                hits = [f"- {h['title']}: {h['url']}\n  {h.get('content','')[:300]}"
                        for h in data.get("results", [])]
                return ("\n".join(hits)) or "no results"
            # Keyless fallback: DuckDuckGo Instant Answer.
            r = await client.get("https://api.duckduckgo.com/", params={
                "q": query, "format": "json", "no_html": 1})
            data = r.json()
            out = []
            if data.get("AbstractText"):
                out.append(data["AbstractText"])
            for t in (data.get("RelatedTopics") or [])[:5]:
                if isinstance(t, dict) and t.get("Text"):
                    out.append(f"- {t['Text']} ({t.get('FirstURL','')})")
            return "\n".join(out) or "no results (set TAVILY_API_KEY for full web search)"
    except Exception as exc:  # noqa: BLE001
        return f"search error: {exc}"


WEB_SEARCH = Tool(
    name="web_search",
    description="Search the web and return the top results. Use for current info.",
    input_schema={"type": "object", "properties": {
        "query": {"type": "string", "description": "The search query"}}, "required": ["query"]},
    executor=_web_search,
)


def _http_tool(spec: dict) -> Tool:
    """A custom tool that POSTs the model's input to a URL you control. The tool's
    auth headers live here on the proxy, not on the agent."""
    url = spec["url"]
    headers = spec.get("headers", {})

    async def _run(args: dict) -> str:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(url, headers=headers, json=args)
        return r.text[:4000]

    return Tool(spec["name"], spec.get("description", ""),
                spec.get("input_schema", {"type": "object", "properties": {}}), _run)


class ToolRegistry:
    def __init__(self, config=None):
        self._tools: dict[str, Tool] = {}
        # web_search is on by default unless explicitly disabled.
        if os.environ.get("PROXYAGENT_DISABLE_WEB_SEARCH") != "1":
            self.register(WEB_SEARCH)
        # Custom tools from PROXYAGENT_TOOLS (JSON list of {name,url,headers,...}).
        raw = os.environ.get("PROXYAGENT_TOOLS")
        if raw:
            try:
                for spec in json.loads(raw):
                    self.register(_http_tool(spec))
            except Exception:
                pass

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return list(self._tools)

    def list(self) -> list[dict]:
        return [{"name": t.name, "description": t.description} for t in self._tools.values()]

    def inject(self, body: dict, provider: str) -> dict:
        """Add registered tools to a request in the provider's format (non-destructive)."""
        if not self._tools:
            return body
        existing = body.get("tools") or []
        names = {self._tool_name(t, provider) for t in existing}
        for t in self._tools.values():
            d = t.anthropic_def() if provider == "anthropic" else t.openai_def()
            if self._tool_name(d, provider) not in names:
                existing.append(d)
        body["tools"] = existing
        return body

    @staticmethod
    def _tool_name(t: dict, provider: str) -> str:
        return t.get("name") if provider == "anthropic" else (t.get("function") or {}).get("name", t.get("name"))

    async def execute(self, name: str, args: dict) -> str:
        tool = self._tools.get(name)
        if not tool:
            return f"error: unknown tool '{name}'"
        return await tool.executor(args)

    def manages(self, name: str) -> bool:
        return name in self._tools
