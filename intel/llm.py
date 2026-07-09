"""LLM provider seam for the attribution agent (issue #17 / finalplan.md §11).

agent.py calls ONLY run_agentic_tool_loop() — it never touches anthropic/groq SDKs directly.
Provider choice: ANTHROPIC_API_KEY -> claude-sonnet-4-6; else GROQ_API_KEY -> Groq's
llama-3.3-70b-versatile; else raise. Swapping providers is a zero-code-change env var flip.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable


class LLMCallError(Exception):
    """Raised when the underlying provider API call itself fails (network, rate limit,
    malformed generation the provider rejects, etc.) — distinct from a successful call
    that returns bad JSON, which is agent.py's problem to retry on."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON schema for the tool's input


def _provider() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    raise RuntimeError(
        "no LLM provider configured — set ANTHROPIC_API_KEY (preferred, claude-sonnet-4-6) "
        "or GROQ_API_KEY (fallback, llama-3.3-70b-versatile)"
    )


def run_agentic_tool_loop(
    system_prompt: str,
    user_prompt: str,
    tools: list[ToolSpec],
    tool_executor: Callable[[str, dict], str],
    max_turns: int = 4,
) -> str:
    """Runs the tool-call loop to completion (or max_turns) and returns final assistant text."""
    provider = _provider()
    loop = _loop_claude if provider == "claude" else _loop_groq
    return loop(system_prompt, user_prompt, tools, tool_executor, max_turns)


def _loop_claude(system_prompt, user_prompt, tools, tool_executor, max_turns) -> str:
    messages = [{"role": "user", "content": user_prompt}]
    for _ in range(max_turns):
        resp = _raw_call_claude(system_prompt, messages, tools)
        if not resp["tool_calls"]:
            return resp["text"] or ""
        messages.append({"role": "assistant", "content": [
            {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["input"]}
            for c in resp["tool_calls"]
        ]})
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": c["id"],
             "content": tool_executor(c["name"], c["input"])}
            for c in resp["tool_calls"]
        ]})
    return ""


def _loop_groq(system_prompt, user_prompt, tools, tool_executor, max_turns) -> str:
    messages = [{"role": "user", "content": user_prompt}]
    for _ in range(max_turns):
        resp = _raw_call_groq(system_prompt, messages, tools)
        if not resp["tool_calls"]:
            return resp["text"] or ""
        messages.append({"role": "assistant", "tool_calls": [
            {"id": c["id"], "type": "function",
             "function": {"name": c["name"], "arguments": json.dumps(c["input"])}}
            for c in resp["tool_calls"]
        ]})
        for c in resp["tool_calls"]:
            messages.append({"role": "tool", "tool_call_id": c["id"],
                              "content": tool_executor(c["name"], c["input"])})
    return ""


def _raw_call_claude(system_prompt: str, messages: list[dict], tools: list[ToolSpec]) -> dict:
    """Real Anthropic call — isolated here so tests can monkeypatch it without a key."""
    import anthropic

    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=system_prompt,
            tools=[{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools],
            messages=messages,
        )
        tool_calls = [{"id": b.id, "name": b.name, "input": b.input}
                      for b in resp.content if b.type == "tool_use"]
        text = "".join(b.text for b in resp.content if b.type == "text") or None
        return {"tool_calls": tool_calls, "text": text}
    except anthropic.APIError as exc:
        raise LLMCallError(str(exc)) from exc


def _raw_call_groq(system_prompt: str, messages: list[dict], tools: list[ToolSpec]) -> dict:
    """Real Groq call — isolated here so tests can monkeypatch it without a key."""
    import groq
    from groq import Groq

    try:
        client = Groq()
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": system_prompt}, *messages],
            tools=[{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters}} for t in tools],
        )
        msg = resp.choices[0].message
        tool_calls = [{"id": c.id, "name": c.function.name, "input": json.loads(c.function.arguments)}
                      for c in (msg.tool_calls or [])]
        return {"tool_calls": tool_calls, "text": msg.content}
    except groq.APIError as exc:
        raise LLMCallError(str(exc)) from exc
