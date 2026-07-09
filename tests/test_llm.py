import pytest

from intel.llm import ToolSpec, run_agentic_tool_loop, _provider
import intel.llm as llm


def test_provider_prefers_claude_when_both_keys_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setenv("GROQ_API_KEY", "y")
    assert _provider() == "claude"


def test_provider_falls_back_to_groq(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "y")
    assert _provider() == "groq"


def test_provider_raises_with_no_keys(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY.*GROQ_API_KEY"):
        _provider()


ECHO_TOOL = ToolSpec(name="echo", description="echoes input", parameters={
    "type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"],
})


def test_loop_returns_final_text_after_one_tool_call(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    calls = {"n": 0}

    def fake_raw_call(system, messages, tool_specs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"tool_calls": [{"id": "call_1", "name": "echo", "input": {"text": "hi"}}], "text": None}
        return {"tool_calls": [], "text": '{"result": "done"}'}

    monkeypatch.setattr(llm, "_raw_call_claude", fake_raw_call)

    seen = []

    def executor(name, args):
        seen.append((name, args))
        return "tool result: hi"

    result = run_agentic_tool_loop("sys", "user prompt", [ECHO_TOOL], executor)
    assert result == '{"result": "done"}'
    assert seen == [("echo", {"text": "hi"})]
    assert calls["n"] == 2


def test_loop_stops_at_max_turns_and_returns_last_text(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")

    def always_calls_tool(system, messages, tool_specs):
        return {"tool_calls": [{"id": "call_x", "name": "echo", "input": {"text": "loop"}}], "text": None}

    monkeypatch.setattr(llm, "_raw_call_claude", always_calls_tool)
    result = run_agentic_tool_loop("sys", "user prompt", [ECHO_TOOL], lambda n, a: "r", max_turns=2)
    assert result == ""  # no final text turn was ever produced
