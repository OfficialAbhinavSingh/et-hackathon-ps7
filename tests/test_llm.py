import anthropic
import groq
import pytest

from intel.llm import LLMCallError, ToolSpec, run_agentic_tool_loop, _provider
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


def test_loop_translates_tool_executor_error_to_llm_call_error(monkeypatch):
    """Live-mode crash guard: the weaker Groq model can emit a tool call whose arguments
    don't match the tool schema (e.g. missing the 'query' key), so agent.py's executor
    raises KeyError mid-loop. That must surface as LLMCallError — which agent.py already
    retries/falls back on — not escape as a raw KeyError and 500 POST /events."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    def calls_tool(system, messages, tool_specs):
        return {"tool_calls": [{"id": "c1", "name": "echo", "input": {}}], "text": None}

    monkeypatch.setattr(llm, "_raw_call_claude", calls_tool)

    def bad_executor(name, args):
        return args["query"]  # KeyError — mirrors intel/agent.py's _make_tool_executor

    with pytest.raises(LLMCallError):
        run_agentic_tool_loop("sys", "user", [ECHO_TOOL], bad_executor)


def test_raw_call_groq_translates_malformed_tool_arguments_to_llm_call_error(monkeypatch):
    """Groq returns HTTP 200 but the model's tool-call `arguments` string is not valid JSON.
    json.loads() then raises JSONDecodeError inside _raw_call_groq — must become LLMCallError,
    not escape uncaught (it isn't a groq.APIError) and crash the pipeline."""
    import groq as groq_module

    class FakeFn:
        name = "echo"
        arguments = "{not valid json"

    class FakeToolCall:
        id = "c1"
        function = FakeFn()

    class FakeMessage:
        tool_calls = [FakeToolCall()]
        content = None

    class FakeCompletions:
        def create(self, **kwargs):
            return type("Resp", (), {"choices": [type("C", (), {"message": FakeMessage()})()]})()

    class FakeChat:
        def __init__(self):
            self.completions = FakeCompletions()

    class FakeClient:
        def __init__(self, *a, **k):
            self.chat = FakeChat()

    monkeypatch.setattr(groq_module, "Groq", FakeClient)

    with pytest.raises(LLMCallError):
        llm._raw_call_groq("sys", [{"role": "user", "content": "hi"}], [ECHO_TOOL])


def test_raw_call_claude_translates_anthropic_api_error_to_llm_call_error(monkeypatch):
    """Live bug (Groq's mirror-image): the provider SDK can reject a call server-side
    (bad request, rate limit, malformed generation) — this must become LLMCallError,
    not an uncaught provider exception, so agent.py can retry/fallback instead of crashing."""
    import httpx

    class FakeMessages:
        def create(self, **kwargs):
            raise anthropic.APIError(
                "boom", httpx.Request("POST", "https://api.anthropic.com/v1/messages"), body=None
            )

    class FakeClient:
        def __init__(self, *a, **k):
            self.messages = FakeMessages()

    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)

    with pytest.raises(LLMCallError):
        llm._raw_call_claude("sys", [{"role": "user", "content": "hi"}], [ECHO_TOOL])


def test_raw_call_groq_translates_groq_api_error_to_llm_call_error(monkeypatch):
    """The real live bug: Groq's llama-3.3-70b-versatile occasionally emits a non-standard
    <function=...> pseudo tool-call tag; Groq's API validates this server-side and raises
    groq.BadRequestError (a groq.APIError) with code 'tool_use_failed'. Must become
    LLMCallError so agent.py's retry loop can catch it instead of the process crashing."""
    import groq as groq_module

    class FakeCompletions:
        def create(self, **kwargs):
            raise groq_module.APIError(
                "Failed to call a function", request=None, body=None
            )

    class FakeChat:
        def __init__(self):
            self.completions = FakeCompletions()

    class FakeClient:
        def __init__(self, *a, **k):
            self.chat = FakeChat()

    monkeypatch.setattr(groq_module, "Groq", FakeClient)

    with pytest.raises(LLMCallError):
        llm._raw_call_groq("sys", [{"role": "user", "content": "hi"}], [ECHO_TOOL])
