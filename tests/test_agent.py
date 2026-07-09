import json

import pytest

from intel.agent import enrich, MAX_JSON_RETRIES
import intel.agent as agent_mod
from orchestrator.schemas import AnomalyEvent

EVENT = AnomalyEvent(
    event_id="evt_test", timestamp="2026-07-09T00:00:00Z",
    src_ip="10.0.0.5", dst_ip="203.0.113.9", anomaly_score=0.93, is_anomaly=True,
    top_features=["sbytes", "dur"], raw_features={"sbytes": 4_500_000, "dur": 12.0},
)

VALID_JSON = json.dumps({
    "attack_technique": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "confidence": 0.82,
    "severity": "high",
    "cve_refs": ["CVE-2023-99999"],
    "certin_refs": [],
    "narrative": "Large outbound transfer consistent with exfiltration.",
    "predicted_next": {"tactic": "Command and Control", "note": "watch for beaconing"},
    "suggested_action": "isolate_host",
})


class FakeCollection:
    pass  # never touched directly — agent.py's tools call intel.ingest.query(collection, ...)


def _grounding_query(collection, text, n_results=3):
    """Fake intel.ingest.query() that "retrieves" exactly the ids VALID_JSON cites, so a
    fake_loop that invokes the tool executor makes those ids grounded via a real tool call."""
    return [
        {"id": "T1048", "name": "Exfiltration", "description": "y", "source_type": "attack", "distance": 0.1},
        {"id": "CVE-2023-99999", "name": "x", "description": "y", "source_type": "cve", "distance": 0.1},
    ]


def test_enrich_returns_valid_enriched_incident_on_first_try(monkeypatch):
    def fake_loop(system_prompt, user_prompt, tools, executor, *a, **k):
        executor("search_attack", {"query": "exfil"})
        executor("lookup_cve", {"query": "exfil"})
        return VALID_JSON

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
    monkeypatch.setattr(agent_mod, "query", _grounding_query)
    result = enrich(EVENT, FakeCollection())
    assert result.event_id == "evt_test"
    assert result.attack_technique.id == "T1048"
    assert result.confidence == 0.82
    assert result.suggested_action.value == "isolate_host"


def test_enrich_retries_on_malformed_json_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_loop(system_prompt, user_prompt, tools, executor, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return "not json at all"
        executor("search_attack", {"query": "exfil"})
        executor("lookup_cve", {"query": "exfil"})
        return VALID_JSON

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
    monkeypatch.setattr(agent_mod, "query", _grounding_query)
    result = enrich(EVENT, FakeCollection())
    assert calls["n"] == 2
    assert result.attack_technique.id == "T1048"


def test_enrich_gives_up_after_max_retries_with_low_confidence_fallback(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: "still not json")
    result = enrich(EVENT, FakeCollection())
    assert result.confidence == 0.0
    assert result.attack_technique.id == "UNKNOWN"
    assert "malformed" in result.narrative.lower()


def test_search_attack_tool_executor_calls_ingest_query(monkeypatch):
    seen = {}

    def fake_query(collection, text, n_results=3):
        seen["args"] = (collection, text, n_results)
        return [{"id": "T1041", "name": "x", "description": "y", "source_type": "attack", "distance": 0.1}]

    monkeypatch.setattr(agent_mod, "query", fake_query)
    seen_ids: set = set()
    executor = agent_mod._make_tool_executor(FakeCollection(), seen_ids)
    result_str = executor("search_attack", {"query": "exfiltration over c2"})
    assert seen["args"][1] == "exfiltration over c2"
    assert "T1041" in result_str
    assert seen_ids == {"T1041"}


UNGROUNDED_JSON = json.dumps({
    "attack_technique": {"id": "T9999", "name": "Made Up Technique"},
    "confidence": 0.9,
    "severity": "high",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "This id was never retrieved via search_attack.",
    "predicted_next": {"tactic": "Command and Control", "note": "watch for beaconing"},
    "suggested_action": "isolate_host",
})

UNKNOWN_JSON = json.dumps({
    "attack_technique": {"id": "UNKNOWN", "name": "Unattributed"},
    "confidence": 0.2,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Nothing relevant was retrieved for this event.",
    "predicted_next": None,
    "suggested_action": "monitor",
})


def test_enrich_retries_when_cited_id_was_never_retrieved(monkeypatch):
    calls = {"n": 0}

    def fake_loop(system_prompt, user_prompt, tools, executor, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            # Model answers from pretrained knowledge without ever calling a tool.
            return UNGROUNDED_JSON
        # Second attempt actually calls the tools before citing — grounded.
        executor("search_attack", {"query": "exfil"})
        executor("lookup_cve", {"query": "exfil"})
        return VALID_JSON

    def fake_query(collection, text, n_results=3):
        # Only ever "retrieves" the ids cited by VALID_JSON, never the ungrounded one.
        return [
            {"id": "T1048", "name": "x", "description": "y", "source_type": "attack", "distance": 0.1},
            {"id": "CVE-2023-99999", "name": "x", "description": "y", "source_type": "cve", "distance": 0.1},
        ]

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
    monkeypatch.setattr(agent_mod, "query", fake_query)
    result = enrich(EVENT, FakeCollection())
    assert calls["n"] == 2
    assert result.attack_technique.id == "T1048"


def test_enrich_falls_back_when_grounding_never_succeeds(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: UNGROUNDED_JSON)
    # Nothing is ever retrieved, so the cited id T9999 is never in seen_ids.
    monkeypatch.setattr(agent_mod, "query", lambda *a, **k: [])
    result = enrich(EVENT, FakeCollection())
    assert result.confidence == 0.0
    assert result.attack_technique.id == "UNKNOWN"
    assert "ungrounded" in result.narrative.lower() or "grounding" in result.narrative.lower()


def test_enrich_accepts_unknown_attack_technique_without_grounding_check(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: UNKNOWN_JSON)
    monkeypatch.setattr(agent_mod, "query", lambda *a, **k: [])
    result = enrich(EVENT, FakeCollection())
    assert result.attack_technique.id == "UNKNOWN"
    assert result.confidence == 0.2


def test_enrich_retries_on_json_array_instead_of_object(monkeypatch):
    calls = {"n": 0}

    def fake_loop(system_prompt, user_prompt, tools, executor, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return json.dumps(["not", "a", "dict"])
        executor("search_attack", {"query": "exfil"})
        executor("lookup_cve", {"query": "exfil"})
        return VALID_JSON

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
    monkeypatch.setattr(agent_mod, "query", _grounding_query)
    result = enrich(EVENT, FakeCollection())
    assert calls["n"] == 2
    assert result.attack_technique.id == "T1048"


def test_enrich_falls_back_on_json_array_exhaustion_without_raising(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop",
                         lambda *a, **k: json.dumps(["not", "a", "dict"]))
    result = enrich(EVENT, FakeCollection())
    assert result.confidence == 0.0
    assert result.attack_technique.id == "UNKNOWN"
