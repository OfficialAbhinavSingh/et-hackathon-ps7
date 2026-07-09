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


def test_enrich_returns_valid_enriched_incident_on_first_try(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: VALID_JSON)
    result = enrich(EVENT, FakeCollection())
    assert result.event_id == "evt_test"
    assert result.attack_technique.id == "T1048"
    assert result.confidence == 0.82
    assert result.suggested_action.value == "isolate_host"


def test_enrich_retries_on_malformed_json_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_loop(*a, **k):
        calls["n"] += 1
        return "not json at all" if calls["n"] == 1 else VALID_JSON

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
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
    executor = agent_mod._make_tool_executor(FakeCollection())
    result_str = executor("search_attack", {"query": "exfiltration over c2"})
    assert seen["args"][1] == "exfiltration over c2"
    assert "T1041" in result_str
