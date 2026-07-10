from orchestrator.agents import AgentActivity, build_orchestration
from orchestrator.schemas import (
    ActionStatus, ActionType, AnomalyEvent, AttackTechnique,
    ContainmentAction, EnrichedIncident, PredictedNext, Severity,
)


def _event():
    return AnomalyEvent(
        event_id="evt_1", timestamp="t", src_ip="10.0.0.5", dst_ip="203.0.113.9",
        anomaly_score=0.97, is_anomaly=True, top_features=["bytes_out"], raw_features={},
    )


def _incident(technique_id="T1498", confidence=0.7):
    return EnrichedIncident(
        event_id="evt_1", attack_technique=AttackTechnique(id=technique_id, name="x"),
        confidence=confidence, severity=Severity.high, cve_refs=[], certin_refs=[],
        narrative="n", predicted_next=PredictedNext(tactic="Impact", note="z"),
        suggested_action=ActionType.isolate_host,
    )


def _action(status=ActionStatus.pending_approval, requires_approval=True):
    return ContainmentAction(
        event_id="evt_1", action=ActionType.isolate_host, target="10.0.0.5",
        status=status, requires_human_approval=requires_approval,
        actor="system", audit_log_id="aud_0001",
    )


def test_build_orchestration_returns_three_agents_in_stage_order():
    acts = build_orchestration(_event(), _incident(), _action(),
                               {"attribution_ms": 1200, "response_ms": 3})
    assert [a.agent_id for a in acts] == ["detection", "attribution", "response"]
    assert [a.stage for a in acts] == [1, 2, 3]
    assert acts[0].name == "Detection Agent"
    assert acts[1].name == "Attribution & Prediction Agent"
    assert acts[2].name == "Response Orchestrator Agent"


def test_detection_has_no_backend_latency_and_reports_score():
    det = build_orchestration(_event(), _incident(), _action(), {})[0]
    assert det.status == "ok"
    assert det.elapsed_ms is None
    assert "0.97" in det.summary and "flagged" in det.summary


def test_attribution_status_is_unknown_for_unattributed_incident():
    acts = build_orchestration(_event(), _incident(technique_id="UNKNOWN", confidence=0.0),
                               _action(), {"attribution_ms": 900})
    attr = acts[1]
    assert attr.status == "unknown"
    assert attr.elapsed_ms == 900
    assert "unattributed" in attr.summary


def test_attribution_status_ok_carries_technique_and_confidence():
    attr = build_orchestration(_event(), _incident(), _action(), {"attribution_ms": 1200})[1]
    assert attr.status == "ok"
    assert "T1498" in attr.summary and "0.70" in attr.summary


def test_response_pending_when_action_awaits_approval():
    resp = build_orchestration(_event(), _incident(),
                               _action(ActionStatus.pending_approval, True),
                               {"response_ms": 5})[2]
    assert resp.status == "pending"
    assert "pending approval" in resp.summary
    assert resp.elapsed_ms == 5


def test_response_ok_when_auto_contained():
    resp = build_orchestration(_event(), _incident(),
                               _action(ActionStatus.simulated_success, False), {})[2]
    assert resp.status == "ok"
    assert "simulated_success" in resp.summary
