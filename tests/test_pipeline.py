from orchestrator.audit import AuditLog
from orchestrator.pipeline import Pipeline
from orchestrator.playbooks import PlaybookEngine
from orchestrator.schemas import AnomalyEvent, EnrichedIncident


def make_event(score):
    return AnomalyEvent(
        event_id="evt_0001",
        timestamp="2026-07-10T12:00:00Z",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        anomaly_score=score,
        is_anomaly=True,
        top_features=["bytes_out"],
        raw_features={"bytes_out": 4500000},
    )


def make_incident(severity):
    return EnrichedIncident(
        event_id="evt_0001",
        attack_technique={"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        confidence=0.9,
        severity=severity,
        narrative="Large outbound transfer on non-standard port.",
        suggested_action="isolate_host",
    )


def build(tmp_path, incident):
    audit = AuditLog(tmp_path / "audit.jsonl")
    playbooks = PlaybookEngine()
    pipeline = Pipeline(enrich=lambda event: incident, audit=audit, playbooks=playbooks)
    return pipeline, audit, playbooks


def test_low_risk_event_blocks_the_external_ip_automatically(tmp_path):
    pipeline, audit, playbooks = build(tmp_path, make_incident("high"))
    result = pipeline.process(make_event(0.8))
    action = result["action"]
    assert action.action == "block_ip"
    assert action.status == "simulated_success"
    assert action.target == "10.0.0.9"  # block the external counterparty (dst_ip)
    assert playbooks.pending() == []


def test_high_risk_event_isolates_the_internal_host_and_holds(tmp_path):
    pipeline, audit, playbooks = build(tmp_path, make_incident("critical"))
    result = pipeline.process(make_event(0.95))
    action = result["action"]
    assert action.action == "isolate_host"
    assert action.status == "pending_approval"
    assert action.target == "10.0.0.5"  # quarantine the compromised internal host (src_ip)
    assert len(playbooks.pending()) == 1


def test_processing_writes_a_verifiable_audit_entry(tmp_path):
    pipeline, audit, playbooks = build(tmp_path, make_incident("high"))
    pipeline.process(make_event(0.95))
    assert len(audit.read_all()) == 1
    assert audit.verify() is True


def test_approving_records_the_confirmed_technique_and_stays_verifiable(tmp_path):
    pipeline, audit, playbooks = build(tmp_path, make_incident("critical"))
    pipeline.process(make_event(0.95))
    released = pipeline.approve(
        "evt_0001", approver="alice", confirmed_technique={"id": "T1048", "name": "Exfil"}
    )
    assert released.status == "simulated_success"
    entries = audit.read_all()
    assert len(entries) == 2  # the event + the approval
    assert "T1048" in entries[-1]["detail"]
    assert audit.verify() is True


def test_process_fills_timings_dict_when_provided(tmp_path):
    pipeline, _, _ = build(tmp_path, make_incident("high"))
    timings = {}
    pipeline.process(make_event(0.8), timings=timings)
    assert "attribution_ms" in timings and "response_ms" in timings
    assert isinstance(timings["attribution_ms"], int)
