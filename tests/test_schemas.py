import pytest
from pydantic import ValidationError

from orchestrator.schemas import AnomalyEvent, ContainmentAction, EnrichedIncident


def test_anomaly_event_parses_a_valid_payload():
    event = AnomalyEvent.model_validate(
        {
            "schema_version": "1.0",
            "event_id": "evt_0001",
            "timestamp": "2026-07-10T12:00:00Z",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "anomaly_score": 0.93,
            "is_anomaly": True,
            "top_features": ["flow_duration", "bytes_out", "dst_port"],
            "raw_features": {"flow_duration": 12000, "bytes_out": 4500000, "dst_port": 4444},
        }
    )
    assert event.event_id == "evt_0001"
    assert event.anomaly_score == 0.93
    assert event.src_ip == "10.0.0.5"
    assert event.top_features == ["flow_duration", "bytes_out", "dst_port"]


def _valid_enriched_payload():
    return {
        "schema_version": "1.0",
        "event_id": "evt_0001",
        "attack_technique": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        "confidence": 0.87,
        "severity": "high",
        "cve_refs": ["CVE-2024-1234"],
        "certin_refs": ["CIAD-2024-0012"],
        "narrative": "Large outbound transfer on non-standard port 4444 after hours...",
        "predicted_next": {"tactic": "Lateral Movement", "note": "watch east-west from 10.0.0.5"},
        "suggested_action": "isolate_host",
    }


def test_enriched_incident_parses_a_valid_payload():
    inc = EnrichedIncident.model_validate(_valid_enriched_payload())
    assert inc.attack_technique.id == "T1048"
    assert inc.severity == "high"
    assert inc.suggested_action == "isolate_host"
    assert inc.predicted_next.tactic == "Lateral Movement"


def test_enriched_incident_allows_null_predicted_next():
    payload = _valid_enriched_payload()
    payload["predicted_next"] = None
    inc = EnrichedIncident.model_validate(payload)
    assert inc.predicted_next is None


def test_enriched_incident_rejects_invalid_severity():
    payload = _valid_enriched_payload()
    payload["severity"] = "extreme"
    with pytest.raises(ValidationError):
        EnrichedIncident.model_validate(payload)


def test_containment_action_parses_a_valid_payload():
    act = ContainmentAction.model_validate(
        {
            "schema_version": "1.0",
            "event_id": "evt_0001",
            "action": "isolate_host",
            "target": "10.0.0.5",
            "status": "pending_approval",
            "requires_human_approval": True,
            "actor": "system",
            "audit_log_id": "aud_0001",
        }
    )
    assert act.action == "isolate_host"
    assert act.status == "pending_approval"
    assert act.requires_human_approval is True


def test_containment_action_rejects_unknown_action():
    with pytest.raises(ValidationError):
        ContainmentAction.model_validate(
            {
                "schema_version": "1.0",
                "event_id": "evt_0001",
                "action": "nuke_datacenter",
                "target": "10.0.0.5",
                "status": "pending_approval",
                "requires_human_approval": True,
                "actor": "system",
                "audit_log_id": "aud_0001",
            }
        )
