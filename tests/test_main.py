import asyncio

from fastapi.testclient import TestClient

from orchestrator.main import Broadcaster, create_app
from orchestrator.schemas import EnrichedIncident

EVENT = {
    "schema_version": "1.0",
    "event_id": "evt_0001",
    "timestamp": "2026-07-10T12:00:00Z",
    "src_ip": "10.0.0.5",
    "dst_ip": "10.0.0.9",
    "anomaly_score": 0.95,
    "is_anomaly": True,
    "top_features": ["bytes_out"],
    "raw_features": {"bytes_out": 4500000},
}


def critical_enrich(event):
    return EnrichedIncident(
        event_id=event.event_id,
        attack_technique={"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        confidence=0.9,
        severity="critical",
        narrative="Large outbound transfer on non-standard port.",
        suggested_action="isolate_host",
    )


def high_enrich(event):
    return EnrichedIncident(
        event_id=event.event_id,
        attack_technique={"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        confidence=0.9,
        severity="high",
        narrative="Large outbound transfer on non-standard port.",
        suggested_action="isolate_host",
    )


def make_client(tmp_path, enrich):
    return TestClient(create_app(audit_path=tmp_path / "audit.jsonl", enrich=enrich))


def test_health(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    assert client.get("/health").json() == {"status": "ok"}


def test_invalid_event_is_rejected(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    assert client.post("/events", json={}).status_code == 422


def test_posting_event_creates_a_held_incident(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    r = client.post("/events", json=EVENT)
    assert r.status_code == 200
    assert r.json()["status"] == "pending_approval"
    incidents = client.get("/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["incident"]["attack_technique"]["id"] == "T1048"


def test_low_risk_event_runs_automatically(tmp_path):
    client = make_client(tmp_path, high_enrich)
    r = client.post("/events", json={**EVENT, "anomaly_score": 0.8})
    assert r.json()["status"] == "simulated_success"


def test_approving_a_held_action(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    client.post("/events", json=EVENT)
    r = client.post("/approve/evt_0001")
    assert r.status_code == 200
    assert r.json()["status"] == "simulated_success"
    assert r.json()["actor"].startswith("human:")


def test_approving_unknown_event_is_404(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    assert client.post("/approve/evt_9999").status_code == 404


def test_audit_endpoint_reports_verified_chain(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    client.post("/events", json=EVENT)
    body = client.get("/audit").json()
    assert body["verified"] is True
    assert len(body["entries"]) >= 1


def test_broadcaster_delivers_to_subscribers():
    async def scenario():
        b = Broadcaster()
        q = b.subscribe()
        await b.publish({"hello": "world"})
        return await q.get()

    assert asyncio.run(scenario()) == {"hello": "world"}
