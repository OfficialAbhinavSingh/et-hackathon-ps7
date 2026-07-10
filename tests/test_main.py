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

AUDIT_FIELDS = {
    "audit_log_id", "timestamp", "event_id", "action", "actor", "detail",
    "prev_hash", "entry_hash",
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


def test_events_publishes_three_typed_frames(tmp_path):
    app = create_app(audit_path=tmp_path / "audit.jsonl", enrich=critical_enrich)
    client = TestClient(app)
    queue = app.state.broadcaster.subscribe()
    client.post("/events", json=EVENT)
    frames = [queue.get_nowait() for _ in range(3)]
    assert [f["kind"] for f in frames] == ["anomaly", "enriched", "containment"]
    assert frames[0]["payload"]["event_id"] == "evt_0001"


def test_approving_a_held_action_with_confirmed_technique(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    client.post("/events", json=EVENT)
    r = client.post("/approve/evt_0001", json={"confirmed_technique": {"id": "T1048", "name": "Exfil"}})
    assert r.status_code == 200
    assert r.json()["status"] == "simulated_success"
    assert r.json()["actor"].startswith("human:")


def test_approving_without_a_body_still_works(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    client.post("/events", json=EVENT)
    assert client.post("/approve/evt_0001").status_code == 200


def test_approving_unknown_event_is_404(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    assert client.post("/approve/evt_9999").status_code == 404


def test_audit_endpoint_returns_a_flat_chain(tmp_path):
    client = make_client(tmp_path, critical_enrich)
    client.post("/events", json=EVENT)
    entries = client.get("/audit").json()
    assert isinstance(entries, list) and len(entries) >= 1
    assert AUDIT_FIELDS <= set(entries[0])


def test_frames_are_recorded_for_reconnect_backlog(tmp_path):
    app = create_app(audit_path=tmp_path / "audit.jsonl", enrich=critical_enrich)
    client = TestClient(app)
    client.post("/events", json=EVENT)
    kinds = [m["kind"] for m in app.state.messages]
    assert kinds == ["anomaly", "enriched", "containment"]


def test_approval_is_appended_to_the_backlog(tmp_path):
    app = create_app(audit_path=tmp_path / "audit.jsonl", enrich=critical_enrich)
    client = TestClient(app)
    client.post("/events", json=EVENT)
    client.post("/approve/evt_0001")
    last = app.state.messages[-1]
    assert last["kind"] == "containment"
    assert last["payload"]["status"] == "simulated_success"


def test_broadcaster_delivers_to_subscribers():
    async def scenario():
        b = Broadcaster()
        q = b.subscribe()
        await b.publish({"hello": "world"})
        return await q.get()

    assert asyncio.run(scenario()) == {"hello": "world"}


def test_live_enrich_mode_uses_intel_agent_when_env_flag_set(tmp_path, monkeypatch):
    import orchestrator.main as main_mod

    called = {}

    def fake_enrich(event, collection):
        called["event_id"] = event.event_id
        return EnrichedIncident(
            event_id=event.event_id,
            attack_technique={"id": "T9999", "name": "test"},
            confidence=0.5,
            severity="low",
            narrative="test",
            suggested_action="monitor",
        )

    monkeypatch.setenv("ENRICH_MODE", "live")
    monkeypatch.setattr("intel.agent.enrich", fake_enrich)
    monkeypatch.setattr("intel.ingest.build_collection", lambda records, persist_dir: object())

    app = main_mod.create_app(audit_path=tmp_path / "audit.jsonl")
    client = TestClient(app)
    r = client.post("/events", json=EVENT)

    assert r.status_code == 200
    assert called["event_id"] == "evt_0001"
