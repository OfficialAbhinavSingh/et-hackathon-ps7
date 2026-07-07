"""FastAPI app + SSE live stream — the running face of the spine.

`POST /events` drives one anomaly through the pipeline and *publishes* the resulting
incident to every open `GET /stream` connection via an in-memory pub/sub (one
asyncio.Queue per client). That publish is how a POST from one client becomes a live
push to every browser. See finalplan §5 (Phase 1) and §10.
"""

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from orchestrator.audit import AuditLog
from orchestrator.pipeline import Pipeline
from orchestrator.playbooks import PlaybookEngine
from orchestrator.schemas import AnomalyEvent, AttackTechnique, EnrichedIncident

DEFAULT_FIXTURES = "data/fixtures/enriched_incidents.json"


class ApproveRequest(BaseModel):
    """Body of POST /approve/{id}. The analyst may confirm/correct the technique."""

    confirmed_technique: AttackTechnique | None = None


class Broadcaster:
    """In-memory pub/sub: each subscriber gets its own queue; publish fans out."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def publish(self, message: dict) -> None:
        for queue in list(self._subscribers):
            await queue.put(message)


def _load_fixture_incidents(fixtures_path) -> dict:
    path = Path(fixtures_path)
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    records = data.values() if isinstance(data, dict) else data
    return {rec["event_id"]: rec for rec in records}


def _make_stub_enrich(fixtures: dict):
    """Phase-1 enrichment: match the event to a committed fixture, else a safe fallback."""

    def enrich(event: AnomalyEvent) -> EnrichedIncident:
        payload = fixtures.get(event.event_id)
        if payload is not None:
            return EnrichedIncident.model_validate(payload)
        return EnrichedIncident(
            event_id=event.event_id,
            attack_technique={"id": "T1046", "name": "Network Service Discovery"},
            confidence=0.5,
            severity="medium",
            narrative=(
                f"Unusual flow {event.src_ip} -> {event.dst_ip}; "
                f"top features {event.top_features}. (fallback enrichment)"
            ),
            suggested_action="monitor",
        )

    return enrich


def create_app(audit_path="audit_log.jsonl", enrich=None, fixtures_path=DEFAULT_FIXTURES):
    app = FastAPI(title="PS7 SOAR Orchestrator")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    audit = AuditLog(audit_path)
    playbooks = PlaybookEngine()
    if enrich is None:
        enrich = _make_stub_enrich(_load_fixture_incidents(fixtures_path))
    pipeline = Pipeline(enrich=enrich, audit=audit, playbooks=playbooks)
    broadcaster = Broadcaster()
    incidents: dict[str, dict] = {}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/events")
    async def ingest(event: AnomalyEvent):
        result = pipeline.process(event)
        incident = result["incident"].model_dump(mode="json")
        action = result["action"].model_dump(mode="json")
        incidents[event.event_id] = {"incident": incident, "action": action}
        # Three typed frames the dashboard accumulates by event_id (contract with frontend).
        await broadcaster.publish({"kind": "anomaly", "payload": event.model_dump(mode="json")})
        await broadcaster.publish({"kind": "enriched", "payload": incident})
        await broadcaster.publish({"kind": "containment", "payload": action})
        return {"event_id": event.event_id, "status": action["status"]}

    @app.get("/incidents")
    def list_incidents():
        return list(incidents.values())

    @app.get("/incidents/{event_id}")
    def get_incident(event_id: str):
        if event_id not in incidents:
            raise HTTPException(status_code=404, detail="unknown incident")
        return incidents[event_id]

    @app.post("/approve/{event_id}")
    async def approve(event_id: str, body: ApproveRequest | None = None):
        confirmed = body.confirmed_technique.model_dump() if body and body.confirmed_technique else None
        try:
            released = pipeline.approve(event_id, confirmed_technique=confirmed)
        except KeyError:
            raise HTTPException(status_code=404, detail="no action pending approval")
        action = released.model_dump(mode="json")
        if event_id in incidents:
            incidents[event_id]["action"] = action
        # The status change arrives back on /stream as a fresh containment frame.
        await broadcaster.publish({"kind": "containment", "payload": action})
        return action

    @app.get("/audit")
    def get_audit():
        # Bare array of flat AuditEntry — the dashboard re-verifies the chain client-side.
        return audit.read_all()

    @app.get("/stream")
    async def stream():
        async def event_generator():
            queue = broadcaster.subscribe()
            try:
                while True:
                    message = await queue.get()
                    yield {"data": json.dumps(message)}
            finally:
                broadcaster.unsubscribe(queue)

        return EventSourceResponse(event_generator())

    app.state.broadcaster = broadcaster
    app.state.incidents = incidents
    return app


app = create_app()
