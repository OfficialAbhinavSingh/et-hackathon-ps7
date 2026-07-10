"""Multi-agent orchestration wrapper (#28, finalplan GAP1).

The Detection -> Attribution -> Response flow already runs linearly through the pipeline;
this presents it as three NAMED coordinating agents by assembling one AgentActivity per stage
from the real runtime objects. Pure observability: it decides nothing (policy.py stays
authoritative) and adds no core contract — AgentActivity is a stream-only model, separate from
the three frozen contracts in schemas.py.
"""

from __future__ import annotations

from pydantic import BaseModel

from orchestrator.schemas import (
    ActionStatus,
    AnomalyEvent,
    ContainmentAction,
    EnrichedIncident,
)


class AgentActivity(BaseModel):
    agent_id: str            # "detection" | "attribution" | "response"
    name: str
    stage: int               # 1..3 — kill-chain order, drives left->right layout
    status: str              # "ok" | "pending" | "unknown" — drives the UI icon
    summary: str
    elapsed_ms: int | None = None  # None for detection: scored in engine/, not measurable here


def build_orchestration(
    event: AnomalyEvent,
    incident: EnrichedIncident,
    action: ContainmentAction,
    timings: dict | None = None,
) -> list[AgentActivity]:
    timings = timings or {}

    detection = AgentActivity(
        agent_id="detection", name="Detection Agent", stage=1, status="ok",
        summary=f"{'flagged' if event.is_anomaly else 'normal'} · score {event.anomaly_score}",
        elapsed_ms=None,
    )

    attributed = incident.attack_technique.id != "UNKNOWN"
    attribution = AgentActivity(
        agent_id="attribution", name="Attribution & Prediction Agent", stage=2,
        status="ok" if attributed else "unknown",
        summary=(f"{incident.attack_technique.id} · conf {incident.confidence:.2f}"
                 if attributed else f"unattributed · conf {incident.confidence:.2f}"),
        elapsed_ms=timings.get("attribution_ms"),
    )

    pending = action.status == ActionStatus.pending_approval
    response = AgentActivity(
        agent_id="response", name="Response Orchestrator Agent", stage=3,
        status="pending" if pending else "ok",
        summary=(f"{action.action.value} · pending approval" if pending
                 else f"{action.action.value} · {action.status.value}"),
        elapsed_ms=timings.get("response_ms"),
    )

    return [detection, attribution, response]
