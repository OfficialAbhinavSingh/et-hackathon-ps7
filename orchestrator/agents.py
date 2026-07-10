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


# Map the containment lifecycle to the Response agent's UI status. Anything unlisted is "ok".
# rejected/failed must NOT read as a green ✓ — they map to "unknown" (⚠) so a failed or
# analyst-rejected containment never renders as success. Kept byte-for-byte in lockstep with
# frontend orchestration.ts (RESPONSE_UI_STATUS).
_RESPONSE_UI_STATUS = {
    ActionStatus.pending_approval: "pending",
    ActionStatus.rejected: "unknown",
    ActionStatus.failed: "unknown",
}

# Human-readable label per status (no raw enum underscores in the panel summary). Lockstep
# with frontend orchestration.ts (STATUS_LABEL).
_STATUS_LABEL = {
    ActionStatus.pending_approval: "pending approval",
    ActionStatus.approved: "approved",
    ActionStatus.simulated_success: "simulated success",
    ActionStatus.rejected: "rejected",
    ActionStatus.failed: "failed",
}


def build_orchestration(
    event: AnomalyEvent,
    incident: EnrichedIncident,
    action: ContainmentAction,
    timings: dict | None = None,
) -> list[AgentActivity]:
    timings = timings or {}

    detection = AgentActivity(
        agent_id="detection", name="Detection Agent", stage=1, status="ok",
        summary=f"{'flagged' if event.is_anomaly else 'normal'} · score {event.anomaly_score:.2f}",
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

    label = _STATUS_LABEL.get(action.status, action.status.value)
    response = AgentActivity(
        agent_id="response", name="Response Orchestrator Agent", stage=3,
        status=_RESPONSE_UI_STATUS.get(action.status, "ok"),
        summary=f"{action.action.value} · {label}",
        elapsed_ms=timings.get("response_ms"),
    )

    return [detection, attribution, response]
