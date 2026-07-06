"""v1.0 JSON contracts shared between Dev 1 (orchestrator/engine) and Dev 2 (agent/frontend).

Source of truth: docs/README.md §4. Bump `schema_version` and update both places
(this file + docs/README.md) whenever a contract changes.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ActionType(str, Enum):
    isolate_host = "isolate_host"
    block_ip = "block_ip"
    revoke_credential = "revoke_credential"
    snapshot_vm = "snapshot_vm"
    monitor = "monitor"


class ActionStatus(str, Enum):
    pending_approval = "pending_approval"
    approved = "approved"
    simulated_success = "simulated_success"
    rejected = "rejected"
    failed = "failed"


class AttackTechnique(BaseModel):
    id: str
    name: str


class PredictedNext(BaseModel):
    tactic: str
    note: str


class AnomalyEvent(BaseModel):
    """Engine -> orchestrator -> agent."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    top_features: list[str]
    raw_features: dict[str, float]

    @field_validator("top_features")
    @classmethod
    def features_must_be_human_readable(cls, v: list[str]) -> list[str]:
        # [v1.0] rule: no one-hot columns (e.g. "proto_tcp") or bare indices —
        # the agent reasons over these names directly.
        for name in v:
            if name.isdigit():
                raise ValueError(f"top_features must be human-readable names, got {name!r}")
        return v


class EnrichedIncident(BaseModel):
    """Agent -> orchestrator -> frontend."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: str
    attack_technique: AttackTechnique
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    cve_refs: list[str] = Field(default_factory=list)
    certin_refs: list[str] = Field(default_factory=list)
    narrative: str
    predicted_next: PredictedNext | None = None
    suggested_action: ActionType


class ContainmentAction(BaseModel):
    """Orchestrator, simulated."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: str
    action: ActionType
    target: str
    status: ActionStatus
    requires_human_approval: bool
    actor: str
    audit_log_id: str

    @field_validator("actor")
    @classmethod
    def actor_must_match_pattern(cls, v: str) -> str:
        if v != "system" and not v.startswith("human:"):
            raise ValueError('actor must be "system" or "human:<name>"')
        return v
