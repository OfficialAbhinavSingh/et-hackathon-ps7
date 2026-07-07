"""The three v1.0 data contracts — the seam of the whole system.

Every other module imports these so the contracts cannot drift. See finalplan §4.
Frozen enums make a bad payload fail loudly instead of flowing through silently.
"""

from enum import Enum

from pydantic import BaseModel


# --- Frozen enums (finalplan §4) ---------------------------------------------

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


# --- Contract 1: Anomaly event ------------------------------------------------

class AnomalyEvent(BaseModel):
    """Detection agent -> orchestrator -> attribution agent."""

    schema_version: str = "1.0"
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    anomaly_score: float
    is_anomaly: bool
    top_features: list[str]
    raw_features: dict


# --- Contract 2: Enriched incident --------------------------------------------

class AttackTechnique(BaseModel):
    id: str
    name: str


class PredictedNext(BaseModel):
    tactic: str
    note: str


class EnrichedIncident(BaseModel):
    """Attribution agent -> orchestrator -> frontend."""

    schema_version: str = "1.0"
    event_id: str
    attack_technique: AttackTechnique
    confidence: float
    severity: Severity
    cve_refs: list[str] = []
    certin_refs: list[str] = []
    narrative: str
    predicted_next: PredictedNext | None = None
    suggested_action: ActionType


# --- Contract 3: Containment action -------------------------------------------

class ContainmentAction(BaseModel):
    """Orchestrator, simulated."""

    schema_version: str = "1.0"
    event_id: str
    action: ActionType
    target: str
    status: ActionStatus
    requires_human_approval: bool
    actor: str
    audit_log_id: str
