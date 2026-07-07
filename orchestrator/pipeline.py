"""The glue: run one anomaly event through the whole spine.

    enrich (stub now, real agent later) -> decide (policy) -> act (playbook)
    -> audit (hash-chained) -> return the incident + action for broadcasting.

`enrich`, `audit`, and `playbooks` are injected so each stays independently testable
and so Phase 3 can swap the stub enrichment for the real LLM agent without touching this.
"""

from orchestrator import policy
from orchestrator.schemas import ActionStatus


class Pipeline:
    def __init__(self, enrich, audit, playbooks, decide=policy.decide):
        self.enrich = enrich
        self.audit = audit
        self.playbooks = playbooks
        self.decide = decide

    def process(self, event) -> dict:
        incident = self.enrich(event)
        decision = self.decide(event.anomaly_score, incident.severity)
        status = (
            ActionStatus.pending_approval
            if decision.requires_human_approval
            else ActionStatus.simulated_success
        )
        record = self.audit.append(
            {
                "event_id": event.event_id,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "technique": incident.attack_technique.id,
                "severity": incident.severity.value,
                "action": decision.action.value,
                "status": status.value,
                "requires_human_approval": decision.requires_human_approval,
                "actor": "system",
            }
        )
        action = self.playbooks.run(
            action=decision.action,
            event_id=event.event_id,
            target=event.src_ip,
            requires_human_approval=decision.requires_human_approval,
            audit_log_id=record["entry_hash"],
        )
        return {"incident": incident, "action": action}

    def approve(self, event_id: str, approver: str = "analyst"):
        released = self.playbooks.approve(event_id, approver)
        self.audit.append(
            {
                "event_id": event_id,
                "action": released.action.value,
                "target": released.target,
                "status": released.status.value,
                "actor": released.actor,
            }
        )
        return released
