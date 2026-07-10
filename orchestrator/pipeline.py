"""The glue: run one anomaly event through the whole spine.

    enrich (stub now, real agent later) -> decide (policy) -> act (playbook)
    -> audit (hash-chained) -> return the incident + action for broadcasting.

`enrich`, `audit`, and `playbooks` are injected so each stays independently testable
and so Phase 3 can swap the stub enrichment for the real LLM agent without touching this.
"""

from time import perf_counter

from orchestrator import policy
from orchestrator.schemas import ActionStatus, ActionType


def _target_for(action: ActionType, event) -> str:
    # block_ip stops the external counterparty; the rest act on the internal host.
    return event.dst_ip if action == ActionType.block_ip else event.src_ip


class Pipeline:
    def __init__(self, enrich, audit, playbooks, decide=policy.decide):
        self.enrich = enrich
        self.audit = audit
        self.playbooks = playbooks
        self.decide = decide

    def process(self, event, timings=None) -> dict:
        _t0 = perf_counter()
        incident = self.enrich(event)
        if timings is not None:
            timings["attribution_ms"] = round((perf_counter() - _t0) * 1000)
        _t1 = perf_counter()
        decision = self.decide(event.anomaly_score, incident.severity)
        requires_approval = decision.requires_human_approval
        status = (
            ActionStatus.pending_approval if requires_approval else ActionStatus.simulated_success
        )
        target = _target_for(decision.action, event)
        detail = (
            f"{incident.attack_technique.id} ({incident.severity.value}, "
            f"conf {incident.confidence:.2f}) -> {decision.action.value} on {target}; "
            f"{incident.narrative}"
        )
        record = self.audit.append(
            event_id=event.event_id,
            action=decision.action.value,
            actor="system",
            detail=detail,
        )
        action = self.playbooks.run(
            action=decision.action,
            event_id=event.event_id,
            target=target,
            requires_human_approval=requires_approval,
            audit_log_id=record["audit_log_id"],
        )
        if timings is not None:
            timings["response_ms"] = round((perf_counter() - _t1) * 1000)
        return {"incident": incident, "action": action}

    def approve(self, event_id: str, approver: str = "analyst", confirmed_technique=None):
        released = self.playbooks.approve(event_id, approver)
        detail = f"human-approved; simulated execution of {released.action.value} on {released.target}"
        if confirmed_technique:
            detail += f"; confirmed_technique={confirmed_technique.get('id')}"
        self.audit.append(
            event_id=event_id,
            action=released.action.value,
            actor=released.actor,
            detail=detail,
        )
        return released
