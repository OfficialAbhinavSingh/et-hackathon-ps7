"""Simulated containment actions + the human-approval gate (finalplan §10).

Everything here is SIMULATED — it sets a status and returns; nothing touches a real
firewall/EDR. High-blast-radius actions are *held* at `pending_approval` in memory
until `approve()` releases them — the graded human-in-the-loop requirement.
"""

from orchestrator.schemas import ActionStatus, ActionType, ContainmentAction


class PlaybookEngine:
    def __init__(self):
        self._pending: dict[str, ContainmentAction] = {}

    def run(
        self,
        action: ActionType,
        event_id: str,
        target: str,
        requires_human_approval: bool,
        audit_log_id: str,
        actor: str = "system",
    ) -> ContainmentAction:
        status = (
            ActionStatus.pending_approval
            if requires_human_approval
            else ActionStatus.simulated_success
        )
        result = ContainmentAction(
            event_id=event_id,
            action=action,
            target=target,
            status=status,
            requires_human_approval=requires_human_approval,
            actor=actor,
            audit_log_id=audit_log_id,
        )
        if requires_human_approval:
            self._pending[event_id] = result
        return result

    def pending(self) -> list[ContainmentAction]:
        return list(self._pending.values())

    def approve(self, event_id: str, approver: str = "analyst") -> ContainmentAction:
        held = self._pending.pop(event_id)  # KeyError if not held — caller handles
        return held.model_copy(
            update={"status": ActionStatus.simulated_success, "actor": f"human:{approver}"}
        )
