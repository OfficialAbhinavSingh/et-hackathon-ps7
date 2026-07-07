"""The authoritative decision table (finalplan §4).

Pure function, no side effects: given the anomaly score and the incident severity,
return the containment action + whether a human must approve it. The agent's
`suggested_action` is only a hint — this is what actually decides.
"""

from typing import NamedTuple

from orchestrator.schemas import ActionType

HIGH_SEVERITIES = {"critical", "high"}


class Decision(NamedTuple):
    action: ActionType
    requires_human_approval: bool


def decide(anomaly_score: float, severity: str) -> Decision:
    if severity in HIGH_SEVERITIES and anomaly_score >= 0.9:
        return Decision(ActionType.isolate_host, True)
    if anomaly_score >= 0.7:
        return Decision(ActionType.block_ip, False)
    return Decision(ActionType.monitor, False)
