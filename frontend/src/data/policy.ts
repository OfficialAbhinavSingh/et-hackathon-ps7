/**
 * Client-side mirror of orchestrator/policy.py — the AUTHORITATIVE decision table (README §4).
 * The agent's `suggested_action` is only a hint; this maps (anomaly_score, severity) to the
 * final action + approval requirement. Keep it a readable table.
 *
 *   severity ∈ {critical, high} AND score ≥ 0.9  -> isolate_host   (human approval required)
 *   score 0.7 – 0.9                              -> block_ip       (auto)
 *   score < 0.7                                  -> monitor        (auto)
 *
 * NOTE: in live mode the backend emits the ContainmentAction directly; this local copy is
 * only used by MockDataService to decide actions. If policy.py changes, update this too.
 */
import type { AnomalyEvent, EnrichedIncident, ActionType } from "../types/contracts";

export interface PolicyDecision {
  action: ActionType;
  target: string;
  requires_human_approval: boolean;
}

export function decide(event: AnomalyEvent, incident: EnrichedIncident): PolicyDecision {
  const score = event.anomaly_score;
  const highSeverity = incident.severity === "critical" || incident.severity === "high";

  if (highSeverity && score >= 0.9) {
    // Highest blast radius: quarantine the compromised internal host, behind approval.
    return { action: "isolate_host", target: event.src_ip, requires_human_approval: true };
  }
  if (score >= 0.7) {
    // Block the external counterparty automatically.
    return { action: "block_ip", target: event.dst_ip, requires_human_approval: false };
  }
  return { action: "monitor", target: event.src_ip, requires_human_approval: false };
}

/** Actions the policy runs without a human (drives automation-coverage metric). */
export function isAutonomous(action: ActionType): boolean {
  return action === "monitor" || action === "block_ip";
}
