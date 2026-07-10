import type { ActionStatus, ContainmentAction, IncidentView, AgentActivity } from "@/types/contracts";

// Map the containment lifecycle to the Response agent's UI status. Anything unlisted is "ok".
// rejected/failed must NOT read as a green ✓ — they map to "unknown" (⚠) so a failed or
// analyst-rejected containment never renders as success. Kept in lockstep with backend
// orchestrator/agents.py (_RESPONSE_UI_STATUS).
const RESPONSE_UI_STATUS: Partial<Record<ActionStatus, AgentActivity["status"]>> = {
  pending_approval: "pending",
  rejected: "unknown",
  failed: "unknown",
};

// Human-readable label per status (no raw enum underscores in the panel summary). Lockstep
// with backend orchestrator/agents.py (_STATUS_LABEL).
const STATUS_LABEL: Record<ActionStatus, string> = {
  pending_approval: "pending approval",
  approved: "approved",
  simulated_success: "simulated success",
  rejected: "rejected",
  failed: "failed",
};

/**
 * The Response agent's activity is built once, at /events time — frozen with whatever status
 * held then (typically "pending"). `view.containment` keeps updating live as the analyst
 * approves the action (both DataService impls already republish it), so derive the Response
 * agent's displayed status/summary from the CURRENT containment on every read instead of
 * trusting the snapshot — otherwise the panel shows "pending approval" forever, even long
 * after the action actually resolved.
 */
function withLiveResponseStatus(activities: AgentActivity[], containment?: ContainmentAction): AgentActivity[] {
  if (!containment) return activities;
  return activities.map((a) => {
    if (a.agent_id !== "response") return a;
    const status = RESPONSE_UI_STATUS[containment.status] ?? "ok";
    return { ...a, status, summary: `${containment.action} · ${STATUS_LABEL[containment.status]}` };
  });
}

/** The newest incident's 3-agent hand-off, or null. `incidents` is newest-first (getIncidents). */
export function latestOrchestration(incidents: IncidentView[]): AgentActivity[] | null {
  for (const v of incidents) {
    if (v.orchestration && v.orchestration.length) return withLiveResponseStatus(v.orchestration, v.containment);
  }
  return null;
}
