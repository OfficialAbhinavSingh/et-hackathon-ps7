import type { ContainmentAction, IncidentView, AgentActivity } from "@/types/contracts";

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
    const pending = containment.status === "pending_approval";
    return { ...a, status: pending ? "pending" : "ok", summary: `${containment.action} · ${containment.status}` };
  });
}

/** The newest incident's 3-agent hand-off, or null. `incidents` is newest-first (getIncidents). */
export function latestOrchestration(incidents: IncidentView[]): AgentActivity[] | null {
  for (const v of incidents) {
    if (v.orchestration && v.orchestration.length) return withLiveResponseStatus(v.orchestration, v.containment);
  }
  return null;
}
