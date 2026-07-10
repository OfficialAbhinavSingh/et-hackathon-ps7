import type { IncidentView, AgentActivity } from "@/types/contracts";

/** The newest incident's 3-agent hand-off, or null. `incidents` is newest-first (getIncidents). */
export function latestOrchestration(incidents: IncidentView[]): AgentActivity[] | null {
  for (const v of incidents) {
    if (v.orchestration && v.orchestration.length) return v.orchestration;
  }
  return null;
}
