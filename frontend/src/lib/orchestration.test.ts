import { describe, it, expect } from "vitest";
import { latestOrchestration } from "./orchestration";
import type { IncidentView, AgentActivity } from "@/types/contracts";

const acts: AgentActivity[] = [
  { agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok", summary: "s", elapsed_ms: null },
  { agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2, status: "ok", summary: "s", elapsed_ms: 1 },
  { agent_id: "response", name: "Response Orchestrator Agent", stage: 3, status: "pending", summary: "s", elapsed_ms: 1 },
];

function view(id: string, orchestration?: AgentActivity[]): IncidentView {
  return {
    event: { schema_version: "1.0", event_id: id, timestamp: "t", src_ip: "a", dst_ip: "b",
             anomaly_score: 0.9, is_anomaly: true, top_features: [], raw_features: {} },
    incident: { schema_version: "1.0", event_id: id, attack_technique: { id: "T1", name: "x" },
                confidence: 0.7, severity: "high", cve_refs: [], certin_refs: [],
                narrative: "n", predicted_next: null, suggested_action: "monitor" },
    orchestration,
  };
}

describe("latestOrchestration", () => {
  it("returns null when no incident has orchestration data", () => {
    expect(latestOrchestration([view("e1")])).toBeNull();
    expect(latestOrchestration([])).toBeNull();
  });

  it("returns the newest incident's activities (list is newest-first)", () => {
    // getIncidents() returns newest-first, so the first with orchestration wins
    expect(latestOrchestration([view("e2", acts), view("e1")])).toEqual(acts);
  });
});
