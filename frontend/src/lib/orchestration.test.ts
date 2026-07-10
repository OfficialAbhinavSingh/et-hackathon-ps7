import { describe, it, expect } from "vitest";
import { latestOrchestration } from "./orchestration";
import type { ContainmentAction, IncidentView, AgentActivity } from "@/types/contracts";

const acts: AgentActivity[] = [
  { agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok", summary: "s", elapsed_ms: null },
  { agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2, status: "ok", summary: "s", elapsed_ms: 1 },
  { agent_id: "response", name: "Response Orchestrator Agent", stage: 3, status: "pending", summary: "isolate_host · pending approval", elapsed_ms: 1 },
];

function containment(status: ContainmentAction["status"]): ContainmentAction {
  return {
    schema_version: "1.0", event_id: "e2", action: "isolate_host", target: "10.0.0.5",
    status, requires_human_approval: true, actor: "system", audit_log_id: "aud_0001",
  };
}

function view(id: string, orchestration?: AgentActivity[], containmentAction?: ContainmentAction): IncidentView {
  return {
    event: { schema_version: "1.0", event_id: id, timestamp: "t", src_ip: "a", dst_ip: "b",
             anomaly_score: 0.9, is_anomaly: true, top_features: [], raw_features: {} },
    incident: { schema_version: "1.0", event_id: id, attack_technique: { id: "T1", name: "x" },
                confidence: 0.7, severity: "high", cve_refs: [], certin_refs: [],
                narrative: "n", predicted_next: null, suggested_action: "monitor" },
    orchestration,
    containment: containmentAction,
  };
}

describe("latestOrchestration", () => {
  it("returns null when no incident has orchestration data", () => {
    expect(latestOrchestration([view("e1")])).toBeNull();
    expect(latestOrchestration([])).toBeNull();
  });

  it("returns the newest incident's activities (list is newest-first)", () => {
    // getIncidents() returns newest-first, so the first with orchestration wins. Detection and
    // Attribution pass through unchanged; Response's summary reflects the live containment.
    const v = view("e2", acts, containment("pending_approval"));
    const result = latestOrchestration([v, view("e1")])!;
    expect(result[0]).toEqual(acts[0]);
    expect(result[1]).toEqual(acts[1]);
    expect(result[2].status).toBe("pending");
  });

  // Regression: the orchestration snapshot is built once, at /events time, with the Response
  // agent showing "pending". If the analyst then approves the action, view.containment updates
  // live (both DataService impls already keep it fresh) but the frozen activities[2] never did
  // — the panel showed "pending approval" forever, even after the action actually resolved.
  it("derives the Response agent's status/summary from the CURRENT containment, not the frozen snapshot", () => {
    const resolved = containment("simulated_success");
    const v = view("e2", acts, resolved);
    const result = latestOrchestration([v, view("e1")])!;
    expect(result[2].status).toBe("ok");
    expect(result[2].summary).toBe("isolate_host · simulated success");
    // Detection/Attribution are untouched — only Response is derived live.
    expect(result[0]).toEqual(acts[0]);
    expect(result[1]).toEqual(acts[1]);
  });

  it("keeps Response 'pending' while containment is still pending_approval", () => {
    const v = view("e2", acts, containment("pending_approval"));
    const result = latestOrchestration([v, view("e1")])!;
    expect(result[2].status).toBe("pending");
    expect(result[2].summary).toBe("isolate_host · pending approval");
  });

  it("shows 'unknown' (not a green ok) when containment failed or was rejected", () => {
    // A failed simulation or analyst rejection must never render as a success ✓.
    for (const status of ["failed", "rejected"] as const) {
      const v = view("e2", acts, containment(status));
      const result = latestOrchestration([v, view("e1")])!;
      expect(result[2].status).toBe("unknown");
      expect(result[2].summary).toBe(`isolate_host · ${status}`);
    }
  });

  it("falls back to the frozen activities when no containment is present yet", () => {
    // Shouldn't happen in practice (orchestration is only built once containment exists too),
    // but must not throw if it ever does.
    const v = view("e2", acts, undefined);
    expect(latestOrchestration([v, view("e1")])).toEqual(acts);
  });
});
