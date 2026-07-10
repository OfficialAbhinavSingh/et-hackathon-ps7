import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { HttpDataService } from "./HttpDataService";
import { hashEntry, GENESIS_PREV_HASH } from "../hashChain";
import type { AuditEntry, IncidentView } from "@/types/contracts";

/**
 * Live-path verification: drive HttpDataService with contract-shaped SSE frames and a
 * stubbed fetch, exactly as the real backend (#11) would. Proves the swap to live works
 * without touching any component — same DataService surface, same client-side derivations.
 */

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  close() {}
  open() {
    this.onopen?.();
  }
  send(obj: unknown) {
    this.onmessage?.({ data: JSON.stringify(obj) });
  }
}

// a correctly-chained audit log, as a compliant Python audit.py would emit
function backendAudit(): AuditEntry[] {
  const rows = [
    { audit_log_id: "aud_0001", timestamp: "2026-07-08T10:00:01Z", event_id: "evt_9001", action: "anomaly_enriched", actor: "system" as const, detail: "T1048 conf 0.87" },
    { audit_log_id: "aud_0002", timestamp: "2026-07-08T10:00:02Z", event_id: "evt_9001", action: "isolate_host", actor: "system" as const, detail: "policy isolate_host" },
  ];
  const out: AuditEntry[] = [];
  let prev = GENESIS_PREV_HASH;
  for (const r of rows) {
    const entry: AuditEntry = { ...r, prev_hash: prev, entry_hash: hashEntry(r, prev) };
    out.push(entry);
    prev = entry.entry_hash;
  }
  return out;
}

const ANOMALY = {
  schema_version: "1.0", event_id: "evt_9001", timestamp: "2026-07-08T10:00:00Z",
  src_ip: "10.0.0.5", dst_ip: "203.0.113.10", anomaly_score: 0.93, is_anomaly: true,
  top_features: ["flow_duration", "bytes_out", "dst_port"],
  raw_features: { flow_duration: 12000, bytes_out: 4500000, dst_port: 4444 },
};
const ENRICHED = {
  schema_version: "1.0", event_id: "evt_9001",
  attack_technique: { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
  confidence: 0.87, severity: "high", cve_refs: ["CVE-2024-1234"], certin_refs: ["CIAD-2024-0012"],
  narrative: "Large outbound transfer on port 4444.", predicted_next: null, suggested_action: "isolate_host",
};
const CONTAINMENT = {
  schema_version: "1.0", event_id: "evt_9001", action: "isolate_host", target: "10.0.0.5",
  status: "pending_approval", requires_human_approval: true, actor: "system", audit_log_id: "aud_0002",
};

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
  fetchMock = vi.fn((url: string) => {
    if (url.endsWith("/audit")) return Promise.resolve({ ok: true, json: () => Promise.resolve(backendAudit()) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({ ok: true }) });
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("HttpDataService (live path)", () => {
  it("connects to <base>/stream on start", () => {
    const svc = new HttpDataService("http://api.test");
    svc.start();
    expect(FakeEventSource.instances[0].url).toBe("http://api.test/stream");
  });

  it("accumulates anomaly + enriched + containment into one IncidentView", () => {
    const svc = new HttpDataService("");
    const seen: IncidentView[] = [];
    svc.subscribeIncidents((v) => seen.push(v));
    svc.start();
    const es = FakeEventSource.instances[0];
    es.open();

    es.send({ kind: "anomaly", payload: ANOMALY });
    expect(svc.getIncidents().length).toBe(0); // needs enrichment before it's a view
    es.send({ kind: "enriched", payload: ENRICHED });
    expect(svc.getIncidents().length).toBe(1);

    es.send({ kind: "containment", payload: CONTAINMENT });
    const v = svc.getIncident("evt_9001")!;
    expect(v.incident.attack_technique.id).toBe("T1048");
    expect(v.containment!.action).toBe("isolate_host");
    expect(svc.getPendingActions().length).toBe(1);
  });

  it("is order-independent (enriched before anomaly still resolves)", () => {
    const svc = new HttpDataService("");
    svc.start();
    const es = FakeEventSource.instances[0];
    es.send({ kind: "enriched", payload: ENRICHED });
    expect(svc.getIncidents().length).toBe(0);
    es.send({ kind: "anomaly", payload: ANOMALY });
    expect(svc.getIncidents().length).toBe(1);
  });

  it("ignores a containment for an unknown event without crashing", () => {
    const svc = new HttpDataService("");
    svc.start();
    const es = FakeEventSource.instances[0];
    expect(() => es.send({ kind: "containment", payload: CONTAINMENT })).not.toThrow();
    expect(svc.getIncidents().length).toBe(0);
  });

  it("derives graph + metrics client-side from the stream (same as mock)", () => {
    const svc = new HttpDataService("");
    svc.start();
    const es = FakeEventSource.instances[0];
    es.send({ kind: "anomaly", payload: ANOMALY });
    es.send({ kind: "enriched", payload: ENRICHED });
    es.send({ kind: "containment", payload: CONTAINMENT });

    const g = svc.getGraph();
    expect(g.nodes.map((n) => n.id).sort()).toContain("203.0.113.10");
    expect(g.edges.some((e) => e.source === "10.0.0.5" && e.target === "203.0.113.10")).toBe(true);

    const m = svc.getMetrics();
    expect(m.total_incidents).toBe(1);
    expect(m.automation_coverage).toBe(0); // one action, isolate_host is not autonomous
  });

  it("approve() POSTs to /approve/{id}", async () => {
    const svc = new HttpDataService("http://api.test");
    svc.start();
    const es = FakeEventSource.instances[0];
    es.send({ kind: "anomaly", payload: ANOMALY });
    es.send({ kind: "enriched", payload: ENRICHED });

    await svc.approve("evt_9001");
    const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/approve/"));
    expect(call?.[0]).toBe("http://api.test/approve/evt_9001");
    expect((call?.[1] as RequestInit)?.method).toBe("POST");
  });

  it("verifies a correctly-chained backend audit log", async () => {
    const svc = new HttpDataService("http://api.test");
    const res = await svc.verifyAuditChain();
    expect(res.ok).toBe(true);
    expect(svc.getAudit().length).toBe(2);
  });

  it("attaches orchestration activities to the incident view", () => {
    const svc = new HttpDataService("http://api.test");
    svc.start();
    const es = FakeEventSource.instances[0];
    es.send({ kind: "anomaly", payload: ANOMALY });
    es.send({ kind: "enriched", payload: ENRICHED });
    es.send({ kind: "containment", payload: CONTAINMENT });
    es.send({
      kind: "orchestration",
      payload: {
        event_id: ANOMALY.event_id,
        activities: [
          { agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok", summary: "flagged", elapsed_ms: null },
          { agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2, status: "ok", summary: "T1", elapsed_ms: 1200 },
          { agent_id: "response", name: "Response Orchestrator Agent", stage: 3, status: "pending", summary: "isolate", elapsed_ms: 3 },
        ],
      },
    });
    const view = svc.getIncident(ANOMALY.event_id);
    expect(view?.orchestration?.length).toBe(3);
    expect(view?.orchestration?.[2].status).toBe("pending");
    // containment still works after the switch change (guards the ingest-branch fix)
    expect(view?.containment?.status).toBe(CONTAINMENT.status);
  });
});
