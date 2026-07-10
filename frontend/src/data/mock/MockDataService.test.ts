import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MockDataService } from "./MockDataService";
import type { IncidentView } from "@/types/contracts";

describe("MockDataService", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("ticker emits incidents over time", async () => {
    const svc = new MockDataService();
    const seen: IncidentView[] = [];
    svc.subscribeIncidents((v) => seen.push(v));
    svc.start(); // emits one immediately, then every 4s

    await vi.advanceTimersByTimeAsync(2000); // first incident's attribution lands
    expect(svc.getIncidents().length).toBe(1);

    await vi.advanceTimersByTimeAsync(4000); // next tick
    expect(svc.getIncidents().length).toBeGreaterThanOrEqual(2);
    expect(seen.length).toBeGreaterThan(0);
    svc.stop();
  });

  it("triggerAttack produces a pending high-severity isolate_host", async () => {
    const svc = new MockDataService();
    svc.triggerAttack(); // fixture evt_0001: score 0.93, high -> isolate_host, needs approval
    await vi.advanceTimersByTimeAsync(700);

    const pending = svc.getPendingActions();
    expect(pending.length).toBe(1);
    expect(pending[0].action).toBe("isolate_host");
    expect(pending[0].requires_human_approval).toBe(true);
    expect(pending[0].status).toBe("pending_approval");
  });

  it("approve advances the lifecycle pending_approval -> approved -> simulated_success", async () => {
    const svc = new MockDataService();
    svc.triggerAttack();
    await vi.advanceTimersByTimeAsync(700);
    const id = svc.getPendingActions()[0].event_id;

    await svc.approve(id);
    expect(svc.getIncident(id)!.containment!.status).toBe("approved");

    await vi.advanceTimersByTimeAsync(1000); // resolution timer
    expect(svc.getIncident(id)!.containment!.status).toBe("simulated_success");
    expect(svc.getPendingActions().length).toBe(0);
  });

  it("records analyst correction as an accuracy miss", async () => {
    const svc = new MockDataService();
    svc.triggerAttack();
    await vi.advanceTimersByTimeAsync(700);
    const id = svc.getPendingActions()[0].event_id;

    await svc.approve(id, { id: "T9999", name: "Wrong" }); // corrected -> incorrect
    await vi.advanceTimersByTimeAsync(1000);

    const m = svc.getMetrics();
    expect(m.reviewed_count).toBe(1);
    expect(m.attribution_accuracy).toBe(0); // the one review was a correction
  });

  it("generates a verifiable audit chain", async () => {
    const svc = new MockDataService();
    svc.triggerAttack();
    await vi.advanceTimersByTimeAsync(700);
    await svc.approve(svc.getPendingActions()[0].event_id);
    await vi.advanceTimersByTimeAsync(1000);

    expect(svc.getAudit().length).toBeGreaterThan(2);
    expect((await svc.verifyAuditChain()).ok).toBe(true);
  });

  it("attaches a 3-agent orchestration to each injected incident", async () => {
    const svc = new MockDataService();
    svc.triggerAttack();                        // fires one scripted incident immediately
    await vi.advanceTimersByTimeAsync(2000);    // let attribution + containment land
    const latest = svc.getIncidents()[0];
    expect(latest.orchestration?.length).toBe(3);
    expect(latest.orchestration?.map((a) => a.agent_id)).toEqual(
      ["detection", "attribution", "response"],
    );
  });
});
