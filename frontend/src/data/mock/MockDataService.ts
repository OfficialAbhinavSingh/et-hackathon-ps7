/**
 * MockDataService — in-memory implementation of the DataService seam.
 *
 * Replays a scripted stream from the 20 python fixtures. Accumulates payloads by event_id
 * into IncidentView objects, patching as each arrives (anomaly -> enriched -> containment).
 * All metrics are computed from REAL measured state transitions via the shared derive.ts
 * (no hardcoded numbers). The audit chain is generated here (the only place generation
 * happens); live mode renders the backend's chain instead.
 */
import type {
  AnomalyEvent,
  EnrichedIncident,
  ContainmentAction,
  IncidentView,
  AuditEntry,
  Metrics,
  ConnectionState,
  AttackTechnique,
  Actor,
} from "../../types/contracts";
import { ANOMALY_FIXTURES, ENRICHED_FIXTURES } from "../fixtures";
import { decide } from "../policy";
import { hashEntry, verifyChain, GENESIS_PREV_HASH, type VerifyResult } from "../hashChain";
import {
  deriveGraph,
  deriveMetrics,
  orderedIncidents,
  type AccumState,
} from "../derive";
import type {
  DataService,
  IncidentListener,
  ConnectionListener,
  Unsubscribe,
  AttackGraph,
} from "../DataService";

const TICK_MS = 4000;

export class MockDataService implements DataService {
  private state: AccumState = {
    views: new Map(),
    order: [],
    timings: new Map(),
    reviews: new Map(),
  };
  private audit: AuditEntry[] = [];

  private incidentListeners = new Set<IncidentListener>();
  private connListeners = new Set<ConnectionListener>();

  private ticker: ReturnType<typeof setInterval> | null = null;
  private pendingTimeouts = new Set<ReturnType<typeof setTimeout>>();
  private seq = 0;
  private connection: ConnectionState = "offline";

  // ---- lifecycle ---------------------------------------------------------

  start(): void {
    if (this.ticker) return;
    this.setConnection("connected");
    this.emitNext(); // don't make the first incident wait a full tick
    this.ticker = setInterval(() => this.emitNext(), TICK_MS);
  }

  stop(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
    for (const t of this.pendingTimeouts) clearTimeout(t);
    this.pendingTimeouts.clear();
    this.setConnection("offline");
  }

  private later(fn: () => void, ms: number): void {
    const t = setTimeout(() => {
      this.pendingTimeouts.delete(t);
      fn();
    }, ms);
    this.pendingTimeouts.add(t);
  }

  // ---- subscriptions -----------------------------------------------------

  subscribeIncidents(onIncident: IncidentListener, onConnectionState?: ConnectionListener): Unsubscribe {
    this.incidentListeners.add(onIncident);
    if (onConnectionState) {
      this.connListeners.add(onConnectionState);
      onConnectionState(this.connection);
    }
    return () => {
      this.incidentListeners.delete(onIncident);
      if (onConnectionState) this.connListeners.delete(onConnectionState);
    };
  }

  private notify(view: IncidentView): void {
    for (const l of this.incidentListeners) l({ ...view });
  }

  private setConnection(state: ConnectionState): void {
    this.connection = state;
    for (const l of this.connListeners) l(state);
  }

  // ---- stream emission ---------------------------------------------------

  private emitNext(): void {
    const idx = this.seq % ANOMALY_FIXTURES.length;
    this.seq += 1;
    this.inject(ANOMALY_FIXTURES[idx], ENRICHED_FIXTURES[idx]);
  }

  triggerAttack(): void {
    // The scripted wow moment: T1048 exfiltration on port 4444 (fixture evt_0001), fired now.
    if (!this.ticker) this.setConnection("connected");
    this.inject(ANOMALY_FIXTURES[0], ENRICHED_FIXTURES[0], true);
  }

  /**
   * Inject one scripted incident. Anomaly lands first; attribution follows after a short,
   * confidence-dependent delay (the measured MTTD); then policy creates a containment action
   * (auto actions resolve themselves, high-blast-radius ones wait for approve()).
   */
  private inject(anomalyFx: AnomalyEvent, enrichedFx: EnrichedIncident, dramatic = false): void {
    const n = String(this.state.order.length + this.state.timings.size + 1).padStart(4, "0");
    const eventId = `evt_live_${n}`;
    const now = new Date();

    const event: AnomalyEvent = { ...anomalyFx, event_id: eventId, timestamp: now.toISOString() };
    const incident: EnrichedIncident = { ...enrichedFx, event_id: eventId };

    this.state.timings.set(eventId, { occurredAt: Date.now() });

    // Attribution latency — lower confidence takes longer to reason about.
    const attributionDelay = dramatic ? 500 : 400 + (1 - incident.confidence) * 1200;

    this.later(() => {
      const t = this.state.timings.get(eventId)!;
      t.detectedAt = Date.now();

      const view: IncidentView = { event, incident };
      this.state.views.set(eventId, view);
      this.state.order.push(eventId);
      this.appendAudit(eventId, "anomaly_enriched", "system", this.detectDetail(event, incident));
      this.notify(view);

      // policy decides the authoritative action
      const decision = decide(event, incident);
      const auditId = this.appendAudit(
        eventId,
        decision.action,
        "system",
        `policy: ${decision.action} on ${decision.target} (score ${event.anomaly_score}, ${incident.severity})`,
      );
      const containment: ContainmentAction = {
        schema_version: "1.0",
        event_id: eventId,
        action: decision.action,
        target: decision.target,
        status: decision.requires_human_approval ? "pending_approval" : "approved",
        requires_human_approval: decision.requires_human_approval,
        actor: "system",
        audit_log_id: auditId,
      };
      t.actionCreatedAt = Date.now();
      view.containment = containment;
      this.notify(view);

      if (!decision.requires_human_approval) {
        this.later(() => this.resolve(eventId, "system"), 300 + Math.random() * 500);
      }
    }, attributionDelay);
  }

  private detectDetail(event: AnomalyEvent, incident: EnrichedIncident): string {
    return (
      `${incident.attack_technique.id} ${incident.attack_technique.name} · ` +
      `conf ${incident.confidence} · ${event.src_ip}->${event.dst_ip} · ` +
      `refs ${[...incident.cve_refs, ...incident.certin_refs].join(",") || "none"}`
    );
  }

  private resolve(eventId: string, actor: Actor): void {
    const view = this.state.views.get(eventId);
    if (!view?.containment) return;
    view.containment = { ...view.containment, status: "simulated_success", actor };
    const t = this.state.timings.get(eventId);
    if (t) t.resolvedAt = Date.now();
    this.appendAudit(eventId, `${view.containment.action}:simulated_success`, actor, "playbook simulated OK");
    this.notify(view);
  }

  // ---- reads (shared derivations) ---------------------------------------

  getIncidents(): IncidentView[] {
    return orderedIncidents(this.state).reverse(); // newest first
  }

  getIncident(id: string): IncidentView | undefined {
    return this.state.views.get(id);
  }

  getPendingActions(): ContainmentAction[] {
    return orderedIncidents(this.state)
      .map((v) => v.containment)
      .filter((c): c is ContainmentAction => !!c && c.status === "pending_approval");
  }

  getGraph(): AttackGraph {
    return deriveGraph(this.state);
  }

  getMetrics(): Metrics {
    return deriveMetrics(this.state);
  }

  // ---- approvals ---------------------------------------------------------

  async approve(id: string, confirmedTechnique?: AttackTechnique): Promise<void> {
    const view = this.state.views.get(id);
    if (!view?.containment || view.containment.status !== "pending_approval") return;

    view.containment = { ...view.containment, status: "approved", actor: "human:analyst" };
    this.appendAudit(id, `${view.containment.action}:approved`, "human:analyst", "analyst approved action");
    this.notify(view);

    // analyst review feeds attribution accuracy (reviewed subset only)
    const actual = view.incident.attack_technique;
    const correct = confirmedTechnique ? confirmedTechnique.id === actual.id : true;
    this.state.reviews.set(id, { correct });
    if (confirmedTechnique && !correct) {
      this.appendAudit(
        id,
        "technique_corrected",
        "human:analyst",
        `analyst corrected ${actual.id} -> ${confirmedTechnique.id} ${confirmedTechnique.name}`,
      );
      this.notify(view);
    }

    this.later(() => this.resolve(id, "human:analyst"), 400 + Math.random() * 400);
  }

  // ---- audit -------------------------------------------------------------

  private appendAudit(eventId: string, action: string, actor: Actor, detail: string): string {
    const prev = this.audit.length ? this.audit[this.audit.length - 1].entry_hash : GENESIS_PREV_HASH;
    const auditId = `aud_${String(this.audit.length + 1).padStart(4, "0")}`;
    const base = {
      audit_log_id: auditId,
      timestamp: new Date().toISOString(),
      event_id: eventId,
      action,
      actor,
      detail,
    };
    this.audit.push({ ...base, prev_hash: prev, entry_hash: hashEntry(base, prev) });
    return auditId;
  }

  getAudit(): AuditEntry[] {
    return [...this.audit];
  }

  async refreshAudit(): Promise<void> {
    // no-op — the mock appends audit entries synchronously as events are generated, always current
  }

  async verifyAuditChain(): Promise<VerifyResult> {
    return verifyChain(this.audit);
  }
}
