/**
 * HttpDataService — live implementation of the DataService seam. STUB until backend #11 lands.
 *
 * Real endpoints (the ONLY ones the backend exposes):
 *   GET  /stream         Server-Sent Events — anomaly / enriched / containment payloads
 *   POST /approve/{id}   advance an action's lifecycle
 *   GET  /audit          the backend's already-hash-chained audit log (we render, never re-gen)
 *
 * The incident list, attack graph, and all metrics are derived CLIENT-SIDE from accumulated
 * stream state using the SAME derive.ts functions the mock uses — flipping VITE_DATA_SOURCE
 * requires zero component changes.
 *
 * TODO(#11): confirm the SSE message envelope with Dev 1. This assumes each event is tagged
 * with a `kind` of "anomaly" | "enriched" | "containment" carrying the matching contract
 * payload. Adjust parseMessage() once the real shape is frozen.
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
} from "../../types/contracts";
import { verifyChain, type VerifyResult } from "../hashChain";
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

const MAX_BACKOFF_MS = 15000;

type StreamMessage =
  | { kind: "anomaly"; payload: AnomalyEvent }
  | { kind: "enriched"; payload: EnrichedIncident }
  | { kind: "containment"; payload: ContainmentAction };

export class HttpDataService implements DataService {
  private state: AccumState = { views: new Map(), order: [], timings: new Map(), reviews: new Map() };
  private audit: AuditEntry[] = [];
  private incidentListeners = new Set<IncidentListener>();
  private connListeners = new Set<ConnectionListener>();

  private es: EventSource | null = null;
  private backoff = 1000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = true;

  private baseUrl: string;

  constructor(baseUrl = "") {
    this.baseUrl = baseUrl;
  }

  // ---- lifecycle + reconnect --------------------------------------------

  start(): void {
    this.stopped = false;
    this.connect();
    void this.refreshAudit();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.es?.close();
    this.es = null;
    this.setConnection("offline");
  }

  private connect(): void {
    this.es?.close();
    this.setConnection("reconnecting");
    const es = new EventSource(`${this.baseUrl}/stream`);
    this.es = es;

    es.onopen = () => {
      this.backoff = 1000;
      this.setConnection("connected");
    };
    es.onmessage = (e) => this.handleRaw(e.data);
    es.onerror = () => {
      // EventSource auto-retries, but we control backoff + status for stage recovery.
      es.close();
      this.es = null;
      if (this.stopped) return;
      this.setConnection("reconnecting");
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.stopped) return;
      this.backoff = Math.min(this.backoff * 2, MAX_BACKOFF_MS);
      this.connect();
    }, this.backoff);
  }

  // ---- stream ingest -----------------------------------------------------

  private handleRaw(raw: string): void {
    let msg: StreamMessage;
    try {
      msg = JSON.parse(raw) as StreamMessage;
    } catch {
      return; // ignore malformed frames (e.g. SSE keep-alive comments)
    }
    this.ingest(msg);
  }

  private ingest(msg: StreamMessage): void {
    const id = msg.payload.event_id;
    if (msg.kind === "anomaly") {
      if (!this.state.timings.has(id)) this.state.timings.set(id, { occurredAt: Date.now() });
      const existing = this.state.views.get(id);
      if (existing) {
        existing.event = msg.payload;
        this.notify(existing);
      }
      // if enriched not yet arrived, hold the anomaly until it does
      this.partialAnomaly.set(id, msg.payload);
      this.tryComplete(id);
    } else if (msg.kind === "enriched") {
      this.partialEnriched.set(id, msg.payload);
      const t = this.state.timings.get(id);
      if (t && !t.detectedAt) t.detectedAt = Date.now();
      this.tryComplete(id);
    } else {
      const view = this.state.views.get(id);
      if (!view) return;
      view.containment = msg.payload;
      const t = this.state.timings.get(id);
      if (t) {
        if (!t.actionCreatedAt) t.actionCreatedAt = Date.now();
        if (msg.payload.status === "simulated_success" && !t.resolvedAt) t.resolvedAt = Date.now();
      }
      this.notify(view);
    }
  }

  private partialAnomaly = new Map<string, AnomalyEvent>();
  private partialEnriched = new Map<string, EnrichedIncident>();

  private tryComplete(id: string): void {
    if (this.state.views.has(id)) return;
    const event = this.partialAnomaly.get(id);
    const incident = this.partialEnriched.get(id);
    if (!event || !incident) return;
    const view: IncidentView = { event, incident };
    this.state.views.set(id, view);
    this.state.order.push(id);
    this.notify(view);
  }

  // ---- subscriptions -----------------------------------------------------

  subscribeIncidents(onIncident: IncidentListener, onConnectionState?: ConnectionListener): Unsubscribe {
    this.incidentListeners.add(onIncident);
    if (onConnectionState) {
      this.connListeners.add(onConnectionState);
      onConnectionState(this.stopped ? "offline" : "connected");
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
    for (const l of this.connListeners) l(state);
  }

  // ---- reads (shared derivations) ---------------------------------------

  getIncidents(): IncidentView[] {
    return orderedIncidents(this.state).reverse();
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

  async approve(id: string, confirmedTechnique?: AttackTechnique): Promise<void> {
    const view = this.state.views.get(id);
    if (view) {
      const actual = view.incident.attack_technique;
      const correct = confirmedTechnique ? confirmedTechnique.id === actual.id : true;
      this.state.reviews.set(id, { correct });
    }
    await fetch(`${this.baseUrl}/approve/${id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirmed_technique: confirmedTechnique ?? null }),
    });
    // the resulting status change arrives back over /stream as a containment message
  }

  // ---- audit (render backend's chain, never regenerate) ------------------

  private async refreshAudit(): Promise<void> {
    try {
      const res = await fetch(`${this.baseUrl}/audit`);
      if (res.ok) this.audit = (await res.json()) as AuditEntry[];
    } catch {
      /* offline — leave audit as-is */
    }
  }

  getAudit(): AuditEntry[] {
    return [...this.audit];
  }

  async verifyAuditChain(): Promise<VerifyResult> {
    await this.refreshAudit();
    return verifyChain(this.audit);
  }

  // ---- demo control ------------------------------------------------------

  triggerAttack(): void {
    // In live mode the backend owns the stream; there is no client-side injection.
    // Wire this to a backend demo endpoint if/when one exists.
    console.warn("triggerAttack is a no-op in live mode; the backend drives the stream.");
  }
}
