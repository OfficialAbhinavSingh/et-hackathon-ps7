/**
 * The seam. Every component talks to this interface — NEVER to fetch/EventSource directly.
 * Two implementations behind it (selected in data/index.ts via VITE_DATA_SOURCE):
 *   - MockDataService  (now)   in-memory, replays a scripted stream
 *   - HttpDataService  (later) EventSource + fetch against the real backend
 * Flipping the env var must require ZERO component changes.
 *
 * Real backend endpoints are ONLY: GET /stream (SSE), POST /approve/{id}, GET /audit.
 * The incident list, attack graph, and all metrics are DERIVED CLIENT-SIDE from accumulated
 * stream state — identically in both impls. There is no /incidents, /graph, or /metrics.
 */
import type {
  IncidentView,
  ContainmentAction,
  AuditEntry,
  Metrics,
  ConnectionState,
  AttackTechnique,
} from "../types/contracts";
import type { VerifyResult } from "./hashChain";

export interface GraphNode {
  id: string; // ip
  layer: 1 | 2 | 3; // 1 external/attacker · 2 edge/gateway · 3 internal CNI
  label: string;
  internal: boolean;
  hitCount: number;
}

export interface GraphEdge {
  id: string;
  source: string; // src_ip
  target: string; // dst_ip
  eastWest: boolean; // internal -> internal (lateral movement)
  event_id: string;
  severity: string;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type IncidentListener = (view: IncidentView) => void;
export type ConnectionListener = (state: ConnectionState) => void;
export type Unsubscribe = () => void;

export interface DataService {
  /** Subscribe to live incident patches. Fires once per accumulated IncidentView update. */
  subscribeIncidents(onIncident: IncidentListener, onConnectionState?: ConnectionListener): Unsubscribe;

  getIncidents(): IncidentView[];
  getIncident(id: string): IncidentView | undefined;

  getPendingActions(): ContainmentAction[];
  /** Advance the lifecycle; optionally the analyst confirms/corrects the technique (feeds accuracy). */
  approve(id: string, confirmedTechnique?: AttackTechnique): Promise<void>;

  getAudit(): AuditEntry[];
  /** Re-fetch/re-sync the audit log so a page mounted after events already happened isn't stuck empty. */
  refreshAudit(): Promise<void>;
  verifyAuditChain(): Promise<VerifyResult>;

  getGraph(): AttackGraph;
  getMetrics(): Metrics;

  /** Demo control — fire the scripted dramatic incident (T1048 exfil on port 4444) on demand. */
  triggerAttack(): void;

  /** Start/stop the live feed (mock ticker or SSE connection). */
  start(): void;
  stop(): void;
}
