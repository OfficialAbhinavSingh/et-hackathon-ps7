/**
 * Pure client-side derivations shared by BOTH MockDataService and HttpDataService.
 * The backend exposes only GET /stream, POST /approve/{id}, GET /audit — there is no
 * /incidents, /graph, or /metrics endpoint. The incident list, attack graph, and every
 * metric are computed here from accumulated stream state, identically in both impls.
 */
import type {
  IncidentView,
  ContainmentAction,
  Metrics,
} from "../types/contracts";
import type { AttackGraph, GraphNode, GraphEdge } from "./DataService";

export interface Timing {
  occurredAt: number; // anomaly injected / first seen
  detectedAt?: number; // attribution attached
  actionCreatedAt?: number; // containment created
  resolvedAt?: number; // simulated_success reached
}

export interface Review {
  correct: boolean;
}

export interface AccumState {
  views: Map<string, IncidentView>;
  order: string[]; // insertion order of event_ids
  timings: Map<string, Timing>;
  reviews: Map<string, Review>;
}

export function isInternal(ip: string): boolean {
  return ip.startsWith("10.");
}

/** Layer 2 = edge/gateway (internal, low octet); Layer 3 = internal CNI; Layer 1 = external. */
export function layerFor(ip: string): 1 | 2 | 3 {
  if (!isInternal(ip)) return 1;
  const lastOctet = Number(ip.split(".").pop() ?? "99");
  return lastOctet <= 2 ? 2 : 3;
}

export function orderedIncidents(state: AccumState): IncidentView[] {
  return state.order.map((id) => state.views.get(id)!).filter(Boolean);
}

export function deriveGraph(state: AccumState): AttackGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const bump = (ip: string) => {
    let node = nodes.get(ip);
    if (!node) {
      node = { id: ip, layer: layerFor(ip), label: ip, internal: isInternal(ip), hitCount: 0 };
      nodes.set(ip, node);
    }
    node.hitCount += 1;
  };
  for (const id of state.order) {
    const v = state.views.get(id);
    if (!v) continue;
    const { src_ip, dst_ip } = v.event;
    bump(src_ip);
    bump(dst_ip);
    edges.push({
      id: `${id}:${src_ip}->${dst_ip}`,
      source: src_ip,
      target: dst_ip,
      eastWest: isInternal(src_ip) && isInternal(dst_ip),
      event_id: id,
      severity: v.incident.severity,
    });
  }
  return { nodes: [...nodes.values()], edges };
}

export function deriveMetrics(state: AccumState): Metrics {
  const views = orderedIncidents(state);

  const mttdSamples: number[] = [];
  const mttrSamples: number[] = [];
  for (const t of state.timings.values()) {
    if (t.detectedAt) mttdSamples.push(t.detectedAt - t.occurredAt);
    if (t.actionCreatedAt && t.resolvedAt) mttrSamples.push(t.resolvedAt - t.actionCreatedAt);
  }

  const actions = views.map((v) => v.containment).filter((c): c is ContainmentAction => !!c);
  const autoCount = actions.filter((c) => c.action === "monitor" || c.action === "block_ip").length;

  const reviewed = [...state.reviews.values()];
  const correct = reviewed.filter((r) => r.correct).length;

  const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

  return {
    mttd_ms: avg(mttdSamples),
    mttr_ms: avg(mttrSamples),
    attribution_accuracy: reviewed.length ? correct / reviewed.length : null,
    automation_coverage: actions.length ? autoCount / actions.length : null,
    total_incidents: views.length,
    reviewed_count: reviewed.length,
  };
}
