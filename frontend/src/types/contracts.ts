/**
 * v1.0 data contracts — TypeScript mirror of docs/README.md §4 (the frozen source of truth).
 *
 * IMPORTANT: this file mirrors README §4. If `schema_version` bumps, THIS file AND
 * orchestrator/schemas.py both change together. Do not let them drift.
 *
 * Three payloads flow over the wire, keyed by `event_id`:
 *   - AnomalyEvent      (Contract 1) engine  -> orchestrator -> agent
 *   - EnrichedIncident  (Contract 2) agent   -> orchestrator -> frontend
 *   - ContainmentAction (Contract 3) orchestrator (simulated)
 */

export const SCHEMA_VERSION = "1.0" as const;

export type Severity = "low" | "medium" | "high" | "critical";

export type ActionType =
  | "isolate_host"
  | "block_ip"
  | "revoke_credential"
  | "snapshot_vm"
  | "monitor";

/** Lifecycle: pending_approval -> approved -> simulated_success | rejected | failed */
export type ActionStatus =
  | "pending_approval"
  | "approved"
  | "simulated_success"
  | "rejected"
  | "failed";

/** "system" or "human:<name>" */
export type Actor = "system" | `human:${string}`;

export interface AttackTechnique {
  id: string;
  name: string;
}

export interface PredictedNext {
  tactic: string;
  note: string;
}

/** Stage of the 3-agent orchestration view (#28). Observability only — not a core contract. */
export interface AgentActivity {
  agent_id: "detection" | "attribution" | "response";
  name: string;
  stage: number; // 1..3
  status: "ok" | "pending" | "unknown";
  summary: string;
  elapsed_ms: number | null; // null for detection (scored in engine/, not the orchestrator)
}

/** Contract 1 — Anomaly event. Carries the network-flow facts (IPs, ports, raw features). */
export interface AnomalyEvent {
  schema_version: "1.0";
  event_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  anomaly_score: number; // 0..1
  is_anomaly: boolean;
  top_features: string[]; // human-readable names, never one-hot columns
  raw_features: Record<string, number>;
}

/** Contract 2 — Enriched incident. Carries the attribution/reasoning fields. */
export interface EnrichedIncident {
  schema_version: "1.0";
  event_id: string;
  attack_technique: AttackTechnique;
  confidence: number; // 0..1
  severity: Severity;
  cve_refs: string[];
  certin_refs: string[];
  narrative: string;
  predicted_next: PredictedNext | null;
  /** advisory ONLY — policy.py is authoritative for the final action */
  suggested_action: ActionType;
}

/** Contract 3 — Containment action. The authoritative decision + lifecycle status. */
export interface ContainmentAction {
  schema_version: "1.0";
  event_id: string;
  action: ActionType;
  target: string;
  status: ActionStatus;
  requires_human_approval: boolean;
  actor: Actor;
  audit_log_id: string;
}

/**
 * Unified view-model. The three contracts each hold different fields the UI needs;
 * the DataService accumulates them by `event_id` and patches this object as each payload
 * arrives (anomaly -> enriched -> containment updates). Components subscribe to
 * IncidentView objects, NEVER to raw contract payloads.
 */
export interface IncidentView {
  event: AnomalyEvent;
  incident: EnrichedIncident;
  containment?: ContainmentAction;
  /** 3-agent hand-off view for this event (#28), set when the orchestration frame arrives. */
  orchestration?: AgentActivity[];
}

export type ConnectionState = "connected" | "reconnecting" | "offline";

/** One entry in the tamper-evident, hash-chained audit log. Mirrors orchestrator/audit.py. */
export interface AuditEntry {
  audit_log_id: string;
  timestamp: string;
  event_id: string;
  action: string; // action type or lifecycle transition
  actor: Actor;
  detail: string; // reasoning / citations / human note
  prev_hash: string;
  entry_hash: string;
}

export interface Metrics {
  /** Mean time to detect (ms): anomaly occurred -> attribution available. */
  mttd_ms: number | null;
  /** Mean time to respond (ms): action created -> simulated_success. */
  mttr_ms: number | null;
  /** analyst-confirmed-correct techniques / human-reviewed incidents (0..1), null if none reviewed. */
  attribution_accuracy: number | null;
  /** auto-handled (monitor|block_ip) / total actions (0..1). */
  automation_coverage: number | null;
  total_incidents: number;
  reviewed_count: number;
}
