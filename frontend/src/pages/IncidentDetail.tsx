import { useMemo, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { useIncidents, dataService } from "@/hooks/useIncidents";
import { Panel, PanelHeader, SeverityBadge, StatusBadge, Button, EmptyState } from "@/components/ui/primitives";
import { fmtPct, SEVERITY_COLOR } from "@/lib/utils";
import { tacticFor } from "@/lib/mitre";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="mono text-[10px] uppercase tracking-[0.16em] text-ink-faint">{label}</span>
      <div className="text-sm text-ink">{children}</div>
    </div>
  );
}

function Chip({ children, href }: { children: ReactNode; href?: string }) {
  const inner = (
    <span className="mono inline-flex items-center gap-1 rounded border border-line bg-surface-2/60 px-2 py-1 text-[11px] text-ink-dim hover:text-signal">
      {children}
      {href && <ExternalLink size={11} />}
    </span>
  );
  return href ? (
    <a href={href} target="_blank" rel="noreferrer">
      {inner}
    </a>
  ) : (
    inner
  );
}

export default function IncidentDetail() {
  const { id = "" } = useParams();
  const { incidents } = useIncidents();
  const view = useMemo(() => incidents.find((v) => v.event.event_id === id) ?? dataService.getIncident(id), [incidents, id]);

  if (!view) {
    return (
      <div className="h-full p-3">
        <Panel className="h-full">
          <EmptyState label="Incident not found" hint="It may not have streamed in yet" />
        </Panel>
      </div>
    );
  }

  const { event, incident, containment } = view;
  const color = SEVERITY_COLOR[incident.severity];

  return (
    <div className="h-full overflow-y-auto p-3">
      <div className="mx-auto flex max-w-4xl flex-col gap-3">
        <Link to="/incidents" className="mono flex w-fit items-center gap-1.5 text-[11px] text-ink-dim hover:text-signal">
          <ArrowLeft size={13} /> back to incidents
        </Link>

        {/* headline */}
        <Panel>
          <div className="flex items-start justify-between gap-4 p-4" style={{ borderLeft: `3px solid ${color}` }}>
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="mono text-lg font-semibold" style={{ color }}>
                  {incident.attack_technique.id}
                </span>
                <span className="text-lg font-semibold text-ink">{incident.attack_technique.name}</span>
              </div>
              <span className="mono text-[11px] text-ink-faint">
                {tacticFor(incident.attack_technique.id)} · event {event.event_id}
              </span>
            </div>
            <div className="flex flex-col items-end gap-1.5">
              <SeverityBadge severity={incident.severity} />
              <span className="mono text-[11px] text-ink-dim">confidence {fmtPct(incident.confidence)}</span>
            </div>
          </div>
        </Panel>

        <div className="grid grid-cols-[1.4fr_1fr] gap-3">
          {/* narrative + prediction */}
          <Panel>
            <PanelHeader eyebrow="analyst brief" title="Narrative" />
            <div className="flex flex-col gap-4 p-4">
              <p className="text-sm leading-relaxed text-ink-dim">{incident.narrative}</p>
              {incident.predicted_next && (
                <div className="rounded-md border border-line bg-surface-2/40 p-3">
                  <span className="mono text-[10px] uppercase tracking-[0.16em] text-sev-high">predicted next stage</span>
                  <div className="mt-1 text-sm font-medium text-ink">{incident.predicted_next.tactic}</div>
                  <div className="text-xs text-ink-faint">{incident.predicted_next.note}</div>
                </div>
              )}
              <div className="flex flex-col gap-2">
                <span className="mono text-[10px] uppercase tracking-[0.16em] text-ink-faint">citations</span>
                <div className="flex flex-wrap gap-1.5">
                  {incident.cve_refs.map((c) => (
                    <Chip key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`}>
                      {c}
                    </Chip>
                  ))}
                  {incident.certin_refs.map((c) => (
                    <Chip key={c}>{c}</Chip>
                  ))}
                  {incident.cve_refs.length === 0 && incident.certin_refs.length === 0 && (
                    <span className="text-xs text-ink-faint">none cited</span>
                  )}
                </div>
              </div>
            </div>
          </Panel>

          {/* telemetry + action */}
          <div className="flex flex-col gap-3">
            <Panel>
              <PanelHeader eyebrow="network flow" title="Telemetry" />
              <div className="grid grid-cols-2 gap-3 p-4">
                <Field label="source">
                  <span className="mono">{event.src_ip}</span>
                </Field>
                <Field label="destination">
                  <span className="mono">{event.dst_ip}</span>
                </Field>
                <Field label="anomaly score">
                  <span className="mono" style={{ color }}>{event.anomaly_score.toFixed(2)}</span>
                </Field>
                <Field label="dst port">
                  <span className="mono">{event.raw_features.dst_port ?? "—"}</span>
                </Field>
                <div className="col-span-2">
                  <Field label="top features">
                    <div className="flex flex-wrap gap-1">
                      {event.top_features.map((f) => (
                        <span key={f} className="mono rounded bg-surface-2/70 px-1.5 py-0.5 text-[10px] text-ink-dim">
                          {f}
                        </span>
                      ))}
                    </div>
                  </Field>
                </div>
              </div>
            </Panel>

            <Panel>
              <PanelHeader eyebrow="policy decision" title="Containment" />
              <div className="flex flex-col gap-2 p-4">
                {containment ? (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="mono text-sm font-semibold text-ink">{containment.action}</span>
                      <StatusBadge status={containment.status} />
                    </div>
                    <div className="mono text-[11px] text-ink-faint">target {containment.target}</div>
                    <div className="mono text-[11px] text-ink-faint">actor {containment.actor}</div>
                    <div className="mono text-[11px] text-ink-faint">audit {containment.audit_log_id}</div>
                    {containment.status === "pending_approval" && (
                      <Button variant="primary" size="sm" className="mt-1" onClick={() => dataService.approve(event.event_id)}>
                        Approve action
                      </Button>
                    )}
                  </>
                ) : (
                  <span className="mono text-xs text-ink-faint">policy deciding…</span>
                )}
                <p className="mt-1 text-[10px] text-ink-faint/70">
                  Advisory from agent: {incident.suggested_action}. Policy engine is authoritative.
                </p>
              </div>
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}
