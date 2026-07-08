import { useNavigate } from "react-router-dom";
import type { IncidentView } from "@/types/contracts";
import { SEVERITY_COLOR, cn, relTime } from "@/lib/utils";
import { SeverityBadge, StatusBadge, EmptyState } from "@/components/ui/primitives";

interface Props {
  incidents: IncidentView[];
  /** filter to a single technique id (kill-chain grid click) */
  filterTechnique?: string | null;
  selectedId?: string;
  onSelect?: (id: string) => void;
}

export function IncidentFeed({ incidents, filterTechnique, selectedId, onSelect }: Props) {
  const navigate = useNavigate();
  const rows = filterTechnique
    ? incidents.filter((v) => v.incident.attack_technique.id === filterTechnique)
    : incidents;

  if (rows.length === 0) {
    return <EmptyState label="Monitoring…" hint={filterTechnique ? "No incidents for this technique yet" : "Awaiting anomalies from the detection engine"} />;
  }

  const select = (id: string) => (onSelect ? onSelect(id) : navigate(`/incidents/${id}`));

  return (
    <ul className="flex flex-col divide-y divide-line-soft">
      {rows.map((v) => {
        const color = SEVERITY_COLOR[v.incident.severity];
        return (
          <li key={v.event.event_id}>
            <button
              onClick={() => select(v.event.event_id)}
              style={{ color, borderLeftColor: color }}
              className={cn(
                "tracer-in flex w-full min-w-0 items-center gap-3 border-l-2 px-4 py-2.5 text-left transition-colors hover:bg-surface-2/50",
                selectedId === v.event.event_id && "bg-surface-2/70",
              )}
            >
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="mono text-[11px] font-semibold shrink-0" style={{ color }}>
                    {v.incident.attack_technique.id}
                  </span>
                  <span className="truncate text-xs font-medium text-ink">
                    {v.incident.attack_technique.name}
                  </span>
                </div>
                <div className="mono flex min-w-0 items-center gap-1.5 truncate text-[10px] text-ink-faint">
                  <span>{v.event.src_ip}</span>
                  <span className="text-ink-faint/50">→</span>
                  <span>{v.event.dst_ip}</span>
                  <span className="text-ink-faint/50">:{v.event.raw_features.dst_port ?? "—"}</span>
                </div>
              </div>
              <div className="flex shrink-0 flex-col items-end gap-1">
                <SeverityBadge severity={v.incident.severity} />
                {v.containment ? (
                  <StatusBadge status={v.containment.status} />
                ) : (
                  <span className="mono text-[10px] text-ink-faint">deciding…</span>
                )}
              </div>
              <div className="mono w-12 shrink-0 text-right text-[10px] text-ink-faint/70">
                {relTime(v.event.timestamp)}
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
