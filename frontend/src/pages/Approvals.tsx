import { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck, PencilLine } from "lucide-react";
import { useIncidents, dataService } from "@/hooks/useIncidents";
import type { ContainmentAction } from "@/types/contracts";
import { Panel, PanelHeader, Button, SeverityBadge, EmptyState } from "@/components/ui/primitives";
import { SEVERITY_COLOR } from "@/lib/utils";

function ApprovalCard({ action }: { action: ContainmentAction }) {
  const view = dataService.getIncident(action.event_id);
  const [correcting, setCorrecting] = useState(false);
  const [tid, setTid] = useState("");
  const [tname, setTname] = useState("");
  if (!view) return null;
  const { incident, event } = view;
  const color = SEVERITY_COLOR[incident.severity];

  const approveCorrect = () => dataService.approve(action.event_id);
  const approveCorrection = () => {
    if (!tid.trim()) return;
    dataService.approve(action.event_id, { id: tid.trim(), name: tname.trim() || tid.trim() });
  };

  return (
    <div className="panel flex flex-col gap-3 p-4" style={{ borderLeft: `3px solid ${color}` }}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <Link to={`/incidents/${event.event_id}`} className="flex items-center gap-2 hover:text-signal">
            <span className="mono text-sm font-semibold" style={{ color }}>
              {incident.attack_technique.id}
            </span>
            <span className="text-sm font-medium text-ink">{incident.attack_technique.name}</span>
          </Link>
          <span className="mono text-[10px] text-ink-faint">
            {event.src_ip} → {event.dst_ip} · score {event.anomaly_score.toFixed(2)}
          </span>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>

      <div className="flex items-center gap-2 rounded-md border border-line bg-surface-2/40 px-3 py-2">
        <span className="mono text-[11px] uppercase tracking-wide text-sev-high">requires approval</span>
        <span className="mono text-sm font-semibold text-ink">{action.action}</span>
        <span className="mono text-[11px] text-ink-faint">→ {action.target}</span>
      </div>

      {!correcting ? (
        <div className="flex items-center gap-2">
          <Button variant="primary" size="sm" onClick={approveCorrect}>
            <ShieldCheck size={14} /> Approve · attribution correct
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setCorrecting(true)}>
            <PencilLine size={14} /> Misattributed?
          </Button>
        </div>
      ) : (
        <div className="flex flex-col gap-2 rounded-md border border-line bg-surface-2/40 p-3">
          <span className="mono text-[10px] uppercase tracking-wide text-ink-faint">correct technique</span>
          <div className="flex gap-2">
            <input
              value={tid}
              onChange={(e) => setTid(e.target.value)}
              placeholder="T1071"
              className="mono w-24 rounded border border-line bg-base px-2 py-1 text-xs text-ink outline-none focus:border-signal"
            />
            <input
              value={tname}
              onChange={(e) => setTname(e.target.value)}
              placeholder="technique name"
              className="flex-1 rounded border border-line bg-base px-2 py-1 text-xs text-ink outline-none focus:border-signal"
            />
          </div>
          <div className="flex gap-2">
            <Button variant="primary" size="sm" onClick={approveCorrection}>
              Approve with correction
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setCorrecting(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Approvals() {
  useIncidents(); // re-render on stream patches
  const pending = dataService.getPendingActions();

  return (
    <div className="h-full p-3">
      <Panel className="h-full">
        <PanelHeader
          eyebrow="human-in-the-loop"
          title="Approval queue"
          right={<span className="mono text-[10px] text-ink-faint">{pending.length} pending</span>}
        />
        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          {pending.length === 0 ? (
            <EmptyState label="Queue clear" hint="High-blast-radius actions land here for analyst sign-off" />
          ) : (
            <div className="grid grid-cols-2 gap-3">
              {pending.map((a) => (
                <ApprovalCard key={a.event_id} action={a} />
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
