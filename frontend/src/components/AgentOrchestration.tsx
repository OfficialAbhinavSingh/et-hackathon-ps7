import type { IncidentView } from "@/types/contracts";
import { latestOrchestration } from "@/lib/orchestration";
import { EmptyState } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const ICON: Record<string, string> = { ok: "✓", pending: "⏳", unknown: "⚠" };
const ICON_COLOR: Record<string, string> = {
  ok: "text-live", pending: "text-sev-high", unknown: "text-sev-critical",
};

export function AgentOrchestration({ incidents }: { incidents: IncidentView[] }) {
  const activities = latestOrchestration(incidents);
  if (!activities) {
    return <EmptyState label="No agent activity yet" hint="Agents light up as events flow through the pipeline" />;
  }
  return (
    <div className="flex items-stretch gap-2 overflow-x-auto p-3">
      {activities.map((a, i) => (
        <div key={a.agent_id} className="flex items-center gap-2">
          <div className="flex min-w-[190px] flex-col gap-0.5 rounded-md border border-line-soft bg-surface-2/50 px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="mono text-[10px] text-ink-faint">
                {String(a.stage).padStart(2, "0")} · {a.name}
              </span>
              <span className={cn("mono text-[12px]", ICON_COLOR[a.status])}>{ICON[a.status]}</span>
            </div>
            <span className="truncate text-[11px] text-ink">{a.summary}</span>
            <span className="mono text-[9px] text-ink-faint">
              {a.elapsed_ms == null ? "—" : `${a.elapsed_ms} ms`}
            </span>
          </div>
          {i < activities.length - 1 && <span className="mono text-ink-faint">→</span>}
        </div>
      ))}
    </div>
  );
}
