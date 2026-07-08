import { useMemo } from "react";
import type { IncidentView, Severity } from "@/types/contracts";
import { KILL_CHAIN, tacticFor } from "@/lib/mitre";
import { SEVERITY_COLOR, SEVERITY_ORDER, cn } from "@/lib/utils";
import { EmptyState } from "@/components/ui/primitives";

interface Cell {
  id: string;
  name: string;
  count: number;
  severity: Severity;
}

interface Props {
  incidents: IncidentView[];
  activeTechnique?: string | null;
  onSelectTechnique?: (id: string | null) => void;
}

export function MitreGrid({ incidents, activeTechnique, onSelectTechnique }: Props) {
  const byTactic = useMemo(() => {
    const cells = new Map<string, Cell>();
    for (const v of incidents) {
      const t = v.incident.attack_technique;
      const cur = cells.get(t.id);
      if (cur) {
        cur.count += 1;
        if (SEVERITY_ORDER[v.incident.severity] < SEVERITY_ORDER[cur.severity]) cur.severity = v.incident.severity;
      } else {
        cells.set(t.id, { id: t.id, name: t.name, count: 1, severity: v.incident.severity });
      }
    }
    const grouped = new Map<string, Cell[]>();
    for (const cell of cells.values()) {
      const tactic = tacticFor(cell.id);
      const arr = grouped.get(tactic) ?? [];
      arr.push(cell);
      grouped.set(tactic, arr);
    }
    // kill-chain order; only tactics that have fired
    return KILL_CHAIN.filter((t) => grouped.has(t)).map((tactic) => ({
      tactic,
      cells: grouped.get(tactic)!.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    }));
  }, [incidents]);

  if (byTactic.length === 0) {
    return <EmptyState label="No techniques observed" hint="Cells light up along the kill chain as attacks are attributed" />;
  }

  return (
    <div className="flex min-h-0 flex-1 gap-2 overflow-x-auto p-3">
      {byTactic.map(({ tactic, cells }, ti) => (
        <div key={tactic} className="flex w-[132px] shrink-0 flex-col gap-1.5">
          <div className="flex items-center gap-1.5 px-0.5">
            <span className="mono text-[9px] text-ink-faint/60">{String(ti + 1).padStart(2, "0")}</span>
            <span className="text-[10px] font-medium leading-tight tracking-tight text-ink-dim">{tactic}</span>
          </div>
          <div className="flex flex-col gap-1.5">
            {cells.map((cell) => {
              const color = SEVERITY_COLOR[cell.severity];
              const active = activeTechnique === cell.id;
              return (
                <button
                  key={cell.id}
                  onClick={() => onSelectTechnique?.(active ? null : cell.id)}
                  style={{ color, borderColor: `color-mix(in srgb, ${color} ${active ? 80 : 35}%, transparent)` }}
                  className={cn(
                    "cell-fire flex flex-col gap-0.5 rounded-md border bg-surface-2/50 px-2 py-1.5 text-left transition-all hover:bg-surface-2",
                    active && "bg-surface-2",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="mono text-[11px] font-semibold">{cell.id}</span>
                    <span
                      className="mono rounded px-1 text-[9px]"
                      style={{ background: `color-mix(in srgb, ${color} 20%, transparent)` }}
                    >
                      {cell.count}
                    </span>
                  </div>
                  <span className="truncate text-[9px] leading-tight text-ink-faint">{cell.name}</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
