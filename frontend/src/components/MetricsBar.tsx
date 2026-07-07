import { useMetrics } from "@/hooks/useIncidents";
import { fmtMs, fmtPct } from "@/lib/utils";
import type { ReactNode } from "react";
import { Timer, Wrench, Crosshair, Bot } from "lucide-react";

function Tile({
  icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  sub?: string;
  accent: string;
}) {
  return (
    <div className="panel flex items-center gap-3 px-4 py-2.5">
      <div
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
        style={{ color: accent, background: `color-mix(in srgb, ${accent} 14%, transparent)` }}
      >
        {icon}
      </div>
      <div className="flex flex-col">
        <span className="mono text-[10px] uppercase tracking-[0.18em] text-ink-faint">{label}</span>
        <div className="flex items-baseline gap-1.5">
          <span className="mono text-xl font-semibold text-ink" style={{ color: accent }}>
            {value}
          </span>
          {sub && <span className="mono text-[10px] text-ink-faint">{sub}</span>}
        </div>
      </div>
    </div>
  );
}

export function MetricsBar() {
  const m = useMetrics();
  return (
    <div className="grid grid-cols-4 gap-3">
      <Tile
        icon={<Timer size={18} />}
        label="MTTD"
        value={fmtMs(m.mttd_ms)}
        sub="detect"
        accent="var(--color-signal)"
      />
      <Tile
        icon={<Wrench size={18} />}
        label="MTTR"
        value={fmtMs(m.mttr_ms)}
        sub="respond"
        accent="var(--color-live)"
      />
      <Tile
        icon={<Crosshair size={18} />}
        label="Attribution accuracy"
        value={fmtPct(m.attribution_accuracy)}
        sub={`${m.reviewed_count} reviewed`}
        accent="var(--color-sev-high)"
      />
      <Tile
        icon={<Bot size={18} />}
        label="Automation coverage"
        value={fmtPct(m.automation_coverage)}
        sub={`${m.total_incidents} total`}
        accent="var(--color-sev-medium)"
      />
    </div>
  );
}
