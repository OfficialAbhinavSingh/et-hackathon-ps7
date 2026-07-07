import { NavLink, Route, Routes } from "react-router-dom";
import { Radar, ShieldAlert, Gavel, Workflow, ScrollText, Zap } from "lucide-react";
import { useIncidents, dataService } from "@/hooks/useIncidents";
import { Button } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import type { ConnectionState } from "@/types/contracts";
import { DATA_SOURCE } from "@/data";

import Operations from "@/pages/Operations";
import Incidents from "@/pages/Incidents";
import IncidentDetail from "@/pages/IncidentDetail";
import Approvals from "@/pages/Approvals";
import GraphPage from "@/pages/GraphPage";
import Audit from "@/pages/Audit";

const NAV = [
  { to: "/", icon: Radar, label: "Operations", end: true },
  { to: "/incidents", icon: ShieldAlert, label: "Incidents" },
  { to: "/approvals", icon: Gavel, label: "Approvals" },
  { to: "/graph", icon: Workflow, label: "Attack graph" },
  { to: "/audit", icon: ScrollText, label: "Audit" },
];

const CONN_META: Record<ConnectionState, { label: string; color: string }> = {
  connected: { label: "Connected", color: "var(--color-live)" },
  reconnecting: { label: "Reconnecting", color: "var(--color-warn)" },
  offline: { label: "Offline", color: "var(--color-down)" },
};

function ConnectionBadge({ state }: { state: ConnectionState }) {
  const meta = CONN_META[state];
  return (
    <div className="flex items-center gap-2 rounded-md border border-line bg-surface-2/60 px-3 py-1.5">
      <span
        className={cn("h-2 w-2 rounded-full", state === "connected" && "pulse-dot")}
        style={{ background: meta.color, ["--pulse" as string]: `color-mix(in srgb, ${meta.color} 60%, transparent)` }}
      />
      <span className="mono text-[11px] tracking-wide text-ink-dim">{meta.label}</span>
    </div>
  );
}

export default function App() {
  const { connection } = useIncidents();

  return (
    <div className="grid h-full grid-cols-[64px_1fr] grid-rows-[56px_1fr] overflow-hidden">
      {/* nav rail */}
      <nav className="row-span-2 flex flex-col items-center gap-1 border-r border-line bg-surface/60 py-3">
        <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-signal/15 text-signal">
          <Radar size={20} strokeWidth={2.2} />
        </div>
        {NAV.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            title={label}
            className={({ isActive }) =>
              cn(
                "group relative flex h-11 w-11 items-center justify-center rounded-lg transition-colors",
                isActive ? "bg-surface-2 text-signal" : "text-ink-faint hover:text-ink hover:bg-surface-2/60",
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 h-6 w-0.5 rounded-r bg-signal" style={{ boxShadow: "0 0 8px var(--color-signal)" }} />
                )}
                <Icon size={19} />
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* header */}
      <header className="col-start-2 flex items-center justify-between border-b border-line bg-surface/40 px-5">
        <div className="flex items-baseline gap-3">
          <span className="text-base font-bold tracking-[0.14em] text-ink">SENTINEL</span>
          <span className="mono text-[10px] uppercase tracking-[0.24em] text-ink-faint">
            AI-SOC · Critical Infrastructure
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="mono text-[10px] uppercase tracking-widest text-ink-faint">
            source: {DATA_SOURCE}
          </span>
          <ConnectionBadge state={connection} />
          <Button variant="danger" size="sm" onClick={() => dataService.triggerAttack()}>
            <Zap size={14} /> Trigger attack
          </Button>
        </div>
      </header>

      {/* routed content */}
      <main className="col-start-2 min-h-0 overflow-hidden">
        <Routes>
          <Route path="/" element={<Operations />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/audit" element={<Audit />} />
        </Routes>
      </main>
    </div>
  );
}
