import { useMemo } from "react";
import { useIncidents } from "@/hooks/useIncidents";
import { IncidentFeed } from "@/components/IncidentFeed";
import { Panel, PanelHeader } from "@/components/ui/primitives";
import { SEVERITY_ORDER } from "@/lib/utils";

export default function Incidents() {
  const { incidents } = useIncidents();

  // risk-ranked: severity first, then anomaly score
  const ranked = useMemo(
    () =>
      [...incidents].sort((a, b) => {
        const s = SEVERITY_ORDER[a.incident.severity] - SEVERITY_ORDER[b.incident.severity];
        return s !== 0 ? s : b.event.anomaly_score - a.event.anomaly_score;
      }),
    [incidents],
  );

  return (
    <div className="h-full p-3">
      <Panel className="h-full">
        <PanelHeader
          eyebrow="risk-ranked queue"
          title="All incidents"
          right={<span className="mono text-[10px] text-ink-faint">{ranked.length} total</span>}
        />
        <div className="min-h-0 flex-1 overflow-y-auto">
          <IncidentFeed incidents={ranked} />
        </div>
      </Panel>
    </div>
  );
}
