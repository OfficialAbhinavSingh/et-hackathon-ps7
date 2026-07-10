import { useState } from "react";
import { useIncidents } from "@/hooks/useIncidents";
import { MetricsBar } from "@/components/MetricsBar";
import { IncidentFeed } from "@/components/IncidentFeed";
import { MitreGrid } from "@/components/MitreGrid";
import { AttackGraph } from "@/components/AttackGraph";
import { Panel, PanelHeader } from "@/components/ui/primitives";
import { AgentOrchestration } from "@/components/AgentOrchestration";

export default function Operations() {
  const { incidents } = useIncidents();
  const [activeTechnique, setActiveTechnique] = useState<string | null>(null);

  return (
    <div className="grid h-full grid-rows-[auto_auto_1fr] gap-3 p-3">
      <MetricsBar />

      <Panel>
        <PanelHeader eyebrow="multi-agent pipeline" title="Agent orchestration" right={<span className="mono text-[10px] text-ink-faint">detection → attribution → response</span>} />
        <AgentOrchestration incidents={incidents} />
      </Panel>

      <div className="grid min-h-0 grid-cols-[minmax(300px,1fr)_1.35fr_1.15fr] gap-3">
        <Panel>
          <PanelHeader
            eyebrow="live stream"
            title="Incident feed"
            right={
              activeTechnique && (
                <button
                  onClick={() => setActiveTechnique(null)}
                  className="mono text-[10px] text-signal hover:underline"
                >
                  clear filter · {activeTechnique}
                </button>
              )
            }
          />
          <div className="min-h-0 flex-1 overflow-y-auto">
            <IncidentFeed incidents={incidents} filterTechnique={activeTechnique} />
          </div>
        </Panel>

        <Panel>
          <PanelHeader eyebrow="MITRE ATT&CK" title="Kill chain" right={<span className="mono text-[10px] text-ink-faint">click to filter feed</span>} />
          <MitreGrid incidents={incidents} activeTechnique={activeTechnique} onSelectTechnique={setActiveTechnique} />
        </Panel>

        <Panel>
          <PanelHeader eyebrow="correlation" title="Attack path" />
          <AttackGraph incidents={incidents} mini />
        </Panel>
      </div>
    </div>
  );
}
