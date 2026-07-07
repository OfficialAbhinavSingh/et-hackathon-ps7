import { useIncidents } from "@/hooks/useIncidents";
import { AttackGraph } from "@/components/AttackGraph";
import { Panel, PanelHeader } from "@/components/ui/primitives";
import { isInternal } from "@/data/derive";

export default function GraphPage() {
  const { incidents } = useIncidents();
  const hosts = new Set<string>();
  let lateral = 0;
  for (const v of incidents) {
    hosts.add(v.event.src_ip);
    hosts.add(v.event.dst_ip);
    if (isInternal(v.event.src_ip) && isInternal(v.event.dst_ip)) lateral += 1;
  }

  return (
    <div className="h-full p-3">
      <Panel className="h-full">
        <PanelHeader
          eyebrow="event correlation · src → dst"
          title="Attack path & lateral movement"
          right={
            <div className="mono flex gap-4 text-[10px] text-ink-faint">
              <span>{hosts.size} hosts</span>
              <span>{incidents.length} edges</span>
              <span className="text-sev-high">{lateral} lateral</span>
            </div>
          }
        />
        <AttackGraph incidents={incidents} />
      </Panel>
    </div>
  );
}
