import { useMemo } from "react";
import { ReactFlow, Background, Controls, MarkerType, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { IncidentView } from "@/types/contracts";
import { isInternal, layerFor } from "@/data/derive";
import { SEVERITY_COLOR } from "@/lib/utils";
import { EmptyState } from "@/components/ui/primitives";

const LAYER_X: Record<1 | 2 | 3, number> = { 1: 40, 2: 360, 3: 680 };
const LAYER_LABEL: Record<1 | 2 | 3, string> = {
  1: "EXTERNAL / ATTACKER",
  2: "EDGE / GATEWAY",
  3: "INTERNAL CNI",
};

interface Props {
  incidents: IncidentView[];
  /** compact mini-view hides controls/legend */
  mini?: boolean;
}

export function AttackGraph({ incidents, mini = false }: Props) {
  const { nodes, edges, hasEastWest } = useMemo(() => {
    const nodeMap = new Map<string, { layer: 1 | 2 | 3; hits: number }>();
    const bump = (ip: string) => {
      const n = nodeMap.get(ip) ?? { layer: layerFor(ip), hits: 0 };
      n.hits += 1;
      nodeMap.set(ip, n);
    };
    for (const v of incidents) {
      bump(v.event.src_ip);
      bump(v.event.dst_ip);
    }

    // stable per-layer vertical stacking
    const perLayerIndex: Record<number, number> = { 1: 0, 2: 0, 3: 0 };
    const nodes: Node[] = [...nodeMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([ip, meta]) => {
        const y = 60 + perLayerIndex[meta.layer]++ * 84;
        return {
          id: ip,
          position: { x: LAYER_X[meta.layer], y },
          data: { label: ip },
          draggable: false,
          style: {
            width: 150,
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--color-ink)",
            background: meta.layer === 3 ? "rgba(53,208,165,0.10)" : "rgba(255,59,107,0.10)",
            border: `1px solid ${isInternal(ip) ? "var(--color-live)" : "var(--color-sev-critical)"}`,
            borderRadius: 8,
            padding: "6px 8px",
          },
        };
      });

    let hasEastWest = false;
    const seen = new Set<string>();
    const edges: Edge[] = [];
    for (const v of incidents) {
      const ew = isInternal(v.event.src_ip) && isInternal(v.event.dst_ip);
      if (ew) hasEastWest = true;
      const key = `${v.event.src_ip}->${v.event.dst_ip}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const color = ew ? "var(--color-sev-high)" : SEVERITY_COLOR[v.incident.severity];
      edges.push({
        id: key,
        source: v.event.src_ip,
        target: v.event.dst_ip,
        animated: ew,
        label: ew ? "lateral" : undefined,
        labelStyle: { fill: "var(--color-sev-high)", fontFamily: "var(--font-mono)", fontSize: 9 },
        labelBgStyle: { fill: "var(--color-surface)" },
        style: { stroke: color, strokeWidth: ew ? 2.5 : 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color },
      });
    }
    return { nodes, edges, hasEastWest };
  }, [incidents]);

  if (nodes.length === 0) {
    return <EmptyState label="No attack paths yet" hint="src → dst edges appear as anomalies stream in" />;
  }

  return (
    <div className="relative min-h-0 flex-1">
      {!mini && (
        <div className="pointer-events-none absolute left-3 top-3 z-10 flex gap-4">
          {([1, 2, 3] as const).map((l) => (
            <span key={l} className="mono text-[9px] uppercase tracking-widest text-ink-faint">
              {LAYER_LABEL[l]}
            </span>
          ))}
        </div>
      )}
      {hasEastWest && (
        <div className="absolute right-3 top-3 z-10 mono rounded bg-sev-high/15 px-2 py-1 text-[10px] text-sev-high">
          ⚠ lateral movement detected
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
      >
        <Background color="#232d40" gap={20} />
        {!mini && <Controls showInteractive={false} />}
      </ReactFlow>
    </div>
  );
}
