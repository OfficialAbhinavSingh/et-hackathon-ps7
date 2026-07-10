import { useEffect, useMemo, useState } from "react";
import { ShieldCheck, ShieldAlert, FlaskConical } from "lucide-react";
import { useIncidents, dataService } from "@/hooks/useIncidents";
import { verifyChain, type VerifyResult } from "@/data/hashChain";
import type { AuditEntry } from "@/types/contracts";
import { Panel, PanelHeader, Button, EmptyState } from "@/components/ui/primitives";
import { shortHash } from "@/lib/utils";

export default function Audit() {
  const { incidents } = useIncidents(); // re-render (and re-fetch below) as new entries append
  const [entries, setEntries] = useState<AuditEntry[]>(() => dataService.getAudit());

  useEffect(() => {
    let alive = true;
    dataService.refreshAudit().then(() => {
      if (alive) setEntries(dataService.getAudit());
    });
    return () => {
      alive = false;
    };
    // re-fetch whenever the incident stream patches — the backend appends audit entries on
    // every anomaly/containment decision, so a page opened after events already happened (or
    // idle between events) must not stay stuck on a stale/empty snapshot.
  }, [incidents]);

  const [tamperIdx, setTamperIdx] = useState<number | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);

  // what is actually shown — verification recomputes over THIS (tampered or not)
  const shown: AuditEntry[] = useMemo(() => {
    if (tamperIdx == null || tamperIdx >= entries.length) return entries;
    return entries.map((e, i) =>
      i === tamperIdx ? { ...e, detail: e.detail + " [ALTERED]" } : e,
    );
  }, [entries, tamperIdx]);

  const verify = async () => setResult(verifyChain(shown));

  const toggleTamper = () => {
    setTamperIdx((cur) => (cur == null ? Math.floor(entries.length / 2) : null));
    setResult(null);
  };

  return (
    <div className="h-full p-3">
      <Panel className="h-full">
        <PanelHeader
          eyebrow="tamper-evident · SHA-256 hash chain"
          title="Audit trail"
          right={
            <div className="flex items-center gap-2">
              {result &&
                (result.ok ? (
                  <span className="mono flex items-center gap-1.5 rounded bg-live/15 px-2 py-1 text-[11px] text-live">
                    <ShieldCheck size={13} /> Verified — chain untampered
                  </span>
                ) : (
                  <span className="mono flex items-center gap-1.5 rounded bg-sev-critical/15 px-2 py-1 text-[11px] text-sev-critical">
                    <ShieldAlert size={13} /> Warning — chain broken at #{result.brokenAt + 1}
                  </span>
                ))}
              <Button variant="ghost" size="sm" onClick={toggleTamper} title="Demo: alter an entry without re-hashing">
                <FlaskConical size={13} /> {tamperIdx == null ? "Simulate tamper" : "Restore"}
              </Button>
              <Button variant="primary" size="sm" onClick={verify}>
                Verify chain integrity
              </Button>
            </div>
          }
        />
        <div className="min-h-0 flex-1 overflow-auto">
          {shown.length === 0 ? (
            <EmptyState label="No audit entries yet" hint="Every decision and action appends a hash-chained record" />
          ) : (
            <table className="w-full border-collapse text-left">
              <thead className="sticky top-0 bg-surface/95 backdrop-blur">
                <tr className="mono text-[10px] uppercase tracking-wider text-ink-faint">
                  <th className="px-3 py-2 font-medium">#</th>
                  <th className="px-3 py-2 font-medium">event</th>
                  <th className="px-3 py-2 font-medium">action</th>
                  <th className="px-3 py-2 font-medium">actor</th>
                  <th className="px-3 py-2 font-medium">detail</th>
                  <th className="px-3 py-2 font-medium">prev</th>
                  <th className="px-3 py-2 font-medium">hash</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((e, i) => {
                  const broken = result && !result.ok && i >= result.brokenAt;
                  const tampered = i === tamperIdx;
                  return (
                    <tr
                      key={e.audit_log_id}
                      className="mono border-t border-line-soft text-[11px] text-ink-dim"
                      style={broken ? { background: "color-mix(in srgb, var(--color-sev-critical) 8%, transparent)" } : undefined}
                    >
                      <td className="px-3 py-1.5 text-ink-faint">{i + 1}</td>
                      <td className="px-3 py-1.5">{e.event_id}</td>
                      <td className="px-3 py-1.5 text-ink">{e.action}</td>
                      <td className="px-3 py-1.5">{e.actor}</td>
                      <td className="max-w-[280px] truncate px-3 py-1.5" style={tampered ? { color: "var(--color-sev-critical)" } : undefined}>
                        {e.detail}
                      </td>
                      <td className="px-3 py-1.5 text-ink-faint/70">{shortHash(e.prev_hash, 8)}</td>
                      <td className="px-3 py-1.5 text-signal/80">{shortHash(e.entry_hash, 8)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Panel>
    </div>
  );
}
