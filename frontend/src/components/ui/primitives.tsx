import type { ReactNode, ButtonHTMLAttributes } from "react";
import { cn, SEVERITY_COLOR } from "@/lib/utils";
import type { Severity, ActionStatus } from "@/types/contracts";

/** Glass panel container. */
export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cn("panel flex min-h-0 flex-col overflow-hidden", className)}>{children}</section>;
}

export function PanelHeader({
  title,
  eyebrow,
  right,
}: {
  title: string;
  eyebrow?: string;
  right?: ReactNode;
}) {
  return (
    <header className="flex items-baseline justify-between gap-3 border-b border-line px-4 py-3">
      <div className="flex flex-col">
        {eyebrow && (
          <span className="mono text-[10px] uppercase tracking-[0.2em] text-ink-faint">{eyebrow}</span>
        )}
        <h2 className="text-sm font-semibold tracking-tight text-ink">{title}</h2>
      </div>
      {right}
    </header>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "danger" | "outline";
  size?: "sm" | "md";
};

export function Button({ variant = "outline", size = "md", className, ...props }: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-md font-medium tracking-tight transition-all outline-none focus-visible:ring-2 focus-visible:ring-signal/70 disabled:opacity-40 disabled:cursor-not-allowed";
  const sizes = { sm: "h-8 px-3 text-xs", md: "h-9 px-4 text-sm" };
  const variants = {
    primary:
      "bg-signal text-base hover:brightness-110 shadow-[0_0_20px_-4px_var(--color-signal)]",
    danger: "bg-sev-critical text-base hover:brightness-110",
    outline: "border border-line bg-surface-2/60 text-ink hover:border-signal/60 hover:text-white",
    ghost: "text-ink-dim hover:text-ink hover:bg-surface-2/60",
  };
  return <button className={cn(base, sizes[size], variants[variant], className)} {...props} />;
}

/** Severity chip — the color IS the severity, consistently across the whole app. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const color = SEVERITY_COLOR[severity];
  return (
    <span
      className={cn(
        "mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em]",
        className,
      )}
      style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${color} 40%, transparent)` }}
    >
      {severity}
    </span>
  );
}

const STATUS_META: Record<ActionStatus, { label: string; color: string }> = {
  pending_approval: { label: "pending approval", color: "var(--color-sev-high)" },
  approved: { label: "approved", color: "var(--color-signal)" },
  simulated_success: { label: "simulated success", color: "var(--color-live)" },
  rejected: { label: "rejected", color: "var(--color-sev-critical)" },
  failed: { label: "failed", color: "var(--color-sev-critical)" },
};

export function StatusBadge({ status, className }: { status: ActionStatus; className?: string }) {
  const meta = STATUS_META[status];
  return (
    <span
      className={cn("mono inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[10px] tracking-wide", className)}
      style={{ color: meta.color, background: `color-mix(in srgb, ${meta.color} 12%, transparent)` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} />
      {meta.label}
    </span>
  );
}

export function EmptyState({ label, hint }: { label: string; hint?: string }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-1 p-8 text-center">
      <div className="mono text-xs uppercase tracking-[0.2em] text-ink-faint">{label}</div>
      {hint && <div className="text-xs text-ink-faint/70">{hint}</div>}
    </div>
  );
}
