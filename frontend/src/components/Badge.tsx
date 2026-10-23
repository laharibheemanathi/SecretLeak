import type { Severity } from "../types/api";

const styles: Record<string, string> = {
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-amber-500/15 text-amber-200 ring-amber-500/30",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return (
    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ${styles[severity] || styles.low}`}>
      {severity}
    </span>
  );
}
