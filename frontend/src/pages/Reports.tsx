import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Scan } from "../types/api";
import { EmptyState } from "../components/EmptyState";

export function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  useEffect(() => {
    api.scans().then((res) => setScans(res.scans));
  }, []);

  if (scans.length === 0) {
    return <EmptyState title="No reports yet" body="Run a scan, then export JSON or CSV. Exports contain masked values only." />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold">Reports</h1>
        <p className="mt-2 text-sm text-slate-400">
          JSON and CSV downloads never include complete credentials or private-key bodies. Cells that look like spreadsheet formulas are neutralized.
        </p>
      </div>
      <div className="space-y-3">
        {scans.map((scan) => (
          <div key={scan.id} className="card flex flex-wrap items-center justify-between gap-3 p-4">
            <div>
              <p className="font-medium">{scan.label}</p>
              <p className="text-xs text-slate-400">{scan.finding_count} findings · {new Date(scan.created_at).toLocaleString()}</p>
            </div>
            <div className="flex gap-2">
              <a className="btn-ghost" href={api.reportUrl(scan.id, "json")}>JSON</a>
              <a className="btn-ghost" href={api.reportUrl(scan.id, "csv")}>CSV</a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
