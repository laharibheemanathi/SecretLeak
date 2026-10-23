import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import type { Finding } from "../types/api";
import { SeverityBadge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";

export function FindingsPage() {
  const [params] = useSearchParams();
  const [items, setItems] = useState<Finding[]>([]);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState(params.get("severity") || "");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const query: Record<string, string> = {};
    if (params.get("scan")) query.scan_id = params.get("scan")!;
    if (severity) query.severity = severity;
    if (q) query.q = q;
    setLoading(true);
    api
      .findings(query)
      .then((res) => setItems(res.findings))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [params, severity, q]);

  const filtered = useMemo(() => items, [items]);

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-accent-glow">Results</p>
        <h1 className="mt-1 text-3xl font-semibold">Findings</h1>
        <p className="mt-2 text-sm text-slate-400">Masked previews only. Raw credentials are never stored, so they cannot be revealed later.</p>
      </div>
      <div className="flex flex-wrap gap-3">
        <input className="rounded-xl border border-white/10 bg-ink-800 px-3 py-2 text-sm" placeholder="Search rule, file, category" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="rounded-xl border border-white/10 bg-ink-800 px-3 py-2 text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </div>
      {loading && <Spinner />}
      {error && <p className="text-rose-300">{error}</p>}
      {!loading && filtered.length === 0 && (
        <EmptyState title="No findings" body="Run a scan or relax the filters. Absence of findings is not a guarantee — pattern scanners miss things." />
      )}
      {filtered.length > 0 && (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-400">
              <tr>
                {["Severity", "Rule", "Location", "Preview", "Confidence", ""].map((h) => (
                  <th key={h} className="px-4 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.id} className="border-t border-white/5">
                  <td className="px-4 py-3"><SeverityBadge severity={item.severity} /></td>
                  <td className="px-4 py-3">{item.rule_name}</td>
                  <td className="px-4 py-3 font-mono text-xs">{item.input_label}:{item.line}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{item.masked_preview}</td>
                  <td className="px-4 py-3 text-xs">{item.confidence}</td>
                  <td className="px-4 py-3">
                    <Link className="text-accent-glow" to={`/findings/${item.id}`}>Details</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
