import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip as RTooltip } from "recharts";
import { api } from "../lib/api";
import type { Dashboard as DashboardData } from "../types/api";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { SeverityBadge } from "../components/Badge";

const COLORS: Record<string, string> = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
};

export function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .dashboard()
      .then(setData)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner label="Loading dashboard" />;
  if (error) return <div className="card p-6 text-rose-300">{error}. Is the backend running on 127.0.0.1:8000?</div>;
  if (!data) return null;

  const chart = Object.entries(data.severity_counts).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-accent-glow">Overview</p>
          <h1 className="mt-1 text-3xl font-semibold">Credential exposure dashboard</h1>
        </div>
        <Link to="/scan" className="btn-primary">
          New Scan
        </Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Total scans", data.total_scans],
          ["Active findings", data.total_findings],
          ["Dismissed", data.dismissed_findings],
          ["Critical", data.severity_counts.critical || 0],
        ].map(([label, value]) => (
          <div key={String(label)} className="card p-5">
            <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
            <p className="mt-2 text-3xl font-semibold">{value}</p>
          </div>
        ))}
      </div>

      {data.total_scans === 0 ? (
        <EmptyState
          title="No scans yet"
          body="Paste source, upload text files, or point SecretLeak at a local Git repository you explicitly select. Scanning stays on this machine."
          action={
            <Link to="/scan" className="btn-primary">
              Start the first scan
            </Link>
          }
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[1.1fr_1fr]">
          <div className="card p-5">
            <h2 className="mb-4 text-sm font-semibold">Findings by severity</h2>
            <div className="h-56">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={chart} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}>
                    {chart.map((entry) => (
                      <Cell key={entry.name} fill={COLORS[entry.name] || "#64748b"} />
                    ))}
                  </Pie>
                  <RTooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {chart.map((item) => (
                <SeverityBadge key={item.name} severity={item.name} />
              ))}
            </div>
          </div>
          <div className="card p-5">
            <h2 className="mb-4 text-sm font-semibold">Recent scans</h2>
            <ul className="space-y-3">
              {data.recent_scans.map((scan) => (
                <li key={scan.id} className="flex items-center justify-between gap-3 rounded-xl bg-white/5 px-3 py-2">
                  <div>
                    <p className="text-sm font-medium">{scan.label}</p>
                    <p className="text-xs text-slate-400">
                      {scan.mode} · {scan.finding_count} finding(s) · {new Date(scan.created_at).toLocaleString()}
                    </p>
                  </div>
                  <Link className="text-xs text-accent-glow" to={`/history`}>
                    View
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
