import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type { Scan } from "../types/api";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Spinner } from "../components/Spinner";

export function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [pending, setPending] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  function load() {
    setLoading(true);
    api.scans().then((res) => setScans(res.scans)).finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function confirmDelete() {
    if (!pending) return;
    await api.deleteScan(pending);
    setPending(null);
    load();
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-semibold">Scan history</h1>
      {loading && <Spinner />}
      {!loading && scans.length === 0 && (
        <EmptyState title="No history" body="Completed scans appear here as metadata only — not the original source." />
      )}
      <div className="space-y-3">
        {scans.map((scan) => (
          <div key={scan.id} className="card flex flex-wrap items-center justify-between gap-3 p-4">
            <div>
              <p className="font-medium">{scan.label}</p>
              <p className="text-xs text-slate-400">
                {scan.mode} · {scan.file_count} files · {scan.finding_count} findings · {new Date(scan.created_at).toLocaleString()}
              </p>
            </div>
            <div className="flex gap-2">
              <Link className="btn-ghost" to={`/findings?scan=${scan.id}`}>View</Link>
              <button className="btn-ghost" type="button" onClick={() => setPending(scan.id)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
      {pending && (
        <Modal title="Delete this scan?" onClose={() => setPending(null)}>
          <p>This removes scan metadata and findings from the local database. Raw source was never stored.</p>
          <button className="btn-primary mt-4" type="button" onClick={confirmDelete}>Delete permanently</button>
        </Modal>
      )}
    </div>
  );
}
