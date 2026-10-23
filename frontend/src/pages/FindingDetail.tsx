import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../lib/api";
import type { Finding } from "../types/api";
import { SeverityBadge } from "../components/Badge";
import { Spinner } from "../components/Spinner";

const REASONS = [
  ["test_fixture", "Test fixture"],
  ["placeholder", "Placeholder"],
  ["false_positive", "False positive"],
  ["approved_exception", "Approved exception"],
];

export function FindingDetailPage() {
  const { id } = useParams();
  const [item, setItem] = useState<Finding | null>(null);
  const [reason, setReason] = useState("false_positive");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  useEffect(() => {
    if (!id) return;
    api.finding(id).then(setItem).catch((err: Error) => setError(err.message));
  }, [id]);

  if (!item && !error) return <Spinner />;
  if (error) return <p className="text-rose-300">{error}</p>;
  if (!item) return null;

  async function dismiss() {
    if (!item) return;
    const updated = await api.dismiss(item.id, reason, note);
    setItem(updated);
    setSaved("Dismissal saved. The raw secret was never stored.");
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={item.severity} />
        <h1 className="text-3xl font-semibold">{item.rule_name}</h1>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="card space-y-3 p-6">
          <h2 className="text-sm font-semibold">Why this was flagged</h2>
          <p className="text-sm leading-6 text-slate-300">{item.description}</p>
          <p className="text-sm leading-6 text-slate-400">{item.why_severity}</p>
          <p className="text-xs text-slate-500">A pattern match does not prove the credential is valid, active, or exploitable.</p>
          <p className="font-mono text-xs text-slate-400">{item.input_label}:{item.line}:{item.column}</p>
          <p className="font-mono text-sm">{item.masked_preview}</p>
          <pre className="overflow-x-auto rounded-xl bg-black/40 p-3 text-xs text-slate-300">{item.context_snippet}</pre>
        </section>
        <section className="card space-y-3 p-6">
          <h2 className="text-sm font-semibold">Remediation</h2>
          <p className="text-sm leading-6 text-slate-300">{item.remediation}</p>
          <h3 className="pt-2 text-sm font-semibold">Rotate or revoke</h3>
          <p className="text-sm text-slate-400">
            Use the provider console to revoke this credential, issue a replacement, and update every consumer. SecretLeak will not revoke anything for you.
          </p>
          <h3 className="text-sm font-semibold">Prevent the next leak</h3>
          <p className="text-sm text-slate-400">
            Keep secrets in a manager or environment variables, add a pre-commit hook, and prefer server-side scanning. Client hooks can be bypassed.
          </p>
        </section>
      </div>
      <section className="card space-y-3 p-6">
        <h2 className="text-sm font-semibold">Dismiss as false positive</h2>
        <select className="rounded-xl border border-white/10 bg-ink-950 px-3 py-2 text-sm" value={reason} onChange={(e) => setReason(e.target.value)}>
          {REASONS.map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
        <textarea className="w-full rounded-xl border border-white/10 bg-ink-950 px-3 py-2 text-sm" placeholder="Optional note (no secrets)" value={note} onChange={(e) => setNote(e.target.value)} />
        <button className="btn-ghost" type="button" onClick={dismiss}>Save dismissal</button>
        {saved && <p className="text-sm text-emerald-300">{saved}</p>}
        {item.dismissed && <p className="text-xs text-slate-400">Already dismissed as {item.dismissal_reason}.</p>}
      </section>
    </div>
  );
}
