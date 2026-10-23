import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { Spinner } from "../components/Spinner";
import { Tooltip } from "../components/Tooltip";

const SAMPLE = `export const config = {
  githubToken: "ghp_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
  db: "postgres://scanuser:H0rseStaple99@localhost:5432/appdb",
};
`;

export function NewScanPage() {
  const nav = useNavigate();
  const [tab, setTab] = useState<"paste" | "upload" | "repo">("paste");
  const [label, setLabel] = useState("pasted-text");
  const [content, setContent] = useState("");
  const [path, setPath] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [history, setHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function run(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      let scan;
      if (tab === "paste") {
        scan = await api.scanText(label, content);
      } else if (tab === "upload") {
        const input = document.getElementById("files") as HTMLInputElement;
        if (!input.files?.length) throw new Error("Choose one or more text-based files.");
        scan = await api.scanUpload(input.files);
      } else {
        if (!confirmed) {
          throw new Error("Confirm the directory before scanning. SecretLeak never scans arbitrary locations automatically.");
        }
        scan = await api.scanRepo(path, history);
      }
      const skipped = scan.skipped_files?.length
        ? ` ${scan.skipped_files.length} file(s) skipped — see scan details.`
        : "";
      setNotice(`Scan complete: ${scan.finding_count} potential secret(s). Values are masked.${skipped}`);
      nav(`/findings?scan=${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-accent-glow">Scanner</p>
        <h1 className="mt-1 text-3xl font-semibold">New scan</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">
          All three modes send content only to the local SecretLeak backend. Nothing is transmitted to third parties.
          Uploaded files are never executed.
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        {(["paste", "upload", "repo"] as const).map((item) => (
          <button
            key={item}
            className={tab === item ? "btn-primary" : "btn-ghost"}
            type="button"
            onClick={() => setTab(item)}
          >
            {item === "paste" ? "Paste text" : item === "upload" ? "File upload" : "Local Git repository"}
          </button>
        ))}
      </div>
      <form className="card space-y-4 p-6" onSubmit={run}>
        {tab === "paste" && (
          <>
            <label className="block text-sm">
              Label
              <input className="mt-1 w-full rounded-xl border border-white/10 bg-ink-950 px-3 py-2" value={label} onChange={(e) => setLabel(e.target.value)} />
            </label>
            <label className="block text-sm">
              Source, config, or logs
              <textarea
                className="mt-1 min-h-48 w-full rounded-xl border border-white/10 bg-ink-950 px-3 py-2 font-mono text-sm"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                required
              />
            </label>
            <button type="button" className="btn-ghost" onClick={() => setContent(SAMPLE)}>
              Insert synthetic sample
            </button>
          </>
        )}
        {tab === "upload" && (
          <label className="block text-sm">
            Text-based files (multiple allowed)
            <input id="files" className="mt-2 block w-full text-sm" type="file" multiple />
            <p className="mt-2 text-xs text-slate-400">
              Source, config, and log files only. Binary types are rejected. Size limits are set in Settings.
            </p>
          </label>
        )}
        {tab === "repo" && (
          <>
            <label className="block text-sm">
              Absolute local path
              <input
                className="mt-1 w-full rounded-xl border border-white/10 bg-ink-950 px-3 py-2 font-mono"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="C:\\Users\\you\\Projects\\app"
                required
              />
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
              I confirm this is the directory I want scanned. SecretLeak will not scan arbitrary locations.
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} />
              Also scan Git history (read-only, no checkout)
              <Tooltip text="Reads commit patches with git log. Does not rewrite history or run hooks.">
                <span className="text-accent-glow">?</span>
              </Tooltip>
            </label>
          </>
        )}
        {error && <p className="rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</p>}
        {notice && <p className="rounded-xl bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{notice}</p>}
        <button className="btn-primary" disabled={busy} type="submit">
          {busy ? "Scanning…" : "Run scan"}
        </button>
        {busy && <Spinner label="Scanning locally" />}
      </form>
    </div>
  );
}
