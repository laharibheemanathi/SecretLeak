import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { DataLocations, Settings } from "../types/api";
import { Modal } from "../components/Modal";
import { Spinner } from "../components/Spinner";

export function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [locations, setLocations] = useState<DataLocations | null>(null);
  const [saved, setSaved] = useState("");
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState(false);

  useEffect(() => {
    api
      .settings()
      .then((res) => {
        setSettings(res.settings);
        setLocations(res.locations);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  if (error) return <div className="card p-6 text-rose-300">{error}</div>;
  if (!settings) return <Spinner label="Loading settings" />;

  async function save() {
    setError("");
    try {
      const res = await api.saveSettings({
        max_upload_mb: settings!.max_upload_mb,
        max_files_per_scan: settings!.max_files_per_scan,
        max_paste_chars: settings!.max_paste_chars,
        entropy_enabled: settings!.entropy_enabled,
        entropy_threshold: settings!.entropy_threshold,
        git_history_enabled: settings!.git_history_enabled,
        max_repo_files: settings!.max_repo_files,
        max_history_commits: settings!.max_history_commits,
        hook_min_severity: settings!.hook_min_severity,
      });
      setSettings(res.settings);
      setSaved("Settings saved on this machine.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    }
  }

  async function wipe() {
    const result = await api.clearHistory();
    setConfirm(false);
    setSaved(`Removed ${result.deleted_scans} scan(s). Settings and HMAC key were left in place.`);
  }

  const num = (key: keyof Settings, value: number) =>
    setSettings({ ...settings, [key]: value } as Settings);
  const bool = (key: keyof Settings, value: boolean) =>
    setSettings({ ...settings, [key]: value } as Settings);

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-accent-glow">Configuration</p>
        <h1 className="mt-1 text-3xl font-semibold">Settings</h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-400">
          Limits and detection toggles apply to new scans. Changes are stored in the local SQLite database.
        </p>
      </div>
      <div className="card space-y-4 p-6">
        <label className="block text-sm">
          Max upload file size (MB)
          <input type="number" min={1} max={50} className="mt-1 w-32 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
            value={settings.max_upload_mb} onChange={(e) => num("max_upload_mb", Number(e.target.value))} />
        </label>
        <label className="block text-sm">
          Max files per scan
          <input type="number" min={1} max={500} className="mt-1 w-32 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
            value={settings.max_files_per_scan} onChange={(e) => num("max_files_per_scan", Number(e.target.value))} />
        </label>
        <label className="block text-sm">
          Max pasted characters
          <input type="number" min={1000} max={5000000} step={1000} className="mt-1 w-40 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
            value={settings.max_paste_chars} onChange={(e) => num("max_paste_chars", Number(e.target.value))} />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={settings.entropy_enabled}
            onChange={(e) => bool("entropy_enabled", e.target.checked)} />
          Generic high-entropy heuristic (LOW severity, more false positives)
        </label>
        <label className="block text-sm">
          Entropy threshold (bits/character)
          <input type="number" min={2.5} max={7.5} step={0.1} disabled={!settings.entropy_enabled}
            className="mt-1 w-32 rounded-xl border border-white/10 bg-ink-950 px-3 py-2 disabled:opacity-40"
            value={settings.entropy_threshold} onChange={(e) => num("entropy_threshold", Number(e.target.value))} />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={settings.git_history_enabled}
            onChange={(e) => bool("git_history_enabled", e.target.checked)} />
          Default to Git history scanning for repository scans (read-only)
        </label>
        <div className="flex flex-wrap gap-4">
          <label className="block text-sm">
            Max repository files
            <input type="number" min={100} max={20000} step={100} className="mt-1 w-32 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
              value={settings.max_repo_files} onChange={(e) => num("max_repo_files", Number(e.target.value))} />
          </label>
          <label className="block text-sm">
            Max history commits
            <input type="number" min={1} max={5000} step={10} className="mt-1 w-32 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
              value={settings.max_history_commits} onChange={(e) => num("max_history_commits", Number(e.target.value))} />
          </label>
          <label className="block text-sm">
            Pre-commit hook blocks at
            <select className="mt-1 w-36 rounded-xl border border-white/10 bg-ink-950 px-3 py-2"
              value={settings.hook_min_severity}
              onChange={(e) => setSettings({ ...settings, hook_min_severity: e.target.value as Settings["hook_min_severity"] })}>
              {["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
        </div>
        <button className="btn-primary" type="button" onClick={save}>Save settings</button>
        {saved && <p className="text-sm text-emerald-300">{saved}</p>}
      </div>

      <div className="card space-y-3 p-6">
        <h2 className="font-semibold">Where your data lives</h2>
        {locations ? (
          <>
            <p className="font-mono text-xs text-slate-400">Data directory: {locations.data_dir}</p>
            <p className="font-mono text-xs text-slate-400">Database: {locations.database_file}</p>
            <p className="font-mono text-xs text-slate-400">HMAC key: {locations.hmac_key_file}</p>
            <p className="text-sm text-slate-400">{locations.note}</p>
          </>
        ) : null}
        <p className="text-sm text-slate-400">
          Clearing history removes scans, findings and dismissals. Python cannot guarantee secrets are wiped
          from process memory after a scan — that clearing is best-effort.
        </p>
        <div className="flex gap-3">
          <button className="btn-ghost" type="button" onClick={() => setConfirm(true)}>Clear local scan history</button>
          <button className="btn-ghost" type="button" onClick={async () => {
            const res = await api.resetSettings();
            setSettings(res.settings);
            setSaved("Settings restored to defaults.");
          }}>Reset to defaults</button>
        </div>
      </div>

      {confirm && (
        <Modal title="Clear all local history?" onClose={() => setConfirm(false)}>
          <p>This deletes scans, findings, and dismissals from SQLite. It cannot be undone.</p>
          <button className="btn-primary mt-4" type="button" onClick={wipe}>Clear history</button>
        </Modal>
      )}
    </div>
  );
}
