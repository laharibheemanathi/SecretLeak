export function AboutPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-semibold">About and security</h1>
      <section className="card space-y-3 p-6 text-sm leading-6 text-slate-300">
        <h2 className="text-lg font-semibold text-white">Architecture</h2>
        <p>
          The React UI talks only to a FastAPI process bound to 127.0.0.1. The detection engine applies regular expressions and an optional entropy heuristic. Findings are masked, fingerprinted with a local HMAC key, and stored in SQLite without raw secrets.
        </p>
        <h2 className="text-lg font-semibold text-white">Limitations</h2>
        <p>
          Pattern-based detection produces both false positives and false negatives. Custom token formats, encrypted blobs, images of credentials, and novel providers may be missed. A match is not proof that a credential is valid or exploitable. Severity is a default ranking, not a risk score for your environment.
        </p>
        <h2 className="text-lg font-semibold text-white">Privacy</h2>
        <p>
          Scanning is local. There is no telemetry, no AI API, and no secret-reputation lookup. Source and secrets are not sent to third parties. Logs omit request bodies. Reports export masked values only. Clearing history deletes SQLite metadata; the HMAC key file remains until you delete it from disk.
        </p>
        <p>
          SecretLeak does not revoke credentials or rewrite Git history. Client-side pre-commit hooks can be bypassed with <code>git commit --no-verify</code> and are not a substitute for server-side scanning.
        </p>
      </section>
    </div>
  );
}
