# SecretLeak: The Forgotten Credentials Hunter

Local-first scanner for accidentally exposed credentials in source code, configuration
files, application logs, and Git repositories.

SecretLeak runs entirely on your machine. It does **not** call paid APIs, AI services,
or secret-reputation endpoints. A pattern match is **not** proof that a credential is
valid, active, or exploitable — SecretLeak masks what it finds, explains why it was
flagged, and tells you how to rotate it. It never revokes credentials or rewrites Git
history for you.

## Features

- **Three scan modes:** paste text, upload text-based files, scan a directory you explicitly confirm
- **Optional read-only Git history scanning** (no checkout, no state changes, no hooks)
- **Provider-shaped detection rules** (GitHub, GitLab, Slack, AWS, JWTs, database URLs, PEM keys, …) plus an optional generic high-entropy heuristic
- **Masked previews and redacted context** — raw secrets are never stored, logged, or exported
- **HMAC fingerprints** (keyed with a locally generated secret) for stable deduplication
- **False-positive dismissal** with reasons (test fixture, placeholder, false positive, approved exception)
- **JSON and CSV reports** with CSV formula-injection protection
- **Local SQLite** scan history, findings metadata, dismissals, and settings
- **Git pre-commit hook** installer that scans *staged* content and blocks on a configurable severity threshold
- **Dark, professional dashboard** built with a reusable design system

## Architecture

```mermaid
flowchart LR
  UI["React + Vite UI<br/>http://127.0.0.1:5173"] -->|"HTTP /api (JSON)"| API["FastAPI backend<br/>127.0.0.1:8000"]
  API --> ENG["Detection engine<br/>regex rules + entropy heuristic"]
  ENG --> RED["Masking & redaction<br/>(raw values never persist)"]
  RED --> HMAC["HMAC-SHA256 fingerprint<br/>(local key file, git-ignored)"]
  API --> DB[("SQLite (WAL)<br/>scans · findings · dismissals · settings")]
  API --> GIT["Read-only git subprocess<br/>rev-list / show (argument arrays)"]
  UI -.downloads.-> RPT["JSON / CSV reports<br/>(masked values only)"]
  CLI["pre-commit hook<br/>(scripts/install_git_hook.py)"] --> CLI_SCAN["backend/app/cli_scan.py<br/>scans staged blobs"]
```

Privacy invariant enforced by tests: **no raw credential ever reaches an API response,
a database row, a log line, a report, or an error message.**

## Tech stack

| Layer | Technology |
| --- | --- |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Lucide icons, Recharts (severity chart) |
| Backend | Python 3.10+, FastAPI, Pydantic, Uvicorn, SQLite (stdlib `sqlite3`) |
| Engine | Python regular expressions + Shannon entropy heuristic + keyed HMAC fingerprints |
| Git access | Safe read-only `git` subprocess calls with argument arrays (no shell strings) |
| Tests | pytest (backend), Vitest + React Testing Library (frontend) |

## Prerequisites (Windows)

- **Python 3.10 or newer** — check with `python --version` (or `py --version`)
- **Node.js 18 or newer** — check with `node --version`
- **Git** — check with `git --version`

> On Windows, `python3` may open the Microsoft Store stub. Use `python` (or `py`) instead.

## Exact Windows setup

Open **Git Bash** or PowerShell in the project root (`SecretLeak/`).

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install -r requirements.txt
```

(Git Bash: use `.venv/Scripts/python` the same way.)

### 2. Frontend

```bash
cd frontend
npm install
```

### 3. Run

Backend (terminal 1):

```bash
cd backend
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend (terminal 2):

```bash
cd frontend
npm run dev
```

Open **http://127.0.0.1:5173** — the Vite dev server proxies `/api` to the backend,
so CORS stays restricted to the local origin. The API docs are at
http://127.0.0.1:8000/api/docs.

> The backend binds to `127.0.0.1` by default. Do not expose it to other hosts;
> it has no authentication (it is a local single-user tool).

## Test commands

Backend (135 tests):

```bash
cd backend
.venv/Scripts/python -m pytest
```

Frontend:

```bash
cd frontend
npm test          # vitest
npm run build     # typecheck + production build
```

## Example scan workflow

1. Click **New Scan** on the dashboard.
2. Choose **Paste text**, give it a label, and paste the contents of
   [`sample_data/leaky.env`](sample_data/leaky.env) (fully synthetic values).
3. Press **Run scan**. SecretLeak returns findings with masked previews
   (`ghp_••••••••••••••••`) and severity badges.
4. Open a finding to see *why* it fired, redacted context, remediation steps,
   and rotation guidance. Dismiss it if it is a false positive (reason required).
5. Go to **Reports** and export the scan as JSON or CSV — masked values only.
6. **Scan History** lists past scans as metadata; deletion asks for confirmation
   and removes associated findings.

Try a repository scan by pointing at `sample_data/hook_demo` after `git init`-ing it,
or at any local repository, optionally including Git history.

## Detection rules

Severity model: **CRITICAL** = highly sensitive material (private keys);
**HIGH** = recognizable provider-token formats or database credentials;
**MEDIUM** = generic credential assignments or suspicious authorization values;
**LOW** = weak heuristic matches (high-entropy strings). Severity is a default
ranking, not proof of exploitability.

| Rule ID | What it matches | Severity | Confidence |
| --- | --- | --- | --- |
| `private-key-block` | PEM/PGP private key headers (`-----BEGIN … PRIVATE KEY-----`); body never retained | CRITICAL | high |
| `github-pat` | GitHub classic PATs (`ghp_` + 36 chars) | HIGH | high |
| `github-fine-grained-pat` | GitHub fine-grained PATs (`github_pat_…_…`) | HIGH | high |
| `github-oauth-app-token` | GitHub `gho_`/`ghu_`/`ghs_`/`ghr_` tokens | HIGH | high |
| `gitlab-pat` | GitLab personal access tokens (`glpat-…`) | HIGH | high |
| `gitlab-runner-token` | GitLab runner tokens (`glrt-…`) | HIGH | high |
| `slack-token` | Slack API tokens (`xoxb-`, `xoxp-`, …) | HIGH | high |
| `slack-webhook-url` | Slack incoming-webhook URLs | HIGH | high |
| `aws-access-key-id` | AWS access key IDs (`AKIA`/`ASIA`/… + 16 chars) | HIGH | medium |
| `database-connection-string` | `postgres://user:pass@host`, MySQL, Mongo, Redis, AMQP, JDBC | HIGH | high |
| `jwt-token` | JWT-shaped strings (`eyJ…​.….…`) | MEDIUM | medium |
| `authorization-bearer` | `Authorization: Bearer/Basic …` credentials | MEDIUM | medium |
| `url-credentials` | Any URL embedding `user:password@` | MEDIUM | medium |
| `api-key-assignment` | `api_key = "…"`-style assignments (entropy-gated) | MEDIUM | medium |
| `password-assignment` | Literal `password = "…"` assignments | MEDIUM | medium |
| `env-var-credential` | `.env`-style `MY_SECRET=…` lines | MEDIUM | medium |
| `log-credential-leak` | Structured log lines echoing credentials (entropy-gated) | MEDIUM | medium |
| `generic-high-entropy` | Long mixed-character strings with high Shannon entropy | LOW | low |

**Placeholder filtering:** values like `YOUR_API_KEY`, `EXAMPLE_TOKEN`, `CHANGEME`,
`REDACTED`, `dummy`, `${VAR}`, `$VAR`, `%VAR%`, `{{var}}`, `<your-key>`, repeated
characters, and runtime references (`process.env…`, `os.environ…`, `input(…)`) are
never reported. Overlapping matches are resolved by rule priority (a JWT inside
`access_token: "…"` is reported once, by the specific rule). Every rule documents
*why* it has its severity in [`backend/app/detectors/rules.py`](backend/app/detectors/rules.py).

## Pre-commit hook

```bash
python scripts/install_git_hook.py . --min-severity high   # install
python scripts/uninstall_git_hook.py .                     # uninstall
```

- Scans **staged content only** (the git index), never unrelated uncommitted files.
- Prints **masked previews only** — full secrets never hit your terminal.
- Exits nonzero (blocking the commit) on findings at/above the threshold; scanner
  *errors* fail open so a broken scanner never traps your work.
- Never overwrites an existing foreign hook without `--force` (a backup is kept).

> Client-side hooks are advisory: `git commit --no-verify` bypasses them and clones
> do not receive them. They are **not** a substitute for server-side secret scanning.

Demo: see [`sample_data/README.md`](sample_data/README.md).

## Privacy and security design

- **All scanning is local.** No telemetry, analytics, AI calls, or reputation lookups.
- **Raw secrets are never persisted.** SQLite stores masked previews, capped redacted
  context, rule metadata, and an HMAC-SHA256 fingerprint — never the credential.
- **The HMAC key** is random, generated on first use, stored outside the database and
  outside version control (`backend/data/.hmac_key`, git-ignored). A plain hash would
  be guessable for low-entropy secrets; a keyed HMAC is not.
- **Request bodies, pasted code, uploads, and authorization headers are never logged.**
  Unhandled errors return a generic message with a reference id; stack traces stay in
  the local server console.
- **PEM private keys** are masked by header only; key bodies are counted, redacted, and
  scrubbed from every context snippet (line-by-line, even when the block's END line is
  outside the visible window).
- **Path safety:** repository scans validate and resolve the user-selected directory,
  refuse filesystem roots, never follow symlinks that escape the root, and never enter
  `.git` or vendor/build directories during working-tree scans.
- **Read-only git access:** only `git rev-list` and `git show` are executed, with
  argument arrays, a sanitized environment, `GIT_OPTIONAL_LOCKS=0`, `--no-ext-diff`
  and `--no-textconv`. Nothing is ever checked out or rewritten.
- **Upload safety:** extension allowlist, binary sniffing (null bytes), per-file size
  limit, file-count limit, filename sanitization. Uploaded content is never executed.
- **SQL injection:** parameterized queries only.
- **CSV reports** neutralize spreadsheet formula injection (`=`, `+`, `-`, `@`, tab, CR).
- **CORS** allows only the explicit local frontend origin (`http://localhost:5173`,
  `http://127.0.0.1:5173`) — never a wildcard.
- **Request-size limits** (default 25 MB) are enforced before parsing.
- **Memory clearing is best-effort.** Python cannot guarantee removal of every copy of a
  secret from process memory during a scan; the raw value lives only in short-lived
  local variables.

## Database

SQLite (WAL mode) with a versioned schema (`PRAGMA user_version`) in
`backend/data/secretleak.db`:

- `scans` — id, timestamp, mode, label, file/finding counts, root path (metadata only)
- `findings` — rule metadata, severity, confidence, location, masked preview, redacted
  context (capped), remediation, HMAC fingerprint. **No raw secret column exists.**
- `dismissals` — finding id, reason, note, timestamp (never the secret)
- `settings` — key/value overrides of documented defaults

Deleting a scan cascades to its findings and dismissals.

## Known limitations

- **False positives and false negatives are inevitable.** Custom token formats,
  encrypted blobs, split/concatenated secrets, credentials inside images or PDFs, and
  novel providers are missed. Generic rules can flag non-secrets.
- A match never proves a credential is **valid or active** — SecretLeak does not call
  providers to check.
- Git history scanning examines content *introduced* by each commit (added lines in
  patches); it is bounded by configurable commit/file limits for performance.
- The entropy heuristic is deliberately conservative but still the noisiest rule.
- The API has no authentication — run it on `127.0.0.1` only.
- Windows symlink scenarios are skipped in tests when the OS denies symlink creation.

## Screenshots

> Run the app locally, then paste screenshots here:
>
> | Dashboard | New Scan | Findings |
> | --- | --- | --- |
> | _screenshot coming soon_ | _screenshot coming soon_ | _screenshot coming soon_ |

## Future improvements

- Rule enable/disable UI backed by the settings table
- Sharded scanning for very large repositories, with progress streaming (SSE)
- Additional providers (Stripe, Twilio, SendGrid, GCP service-account JSON)
- Entropy tuning per language/dialect and per path allowlists
- Optional server-side CI integration (GitHub Action wrapper around the CLI)
- Multi-select bulk dismiss and report filtering

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never commit real credentials — not even in
tests. All fixtures must be synthetic.

## License

[MIT](LICENSE)

## Author

**Your Name** — replace this line with your name and contact.
