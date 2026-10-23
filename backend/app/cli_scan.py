"""Command-line scanner used by the SecretLeak pre-commit hook.

Usage examples (run from anywhere):

    python backend/app/cli_scan.py --staged
    python backend/app/cli_scan.py --staged --min-severity high
    python backend/app/cli_scan.py --path src/config.py

Behavior:
* --staged scans the content staged in the Git index (not the working tree),
  so unrelated uncommitted files are never scanned.
* Output shows masked previews only — a full secret is never printed.
* Exit codes: 0 = clean (or scan error — fail-open, advisory), 2 = findings at
  or above --min-severity (blocking). Client-side hooks can be bypassed with
  `git commit --no-verify`; they are not a substitute for server-side scanning.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Allow running as a plain script: python backend/app/cli_scan.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import UPLOAD_EXTENSIONS  # noqa: E402
from app.database import db  # noqa: E402
from app.detectors import scan_text  # noqa: E402
from app.detectors.redaction import BULLET  # noqa: E402
from app.detectors.rules import SEVERITY_ORDER  # noqa: E402
from app.services import git_scanner  # noqa: E402
from app.services.git_scanner import GitScanError  # noqa: E402

MAX_STAGED_BYTES = 1024 * 1024


def _git(args: list[str], cwd: Path) -> list[str]:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True,
        timeout=30, shell=False,  # noqa: S603
        env=git_scanner._git_env(),
    )
    if proc.returncode != 0:
        raise GitScanError(proc.stderr.strip().splitlines()[0] if proc.stderr.strip() else "git failed")
    return [line for line in proc.stdout.split("\n") if line]


def staged_files(repo: Path) -> list[str]:
    return [f for f in _git(["diff", "--cached", "--name-only"], repo) if f.strip()]


def staged_content(repo: Path, path: str) -> str | None:
    """Read the staged (index) version of a file, never the working tree copy."""
    try:
        proc = subprocess.run(
            ["git", "show", f":{path}"], cwd=str(repo), capture_output=True,
            timeout=30, shell=False,  # noqa: S603
            env=git_scanner._git_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    data = proc.stdout[: MAX_STAGED_BYTES + 1]
    if len(data) > MAX_STAGED_BYTES or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _allowed(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(".env"):
        return True
    return any(lowered.endswith(ext) for ext in UPLOAD_EXTENSIONS)


def scan_staged(min_severity: str) -> int:
    try:
        repo = Path(_git(["rev-parse", "--show-toplevel"], Path.cwd())[0]).resolve()
        files = staged_files(repo)
    except (GitScanError, IndexError, OSError) as exc:
        print(f"[secretleak] warning: cannot read git state ({exc}); skipping scan.")
        return 0

    threshold = SEVERITY_ORDER[min_severity]
    blocking = 0
    scanned = 0
    for rel in files:
        if not _allowed(rel):
            continue
        text = staged_content(repo, rel)
        if text is None:
            continue
        scanned += 1
        for draft in scan_text(text, label=rel):
            if SEVERITY_ORDER[draft.severity] >= threshold:
                blocking += 1
                print(
                    f"[secretleak] {draft.severity.upper():8s} {rel}:{draft.line}:{draft.column} "
                    f"{draft.rule_id} -> {draft.masked_preview}"
                )
                print(f"            remediation: {draft.remediation.splitlines()[0][:100]}")

    if blocking:
        print(f"\n[secretleak] {blocking} finding(s) at or above '{min_severity}' in staged files "
              f"({scanned} scanned).")
        print("[secretleak] Rotate exposed credentials; use `git commit --no-verify` to bypass "
              "(hooks are not a security boundary).")
        return 2
    print(f"[secretleak] clean: {scanned} staged file(s) scanned, no findings at or above '{min_severity}'.")
    return 0


def scan_paths(paths: list[str], min_severity: str) -> int:
    threshold = SEVERITY_ORDER[min_severity]
    blocking = 0
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for file_path in git_scanner.iter_worktree_files(path.resolve(), 2000):
                text = git_scanner.read_text_file(file_path)
                if text is None:
                    continue
                for draft in scan_text(text, label=str(file_path)):
                    if SEVERITY_ORDER[draft.severity] >= threshold:
                        blocking += 1
                        print(f"[secretleak] {draft.severity.upper():8s} {file_path.name}:{draft.line} "
                              f"{draft.rule_id} -> {draft.masked_preview}")
        elif path.is_file():
            text = git_scanner.read_text_file(path)
            if text is None:
                continue
            for draft in scan_text(text, label=path.name):
                if SEVERITY_ORDER[draft.severity] >= threshold:
                    blocking += 1
                    print(f"[secretleak] {draft.severity.upper():8s} {path.name}:{draft.line} "
                          f"{draft.rule_id} -> {draft.masked_preview}")
    return 2 if blocking else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecretLeak CLI scanner (local, offline).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--staged", action="store_true", help="scan staged git content")
    group.add_argument("--path", action="append", help="scan a file or directory (repeatable)")
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="high")
    args = parser.parse_args(argv)

    # Silence the SQL logger noise; CLI prints only masked findings.
    db.init_db()
    try:
        if args.staged:
            return scan_staged(args.min_severity)
        return scan_paths(args.path or [], args.min_severity)
    except GitScanError as exc:
        print(f"[secretleak] warning: {exc}; skipping scan (fail-open).")
        return 0
    except Exception as exc:  # advisory tool: never hard-block on internal errors
        print(f"[secretleak] warning: scan failed ({type(exc).__name__}); failing open.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
