"""Safe, read-only Git access for repository scans.

Security properties:

* Only `git rev-list` and `git show` are executed — read-only commands, never a
  checkout, never a rewrite, never a hook, never a `git config` with writes.
* Commands are executed with argument arrays (no shell strings), a sanitized
  environment, `GIT_OPTIONAL_LOCKS=0` and `--no-ext-diff --no-textconv` so no
  user config can execute external programs on repository content.
* Working-tree scans never descend into `.git` or vendor/build directories and
  never follow symlinks that point outside the selected repository root.
* Binary and oversized files are skipped; malformed encodings are decoded with
  replacement characters instead of crashing.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..core.config import EXCLUDED_DIRS
from ..core.logging_config import get_logger
from .path_safety import is_within

logger = get_logger(__name__)

GIT_TIMEOUT_SECONDS = 30
MAX_FILE_BYTES = 2 * 1024 * 1024  # matches the default upload limit
BINARY_SNIFF_BYTES = 8192

_DIFF_FILE_RE = re.compile(r"^\+\+\+ [ab]/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_GIT_ENV_BASE = {
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_ASKPASS": "",
    "GIT_CONFIG_NOSYSTEM": "1",
}


class GitScanError(RuntimeError):
    """Raised when the repository cannot be read with git."""


def _git_env() -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items()
        if k.startswith(("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
                         "TEMP", "TMP", "LANG", "LC_"))
    }
    env.update(_GIT_ENV_BASE)
    return env


def run_git(repo: Path, args: list[str], timeout: int = GIT_TIMEOUT_SECONDS) -> str:
    """Run a read-only git command and return stdout as text."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_git_env(),
            shell=False,  # noqa: S603 - argument array, no shell
        )
    except FileNotFoundError as exc:
        raise GitScanError("Git is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitScanError(f"Git command timed out: git {' '.join(args[:2])}") from exc
    if proc.returncode != 0:
        message = (proc.stderr or "").strip().splitlines()
        short = message[0] if message else "unknown git error"
        raise GitScanError(f"git {args[0]} failed: {short}")
    return proc.stdout


def is_git_repository(path: Path) -> bool:
    try:
        out = run_git(path, ["rev-parse", "--is-inside-work-tree"], timeout=10)
    except GitScanError:
        return False
    return out.strip() == "true"


def read_text_file(path: Path) -> str | None:
    """Read a file as text; return None for binary or oversized files."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(BINARY_SNIFF_BYTES)
            if b"\x00" in head:
                return None
            rest = fh.read()
    except OSError:
        return None
    return (head + rest).decode("utf-8", errors="replace")


def iter_worktree_files(root: Path, max_files: int) -> Iterator[Path]:
    """Yield scannable text files inside the working tree, safely."""
    yielded = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        # Prune excluded directories in-place (also breaks symlinked dirs).
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            if yielded >= max_files:
                return
            candidate = current / name
            try:
                if candidate.is_symlink() and not is_within(candidate, root):
                    continue  # symlink escaping the selected root
                if not candidate.is_file():
                    continue
            except OSError:
                continue
            yielded += 1
            yield candidate


@dataclass
class HistoryPatch:
    commit: str
    path: str
    lines: list[tuple[int, str]]  # (new line number, added text)


def history_commits(root: Path, max_commits: int) -> list[str]:
    """Most recent commits across all refs, newest first."""
    out = run_git(root, ["rev-list", "--all", f"--max-count={max_commits}"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def iter_history_patches(root: Path, commits: list[str]) -> Iterator[HistoryPatch]:
    """Yield added lines (with commit-accurate line numbers) from each commit.

    We scan content *introduced* by each commit — that is exactly where leaked
    secrets enter a repository. Nothing is checked out and no state changes.
    """
    for sha in commits:
        try:
            diff = run_git(
                root,
                ["show", "--format=", "--unified=0", "--no-ext-diff",
                 "--no-textconv", "--no-color", "--no-renames", sha],
            )
        except GitScanError as exc:
            logger.warning("Skipping commit %.8s: %s", sha, str(exc)[:120])
            continue
        yield from _parse_diff(sha, diff)


def _parse_diff(sha: str, diff: str) -> Iterator[HistoryPatch]:
    current_path: str | None = None
    new_line = 0
    in_hunk = False
    buffer: list[tuple[int, str]] = []

    def flush() -> HistoryPatch | None:
        nonlocal buffer, current_path
        if current_path is not None and buffer:
            patch = HistoryPatch(commit=sha, path=current_path, lines=list(buffer))
            buffer = []
            return patch
        buffer = []
        return None

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            flushed = flush()
            if flushed:
                yield flushed
            current_path = None
            in_hunk = False
            continue
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            current_path = file_match.group(1)
            continue
        if line.startswith("@@"):
            flushed = flush()
            if flushed:
                yield flushed
            hunk = _HUNK_RE.match(line)
            new_line = int(hunk.group(1)) if hunk else 0
            in_hunk = True
            continue
        if not in_hunk or current_path is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            buffer.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith(("-", " ", "\\")):
            continue
        elif line.startswith(("index ", "new file", "deleted file", "old mode",
                              "new mode", "similarity", "rename", "Binary")):
            in_hunk = False

    flushed = flush()
    if flushed:
        yield flushed
