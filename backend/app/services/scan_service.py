"""Scan orchestration: text, uploads and local repositories.

Every finding that reaches storage is already masked and fingerprinted by the
engine — this service only persists metadata (rule, severity, location, masked
preview, redacted context, remediation). Raw values are never written to the
database, logs or temp files.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..core.config import (
    HARD_MAX_FILES_PER_SCAN,
    HARD_MAX_UPLOAD_MB,
    UPLOAD_EXTENSIONS,
)
from ..core.logging_config import get_logger
from ..database import db
from ..detectors import scan_text
from ..detectors.engine import FindingDraft
from . import git_scanner, path_safety, settings_service

logger = get_logger(__name__)

MAX_CONTEXT_SNIPPET_CHARS = 1200


class ScanError(ValueError):
    """Raised for user-correctable scan problems (mapped to HTTP 400)."""


def _settings() -> dict[str, Any]:
    return settings_service.get_settings()


def _draft_to_row(draft: FindingDraft, file_path: str | None) -> dict[str, Any]:
    return {
        "id": db.new_id(),
        "rule_id": draft.rule_id,
        "rule_name": draft.rule_name,
        "category": draft.category,
        "severity": draft.severity,
        "confidence": draft.confidence,
        "input_label": draft.label,
        "file_path": file_path,
        "line": draft.line,
        "column": draft.column,
        "masked_preview": draft.masked_preview,
        "context_snippet": draft.context_snippet[:MAX_CONTEXT_SNIPPET_CHARS],
        "remediation": draft.remediation,
        "description": draft.description,
        "why_severity": draft.why_severity,
        "fingerprint": draft.fingerprint,
        "created_at": db.utcnow(),
    }


def _persist_scan(
    mode: str,
    label: str,
    drafts_with_files: list[tuple[FindingDraft, str | None]],
    file_count: int,
    skipped_files: list[dict[str, str]],
    duration_ms: int,
    root_path: str | None = None,
    include_history: bool = False,
) -> dict[str, Any]:
    scan = {
        "id": db.new_id(),
        "created_at": db.utcnow(),
        "mode": mode,
        "label": label[:120],
        "file_count": file_count,
        "finding_count": len(drafts_with_files),
        "skipped_count": len(skipped_files),
        "root_path": root_path,
        "include_history": include_history,
        "duration_ms": duration_ms,
        "skipped_files": skipped_files[:50],
    }
    db.insert_scan(scan)
    for draft, file_path in drafts_with_files:
        db.insert_finding(scan["id"], _draft_to_row(draft, file_path))
    logger.info(
        "Scan %s finished: mode=%s files=%d findings=%d skipped=%d duration_ms=%d",
        scan["id"][:8], mode, file_count, len(drafts_with_files), len(skipped_files), duration_ms,
    )
    return db.get_scan(scan["id"]) or scan


# --- text ---------------------------------------------------------------------


def create_text_scan(label: str, content: str) -> dict[str, Any]:
    settings = _settings()
    max_chars = int(settings["max_paste_chars"])
    if len(content) > max_chars:
        raise ScanError(
            f"Pasted text is too large ({len(content):,} characters). "
            f"Limit is {max_chars:,} characters; adjust it in Settings."
        )
    started = time.perf_counter()
    drafts = scan_text(
        content,
        label=label or "pasted text",
        entropy_enabled=bool(settings["entropy_enabled"]),
        entropy_threshold=float(settings["entropy_threshold"]),
    )
    duration_ms = int((time.perf_counter() - started) * 1000)
    pairs = [(draft, None) for draft in drafts]
    return _persist_scan("text", label or "pasted text", pairs, 1, [], duration_ms)


# --- upload -------------------------------------------------------------------

_BLOCKED_EXTENSIONS = (
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".wasm",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".iso",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mp4", ".mp3",
)


def _is_allowed_filename(name: str) -> bool:
    lowered = name.lower()
    if any(lowered.endswith(ext) for ext in _BLOCKED_EXTENSIONS):
        return False
    if lowered.startswith(".env"):
        return True
    return any(lowered.endswith(ext) for ext in UPLOAD_EXTENSIONS)


def create_upload_scan(label: str, files: list[tuple[str, bytes]]) -> dict[str, Any]:
    """files: list of (filename, raw bytes) — validated, never executed."""
    settings = _settings()
    max_files = min(int(settings["max_files_per_scan"]), HARD_MAX_FILES_PER_SCAN)
    max_bytes = min(int(settings["max_upload_mb"]), HARD_MAX_UPLOAD_MB) * 1024 * 1024

    if not files:
        raise ScanError("No files were provided.")
    if len(files) > max_files:
        raise ScanError(f"Too many files ({len(files)}). The limit is {max_files} per scan.")

    skipped: list[dict[str, str]] = []
    accepted: list[tuple[str, bytes]] = []
    for name, data in files:
        clean_name = Path(name.replace("\\", "/")).name.strip()
        if not clean_name or any(ord(ch) < 32 for ch in clean_name) or len(clean_name) > 255:
            skipped.append({"name": name[:120], "reason": "Invalid filename."})
            continue
        if len(data) > max_bytes:
            skipped.append({
                "name": clean_name,
                "reason": f"File exceeds the {settings['max_upload_mb']} MB size limit.",
            })
            continue
        if b"\x00" in data[:8192]:
            skipped.append({"name": clean_name, "reason": "Binary files are not scanned."})
            continue
        if not _is_allowed_filename(clean_name):
            skipped.append({
                "name": clean_name,
                "reason": "Unsupported file type. SecretLeak scans text-based source, "
                          "config and log files only.",
            })
            continue
        accepted.append((clean_name, data))

    started = time.perf_counter()
    pairs: list[tuple[FindingDraft, str | None]] = []
    for name, data in accepted:
        text = data.decode("utf-8", errors="replace")
        drafts = scan_text(
            text,
            label=name,
            entropy_enabled=bool(settings["entropy_enabled"]),
            entropy_threshold=float(settings["entropy_threshold"]),
        )
        pairs.extend((draft, name) for draft in drafts)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return _persist_scan("upload", label or "uploaded files", pairs, len(accepted), skipped, duration_ms)


# --- repository ---------------------------------------------------------------


def create_repository_scan(
    raw_path: str,
    include_history: bool = False,
    label: str | None = None,
) -> dict[str, Any]:
    settings = _settings()
    try:
        root = path_safety.validate_repository_path(raw_path)
    except path_safety.PathSafetyError as exc:
        raise ScanError(str(exc)) from exc

    max_files = int(settings["max_repo_files"])
    max_commits = int(settings["max_history_commits"]) if include_history else 0

    started = time.perf_counter()
    pairs: list[tuple[FindingDraft, str | None]] = []
    skipped: list[dict[str, str]] = []
    file_count = 0

    # 1) working tree (never .git internals, never symlinks escaping the root)
    for file_path in git_scanner.iter_worktree_files(root, max_files):
        text = git_scanner.read_text_file(file_path)
        rel = file_path.relative_to(root).as_posix()  # stable forward slashes on all OSes
        if text is None:
            skipped.append({"name": rel, "reason": "Binary, unreadable or over the size limit."})
            continue
        file_count += 1
        drafts = scan_text(
            text,
            label=rel,
            entropy_enabled=bool(settings["entropy_enabled"]),
            entropy_threshold=float(settings["entropy_threshold"]),
        )
        pairs.extend((draft, rel) for draft in drafts)

    # 2) optional git history: content introduced by each commit
    if include_history:
        if not git_scanner.is_git_repository(root):
            skipped.append({
                "name": ".git",
                "reason": "History scan requested but this directory is not a Git repository.",
            })
        else:
            try:
                commits = git_scanner.history_commits(root, max_commits)
            except git_scanner.GitScanError as exc:
                skipped.append({"name": "git history", "reason": str(exc)[:200]})
                commits = []
            for patch in git_scanner.iter_history_patches(root, commits):
                pseudo = "\n".join(text for _ln, text in patch.lines)
                if not pseudo.strip():
                    continue
                drafts = scan_text(
                    pseudo,
                    label=f"{patch.path} @{patch.commit[:8]}",
                    entropy_enabled=bool(settings["entropy_enabled"]),
                    entropy_threshold=float(settings["entropy_threshold"]),
                )
                # Pseudo-line numbers match real new-file line numbers only when
                # hunks are contiguous; remap to the recorded line numbers.
                line_map = {idx + 1: ln for idx, (ln, _t) in enumerate(patch.lines)}
                for draft in drafts:
                    draft.line = line_map.get(draft.line, draft.line)
                    pairs.append((draft, f"{patch.path} @{patch.commit[:8]}"))

    duration_ms = int((time.perf_counter() - started) * 1000)
    scan_label = label or f"repository: {root.name}"
    return _persist_scan(
        "repository", scan_label, pairs, file_count, skipped, duration_ms,
        root_path=str(root), include_history=include_history,
    )


# --- listing ------------------------------------------------------------------


def get_scan_or_raise(scan_id: str) -> dict[str, Any]:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise ScanError("Scan not found.")
    return scan
