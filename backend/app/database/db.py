"""SQLite persistence layer.

Design notes:

* Parameterized queries only — no string-built SQL.
* No raw secret values, no full source snippets. Findings store masked
  previews, capped redacted context, rule metadata and an HMAC fingerprint.
* Versioned schema via PRAGMA user_version with small migration steps.
* SQLite runs with WAL mode; connections are short-lived and thread-safe
  through a lock, which keeps things simple for a local single-user app.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..core.config import get_db_path
from ..core.logging_config import get_logger

logger = get_logger(__name__)

_LOCK = threading.Lock()
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('text', 'upload', 'repository')),
    label TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    dismissed_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    root_path TEXT,
    include_history INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    skipped_files TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    confidence TEXT NOT NULL,
    input_label TEXT NOT NULL,
    file_path TEXT,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    masked_preview TEXT NOT NULL,
    context_snippet TEXT NOT NULL,
    remediation TEXT NOT NULL,
    description TEXT NOT NULL,
    why_severity TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dismissals (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    dismissed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
"""

_MIGRATIONS: dict[int, str] = {
    1: _SCHEMA,
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db(path: Path | None = None) -> None:
    """Create or migrate the schema. Safe to call repeatedly."""
    db_path = path or get_db_path()
    with _LOCK:
        conn = _connect(db_path)
        try:
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            for version in range(current + 1, SCHEMA_VERSION + 1):
                script = _MIGRATIONS.get(version)
                if script:
                    conn.executescript(script)
                    conn.execute(f"PRAGMA user_version={version}")
            conn.commit()
        finally:
            conn.close()


@contextmanager
def get_conn(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    db_path = path or get_db_path()
    with _LOCK:
        conn = _connect(db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# --- scans -------------------------------------------------------------------


def insert_scan(scan: dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans
               (id, created_at, mode, label, file_count, finding_count,
                dismissed_count, skipped_count, root_path, include_history,
                duration_ms, skipped_files)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)""",
            (
                scan["id"], scan["created_at"], scan["mode"], scan["label"],
                scan["file_count"], scan["finding_count"], scan["skipped_count"],
                scan.get("root_path"), 1 if scan.get("include_history") else 0,
                scan.get("duration_ms", 0),
                json.dumps(scan.get("skipped_files", [])),
            ),
        )


def insert_finding(scan_id: str, finding: dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO findings
               (id, scan_id, rule_id, rule_name, category, severity, confidence,
                input_label, file_path, line, column, masked_preview,
                context_snippet, remediation, description, why_severity,
                fingerprint, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding["id"], scan_id, finding["rule_id"], finding["rule_name"],
                finding["category"], finding["severity"], finding["confidence"],
                finding["input_label"], finding.get("file_path"), finding["line"],
                finding["column"], finding["masked_preview"],
                finding["context_snippet"], finding["remediation"],
                finding["description"], finding["why_severity"],
                finding["fingerprint"], finding["created_at"],
            ),
        )


def _scan_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["include_history"] = bool(data.get("include_history"))
    try:
        data["skipped_files"] = json.loads(data.get("skipped_files") or "[]")
    except json.JSONDecodeError:
        data["skipped_files"] = []
    return data


def list_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [_scan_from_row(r) for r in rows]


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _scan_from_row(row) if row else None


def count_scans() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and all associated findings/dismissals (FK cascade)."""
    with get_conn() as conn:
        existing = conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return True


def clear_all_scans() -> int:
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM dismissals")
        conn.execute("DELETE FROM scans")
    return count


# --- findings ----------------------------------------------------------------


def _finding_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["dismissed"] = data.pop("dismissal_reason", None) is not None
    return data


_FINDING_SELECT = """
SELECT f.*, d.reason AS dismissal_reason, d.note AS dismissal_note
FROM findings f
LEFT JOIN dismissals d ON d.finding_id = f.id
"""


def list_findings(
    *,
    scan_id: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    category: str | None = None,
    file_path: str | None = None,
    search: str | None = None,
    include_dismissed: bool = True,
    sort: str = "severity",
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if scan_id:
        clauses.append("f.scan_id = ?")
        params.append(scan_id)
    if severity:
        clauses.append("f.severity = ?")
        params.append(severity)
    if rule_id:
        clauses.append("f.rule_id = ?")
        params.append(rule_id)
    if category:
        clauses.append("f.category = ?")
        params.append(category)
    if file_path:
        clauses.append("f.input_label LIKE ?")
        params.append(f"%{file_path}%")
    if search:
        clauses.append(
            "(f.input_label LIKE ? OR f.rule_name LIKE ? OR f.rule_id LIKE ? OR f.masked_preview LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if not include_dismissed:
        clauses.append("d.finding_id IS NULL")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = {
        "severity": "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.input_label, f.line",
        "location": "ORDER BY f.input_label, f.line, f.column",
        "rule": "ORDER BY f.rule_id, f.input_label, f.line",
    }.get(sort, "ORDER BY f.severity")

    with get_conn() as conn:
        rows = conn.execute(
            f"{_FINDING_SELECT} {where} {order} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return [_finding_from_row(r) for r in rows]


def count_findings(scan_id: str | None = None) -> int:
    with get_conn() as conn:
        if scan_id:
            row = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
    return row[0]


def get_finding(finding_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            f"{_FINDING_SELECT} WHERE f.id = ?", (finding_id,)
        ).fetchone()
    return _finding_from_row(row) if row else None


def severity_counts(active_only: bool = True) -> dict[str, int]:
    with get_conn() as conn:
        if active_only:
            rows = conn.execute(
                """SELECT f.severity, COUNT(*) AS n
                   FROM findings f LEFT JOIN dismissals d ON d.finding_id = f.id
                   WHERE d.finding_id IS NULL GROUP BY f.severity"""
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            ).fetchall()
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    counts.update({r["severity"]: r["n"] for r in rows})
    return counts


def top_rules(limit: int = 5) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT f.rule_id, f.rule_name, COUNT(*) AS n
               FROM findings f LEFT JOIN dismissals d ON d.finding_id = f.id
               WHERE d.finding_id IS NULL
               GROUP BY f.rule_id, f.rule_name ORDER BY n DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# --- dismissals --------------------------------------------------------------


def dismiss_finding(finding_id: str, reason: str, note: str = "") -> bool:
    with get_conn() as conn:
        exists = conn.execute("SELECT 1 FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not exists:
            return False
        conn.execute(
            """INSERT INTO dismissals (finding_id, reason, note, dismissed_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(finding_id) DO UPDATE SET reason=excluded.reason,
               note=excluded.note, dismissed_at=excluded.dismissed_at""",
            (finding_id, reason, note, utcnow()),
        )
    return True


def undismiss_finding(finding_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM dismissals WHERE finding_id = ?", (finding_id,))
    return cur.rowcount > 0


def count_dismissed() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0]


# --- settings ----------------------------------------------------------------


def get_setting_rows() -> dict[str, Any]:
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    out: dict[str, Any] = {}
    for row in rows:
        try:
            out[row["key"]] = json.loads(row["value"])
        except json.JSONDecodeError:
            continue
    return out


def set_setting_rows(values: dict[str, Any]) -> None:
    with get_conn() as conn:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )


def clear_settings() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM settings")
