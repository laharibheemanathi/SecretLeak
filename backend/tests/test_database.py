"""SQLite persistence tests: round trips, cascade deletion, settings."""

from __future__ import annotations

from app.database import db


def _make_scan_with_finding():
    scan = {
        "id": db.new_id(), "created_at": db.utcnow(), "mode": "text",
        "label": "db-test", "file_count": 1, "finding_count": 1,
        "skipped_count": 0, "root_path": None, "include_history": False,
        "duration_ms": 5, "skipped_files": [],
    }
    db.insert_scan(scan)
    finding = {
        "id": db.new_id(), "rule_id": "github-pat", "rule_name": "GitHub PAT",
        "category": "Provider token", "severity": "high", "confidence": "high",
        "input_label": "db-test", "file_path": None, "line": 1, "column": 1,
        "masked_preview": "ghp_" + "x" * 16,
        "context_snippet": "k = ghp_" + "x" * 16,
        "remediation": "rotate", "description": "d", "why_severity": "w",
        "fingerprint": "abc123", "created_at": db.utcnow(),
    }
    db.insert_finding(scan["id"], finding)
    return scan, finding


def test_scan_and_finding_roundtrip(data_dir):
    scan, finding = _make_scan_with_finding()
    loaded = db.get_scan(scan["id"])
    assert loaded is not None and loaded["label"] == "db-test"
    findings = db.list_findings(scan_id=scan["id"])
    assert len(findings) == 1
    assert findings[0]["masked_preview"].startswith("ghp_")
    assert findings[0]["dismissed"] is False


def test_deleting_scan_cascades(data_dir):
    scan, finding = _make_scan_with_finding()
    db.dismiss_finding(finding["id"], "false_positive")
    assert db.delete_scan(scan["id"]) is True
    assert db.get_scan(scan["id"]) is None
    assert db.get_finding(finding["id"]) is None
    assert db.count_dismissed() == 0


def test_severity_counts_and_dismissal(data_dir):
    _make_scan_with_finding()
    counts = db.severity_counts(active_only=True)
    assert counts["high"] == 1
    finding = db.list_findings()[0]
    db.dismiss_finding(finding["id"], "placeholder")
    assert db.severity_counts(active_only=True)["high"] == 0
    assert db.count_dismissed() == 1
    # not dismissed filter
    assert db.list_findings(include_dismissed=False) == []
    assert db.undismiss_finding(finding["id"]) is True
    assert db.severity_counts(active_only=True)["high"] == 1


def test_dismiss_unknown_finding_fails(data_dir):
    assert db.dismiss_finding("missing", "false_positive") is False


def test_settings_override_and_reset(data_dir):
    assert db.get_setting_rows() == {}
    db.set_setting_rows({"entropy_enabled": False})
    assert db.get_setting_rows() == {"entropy_enabled": False}
    db.clear_settings()
    assert db.get_setting_rows() == {}


def test_clear_all_scans(data_dir):
    _make_scan_with_finding()
    deleted = db.clear_all_scans()
    assert deleted == 1
    assert db.count_scans() == 0
    assert db.count_findings() == 0


def test_no_raw_secret_column_exists(data_dir):
    """The schema must not have any column capable of holding raw secrets."""
    _make_scan_with_finding()
    with db.get_conn() as conn:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
    forbidden = {"raw_value", "secret", "value", "raw_secret", "full_value"}
    assert forbidden.isdisjoint(cols)
