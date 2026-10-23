"""Report generation: JSON and CSV, masked values only.

Both formats contain metadata (rule ids, severities, locations, remediation)
and masked previews. Raw credentials and private-key material are never
included because they were never stored. CSV cells that begin with a formula
trigger character (=, +, -, @, tab, CR) are prefixed with an apostrophe so
spreadsheet apps cannot execute them.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .. import __version__
from ..database import db
from .scan_service import ScanError

REPORT_FIELDS = [
    "scan_id", "scan_created_at", "scan_mode", "finding_id", "rule_id", "rule_name",
    "category", "severity", "confidence", "file", "line", "column",
    "masked_preview", "remediation", "dismissed", "dismissal_reason",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value: Any) -> str:
    """Prevent CSV formula injection in spreadsheet applications."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def build_report(scan_id: str) -> dict[str, Any]:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise ScanError("Scan not found.")
    findings = db.list_findings(scan_id=scan_id, sort="severity", limit=10_000)
    return {
        "tool": "SecretLeak",
        "version": __version__,
        "generated_at": db.utcnow(),
        "notice": (
            "All secret values are masked. A pattern match does not prove that a "
            "credential is valid or active."
        ),
        "scan": scan,
        "findings": [
            {
                "finding_id": f["id"],
                "rule_id": f["rule_id"],
                "rule_name": f["rule_name"],
                "category": f["category"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "file": f["input_label"],
                "line": f["line"],
                "column": f["column"],
                "masked_preview": f["masked_preview"],
                "remediation": f["remediation"],
                "dismissed": f["dismissed"],
                "dismissal_reason": f.get("dismissal_reason") or "",
            }
            for f in findings
        ],
    }


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def report_to_csv(report: dict[str, Any]) -> str:
    scan = report["scan"]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(REPORT_FIELDS)
    for finding in report["findings"]:
        row = [
            scan["id"], scan["created_at"], scan["mode"],
            finding["finding_id"], finding["rule_id"], finding["rule_name"],
            finding["category"], finding["severity"], finding["confidence"],
            finding["file"], finding["line"], finding["column"],
            finding["masked_preview"], finding["remediation"],
            "yes" if finding["dismissed"] else "no", finding["dismissal_reason"],
        ]
        writer.writerow([_sanitize_cell(cell) for cell in row])
    return buffer.getvalue()
