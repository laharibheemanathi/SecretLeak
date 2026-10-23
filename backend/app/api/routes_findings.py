"""Finding endpoints: list, detail, dismiss/restore."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from ..database import db
from ..schemas.models import DismissRequest

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
def list_findings(
    scan_id: Optional[str] = Query(default=None, max_length=64),
    severity: Optional[Literal["critical", "high", "medium", "low"]] = None,
    rule_id: Optional[str] = Query(default=None, max_length=80),
    category: Optional[str] = Query(default=None, max_length=80),
    file: Optional[str] = Query(default=None, max_length=300),
    q: Optional[str] = Query(default=None, max_length=120),
    include_dismissed: bool = True,
    sort: Literal["severity", "location", "rule"] = "severity",
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    findings = db.list_findings(
        scan_id=scan_id, severity=severity, rule_id=rule_id, category=category,
        file_path=file, search=q, include_dismissed=include_dismissed,
        sort=sort, limit=limit, offset=offset,
    )
    return {"findings": findings, "count": len(findings)}


@router.get("/{finding_id}")
def get_finding(finding_id: str) -> dict:
    finding = db.get_finding(finding_id)
    if finding is None:
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": "Finding not found."}},
        )
    return finding


@router.post("/{finding_id}/dismiss", status_code=200)
def dismiss_finding(finding_id: str, request: DismissRequest) -> dict:
    if not db.dismiss_finding(finding_id, request.reason, request.note):
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": "Finding not found."}},
        )
    return db.get_finding(finding_id)


@router.post("/{finding_id}/restore", status_code=200)
def restore_finding(finding_id: str) -> dict:
    if not db.undismiss_finding(finding_id):
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": "Finding is not dismissed."}},
        )
    return db.get_finding(finding_id)
