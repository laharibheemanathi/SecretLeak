"""Scan endpoints: text paste, file upload, local repository, list/get/delete."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, File, Form, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from ..core.config import HARD_MAX_UPLOAD_MB
from ..database import db
from ..schemas.models import RepositoryScanRequest, TextScanRequest
from ..services import scan_service

router = APIRouter(prefix="/scans", tags=["scans"])

_HARD_READ_CAP = (HARD_MAX_UPLOAD_MB + 1) * 1024 * 1024


@router.post("/text", status_code=201)
def create_text_scan(request: TextScanRequest) -> dict:
    return scan_service.create_text_scan(request.label, request.content)


@router.post("/upload", status_code=201)
async def create_upload_scan(
    label: str = Form(default="uploaded files", max_length=120),
    files: list[UploadFile] = File(...),
) -> dict:
    """Read uploaded files (capped in size), never execute them."""
    if len(files) > 500:
        return JSONResponse(
            status_code=400,
            content={"detail": {"code": "too_many_files", "message": "Too many files in one scan (max 500)."}},
        )
    payloads: list[tuple[str, bytes]] = []
    for upload in files:
        data = await upload.read(_HARD_READ_CAP + 1)
        payloads.append((upload.filename or "unnamed", data))
    return await run_in_threadpool(scan_service.create_upload_scan, label, payloads)


@router.post("/repository", status_code=201)
def create_repository_scan(request: RepositoryScanRequest) -> dict:
    return scan_service.create_repository_scan(
        request.path, include_history=request.include_history, label=request.label
    )


@router.get("")
def list_scans(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    return {"scans": db.list_scans(limit=limit, offset=offset)}


@router.delete("", status_code=200)
def clear_scans() -> dict:
    """Clear all scan history (metadata + findings). Settings are kept."""
    deleted = db.clear_all_scans()
    return {"deleted_scans": deleted}


@router.get("/{scan_id}")
def get_scan(scan_id: str) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": "Scan not found."}},
        )
    findings = db.list_findings(scan_id=scan_id, sort="severity")
    return {"scan": scan, "findings": findings}


@router.delete("/{scan_id}", status_code=200)
def delete_scan(scan_id: str) -> dict:
    if not db.delete_scan(scan_id):
        return JSONResponse(
            status_code=404,
            content={"detail": {"code": "not_found", "message": "Scan not found."}},
        )
    return {"deleted": True, "scan_id": scan_id}
