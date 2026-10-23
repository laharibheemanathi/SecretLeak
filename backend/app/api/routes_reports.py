"""Report endpoints: downloadable JSON and CSV (masked values only)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Response

from ..services import report_service
from ..services.scan_service import ScanError

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}")
def get_report(scan_id: str, format: Literal["json", "csv"] = "json") -> Response:
    report = report_service.build_report(scan_id)
    filename = f"secretleak-report-{scan_id[:8]}.{format}"
    if format == "csv":
        body = report_service.report_to_csv(report)
        media = "text/csv; charset=utf-8"
    else:
        body = report_service.report_to_json(report)
        media = "application/json; charset=utf-8"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
