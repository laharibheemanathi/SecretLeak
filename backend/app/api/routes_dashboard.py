"""Dashboard summary endpoint."""

from fastapi import APIRouter

from ..database import db

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def dashboard() -> dict:
    counts = db.severity_counts(active_only=True)
    return {
        "total_scans": db.count_scans(),
        "total_findings": sum(counts.values()),
        "dismissed_findings": db.count_dismissed(),
        "severity_counts": counts,
        "top_rules": db.top_rules(5),
        "recent_scans": db.list_scans(limit=5),
    }
