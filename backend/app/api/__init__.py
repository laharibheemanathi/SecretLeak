"""API package: routers for scans, findings, reports and settings."""

from fastapi import APIRouter

from . import (
    routes_dashboard,
    routes_findings,
    routes_health,
    routes_reports,
    routes_scans,
    routes_settings,
)

api_router = APIRouter()
api_router.include_router(routes_health.router)
api_router.include_router(routes_dashboard.router)
api_router.include_router(routes_scans.router)
api_router.include_router(routes_findings.router)
api_router.include_router(routes_reports.router)
api_router.include_router(routes_settings.router)
