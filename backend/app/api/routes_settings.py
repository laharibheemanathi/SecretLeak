"""Settings endpoints plus data-location transparency."""

from __future__ import annotations

from fastapi import APIRouter

from ..core.config import get_data_dir, get_db_path, get_hmac_key_path
from ..schemas.models import SettingsUpdate
from ..services import settings_service

router = APIRouter(prefix="/settings", tags=["settings"])


def _locations() -> dict:
    data_dir = get_data_dir()
    return {
        "data_dir": str(data_dir),
        "database_file": str(get_db_path()),
        "hmac_key_file": str(get_hmac_key_path()),
        "note": (
            "All data stays on this machine. The database stores scan metadata and "
            "masked findings only — never raw credentials. The HMAC key is used to "
            "fingerprint secrets for deduplication and is excluded from version control."
        ),
    }


@router.get("")
def get_settings() -> dict:
    return {"settings": settings_service.get_settings(), "locations": _locations()}


@router.put("")
def update_settings(request: SettingsUpdate) -> dict:
    updates = request.model_dump(exclude_none=True)
    settings = settings_service.update_settings(updates) if updates else settings_service.get_settings()
    return {"settings": settings, "locations": _locations()}


@router.post("/reset", status_code=200)
def reset_settings() -> dict:
    settings = settings_service.reset_settings()
    return {"settings": settings, "locations": _locations()}
