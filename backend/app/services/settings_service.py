"""Application settings: defaults plus user overrides stored in SQLite."""

from __future__ import annotations

from typing import Any

from ..database import db

DEFAULTS: dict[str, Any] = {
    # Upload limits
    "max_upload_mb": 5,           # per file, 1..50
    "max_files_per_scan": 50,     # 1..500
    # Paste limits
    "max_paste_chars": 1_000_000, # 1k..5M
    # Detection toggles
    "entropy_enabled": True,
    "entropy_threshold": 4.5,     # 2.5..7.5 bits/char
    # Repository scanning
    "git_history_enabled": False, # opt-in per scan anyway
    "max_repo_files": 5000,       # 100..20000
    "max_history_commits": 200,   # 1..5000
    # Pre-commit hook default threshold
    "hook_min_severity": "high",  # low|medium|high|critical
}

_RANGES: dict[str, tuple[float, float]] = {
    "max_upload_mb": (1, 50),
    "max_files_per_scan": (1, 500),
    "max_paste_chars": (1_000, 5_000_000),
    "entropy_threshold": (2.5, 7.5),
    "max_repo_files": (100, 20_000),
    "max_history_commits": (1, 5_000),
}

VALID_SEVERITIES = ("low", "medium", "high", "critical")


class SettingsError(ValueError):
    pass


def get_settings() -> dict[str, Any]:
    """Merged settings: defaults overridden by persisted user values."""
    merged = dict(DEFAULTS)
    overrides = db.get_setting_rows()
    for key, value in overrides.items():
        if key in DEFAULTS:
            merged[key] = value
    return merged


def _validate(key: str, value: Any) -> Any:
    default = DEFAULTS[key]
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise SettingsError(f"{key} must be a boolean")
        return value
    if isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise SettingsError(f"{key} must be an integer")
        lo, hi = _RANGES[key]
        if not (lo <= value <= hi):
            raise SettingsError(f"{key} must be between {lo} and {hi}")
        return value
    if isinstance(default, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SettingsError(f"{key} must be a number")
        lo, hi = _RANGES[key]
        value = float(value)
        if not (lo <= value <= hi):
            raise SettingsError(f"{key} must be between {lo} and {hi}")
        return value
    if key == "hook_min_severity":
        if value not in VALID_SEVERITIES:
            raise SettingsError(f"hook_min_severity must be one of {VALID_SEVERITIES}")
        return value
    raise SettingsError(f"Unknown setting: {key}")


def update_settings(updates: dict[str, Any]) -> dict[str, Any]:
    """Validate and persist the given settings subset."""
    unknown = set(updates) - set(DEFAULTS)
    if unknown:
        raise SettingsError(f"Unknown settings: {', '.join(sorted(unknown))}")
    clean = {key: _validate(key, value) for key, value in updates.items()}
    db.set_setting_rows(clean)
    return get_settings()


def reset_settings() -> dict[str, Any]:
    """Restore all defaults."""
    db.clear_settings()
    return get_settings()
