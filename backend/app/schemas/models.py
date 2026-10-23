"""Pydantic request/response models.

Input is validated strictly; error responses never echo submitted content
back (values are stripped by the API exception handler).
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

DismissReason = Literal["test_fixture", "placeholder", "false_positive", "approved_exception"]


class TextScanRequest(BaseModel):
    label: str = Field(default="pasted text", min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=5_000_000)

    @field_validator("label")
    @classmethod
    def strip_label(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("label must not be blank")
        return cleaned


class RepositoryScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    include_history: bool = False
    label: Optional[str] = Field(default=None, max_length=120)

    @field_validator("path")
    @classmethod
    def strip_path(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("path must not be blank")
        return cleaned


class DismissRequest(BaseModel):
    reason: DismissReason
    note: str = Field(default="", max_length=300)


class SettingsUpdate(BaseModel):
    max_upload_mb: Optional[int] = Field(default=None, ge=1, le=50)
    max_files_per_scan: Optional[int] = Field(default=None, ge=1, le=500)
    max_paste_chars: Optional[int] = Field(default=None, ge=1_000, le=5_000_000)
    entropy_enabled: Optional[bool] = None
    entropy_threshold: Optional[float] = Field(default=None, ge=2.5, le=7.5)
    git_history_enabled: Optional[bool] = None
    max_repo_files: Optional[int] = Field(default=None, ge=100, le=20_000)
    max_history_commits: Optional[int] = Field(default=None, ge=1, le=5_000)
    hook_min_severity: Optional[Literal["low", "medium", "high", "critical"]] = None

    model_config = {"extra": "forbid"}
