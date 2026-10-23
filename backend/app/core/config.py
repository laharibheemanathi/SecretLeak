"""Runtime configuration for SecretLeak.

All values are read from environment variables at call time so that tests can
override them, with safe local defaults. Nothing here contacts the network.
"""

from __future__ import annotations

import os
from pathlib import Path

# backend/ directory (this file lives in backend/app/core/)
BACKEND_DIR = Path(__file__).resolve().parents[2]

DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
DEFAULT_MAX_REQUEST_MB = 25

APP_NAME = "SecretLeak"


def get_data_dir() -> Path:
    """Directory where local application data (SQLite DB, HMAC key) lives."""
    raw = os.environ.get("SECRELEAK_DATA_DIR", "").strip()
    path = Path(raw).expanduser() if raw else BACKEND_DIR / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_db_path() -> Path:
    return get_data_dir() / "secretleak.db"


def get_hmac_key_path() -> Path:
    """Location of the HMAC key file. Never inside the database or git."""
    raw = os.environ.get("SECRELEAK_HMAC_KEY_FILE", "").strip()
    if raw:
        return Path(raw).expanduser()
    return get_data_dir() / ".hmac_key"


def get_cors_origins() -> list[str]:
    """Explicit local origins only — never a wildcard."""
    raw = os.environ.get("SECRELEAK_CORS_ORIGINS", "").strip() or DEFAULT_CORS_ORIGINS
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def get_max_request_mb() -> int:
    raw = os.environ.get("SECRELEAK_MAX_REQUEST_MB", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_REQUEST_MB
    except ValueError:
        value = DEFAULT_MAX_REQUEST_MB
    return max(1, min(value, 512))


# File types accepted for upload scanning (text-based files only).
UPLOAD_EXTENSIONS: tuple[str, ...] = (
    ".txt", ".log", ".md", ".rst",
    ".py", ".rb", ".php", ".pl", ".sh", ".bash", ".zsh", ".bat", ".ps1",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".java", ".kt", ".cs", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties",
    ".xml", ".csv", ".tsv", ".sql", ".tf", ".tfvars", ".hcl", ".plist",
    ".env", ".example", ".sample", ".template", ".dist",
    ".gitignore", ".gitattributes",
)

# Directory names never scanned in a working tree (plus .git handled separately).
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn",
        "node_modules", "bower_components", "vendor",
        ".venv", "venv", "env",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
        "dist", "build", "out", "target", "coverage",
        ".idea", ".vscode", ".next", ".nuxt", ".cache",
        ".terraform", ".gradle",
    }
)

# Upload safety limits (settings can lower, not raise, these hard caps).
HARD_MAX_FILES_PER_SCAN = 500
HARD_MAX_UPLOAD_MB = 50
