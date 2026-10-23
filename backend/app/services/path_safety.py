"""Path safety helpers.

Repository scanning only ever operates on a directory the user explicitly
selected. These helpers validate and normalize that path, refuse drive roots,
and ensure anything discovered inside (including symlinks) stays inside the
selected root.
"""

from __future__ import annotations

from pathlib import Path


class PathSafetyError(ValueError):
    """Raised when a requested path is missing, unsafe or outside the root."""


def validate_repository_path(raw: str) -> Path:
    """Validate a user-supplied repository path and return its resolved form."""
    if not raw or not raw.strip():
        raise PathSafetyError("A repository path is required.")
    if "\x00" in raw:
        raise PathSafetyError("Invalid characters in path.")
    expanded = Path(raw.strip()).expanduser()
    try:
        resolved = expanded.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathSafetyError(f"Path does not exist or cannot be accessed: {raw}") from exc
    if not resolved.is_dir():
        raise PathSafetyError(f"Path is not a directory: {raw}")
    if resolved.parent == resolved or len(resolved.parts) == 1:
        raise PathSafetyError("Refusing to scan a filesystem root.")
    return resolved


def is_within(child: Path, root: Path) -> bool:
    """True when *child* is inside *root* after resolving symlinks."""
    try:
        child_resolved = child.resolve()
        root_resolved = root.resolve()
    except (OSError, RuntimeError):
        return False
    return child_resolved == root_resolved or root_resolved in child_resolved.parents
