"""Path traversal and symlink restriction tests."""

from __future__ import annotations

import pytest

from app.services import git_scanner
from app.services.path_safety import PathSafetyError, is_within, validate_repository_path


def test_missing_path_rejected(tmp_path):
    with pytest.raises(PathSafetyError):
        validate_repository_path(str(tmp_path / "nope"))


def test_file_not_directory_rejected(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(PathSafetyError):
        validate_repository_path(str(f))


def test_empty_path_rejected():
    with pytest.raises(PathSafetyError):
        validate_repository_path("   ")


def test_nul_byte_rejected():
    with pytest.raises(PathSafetyError):
        validate_repository_path("/tmp/\x00evil")


def test_traversal_dotdot_resolves_inside(tmp_path):
    """.. components are resolved to a real location, not traversed blindly."""
    target = tmp_path / "real"
    target.mkdir()
    resolved = validate_repository_path(str(target / ".." / "real"))
    assert resolved == target.resolve()


def test_dotdot_outside_root_not_scanned(git_repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("data", encoding="utf-8")
    files = list(git_scanner.iter_worktree_files(git_repo, 100))
    assert outside not in files


def test_symlink_escaping_root_ignored(git_repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.txt"
    target.write_text("data", encoding="utf-8")
    link = git_repo / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this system/permissions")
    files = [p for p in git_scanner.iter_worktree_files(git_repo, 100)]
    assert link.resolve() == target.resolve()
    # the symlinked file must not be yielded (it escapes the root)
    assert link not in files


def test_is_within_basic(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "a" / "b"
    b.mkdir(parents=True)
    c = tmp_path / "c"
    c.mkdir()
    assert is_within(b, a)
    assert not is_within(c, a)


def test_filesystem_root_refused():
    with pytest.raises(PathSafetyError):
        validate_repository_path("/")
