"""End-to-end tests for the pre-commit hook: install, block, uninstall.

Uses a real temporary git repository and the real installer scripts.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import GH_PAT

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = PROJECT_ROOT / "scripts" / "install_git_hook.py"

pytestmark = pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
    reason="git not available",
)


def _run(args, cwd, env=None):
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        args, cwd=str(cwd), capture_output=True, text=True, env=merged, timeout=120
    )


def _installer(repo, command, *extra, env=None):
    return _run(
        [sys.executable, str(INSTALLER), command, str(repo), *extra],
        cwd=PROJECT_ROOT, env=env,
    )


def _hook_path(repo) -> Path:
    return repo / ".git" / "hooks" / "pre-commit"


def _setup_repo_with_staged_secret(git_repo, data_dir_env):
    (git_repo / "app.py").write_text(f'TOKEN = "{GH_PAT}"\n', encoding="utf-8")
    _run(["git", "add", "app.py"], git_repo)
    return {"SECRELEAK_DATA_DIR": str(data_dir_env)}


def test_install_then_uninstall_roundtrip(git_repo, tmp_path):
    result = _installer(git_repo, "install")
    assert result.returncode == 0, result.stderr
    hook = _hook_path(git_repo)
    assert hook.exists()
    assert "SecretLeak managed pre-commit hook" in hook.read_text(encoding="utf-8")

    result = _installer(git_repo, "uninstall")
    assert result.returncode == 0
    assert not hook.exists()


def test_hook_blocks_commit_with_staged_secret(git_repo, tmp_path):
    env = _setup_repo_with_staged_secret(git_repo, tmp_path / "data")
    assert _installer(git_repo, "install").returncode == 0

    result = _run(["git", "commit", "-m", "test commit"], git_repo, env=env)
    output = result.stdout + result.stderr
    assert result.returncode != 0, "commit with staged secret should be blocked"
    assert GH_PAT not in output
    assert "ghp_" in output  # masked preview is shown

    # the commit really did not happen
    log = _run(["git", "log", "--oneline"], git_repo)
    assert "test commit" not in log.stdout


def test_hook_allows_clean_commit(git_repo, tmp_path):
    env = {"SECRELEAK_DATA_DIR": str(tmp_path / "data")}
    (git_repo / "readme.txt").write_text("hello world\n", encoding="utf-8")
    _run(["git", "add", "readme.txt"], git_repo)
    assert _installer(git_repo, "install").returncode == 0

    result = _run(["git", "commit", "-m", "clean commit"], git_repo, env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_hook_scans_staged_content_only(git_repo, tmp_path):
    env = {"SECRELEAK_DATA_DIR": str(tmp_path / "data")}
    (git_repo / "clean.py").write_text("value = 1\n", encoding="utf-8")
    _run(["git", "add", "clean.py"], git_repo)
    # untracked file with a secret — must NOT block the commit
    (git_repo / "untracked_secret.py").write_text(f'k = "{GH_PAT}"\n', encoding="utf-8")
    assert _installer(git_repo, "install").returncode == 0

    result = _run(["git", "commit", "-m", "only staged"], git_repo, env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_installer_refuses_foreign_hook_without_force(git_repo):
    hook = _hook_path(git_repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho custom hook\n", encoding="utf-8")

    result = _installer(git_repo, "install")
    assert result.returncode == 1
    assert "custom hook" in hook.read_text(encoding="utf-8")

    result = _installer(git_repo, "install", "--force")
    assert result.returncode == 0
    assert "SecretLeak" in hook.read_text(encoding="utf-8")
    assert hook.with_suffix(".pre-secretleak-backup").exists()


def test_uninstaller_leaves_foreign_hook(git_repo):
    hook = _hook_path(git_repo)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho keep me\n", encoding="utf-8")
    result = _installer(git_repo, "uninstall")
    assert result.returncode == 1
    assert hook.exists()


def test_installer_rejects_non_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    result = _installer(plain, "install")
    assert result.returncode == 1
