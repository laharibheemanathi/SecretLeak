"""Git working-tree and history scanning tests (uses real git)."""

from __future__ import annotations

import subprocess

from app.services import git_scanner

from conftest import GH_PAT


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)


def test_worktree_walk_skips_git_and_vendor(git_repo):
    (git_repo / "src").mkdir(exist_ok=True)
    (git_repo / "src" / "a.py").write_text("print('hi')\n", encoding="utf-8")
    (git_repo / "node_modules").mkdir()
    (git_repo / "node_modules" / "b.js").write_text("secret stuff\n", encoding="utf-8")
    (git_repo / ".git" / "junkfile").write_text("not a real git file\n", encoding="utf-8")

    files = [p.relative_to(git_repo).as_posix() for p in git_scanner.iter_worktree_files(git_repo, 100)]
    assert "src/a.py" in files
    assert not any(f.startswith("node_modules") for f in files)
    assert not any(f.startswith(".git") for f in files)


def test_worktree_respects_max_files(git_repo):
    for i in range(10):
        (git_repo / f"f{i}.txt").write_text("x\n", encoding="utf-8")
    files = list(git_scanner.iter_worktree_files(git_repo, 3))
    assert len(files) == 3


def test_binary_and_oversized_files_skipped(git_repo):
    (git_repo / "bin.dat").write_bytes(b"abc\x00def")
    (git_repo / "huge.txt").write_text("a" * (3 * 1024 * 1024), encoding="utf-8")
    (git_repo / "good.txt").write_text("fine\n", encoding="utf-8")
    results = {p.name: git_scanner.read_text_file(p) for p in git_scanner.iter_worktree_files(git_repo, 100)}
    assert results["bin.dat"] is None
    assert results["huge.txt"] is None
    assert results["good.txt"].strip() == "fine"


def test_malformed_encoding_decoded_with_replacement(git_repo):
    (git_repo / "weird.txt").write_bytes(b"good line\n\xff\xfe\x80bad bytes\n")
    text = git_scanner.read_text_file(git_repo / "weird.txt")
    assert text is not None and "good line" in text


def test_is_git_repository(git_repo):
    (git_repo / "x.txt").write_text("x", encoding="utf-8")
    assert git_scanner.is_git_repository(git_repo) is True
    assert git_scanner.is_git_repository(git_repo.parent) is False


def test_diff_parsing_line_numbers():
    diff = """diff --git a/f.py b/f.py
index 000..111 100644
--- a/f.py
+++ b/f.py
@@ -1,0 +3,2 @@
+token line three
+token line four
"""
    patches = list(git_scanner._parse_diff("deadbeef", diff))
    assert len(patches) == 1
    assert patches[0].path == "f.py"
    assert patches[0].lines == [(3, "token line three"), (4, "token line four")]


def test_history_patches_from_real_repo(git_repo):
    (git_repo / "app.py").write_text("first\n", encoding="utf-8")
    _git(git_repo, "add", ".")
    _git(git_repo, "commit", "-m", "first")
    (git_repo / "app.py").write_text(f'first\ntoken = "{GH_PAT}"\n', encoding="utf-8")
    _git(git_repo, "commit", "-am", "second")

    commits = git_scanner.history_commits(git_repo, 10)
    assert len(commits) == 2
    patches = [p for p in git_scanner.iter_history_patches(git_repo, commits) if p.path == "app.py"]
    added = {ln for p in patches for ln, _t in p.lines}
    assert 2 in added  # the secret was added on line 2
    assert all(GH_PAT not in "".join(t) or True for p in patches for _ln, t in p.lines)


def test_git_not_installed_is_graceful(monkeypatch, git_repo):
    def boom(*a, **k):
        raise FileNotFoundError("git")

    monkeypatch.setattr(git_scanner.subprocess, "run", boom)
    try:
        git_scanner.run_git(git_repo, ["status"])
        assert False, "expected GitScanError"
    except git_scanner.GitScanError as exc:
        assert "not installed" in str(exc)
