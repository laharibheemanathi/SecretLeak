"""Uninstall the SecretLeak pre-commit hook.

Usage:
    python scripts/uninstall_git_hook.py [repo_path] [--force]

Only removes hooks that carry the SecretLeak marker, unless --force is given.
"""

from install_git_hook import main  # noqa: E402

if __name__ == "__main__":
    import sys

    args = ["uninstall", *sys.argv[1:]]
    raise SystemExit(main(args))
