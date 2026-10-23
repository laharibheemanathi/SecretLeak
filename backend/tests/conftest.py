"""Pytest fixtures.

All synthetic secrets in this suite are format-valid but cannot authenticate
anywhere. The data directory is redirected to a temp path so tests never touch
real application data.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# --- synthetic secrets (fake values; cannot authenticate anywhere) -----------

GH_PAT = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX2yZ4xK9"   # 36 chars after prefix
GH_FINE_PAT = (
    "github_pat_" + "aBcDeFgHiJkLmNoPqRsT12" + "_"
    + "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX2yZ4aB3dE5fG7hJ9kL1mN3pQrS9xYz"
)
GH_OAUTH = "gho_" + "Z9yX8wV7uT6sR5qP4oN3mL2kJ1hG0fEdCbAB"     # 36
GITLAB_PAT = "glpat-" + "aBcDeFgHiJkLmNoPqRsT"
GITLAB_RUNNER = "glrt-" + "aBcDeFgHiJkLmNoPqRsTuVw"
SLACK_TOKEN = "xoxb-" + "1234567890-1234567890-abcdefghijklmnop"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T12345678/B87654321/aBcDeFg1HiJkLmNoPqRsT"
AWS_KEY_ID = "AKIA" + "BCDFGHJKLMNPQRS2"
JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
JWT_PAYLOAD = "eyJzdWIiOiI0MjQyNDIiLCJuYW1lIjoiU2VjcmV0TGVhayJ9"
JWT_SIG = "c2lnbmF0dXJlLWJ5dGVzLWZvci10ZXN0"
JWT_TOKEN = f"{JWT_HEADER}.{JWT_PAYLOAD}.{JWT_SIG}"
DB_URL = "postgres://dbuser:S3cr3tP4ss99@db.internal:5432/appdb"
URL_CREDS = "ftp://backup:Zx9mQ2wE7tR@files.internal/share"
API_KEY_VALUE = "sk_a9Xk2Pm7Qr4Tv6Wx8Za3Bc5De7Fg9Hi0J"
PASSWORD_VALUE = "Tr0ub4dor&3x"
ENV_VALUE = "Vq7Zn2Mc5Xr8Tb4Wd9Ye1Uf6As3Dg0Hj"
BEARER_VALUE = "AbCdEf0123456789ghIjKlMnOpQrStUvWxYz"
LOG_KEY_VALUE = "Lk8Qm2Np5Rt7Vw9Xy3Za6Bc4De8Fg1Hi0J"
ENTROPY_VALUE = "kR8mQp2Nt5Vw7Xa9Zc3Bd6Ef1Gh4Jk8Lm0Pn"

PEM_BLOCK = "\n".join(
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA0ZcV9rQm5xL3nT8pW2yJ6kD1sA4fH7gB9mC0vE2xQ5rN8tU",
        "3iY6oP1lK4jS7dF0aG2hJ5kL8mN1bV3xC6zQ9wE2rT5yU8iO1pA4sD7fG0hJ3",
        "-----END RSA PRIVATE KEY-----",
    ]
)

PLACEHOLDERS = [
    "YOUR_API_KEY", "EXAMPLE_TOKEN", "CHANGEME", "REDACTED", "dummy",
    "${API_TOKEN}", "$API_TOKEN", "%API_TOKEN%", "{{api_key}}",
    "<your-key-here>", "00000000", "aaaaaaaaaaaaaa", "password",
    "process.env.SECRET_KEY", "os.environ.get('X')",
]

ALL_SYNTHETIC_SECRETS = [
    GH_PAT, GH_FINE_PAT, GH_OAUTH, GITLAB_PAT, GITLAB_RUNNER, SLACK_TOKEN,
    SLACK_WEBHOOK, AWS_KEY_ID, JWT_TOKEN, DB_URL, URL_CREDS, API_KEY_VALUE,
    PASSWORD_VALUE, ENV_VALUE, BEARER_VALUE, LOG_KEY_VALUE, ENTROPY_VALUE,
    PEM_BLOCK.splitlines()[1],  # key body line
]


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    """Redirect all application data to a temp directory per test."""
    target = tmp_path / "secretleak-data"
    monkeypatch.setenv("SECRELEAK_DATA_DIR", str(target))
    from app.core.security import clear_key_cache

    clear_key_cache()
    from app.database import db

    db.init_db()
    yield target
    clear_key_cache()


@pytest.fixture()
def client(data_dir):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def git_repo(tmp_path):
    """A real temporary git repository (no commits unless a test adds them)."""
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=str(repo), check=True)
    return repo


def git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)
