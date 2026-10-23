"""Every rule must fire on a synthetic positive and stay quiet on placeholders."""

from __future__ import annotations

import pytest

from app.detectors.engine import scan_text
from app.detectors.rules import RULES

from conftest import (
    API_KEY_VALUE, AWS_KEY_ID, BEARER_VALUE, DB_URL, ENV_VALUE, ENTROPY_VALUE,
    GH_FINE_PAT, GH_OAUTH, GH_PAT, GITLAB_PAT, GITLAB_RUNNER, JWT_TOKEN,
    LOG_KEY_VALUE, PASSWORD_VALUE, PEM_BLOCK, PLACEHOLDERS, SLACK_TOKEN,
    SLACK_WEBHOOK, URL_CREDS,
)

POSITIVE_SAMPLES = {
    "github-pat": f'GITHUB_TOKEN = "{GH_PAT}"',
    "github-fine-grained-pat": f'PAT="{GH_FINE_PAT}"',
    "github-oauth-app-token": f'oauth = "{GH_OAUTH}"',
    "gitlab-pat": f'glab_token: {GITLAB_PAT}',
    "gitlab-runner-token": f'runner = "{GITLAB_RUNNER}"',
    "slack-token": f'SLACK={SLACK_TOKEN}',
    "slack-webhook-url": f'webhook = "{SLACK_WEBHOOK}"',
    "aws-access-key-id": f'aws_key = "{AWS_KEY_ID}"',
    "private-key-block": PEM_BLOCK,
    "jwt-token": f'jwt = "{JWT_TOKEN}"',
    "database-connection-string": f'DATABASE_URL="{DB_URL}"',
    "url-credentials": f'remote = "{URL_CREDS}"',
    "api-key-assignment": f'API_KEY = "{API_KEY_VALUE}"',
    "password-assignment": f'password = "{PASSWORD_VALUE}"',
    "env-var-credential": f'DB_PASSWORD={ENV_VALUE}',
    "authorization-bearer": f'headers["Authorization"] = "Bearer {BEARER_VALUE}"',
    "log-credential-leak": f'2024-05-01 10:00:00 INFO api_key={LOG_KEY_VALUE} request_id=42',
}


@pytest.mark.parametrize("rule_id", sorted(POSITIVE_SAMPLES))
def test_rule_fires_on_synthetic_positive(rule_id: str):
    drafts = scan_text(POSITIVE_SAMPLES[rule_id], label="sample")
    matched_ids = {d.rule_id for d in drafts}
    assert rule_id in matched_ids, f"{rule_id} did not fire on its sample"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_documented(rule):
    assert rule.description and rule.why_severity and rule.remediation
    assert rule.severity in {"critical", "high", "medium", "low"}
    assert rule.confidence in {"high", "medium", "low"}


@pytest.mark.parametrize("placeholder", PLACEHOLDERS)
def test_placeholders_never_reported(placeholder: str):
    text = (
        f'API_KEY = "{placeholder}"\n'
        f'password = "{placeholder}"\n'
        f'Authorization: Bearer {placeholder}\n'
        f'SECRET_TOKEN={placeholder}\n'
    )
    drafts = scan_text(text, label="sample")
    assert drafts == [], f"placeholder {placeholder!r} produced findings"


def test_entropy_rule_reports_low_severity():
    drafts = scan_text(f'const x = "{ENTROPY_VALUE}";', label="sample")
    entropy_findings = [d for d in drafts if d.rule_id == "generic-high-entropy"]
    assert entropy_findings, "entropy heuristic did not fire"
    assert all(d.severity == "low" and d.confidence == "low" for d in entropy_findings)


def test_entropy_rule_can_be_disabled():
    text = f'const x = "{ENTROPY_VALUE}";'
    assert scan_text(text, label="s", entropy_enabled=False) == []


def test_prose_does_not_trigger_findings():
    text = (
        "The deployment pipeline uses tokens for authentication and rotates "
        "them regularly. Remember to change passwords often and never share keys.\n"
    )
    assert scan_text(text, label="notes") == []
