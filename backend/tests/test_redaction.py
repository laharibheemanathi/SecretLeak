"""Redaction, masking and placeholder filtering tests."""

from __future__ import annotations

from app.detectors.redaction import (
    BULLET,
    is_placeholder,
    mask_secret,
    redact_context_snippet,
)

from conftest import GH_PAT, JWT_TOKEN, PEM_BLOCK, SLACK_WEBHOOK


def test_mask_keeps_provider_prefix_only():
    masked = mask_secret(GH_PAT)
    assert masked.startswith("ghp_")
    assert BULLET in masked
    assert GH_PAT not in masked
    assert masked.count(BULLET) >= 8


def test_mask_generic_value():
    masked = mask_secret("AbCdEf0123456789ghIjKlMnOpQrStUvWxYz")
    assert masked.startswith("AbCd")
    assert masked.endswith(BULLET * 4) or BULLET in masked
    assert "Ef0123" not in masked


def test_mask_private_key_header():
    masked = mask_secret(PEM_BLOCK.splitlines()[0])
    assert masked.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert "MIIE" not in masked


def test_mask_short_values_fully_hidden():
    masked = mask_secret("abcd")
    assert masked == BULLET * 4


def test_context_redaction_masks_all_known_values():
    snippet = f'token={GH_PAT} jwt={JWT_TOKEN}'
    redacted = redact_context_snippet(snippet, [GH_PAT, JWT_TOKEN])
    assert GH_PAT not in redacted
    assert JWT_TOKEN not in redacted


def test_context_redaction_masks_tokenish_even_if_unlisted():
    snippet = f"webhook: {SLACK_WEBHOOK}"
    redacted = redact_context_snippet(snippet, [])
    assert SLACK_WEBHOOK not in redacted


def test_placeholder_matrix():
    for value in ["YOUR_API_KEY", "CHANGEME", "REDACTED", "dummy", "EXAMPLE_TOKEN",
                  "${VAR}", "$VAR", "%VAR%", "{{var}}", "<key>", "aaaaaa", "password",
                  "000000", "process.env.X", "os.environ.get('X')", ""]:
        assert is_placeholder(value), value


def test_real_looking_values_not_placeholders():
    for value in [GH_PAT, "Tr0ub4dor&3x", "Vq7Zn2Mc5Xr8Tb4Wd9Ye1Uf6As3Dg0Hj"]:
        assert not is_placeholder(value)
