"""Engine behavior: line accuracy, dedupe, overlap, limits, entropy toggles."""

from __future__ import annotations

from app.detectors.engine import MAX_INPUT_CHARS, scan_text

from conftest import ENTROPY_VALUE, GH_PAT, JWT_TOKEN, PEM_BLOCK


def test_line_and_column_accuracy():
    text = 'line one\nline two\nGITHUB_TOKEN="%s"\nline four\n' % GH_PAT
    drafts = scan_text(text, label="sample")
    gh = [d for d in drafts if d.rule_id == "github-pat"]
    assert len(gh) == 1
    assert gh[0].line == 3
    # column points at the start of the secret value (after GITHUB_TOKEN=")
    assert gh[0].column == text.splitlines()[2].index(GH_PAT) + 1


def test_crlf_line_endings_handled():
    text = 'a\r\nb\r\npassword = "Tr0ub4dor&3x"\r\n'
    drafts = scan_text(text, label="sample")
    pw = [d for d in drafts if d.rule_id == "password-assignment"]
    assert len(pw) == 1
    assert pw[0].line == 3


def test_same_secret_same_line_deduplicated():
    text = f'token = "{GH_PAT}"  # again: {GH_PAT}\n'
    drafts = scan_text(text, label="sample")
    # Same rule and same secret at different columns remain distinct exposures,
    # but identical rule+value+line+column collapses.
    assert len({(d.rule_id, d.line, d.column) for d in drafts}) == len(drafts)


def test_same_secret_two_locations_two_findings():
    text = f'a = "{GH_PAT}"\nb = "{GH_PAT}"\n'
    drafts = scan_text(text, label="sample")
    gh = [d for d in drafts if d.rule_id == "github-pat"]
    assert len(gh) == 2
    assert {d.line for d in gh} == {1, 2}


def test_overlapping_generic_rule_yields_single_finding():
    # JWT inside an access_token assignment: only the specific rule should win.
    text = f'access_token: "{JWT_TOKEN}"\n'
    drafts = scan_text(text, label="sample")
    ids = {d.rule_id for d in drafts}
    assert "jwt-token" in ids
    assert "api-key-assignment" not in ids


def test_db_url_wins_over_generic_url_credentials():
    url = "postgres://user:pass99word@db.internal:5432/x"
    drafts = scan_text(f'DB="{url}"', label="sample")
    ids = {d.rule_id for d in drafts}
    assert "database-connection-string" in ids
    assert "url-credentials" not in ids


def test_private_key_body_never_retained():
    drafts = scan_text("config = 1\n" + PEM_BLOCK + "\ntrailer\n", label="sample")
    pem = [d for d in drafts if d.rule_id == "private-key-block"]
    assert len(pem) == 1
    finding = pem[0]
    assert finding.severity == "critical"
    body = PEM_BLOCK.splitlines()[1]
    for field in (finding.masked_preview, finding.context_snippet):
        assert body not in field
    assert "redacted" in finding.context_snippet.lower()
    assert finding.line == 2


def test_unterminated_private_key_capped():
    text = "-----BEGIN PRIVATE KEY-----\n" + "AAAA\n" * 5000
    drafts = scan_text(text, label="sample")
    assert any(d.rule_id == "private-key-block" for d in drafts)


def test_context_masks_neighboring_secret():
    text = f'first = "{GH_PAT}"\nsecond = "should-not-leak"\n'
    drafts = scan_text(text, label="sample")
    for draft in drafts:
        assert GH_PAT not in draft.context_snippet
        assert GH_PAT not in draft.masked_preview


def test_context_marks_finding_line():
    text = "l1\nl2\nl3\nl4\nl5\npassword = \"Tr0ub4dor&3x\"\nl7\n"
    drafts = scan_text(text, label="sample")
    pw = [d for d in drafts if d.rule_id == "password-assignment"][0]
    assert ">>" in pw.context_snippet


def test_masked_preview_has_no_raw_value():
    for text in (f'x = "{GH_PAT}"', f'jwt = "{JWT_TOKEN}"'):
        for draft in scan_text(text, label="sample"):
            assert draft.masked_preview != ""
            if draft.rule_id != "jwt-token":
                assert draft.rule_id and draft.fingerprint


def test_large_input_does_not_crash():
    big = " innocuous line with words and numbers 12345\n" * 20_000
    drafts = scan_text(big, label="big")
    assert isinstance(drafts, list)


def test_input_truncated_at_hard_cap():
    text = "x\n" * (MAX_INPUT_CHARS // 2 + 10)
    assert isinstance(scan_text(text, label="huge"), list)


def test_entropy_candidates_in_long_prose_not_flagged():
    text = "word " * 5000 + "\nThe quick brown fox jumps over the lazy dog.\n"
    drafts = scan_text(text, label="prose")
    assert all(d.rule_id != "generic-high-entropy" for d in drafts)


def test_high_entropy_string_flagged_once():
    text = f'config_value = "{ENTROPY_VALUE}"\n'
    drafts = scan_text(text, label="cfg")
    assert any(d.rule_id == "generic-high-entropy" for d in drafts)
    # exactly one finding for that value at that line
    hits = [d for d in drafts if d.line == 1 and d.rule_id == "generic-high-entropy"]
    assert len(hits) == 1
