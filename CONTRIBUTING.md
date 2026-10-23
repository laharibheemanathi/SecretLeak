# Contributing to SecretLeak

Thanks for your interest in improving SecretLeak! This project is a local-first,
pattern-based secret scanner. Because it is a security tool, contributions are
held to a slightly higher bar than usual.

## Ground rules

1. **Never commit real credentials** — not in code, tests, fixtures, docs, or screenshots.
   All test secrets must be synthetic values that cannot authenticate anywhere
   (for example `ghp_` followed by zeros).
2. **No network calls at scan time.** The scanner must work fully offline. Do not add
   telemetry, reputation-service lookups, or AI API calls to the scanning path.
3. **Never persist raw secrets.** Findings store masked previews, redacted context and
   an HMAC fingerprint only.
4. Keep the code readable — this project is aimed at students and junior developers.

## Development setup

See the [README](README.md) for exact Windows setup instructions.

- Backend: `cd backend && python -m venv .venv && .venv\Scripts\pip install -r requirements.txt`
- Frontend: `cd frontend && npm install`
- Backend tests: `cd backend && .venv\Scripts\python -m pytest`
- Frontend tests: `cd frontend && npm test`

## Adding a detection rule

1. Add a `Rule` to `backend/app/detectors/rules.py` with a stable `id`, severity,
   confidence, remediation text and a short explanation of **why** the severity
   was chosen.
2. Add synthetic positive **and** negative (placeholder) test cases to
   `backend/tests/test_rules.py`. Every rule needs at least one test that asserts
   the rule fires, and one that asserts a placeholder does **not** fire.
3. Provider-specific rules must match real format shapes (prefix + charset + length)
   but must use fake values in tests.

## Pull requests

- Keep PRs focused; one idea per PR.
- All tests must pass.
- Update the README rule table when adding/removing rules.
- Describe false-positive trade-offs in the PR text.
