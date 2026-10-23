# Sample data (100% synthetic)

Every value in this folder is **fabricated**. None of these strings can
authenticate to any service. They exist so you can exercise SecretLeak safely.

| File | What it demonstrates | Rules it should trigger |
| --- | --- | --- |
| `leaky.env` | A committed `.env` with provider-shaped tokens and placeholders | `github-pat`, `database-connection-string`, `aws-access-key-id` (the `YOUR_API_KEY` and `YOUR-TOKEN-HERE` lines must **not** be reported) |
| `app.log` | An application log line that echoes an API key | `log-credential-leak` |
| `hook_demo/leaky.py` | A staged-commit scenario for the pre-commit hook demo | `github-pat` |

## Try it

1. Start the backend and frontend (see the main README).
2. Open **New Scan → Paste text**, paste the contents of `leaky.env`, and run the scan.
3. Or upload the files directly (**New Scan → File upload**).

## Pre-commit hook demo

```bash
cd sample_data/hook_demo
git init
git config user.email "demo@example.invalid"
git config user.name "Demo"
git add leaky.py
python ../../scripts/install_git_hook.py .
git commit -m "should be blocked"   # exits nonzero, prints masked previews only
python ../../scripts/uninstall_git_hook.py .
```
