"""API endpoint tests: validation, scans, findings, reports, settings, limits."""

from __future__ import annotations

import io

from conftest import AWS_KEY_ID, GH_PAT, PEM_BLOCK


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["mode"] == "local"


def test_text_scan_end_to_end(client):
    content = f'config:\n  github_token: "{GH_PAT}"\n  password: "Tr0ub4dor&3x"\n'
    resp = client.post("/api/scans/text", json={"label": "config.yml", "content": content})
    assert resp.status_code == 201
    body = resp.json()
    assert body["mode"] == "text"
    assert body["finding_count"] >= 2

    findings = client.get("/api/findings", params={"scan_id": body["id"]}).json()["findings"]
    rule_ids = {f["rule_id"] for f in findings}
    assert "github-pat" in rule_ids and "password-assignment" in rule_ids
    # Raw values never appear in API responses.
    raw = resp.text + str(findings)
    assert GH_PAT not in raw
    for finding in findings:
        assert finding["masked_preview"]
        assert finding["remediation"]


def test_text_scan_validation_rejects_empty(client):
    resp = client.post("/api/scans/text", json={"label": "x", "content": ""})
    assert resp.status_code == 422
    assert "detail" in resp.json()


def test_text_scan_rejects_oversize_content(client, monkeypatch):
    monkeypatch.setenv("SECRELEAK_MAX_REQUEST_MB", "1")
    resp = client.post(
        "/api/scans/text",
        json={"label": "big", "content": "a" * (2 * 1024 * 1024)},
    )
    assert resp.status_code == 413


def test_paste_limit_from_settings(client):
    settings = client.get("/api/settings").json()["settings"]
    assert settings["max_paste_chars"] >= 1000
    resp = client.put("/api/settings", json={"max_paste_chars": 1000})
    assert resp.status_code == 200
    resp = client.post("/api/scans/text", json={"label": "big", "content": "x" * 2000})
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"]["message"].lower()


def test_upload_scan(client):
    files = [
        ("files", ("app.py", io.BytesIO(f'API_KEY = "{GH_PAT}"\n'.encode()), "text/x-python")),
        ("files", ("notes.md", io.BytesIO(b"# nothing here\n"), "text/markdown")),
    ]
    resp = client.post("/api/scans/upload", files=files, data={"label": "uploads"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["file_count"] == 2
    assert body["finding_count"] >= 1


def test_upload_rejects_unsupported_and_binary(client):
    files = [
        ("files", ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")),
        ("files", ("photo.png", io.BytesIO(b"\x89PNG\x00\x00binary"), "image/png")),
    ]
    resp = client.post("/api/scans/upload", files=files)
    assert resp.status_code == 201
    body = resp.json()
    assert body["file_count"] == 0
    reasons = " ".join(s["reason"].lower() for s in body["skipped_files"])
    assert "unsupported" in reasons or "binary" in reasons


def test_upload_enforces_size_limit(client):
    client.put("/api/settings", json={"max_upload_mb": 1})
    big = b"A" * (1024 * 1024 + 100)
    files = [("files", ("big.txt", io.BytesIO(big), "text/plain"))]
    resp = client.post("/api/scans/upload", files=files)
    assert resp.status_code == 201
    body = resp.json()
    assert body["file_count"] == 0
    assert any("exceeds" in s["reason"].lower() for s in body["skipped_files"])


def test_upload_file_count_limit(client):
    client.put("/api/settings", json={"max_files_per_scan": 2})
    files = [("files", (f"f{i}.txt", io.BytesIO(b"hello"), "text/plain")) for i in range(5)]
    resp = client.post("/api/scans/upload", files=files)
    assert resp.status_code == 400


def test_repository_scan_requires_existing_path(client):
    resp = client.post("/api/scans/repository", json={"path": "/definitely/not/here/xyz"})
    assert resp.status_code == 400


def test_repository_scan_worktree(client, git_repo):
    import subprocess

    (git_repo / "src").mkdir(exist_ok=True)
    secret_file = git_repo / "src" / "settings.py"
    secret_file.write_text(f'TOKEN = "{GH_PAT}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "add settings"], cwd=str(git_repo), check=True)

    resp = client.post("/api/scans/repository", json={"path": str(git_repo)})
    assert resp.status_code == 201
    body = resp.json()
    assert body["mode"] == "repository"
    findings = client.get("/api/findings", params={"scan_id": body["id"]}).json()["findings"]
    labels = {f["input_label"] for f in findings}
    assert "src/settings.py" in labels


def test_repository_scan_history(client, git_repo):
    import subprocess

    secret_file = git_repo / "legacy.ini"
    secret_file.write_text(f'aws = "{AWS_KEY_ID}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "add legacy"], cwd=str(git_repo), check=True)
    secret_file.write_text("cleaned = true\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-am", "clean up"], cwd=str(git_repo), check=True)

    resp = client.post(
        "/api/scans/repository", json={"path": str(git_repo), "include_history": True}
    )
    assert resp.status_code == 201
    findings = client.get(
        "/api/findings", params={"scan_id": resp.json()["id"]}
    ).json()["findings"]
    aws = [f for f in findings if f["rule_id"] == "aws-access-key-id"]
    assert aws, "history scan should find the secret introduced by an old commit"
    assert "@" in aws[0]["input_label"]  # labeled with commit sha


def test_scan_get_and_delete(client):
    resp = client.post("/api/scans/text", json={"label": "t", "content": f'k="{GH_PAT}"'})
    scan_id = resp.json()["id"]
    assert client.get(f"/api/scans/{scan_id}").status_code == 200
    assert client.delete(f"/api/scans/{scan_id}").json()["deleted"] is True
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert client.delete(f"/api/scans/{scan_id}").status_code == 404
    # findings gone with the scan
    findings = client.get("/api/findings", params={"scan_id": scan_id}).json()["findings"]
    assert findings == []


def test_findings_filters_and_sort(client):
    content = f'a="{GH_PAT}"\nb="{AWS_KEY_ID}"\npassword="Tr0ub4dor&3x"\n'
    scan = client.post("/api/scans/text", json={"label": "multi", "content": content}).json()

    by_sev = client.get("/api/findings", params={"scan_id": scan["id"], "severity": "high"}).json()
    assert by_sev["count"] >= 2
    assert all(f["severity"] == "high" for f in by_sev["findings"])

    by_rule = client.get("/api/findings", params={"scan_id": scan["id"], "rule_id": "github-pat"}).json()
    assert by_rule["count"] == 1

    search = client.get("/api/findings", params={"q": "github"}).json()
    assert search["count"] >= 1

    by_file = client.get("/api/findings", params={"file": "multi"}).json()
    assert by_file["count"] >= 1


def test_finding_detail_and_dismiss_flow(client):
    scan = client.post("/api/scans/text", json={"label": "d", "content": f'k="{GH_PAT}"'}).json()
    finding = client.get("/api/findings", params={"scan_id": scan["id"]}).json()["findings"][0]

    detail = client.get(f"/api/findings/{finding['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["context_snippet"]
    assert body["why_severity"] and body["description"]

    dismissed = client.post(
        f"/api/findings/{finding['id']}/dismiss", json={"reason": "test_fixture", "note": "synthetic"}
    )
    assert dismissed.status_code == 200
    assert dismissed.json()["dismissed"] is True

    active = client.get("/api/findings", params={"scan_id": scan["id"], "include_dismissed": False}).json()
    assert active["count"] == 0

    restored = client.post(f"/api/findings/{finding['id']}/restore")
    assert restored.json()["dismissed"] is False

    bad = client.post(f"/api/findings/{finding['id']}/dismiss", json={"reason": "because"})
    assert bad.status_code == 422


def test_finding_404(client):
    assert client.get("/api/findings/doesnotexist").status_code == 404
    assert client.post("/api/findings/doesnotexist/dismiss", json={"reason": "placeholder"}).status_code == 404


def test_reports_json_and_csv(client):
    scan = client.post(
        "/api/scans/text", json={"label": "r", "content": f'k="{GH_PAT}"'}
    ).json()

    resp = client.get(f"/api/reports/{scan['id']}", params={"format": "json"})
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert GH_PAT not in resp.text
    report = resp.json()
    assert report["findings"]
    assert report["findings"][0]["masked_preview"]

    resp = client.get(f"/api/reports/{scan['id']}", params={"format": "csv"})
    assert resp.status_code == 200
    assert GH_PAT not in resp.text
    assert "rule_id" in resp.text.splitlines()[0]

    assert client.get("/api/reports/nope", params={"format": "json"}).status_code == 400


def test_csv_formula_injection_guard(client, monkeypatch):
    # A file name starting with a formula trigger must be neutralized in CSV.
    files = [("files", ("=cmd|'calc'!A0.txt", io.BytesIO(f'k="{GH_PAT}"\n'.encode()), "text/plain"))]
    scan = client.post("/api/scans/upload", files=files).json()
    resp = client.get(f"/api/reports/{scan['id']}", params={"format": "csv"})
    assert GH_PAT not in resp.text
    assert "'=cmd" in resp.text


def test_settings_roundtrip(client):
    resp = client.get("/api/settings")
    body = resp.json()
    assert "max_upload_mb" in body["settings"]
    assert body["locations"]["data_dir"]

    resp = client.put("/api/settings", json={"entropy_enabled": False, "max_upload_mb": 3})
    assert resp.status_code == 200
    assert resp.json()["settings"]["entropy_enabled"] is False
    assert client.get("/api/settings").json()["settings"]["max_upload_mb"] == 3

    bad = client.put("/api/settings", json={"max_upload_mb": 999})
    assert bad.status_code == 422
    bad = client.put("/api/settings", json={"unknown_key": 1})
    assert bad.status_code == 422


def test_settings_reset(client):
    client.put("/api/settings", json={"max_upload_mb": 2})
    body = client.post("/api/settings/reset").json()
    assert body["settings"]["max_upload_mb"] == 5


def test_dashboard_shape(client):
    client.post("/api/scans/text", json={"label": "dash", "content": f'k="{GH_PAT}"'})
    body = client.get("/api/dashboard").json()
    assert body["total_scans"] >= 1
    assert body["total_findings"] >= 1
    assert set(body["severity_counts"]) == {"critical", "high", "medium", "low"}
    assert body["recent_scans"]


def test_clear_scan_history(client):
    client.post("/api/scans/text", json={"label": "a", "content": f'k="{GH_PAT}"'})
    body = client.delete("/api/scans").json()
    assert body["deleted_scans"] >= 1
    assert client.get("/api/scans").json()["scans"] == []


def test_validation_errors_do_not_echo_content(client):
    resp = client.post("/api/scans/text", json={"label": "x", "content": GH_PAT, "extra": 1})
    # content is valid here; force a validation error that would echo the secret
    resp = client.post("/api/scans/text", json={"label": "", "content": GH_PAT})
    assert resp.status_code == 422
    assert GH_PAT not in resp.text


def test_cors_no_wildcard(client):
    resp = client.options(
        "/api/health", headers={"Origin": "https://evil.example",
                                "Access-Control-Request-Method": "GET"},
    )
    assert resp.headers.get("access-control-allow-origin") is None
