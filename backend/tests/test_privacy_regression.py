"""THE privacy regression test.

Drives every API flow with the full set of synthetic secrets, then asserts the
complete raw values never appear in: API responses, database records, generated
reports, application logs, or error messages.
"""

from __future__ import annotations

import io
import logging

from app.database import db

from conftest import ALL_SYNTHETIC_SECRETS, GH_PAT, PEM_BLOCK


def _dump_database() -> str:
    chunks: list[str] = []
    with db.get_conn() as conn:
        tables = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        for table in tables:
            for row in conn.execute(f"SELECT * FROM {table}").fetchall():  # noqa: S608 - table name from sqlite_master
                chunks.append(str(tuple(row)))
    return "\n".join(chunks)


def test_raw_secrets_never_leave_the_application(client, caplog):
    caplog.set_level(logging.DEBUG)
    responses: list[str] = []

    def record(resp) -> None:
        responses.append(resp.text)

    # 1) text scan containing every synthetic secret (PEM among them)
    content = "\n".join(
        [
            f'github_token = "{GH_PAT}"',
            f'API_KEY = "sk_a9Xk2Pm7Qr4Tv6Wx8Za3Bc5De7Fg9Hi0J"',
            PEM_BLOCK,
            "db_url = \"postgres://dbuser:S3cr3tP4ss99@db.internal:5432/appdb\"",
            "Authorization: Bearer AbCdEf0123456789ghIjKlMnOpQrStUvWxYz",
        ]
    )
    record(client.post("/api/scans/text", json={"label": "everything", "content": content}))

    # 2) upload scan
    files = [("files", ("secrets.env", io.BytesIO(
        f'DB_PASSWORD=Vq7Zn2Mc5Xr8Tb4Wd9Ye1Uf6As3Dg0Hj\n'.encode()
    ), "text/plain"))]
    record(client.post("/api/scans/upload", files=files))

    # 3) error paths that could echo content
    record(client.post("/api/scans/text", json={"label": "", "content": GH_PAT}))

    # 4) findings + dismissal + reports for the first scan
    scan_id = client.post(
        "/api/scans/text", json={"label": "regression", "content": content}
    ).json()["id"]
    record(client.get("/api/scans", params={"limit": 100}))
    record(client.get("/api/findings", params={"limit": 1000}))
    findings = client.get("/api/findings", params={"scan_id": scan_id}).json()["findings"]
    assert findings, "expected findings for regression content"
    record(client.get(f"/api/findings/{findings[0]['id']}"))
    record(client.post(
        f"/api/findings/{findings[0]['id']}/dismiss", json={"reason": "test_fixture"}
    ))
    record(client.get(f"/api/reports/{scan_id}", params={"format": "json"}))
    record(client.get(f"/api/reports/{scan_id}", params={"format": "csv"}))
    record(client.get("/api/dashboard"))

    api_text = "\n".join(responses)
    db_text = _dump_database()
    log_text = caplog.text

    for secret in ALL_SYNTHETIC_SECRETS:
        assert secret not in api_text, f"secret leaked in API response: {secret[:12]}..."
        assert secret not in db_text, f"secret leaked in database: {secret[:12]}..."
        assert secret not in log_text, f"secret leaked in logs: {secret[:12]}..."

    # PEM body specifically
    pem_body = PEM_BLOCK.splitlines()[1]
    assert pem_body not in api_text and pem_body not in db_text


def test_fingerprints_are_keyed_not_plain_hashes(client):
    import hashlib

    scan = client.post("/api/scans/text", json={"label": "fp", "content": f'k="{GH_PAT}"'}).json()
    finding = client.get("/api/findings", params={"scan_id": scan["id"]}).json()["findings"][0]
    fp = finding["fingerprint"]
    assert fp != hashlib.sha256(GH_PAT.encode()).hexdigest()
    assert fp != hashlib.sha256(f"github-pat:{GH_PAT}".encode()).hexdigest()
    assert len(fp) == 32


def test_fingerprint_stable_across_scans(client):
    one = client.post("/api/scans/text", json={"label": "a", "content": f'k="{GH_PAT}"'}).json()
    two = client.post("/api/scans/text", json={"label": "b", "content": f'x="{GH_PAT}"'}).json()
    f1 = client.get("/api/findings", params={"scan_id": one["id"]}).json()["findings"][0]
    f2 = client.get("/api/findings", params={"scan_id": two["id"]}).json()["findings"][0]
    assert f1["fingerprint"] == f2["fingerprint"]
    assert f1["id"] != f2["id"]
