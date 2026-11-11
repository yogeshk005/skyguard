import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app import db
from app.main import app


def test_local_syntax_finding_reaches_dashboard_findings_api(tmp_path, monkeypatch):
    repository = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repository / "agent"))
    from skyguard_agent.scanner import scan_project

    project_path = tmp_path / "student-project"
    project_path.mkdir()
    (project_path / "broken.py").write_text("def greet(name):\n    return f'hello {name}'\n    if True print('broken')\n", encoding="utf-8")
    scanned = scan_project(project_path)
    finding = next(item for item in scanned["findings"] if item["file_path"] == "broken.py")

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "skyguard-test.db")
    db.init_db()
    client = TestClient(app)
    owner = client.post("/api/auth/register", json={"email": "scan-ui@example.test", "password": "long-enough-test-password"}).json()
    owner_headers = {"Authorization": "Bearer " + owner["access_token"]}
    project = client.post("/api/projects", headers=owner_headers, json={"name": "Student project"}).json()
    uploaded = client.post("/api/findings/bulk", headers={"Authorization": "Bearer " + project["connection_token"]}, json={
        "project_id": project["id"], "findings": [finding], "files_scanned": scanned["scanned_files"],
    })
    assert uploaded.status_code == 200, uploaded.text

    dashboard_findings = client.get(f"/api/projects/{project['id']}/findings", headers=owner_headers)
    assert dashboard_findings.status_code == 200
    shown = next(item for item in dashboard_findings.json() if item["file_path"] == "broken.py")
    assert shown["line"] == finding["line"]
    assert shown["code_snippet"]
    scans = client.get(f"/api/projects/{project['id']}/scans", headers=owner_headers).json()
    assert scans[0]["files_scanned"] == scanned["scanned_files"]
    assert scans[0]["findings_count"] == len(scanned["findings"])

    client.post(f"/api/findings/{shown['id']}/status", headers=owner_headers, json={"status": "fixed"})
    still_broken = client.post("/api/findings/bulk", headers={"Authorization": "Bearer " + project["connection_token"]}, json={
        "project_id": project["id"], "findings": [finding], "files_scanned": scanned["scanned_files"],
    })
    assert still_broken.json()["updated"] >= 1
    reopened = client.get(f"/api/projects/{project['id']}/findings", headers=owner_headers).json()
    assert next(item for item in reopened if item["fingerprint"] == finding["fingerprint"])["status"] == "open"

    (project_path / "broken.py").write_text("def greet(name):\n    return f'hello {name}'\n", encoding="utf-8")
    clean_scan = scan_project(project_path)
    cleaned = client.post("/api/findings/bulk", headers={"Authorization": "Bearer " + project["connection_token"]}, json={
        "project_id": project["id"], "findings": clean_scan["findings"], "files_scanned": clean_scan["scanned_files"],
    })
    assert cleaned.status_code == 200
    current = client.get(f"/api/projects/{project['id']}/findings", headers=owner_headers).json()
    assert all(item["fingerprint"] != finding["fingerprint"] for item in current)
