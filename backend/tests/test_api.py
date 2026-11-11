from fastapi.testclient import TestClient
from app import db
from app.main import app

def test_authenticated_projects_and_agent_ingestion(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    client = TestClient(app)
    signup = client.post("/api/auth/register", json={"email":"owner@example.test","password":"long-enough-test-password"})
    assert signup.status_code == 200
    login=client.post("/api/auth/login", json={"email":"OWNER@example.test","password":"long-enough-test-password"})
    assert login.status_code == 200
    assert client.get("/api/auth/me",headers={"Authorization":"Bearer "+login.json()["access_token"]}).json()["email"] == "owner@example.test"
    owner = {"Authorization": "Bearer " + signup.json()["access_token"]}
    created = client.post("/api/projects", headers=owner, json={"name":"demo"})
    assert created.status_code == 200
    p = created.json()
    finding = {"fingerprint":"stable-fingerprint","title":"Bad syntax","message":"parse failed","file_path":"app.py","line":2,"analyzer":"test"}
    up = client.post("/api/findings/bulk", headers={"Authorization":"Bearer "+p["connection_token"]}, json={"project_id":p["id"],"findings":[finding],"files_scanned":4})
    assert up.status_code == 200 and up.json()["inserted"] == 1
    dup = client.post("/api/findings/bulk", headers={"Authorization":"Bearer "+p["connection_token"]}, json={"project_id":p["id"],"findings":[finding]})
    assert dup.json()["inserted"] == 0
    assert len(client.get(f"/api/projects/{p['id']}/findings",headers=owner).json()) == 1
    runtime=client.post(f"/api/projects/{p['id']}/runtime-logs",headers={"Authorization":"Bearer "+p["connection_token"]},json={"level":"ERROR","message":"Deliberate RuntimeError","stack_trace":"Traceback ... password=should-not-leak","file_path":"server.py","line":42})
    assert runtime.status_code == 200 and runtime.json()["finding_created"] is True
    runtime_findings=client.get(f"/api/projects/{p['id']}/findings",headers=owner).json()
    assert len(runtime_findings) == 2 and any(x["category"]=="RUNTIME_ERROR" for x in runtime_findings)
    runtime_finding=next(x for x in runtime_findings if x["category"]=="RUNTIME_ERROR")
    assert "should-not-leak" not in runtime_finding["code_snippet"] and "[REDACTED]" in runtime_finding["code_snippet"]
    missing_route=client.post(f"/api/projects/{p['id']}/runtime-logs",headers={"Authorization":"Bearer "+p["connection_token"]},json={"level":"WARNING","message":"HTTP error response: 404 GET /missing"})
    assert missing_route.status_code == 200 and missing_route.json()["finding_created"] is True
    runtime_findings=client.get(f"/api/projects/{p['id']}/findings",headers=owner).json()
    assert any(x["category"]=="HTTP_ERROR" and "404" in x["title"] for x in runtime_findings)
    stranger = client.post("/api/auth/register", json={"email":"other@example.test","password":"long-enough-test-password"}).json()
    denied = client.get(f"/api/projects/{p['id']}/findings",headers={"Authorization":"Bearer "+stranger["access_token"]})
    assert denied.status_code == 404
    assert len(client.get(f"/api/projects/{p['id']}/scans",headers=owner).json()) == 2
