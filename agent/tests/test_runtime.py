import logging
from pathlib import Path
from skyguard_agent.runtime import SkyGuardLogHandler
from fastapi import FastAPI
from fastapi.testclient import TestClient
from skyguard_agent.runtime import configure_fastapi_monitoring

class Response:
    def raise_for_status(self): pass

def test_runtime_handler_forwards_traceback_and_relative_path(monkeypatch, tmp_path):
    sent=[]
    def post(url, **kwargs):
        sent.append((url, kwargs))
        return Response()
    monkeypatch.setattr("skyguard_agent.runtime.requests.post", post)
    try:
        raise RuntimeError("deliberate")
    except RuntimeError:
        record=logging.LogRecord("uvicorn.error",logging.ERROR,"server.py",9,"request failed",(),__import__('sys').exc_info())
    project_root=Path(__file__).resolve().parents[1]
    handler=SkyGuardLogHandler("http://127.0.0.1:8000","prj_test","sgp_test",project_root=str(project_root))
    handler.emit(record)
    assert len(sent)==1
    assert sent[0][1]["json"]["file_path"] == "tests/test_runtime.py"
    assert "RuntimeError: deliberate" in sent[0][1]["json"]["stack_trace"]
    assert sent[0][1]["headers"]["Authorization"] == "Bearer sgp_test"

def test_fastapi_monitor_reports_missing_route(monkeypatch):
    sent=[]
    def post(url, **kwargs):
        sent.append(kwargs)
        return Response()
    monkeypatch.setattr("skyguard_agent.runtime.requests.post", post)
    app=FastAPI()
    configure_fastapi_monitoring(app,"http://127.0.0.1:8000","prj_test","sgp_test")
    response=TestClient(app).get("/api/test/runtime-error")
    assert response.status_code == 404
    assert len(sent) == 1
    assert sent[0]["json"]["level"] == "WARNING"
    assert sent[0]["json"]["message"] == "HTTP error response: 404 GET /api/test/runtime-error"
