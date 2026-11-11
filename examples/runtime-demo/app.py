"""Minimal FastAPI app for verifying SkyGuard runtime event forwarding."""
import os

from fastapi import FastAPI

app=FastAPI(title="SkyGuard Runtime Demo")

api_url=os.getenv("SKYGUARD_API_URL","http://127.0.0.1:8000")
project_id=os.getenv("SKYGUARD_PROJECT_ID")
project_token=os.getenv("SKYGUARD_PROJECT_TOKEN")
if project_id and project_token:
    from skyguard_agent.runtime import configure_fastapi_monitoring, configure_runtime_monitoring
    configure_fastapi_monitoring(app,api_url,project_id,project_token)
    configure_runtime_monitoring(api_url,project_id,project_token,project_root=os.path.dirname(__file__))

@app.get("/health")
def health():
    return {"status":"ok"}

@app.get("/api/test/runtime-error")
def runtime_error():
    raise RuntimeError("Intentional SkyGuard runtime demo failure")
