# Runtime demo

Run this only after starting SkyGuard's backend and creating a project. Activate the Python environment in which FastAPI and the SkyGuard agent are installed, then set the project credentials and start Uvicorn:

```powershell
$env:SKYGUARD_API_URL = "http://127.0.0.1:8000"
$env:SKYGUARD_PROJECT_ID = "YOUR_PROJECT_ID"
$env:SKYGUARD_PROJECT_TOKEN = "YOUR_PROJECT_TOKEN"
uvicorn app:app --app-dir examples/runtime-demo --reload --port 8001
```

Request `http://127.0.0.1:8001/api/test/runtime-error` to produce a logged 500, or request an unknown route to produce a 404. Both should create findings when the token is valid. Do not commit real project tokens.
