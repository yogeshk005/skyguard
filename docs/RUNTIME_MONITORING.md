# Runtime monitoring

Static scans do not execute apps or inspect another process's terminal. For Python apps, SkyGuard provides two opt-in integrations: a logging handler forwards ERROR+ records and exception tracebacks, while FastAPI middleware forwards HTTP 4xx/5xx responses (including 404 route misses). The API stores events and creates deduplicated `RUNTIME_ERROR` or `HTTP_ERROR` findings, visible in the regular Findings list.

Install the local SkyGuard agent package in the app's environment:

```powershell
py -m pip install -e "C:\path\to\SkyGuard\agent"
```

In the app module that Uvicorn imports, configure logging before starting Uvicorn (use the values for the same dashboard project):

```python
from skyguard_agent.runtime import configure_fastapi_monitoring, configure_runtime_monitoring

configure_fastapi_monitoring(
    app,
    api_url="http://127.0.0.1:8000",
    project_id="prj_your_project_id",
    token="sgp_your_project_token",
)

configure_runtime_monitoring(
    api_url="http://127.0.0.1:8000",
    project_id="prj_your_project_id",
    token="sgp_your_project_token",
    project_root=r"C:\path\to\your\app",
)
```

For Uvicorn `--reload`, put this in the imported app module after `app = FastAPI(...)`, so it runs in the server process. The logger attaches to root and `uvicorn.error`; both integrations use a short timeout and do not delay responses if SkyGuard is offline. Keep the token in an environment variable for ongoing use; do not commit it. This captures HTTP error responses and logged exceptions, not payment/auth events, metrics, slow requests, or errors from other languages. Logs may contain sensitive data; review your logging and do not send secrets or personal data.

## Node.js and Express

The agent also includes `skyguard_agent/runtime_node.cjs` for Node server processes. It uses Node's built-in `fetch` and does not expose the project token to browser code:

```javascript
const { configureSkyGuardNode } = require('C:/path/to/SkyGuard-project/agent/skyguard_agent/runtime_node.cjs');
const monitor = configureSkyGuardNode({
  apiUrl: process.env.SKYGUARD_API_URL || 'http://127.0.0.1:8000',
  projectId: process.env.SKYGUARD_PROJECT_ID,
  token: process.env.SKYGUARD_PROJECT_TOKEN,
  projectRoot: process.cwd(),
});
app.use(monitor.expressMiddleware); // after creating Express app
```

This reports Express 4xx/5xx responses and process-level uncaught exceptions/rejections. For other frameworks, use the authenticated runtime ingestion endpoint from server-side code. Client-side browser errors require a trusted backend relay; never embed the project token in frontend JavaScript.
