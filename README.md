# SkyGuard
AI-assisted codebase error detection and resolution platform.

SkyGuard is a standalone platform. The local CLI/agent reads the selected project, scans supported files and synchronizes redacted source context to the configured SkyGuard API. `.env` files are validated locally but never uploaded. The API stores the source index for project-aware Gemini explanations and fix suggestions; use a trusted API endpoint.

## Architecture
- `agent/`: local multi-language scanner and CLI
- `backend/`: FastAPI service, SQLite persistence, optional Gemini explanations/fix suggestions
- `frontend/`: React/Vite dashboard
- `examples/`: intentionally faulty demo project
- `docs/`: setup and security notes

## Supported checks in this starter
- Python: syntax parsing via `ast`, Ruff lint diagnostics, and mypy type diagnostics
- Java: syntax diagnostics via local JDK `javac`; dependency-aware type/build diagnostics require the project's configured build
- JavaScript/Node: syntax via Node and core ESLint rules when local ESLint is installed
- React/Next: JSX/TSX syntax via local esbuild and TypeScript diagnostics via local `tsc` when project config/dependencies are present
- `.env`: local dotenv assignment/duplicate/quote checks; values are withheld from findings and never uploaded
- JSON: parsing
- HTML: strict parser errors and missing image alt text
- CSS: token/declaration parsing and delimiter checks
- YAML, SQL, TOML, XML, INI and basic Dockerfile checks
- Pytest failures only when explicitly enabled with `--run-pytest`
- Runtime logs and FastAPI HTTP failures: opt-in integrations; see `docs/RUNTIME_MONITORING.md`
- Node/Express runtime and HTTP errors: opt-in server-side helper in `agent/skyguard_agent/runtime_node.cjs`
- Gemini: optional explanation and suggested patch generation

This is not a universal detector. Language-specific semantic/type/build errors require the relevant compiler, linter, tests and project dependencies. Logic errors generally require meaningful tests or runtime signals. SkyGuard reports the analyzer and check used for each finding.

Static scans do not execute applications. For Python runtime events and HTTP responses, instrument the FastAPI app as described in `docs/RUNTIME_MONITORING.md`. A Node/Express helper is included; other frameworks need their own server-side forwarding integration.

## Requirements
- Python 3.10+
- Node.js 18+ (for frontend and optional JS checks)
- npm

## Run on Windows
### 1. Backend
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
API docs: http://127.0.0.1:8000/docs

### 2. Frontend (new terminal)
```powershell
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

### 3. Scan a project with the local agent
```powershell
cd agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py -m skyguard_agent scan "C:\path\to\your-project" --local-only --output findings.json
```
The CLI prints a structured summary for every scan, including the error category, absolute file path, line, source line, and analyzer description. Use `--html report.html` to create an HTML report. A scan with no findings prints an explicit success message. Findings remain visible in the terminal if API upload fails. The dashboard polls findings and shows the latest scan's file and finding counts. Its **Scan & refresh** button asks the local agent service to rescan the connected folder, then reloads the findings.

To connect once and save credentials for later scans:

```powershell
py -m skyguard_agent connect "C:\path\to\your-project" --api http://127.0.0.1:8000 --project-id prj_your_project_id --token sgp_your_project_token --output skyguard-report.json --html skyguard-report.html
```

`connect` saves the API URL, project ID, and token in the current user's SkyGuard configuration directory (Windows: `%APPDATA%\SkyGuard\connections`; macOS/Linux: `$XDG_CONFIG_HOME/SkyGuard/connections` or `~/.config/SkyGuard/connections`). The token is not written into the project. Later commands can omit `--project-id` and `--token`:

```powershell
py -m skyguard_agent scan "C:\path\to\your-project" --output skyguard-report.json --html skyguard-report.html
py -m skyguard_agent watch "C:\path\to\your-project"
```

To make the dashboard button run a fresh scan, choose **Refresh rescans** in the connection panel and run the two generated commands in a terminal. Keep the second command (`serve`) running while using the dashboard. The agent listens only on `127.0.0.1:8765`; the browser sends it a scan request, and the agent scans the saved project folder and uploads the new results. A successful complete scan removes old static findings it no longer detects; runtime findings remain available.

Gemini is paused by default while you verify scanning and dashboard delivery. To opt in later, add `--with-gemini` to a `scan` or `connect` command and set the key in the environment of the terminal running the agent:

```powershell
$env:GEMINI_API_KEY = "your-key"
py -m skyguard_agent scan "C:\path\to\your-project" --local-only --with-gemini --output skyguard-report.json
```

On macOS/Linux use `export GEMINI_API_KEY="your-key"`. The agent sends bounded, redacted source context and findings to Gemini. `.env` contents are never included. API failures appear in the report status; local detection still completes.

Review a report, then optionally apply an exact Gemini suggestion after an interactive confirmation for each file. The original is backed up under `.skyguard-backups`:

```powershell
py -m skyguard_agent apply skyguard-report.json
```

Static analyzers cannot establish every runtime exception or logic defect. For those, configure the project's compiler, tests, and runtime monitoring integrations. Error categories are best-fit classifications of analyzer evidence, not a guarantee that all possible instances are detectable.

For the dashboard workflow:
1. Register or sign in, then click **Add project**.
2. Select the newly created project and click **Scan instructions**.
3. In a terminal, enter the `agent` folder and install its requirements.
4. Copy the generated scan command and replace the sample folder path with your actual project path. The command includes the project ID and one-time displayed connection token, so later scans remain grouped under the same project. For dashboard-triggered rescans, select **Refresh rescans**, run both generated commands, and leave `serve` running.
5. The agent sends findings and a redacted, bounded source index to the configured API; the dashboard shows its file map. Gemini uses relevant indexed files when you request explanations or fix suggestions. For runtime/HTTP errors, enable the app monitoring integration and restart the app.

For continuous local scans, use the same project ID and token with `py -m skyguard_agent watch "C:\path\to\your-project" --api http://127.0.0.1:8000 --project-id PROJECT_ID --token PROJECT_TOKEN`. It polls supported source files and uploads a scan when it detects changes; press Ctrl+C to stop. Add `--no-context-upload` to opt out of source indexing.

Example for a project already registered in the dashboard:
```powershell
py -m skyguard_agent scan "C:\path\to\your-project" --api http://127.0.0.1:8000 --project-id prj_your_project_id --token sgp_your_project_token
```

Or run a local-only scan:
```powershell
py -m skyguard_agent scan "C:\path\to\your-project" --output findings.json
```
The agent excludes `.git`, virtual environments, `node_modules`, build outputs, common generated folders, `.env*` and other common secret files from source upload. It checks dotenv syntax locally without uploading values, reads basic `.gitignore` patterns, redacts common credential patterns heuristically, and caps indexed text at 5,000 files and 25 MB. Review the index and use `--no-context-upload` when source must stay local. The Refresh button reloads saved findings; it does not scan files.

Project uploads require an account and a project connection token. A newly created project returns the token once; copy it from the generated scan command. Never commit or share this token.

## Gemini setup
Set `GEMINI_API_KEY` and optionally `GEMINI_MODEL` in `backend/.env`. Restart backend. Without a key, AI endpoints return a clear configuration error; scanning still works.

## API overview
- `GET /api/health`
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `GET /api/projects` (authenticated)
- `POST /api/projects` (authenticated; returns one-time project token)
- `DELETE /api/projects/{project_id}` (owner only; deletes related project data)
- `GET /api/projects/{project_id}/summary`
- `GET /api/projects/{project_id}/findings`
- `GET /api/projects/{project_id}/context` (owner-only indexed file map)
- `POST /api/projects/{project_id}/context` (project-token source-context synchronization)
- `DELETE /api/projects/{project_id}/context` (project-token context removal)
- `POST /api/findings/bulk`
- `GET /api/projects/{project_id}/scans` (owner only)
- `POST /api/projects/{project_id}/runtime-logs` (project-token authenticated)
- `GET /api/findings/{finding_id}`
- `POST /api/findings/{finding_id}/explain`
- `POST /api/findings/{finding_id}/suggest-fix`
- `POST /api/findings/{finding_id}/status`

## Safety
- Scanning runs on the developer's machine.
- By default, the agent sends a bounded, heuristically redacted text-source index to the configured API. `.env` values are excluded; source is stored for project-aware explanations. Use a trusted API endpoint or `--no-context-upload` to clear and disable the index.
- Review AI suggestions before applying them. This starter does not automatically modify project files.
- Do not scan projects you do not own or have permission to inspect.
- Do not expose the API publicly without authentication, HTTPS, rate limiting, tenant isolation and deployment hardening.
- Set a unique random `JWT_SECRET` before non-local deployment. The fallback is for local development only.
