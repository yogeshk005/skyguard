# Installation

Windows PowerShell, from the repository root:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal, start the UI:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and register. For the local agent, see [AGENT_SETUP.md](AGENT_SETUP.md). Linux/macOS can use `python3 -m venv .venv`, `source .venv/bin/activate`, and the same pip/npm commands. Local development uses SQLite; production setup is not ready.
