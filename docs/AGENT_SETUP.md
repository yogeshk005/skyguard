# Local agent setup

Windows PowerShell:

```powershell
cd agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py -m skyguard_agent scan "C:\path\to\project" --api http://127.0.0.1:8000 --project-id PROJECT_ID --token PROJECT_TOKEN
```

Use `--local-only --output report.json` to scan without uploading. By default, scans upload findings and a redacted, bounded source index to the configured API for project context. Use `--no-context-upload` to clear/disable that index. `.env` values are parsed locally and never uploaded. Keep tokens out of source control and shell history. The dashboard connection panel offers one-time scan and watch commands; watch keeps rescanning after file changes. The agent does not execute arbitrary project builds or tests automatically.
