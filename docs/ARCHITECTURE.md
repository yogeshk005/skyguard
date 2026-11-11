# Architecture

SkyGuard has three trust zones. The browser talks to FastAPI using an expiring user bearer token. The local agent scans a developer-selected directory and uploads bounded findings using a per-project bearer token. The API persists accounts, projects, findings, scans and runtime logs in SQLite. Gemini is an optional backend-only integration.

```text
React/Vite ── user JWT ──> FastAPI ──> SQLite
Local agent ─ project token ────────> FastAPI
                                      └─ optional Gemini API
```

The hosted API does not access the developer's filesystem. Scanner checks are explicitly limited; see [SCANNING_ENGINE.md](SCANNING_ENGINE.md) and [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). PostgreSQL and production migrations are not implemented yet.
