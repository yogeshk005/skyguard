# Implementation status

Updated 2026-11-05. “Complete” means implemented and exercised by a test in this checkout. Source indexing and broader analyzers are partial; the full request is not complete.

| Feature | Status | Files modified | Tests executed / result | Remaining limitations |
|---|---|---|---|---|
| Existing SQLite schema upgrade, ownership columns, scan/runtime tables, unique finding fingerprints | Partial | `backend/app/db.py` | `python -m compileall -q app`; initialization passed; API test passed | SQLite only; no migration framework; legacy projects have no owner and are intentionally inaccessible |
| Registration/login, scrypt password hashes, signed expiring bearer tokens, project ownership | Partial | `backend/app/main.py`, `backend/app/schemas.py`, `backend/app/config.py`, `.env.example`, frontend | Backend API integration test passed | No password reset/email verification, refresh/revocation, rate limiting, CSRF strategy or complete security review; development JWT fallback must be replaced |
| Project token creation/rotation and authenticated local-agent upload | Partial | `backend/app/main.py`, `agent/skyguard_agent/cli.py`, frontend | Backend integration test covers token upload and duplicate rejection | Token rotation is available in connection setup; no full project settings screen; token is only visible after creation/rotation |
| Findings list/status/AI endpoints with owner isolation | Partial | `backend/app/main.py`, frontend | Backend API test covers list and tenant isolation | No history/audit trail, pagination UI, related findings, or safe fix apply/rollback |
| Local scans for Python lint/types, Java/JS/JSX/TS syntax, dotenv, config, HTML/CSS/SQL and Dockerfile; explicit pytest; watch mode | Partial | `agent/skyguard_agent/scanner.py`, `agent/skyguard_agent/cli.py`, `agent/requirements.txt`, `agent/pyproject.toml` | Demo scan detects Python, Java, JavaScript, dotenv, JSON, YAML, SQL, HTML, CSS, TOML, XML and Dockerfile cases; interview-app JSX-aware scan detected its malformed import | TypeScript/ESLint/JSX checks depend on project tools; Java semantic checks need its build/classpath; no universal logic-error detection |
| Redacted project context sync, file map and relevant-context retrieval for Gemini explanations/fixes | Partial | `agent/skyguard_agent/scanner.py`, `agent/skyguard_agent/cli.py`, `backend/app/db.py`, `backend/app/schemas.py`, `backend/app/main.py`, `frontend/src/main.jsx` | Backend/agent compile checks, frontend production build, demo scan | 5,000-file/25 MB cap; source redaction is heuristic; context retrieval is lexical and bounded, not a full semantic/embedding index |
| Scan history | Partial | `backend/app/db.py`, `backend/app/main.py` | Backend API test confirms ingestion creates scan records | No scan lifecycle/failure record, duration/new/resolved counts, scan detail UI |
| Runtime log ingestion, FastAPI HTTP capture, Node/Express helper | Partial | `backend/app/db.py`, `backend/app/main.py`, `agent/skyguard_agent/runtime.py`, `agent/skyguard_agent/runtime_node.cjs` | Backend API test covers runtime and HTTP 404 findings; Python/Node middleware forwarding tests pass | Integrations must be installed/configured in application code; other languages/frameworks and client-side failures need additional hooks; no metrics, Fluent Bit or anomaly model |
| Responsive monochrome authentication and findings dashboard | Partial | `frontend/src/main.jsx`, `frontend/src/style.css` | `npm run build` passed | No full analytics/navigation/notifications/project detail UI; password reset and account recovery absent |
| Gemini assistance | Partial | Existing `backend/app/ai.py`, `backend/app/main.py` | Not tested without external key | No persisted explanation entity, structured response validation, or fix review/apply workflow |
| Docker, PostgreSQL, CI/CD, production deployment | Pending | — | Not run | Not implemented; current API uses SQLite-specific SQL |
| Required documentation set | Partial | `README.md`, `docs/*.md` | Documentation files created and checked against delivered behavior | Content is concise; deployment, PostgreSQL, analyzer, and runtime docs must expand as features land |

## Verification

- Earlier backend suite: 1 passed. Earlier agent suite: 9 passed; these ran before the current source-index and analyzer expansion.
- Current backend and agent `compileall` checks — passed. Current frontend `npm run build` — passed.
- Demo scan: 16 findings detected, including Python undefined name, Java syntax, JavaScript syntax, malformed dotenv, invalid JSON/YAML/SQL/TOML/XML, HTML accessibility, CSS structure and Dockerfile issues.
- Interview simulator scan: 45 supported text files indexed; `frontend/src/pages/Dashboard.js:3` reported as an unterminated JavaScript/JSX string.
- Initial pytest runs failed because the host's shared default temp directory was inaccessible; using workspace-local `--basetemp` resolved it.

## Next unfinished task

Next: broaden dependency-aware analyzers and build/test integrations, add reliable finding resolution, and improve context retrieval beyond lexical ranking. Universal bug detection remains impossible; PostgreSQL, Docker/CI, deployment hardening, account recovery and analytics also remain outstanding.
