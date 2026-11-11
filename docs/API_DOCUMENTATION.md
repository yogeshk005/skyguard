# API documentation

Interactive OpenAPI docs are available at `http://127.0.0.1:8000/docs` while the local backend is running.

Authentication: `POST /api/auth/register`, `POST /api/auth/login`; send returned JWT as `Authorization: Bearer <token>` to user routes. `GET /api/auth/me` returns the current account.

User routes: `GET/POST /api/projects`, `POST /api/projects/{id}/token`, `DELETE /api/projects/{id}`, `GET /api/projects/{id}/summary`, `GET /api/projects/{id}/findings`, `GET /api/projects/{id}/scans`, `GET /api/projects/{id}/runtime-logs`, `GET /api/findings/{id}`, `POST /api/findings/{id}/status|explain|suggest-fix`.

Agent routes: `POST /api/findings/bulk` and `POST /api/projects/{id}/runtime-logs`, authenticated with the project connection token. User routes enforce project ownership. This API currently lacks production rate limiting and a stable versioning policy.
