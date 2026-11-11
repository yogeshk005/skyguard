# Deployment

This checkout is for local development only. It uses SQLite-specific SQL and the API does not yet provide PostgreSQL support, rate limiting, hardened production headers, a migration runner, Docker images or CI. Do not expose it to the public internet.

Before a future deployment, implement PostgreSQL support and migrations, use HTTPS, set a unique high-entropy `JWT_SECRET`, configure exact CORS origins, add rate limits/monitoring/backups, and run security and isolation tests. The local UI can be built with `npm run build`.
