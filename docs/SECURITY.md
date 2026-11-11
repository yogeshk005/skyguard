# Security notes

- The agent scans only the directory explicitly passed on the command line. By default it uploads a bounded, redacted text-source index to the configured API; `.env` values and common secret files are excluded. Heuristic redaction can miss credentials. Use a trusted API endpoint, review the index, or pass `--no-context-upload` to clear and disable source indexing.
- Dashboard APIs require an expiring bearer token and scope projects to the owning user. Agent ingestion requires a per-project token stored as a hash; token rotation invalidates the previous token.
- Passwords are stored using scrypt. User JWTs use HMAC-SHA256. Set a long random `JWT_SECRET` in `backend/.env` outside local development; the fallback secret is not safe for deployment.
- Gemini keys stay in backend configuration. AI output is untrusted and no generated patch is applied automatically.
- The backend has no rate limiting, formal token revocation, audit trail, production security headers, TLS termination, or external security review. It is not ready for public hosting. Use localhost only until those controls are added.
- Never commit `.env`, project connection tokens, database files, or source credentials. The API can access only files explicitly indexed by the local agent, but indexed source is stored in its database and relevant files are sent to Gemini when an explanation/fix is requested and a Gemini key is configured.
