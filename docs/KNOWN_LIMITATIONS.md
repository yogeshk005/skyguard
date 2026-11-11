# Known limitations

- Authentication is a first local implementation: no password recovery, verification, token revocation or rate limiting. Replace the development JWT fallback before use beyond localhost.
- Existing pre-authentication projects have no owner and are not visible to newly registered accounts.
- Database is SQLite only; there is no formal migration framework.
- Ruff and mypy provide Python lint/type checks. Fixed ESLint core rules run only when local ESLint exists; project configs/plugins are deliberately not loaded. TypeScript diagnostics require `tsconfig.json` and local TypeScript; JSX/TSX syntax requires local esbuild; Java syntax requires a JDK. Dependency-aware Java builds, React hook/component semantics, Next builds and other project build execution are not automatic.
- Source context is synchronized to the configured API by default (up to 5,000 text files/25 MB); credential redaction is heuristic and cannot guarantee secret removal. `.env` files are checked locally but never uploaded. Use a trusted API or `--no-context-upload`.
- `.gitignore` matching is basic. Static logic errors cannot be reliably found without relevant tests or runtime signals; no analyzer covers every language feature or bug.
- Runtime capture is opt-in Python logging/FastAPI middleware or Node/Express helper. Applications must install/configure it; other languages and non-HTTP unlogged failures are not captured. Anomaly detection and a separate runtime dashboard are absent.
- AI requires a Gemini key and is not locally simulated. Fix suggestions cannot be approved/applied or rolled back through the app.
- Analytics, notification system, scan detail UI, Docker, PostgreSQL, CI/CD and full automated E2E remain unimplemented.
