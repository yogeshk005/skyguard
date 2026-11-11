# Scanning engine

The agent scans locally and sends normalized findings with fingerprints and bounded snippets. By default, it also synchronizes a redacted source index to the configured SkyGuard API for codebase-aware assistance. `.env` files are inspected locally for syntax issues but never uploaded. Use `--no-context-upload` to keep source code on the scanning machine. Source redaction is heuristic; use a trusted API endpoint. Files over 1 MB, codebase context over 5,000 text files/25 MB, and scans over 12,000 files are bounded/skipped.

## Built-in and installed checks

- Python: AST syntax validation, Ruff lint rules such as undefined names/unused imports, and mypy type diagnostics. The scanner does not load project mypy plugins/config files.
- Java: `javac` syntax diagnostics with annotation processing disabled. Dependency-aware type/build failures need the project's configured build/classpath.
- JavaScript: Node `--check` syntax validation and fixed core ESLint rules when local ESLint exists (project configs/plugins are deliberately not loaded). JSX/TSX syntax uses project-local esbuild.
- TypeScript: the project's local `tsc --noEmit` when `tsconfig.json` and `node_modules/typescript` exist.
- JSON/package files, YAML parsing, TOML, XML, and INI configuration parsing.
- SQL syntax parsing with sqlglot.
- CSS parser diagnostics with tinycss2, plus unmatched delimiter fallback.
- HTML parser errors and missing image alt text.
- `.env`/dotenv: assignment syntax, duplicate keys, and unclosed quote checks; values are never included in findings or uploaded.
- Project context: redacted, incremental source index capped at 5,000 files/25 MB. Explain/Suggest fix retrieve relevant files by path and terms.
- Basic Dockerfile checks including missing FROM and likely secrets in ARG/ENV.
- Test failures only when a user explicitly runs `skyguard scan ... --run-pytest`; it executes pytest code with a timeout.

No project build, test suite, custom script or application is run by default. TypeScript, JSX, Java and ESLint checks rely on installed tools/config. The supported checks find common classes of errors but cannot prove a project is bug-free. Review analyzer warnings and missing-tool reports; runtime errors require an opt-in runtime SDK/middleware.
