# Testing

Run the backend, agent, and frontend checks from PowerShell:

```powershell
cd backend; python -m pytest tests -q --basetemp=.pytest-tmp
cd ..\agent; python -m pytest tests -q --basetemp=.pytest-tmp
cd ..\frontend; npm run build
```

The agent tests cover finding normalization for Ruff/TypeScript diagnostics, explicit pytest result normalization, Python runtime logging, FastAPI 404 forwarding, Node/Express 404 forwarding, and parser basics. The bundled `examples/demo-project` intentionally contains Python, Java, JavaScript, dotenv, JSON, YAML, SQL, HTML, CSS, TOML, XML and Dockerfile issues; after installing the updated agent dependencies, scan it with `python -m skyguard_agent scan ..\examples\demo-project --local-only`.

Executing project tests is off by default. To opt in for a project you trust, use `skyguard scan PATH --project-id ID --token TOKEN --run-pytest`; this runs test code, with a 120-second default timeout. `--pytest-python` selects the target project's interpreter. Frontend has a production build check but no browser component-test suite. No full browser E2E workflow has been verified.
