"""Opt-in Python runtime error forwarding to a SkyGuard project."""
import logging
import re
import threading
import traceback
import asyncio
from pathlib import Path
from urllib.parse import quote

import requests


def _send_event(api_url, project_id, token, timeout, payload):
    requests.post(
        f"{api_url.rstrip('/')}/api/projects/{quote(project_id, safe='')}/runtime-logs",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    ).raise_for_status()


class SkyGuardLogHandler(logging.Handler):
    """Forward ERROR+ records (including exception tracebacks) to SkyGuard."""

    def __init__(self, api_url: str, project_id: str, token: str, timeout: float = 4.0, project_root: str | None = None):
        super().__init__(level=logging.ERROR)
        self.api_url = api_url.rstrip("/")
        self.project_id = project_id
        self.token = token
        self.timeout = timeout
        self.project_root = Path(project_root).resolve() if project_root else None
        self._local = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        # Never let network failures recursively produce more log records.
        if getattr(self._local, "sending", False):
            return
        try:
            message = self.format(record)
            stack = "".join(traceback.format_exception(*record.exc_info)) if record.exc_info else ""
            if self.project_root:
                stack = stack.replace(str(self.project_root), ".").replace(str(self.project_root).replace("\\", "/"), ".")
            secret_pattern = r"(?i)(api[_-]?key|secret|password|token|authorization)(\s*[=:]\s*)(['\"]?)[^\s,'\";]+"
            message = re.sub(secret_pattern, r"\1\2\3[REDACTED]", message)
            stack = re.sub(secret_pattern, r"\1\2\3[REDACTED]", stack)
            file_path, line = record.pathname, record.lineno
            match = re.search(r'File "([^"]+)", line (\d+)', stack)
            if match:
                file_path, line = match.group(1), int(match.group(2))
            try:
                file_path = Path(file_path).resolve().relative_to(self.project_root).as_posix() if self.project_root else Path(file_path).name
            except (OSError, ValueError):
                file_path = Path(file_path).name
            self._local.sending = True
            _send_event(self.api_url,self.project_id,self.token,self.timeout,
                {"level": record.levelname, "message": message[:6000], "stack_trace": stack[:12000],
                 "file_path": file_path[:1000], "line": line})
        except Exception:
            # Keep application behavior unchanged if SkyGuard is unavailable.
            self.handleError(record)
        finally:
            self._local.sending = False


def configure_runtime_monitoring(api_url: str, project_id: str, token: str,
                                 logger_names=("", "uvicorn.error"), level=logging.ERROR, project_root: str | None = None):
    """Attach a handler to root and selected loggers; safe to call more than once."""
    handler = SkyGuardLogHandler(api_url, project_id, token, project_root=project_root)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    for name in logger_names:
        target = logging.getLogger(name)
        if not any(isinstance(h, SkyGuardLogHandler) and h.project_id == project_id for h in target.handlers):
            target.addHandler(handler)
    return handler


def configure_fastapi_monitoring(app, api_url: str, project_id: str, token: str, timeout: float = 4.0):
    """Report HTTP 4xx/5xx responses (including route-not-found 404s) to SkyGuard.

    Call once after creating the FastAPI app. HTTP response events are forwarded
    off the event loop so a local SkyGuard outage does not delay API responses.
    """
    endpoint=api_url.rstrip("/")

    @app.middleware("http")
    async def skyguard_http_errors(request, call_next):
        try:
            response=await call_next(request)
        except Exception as exc:
            payload={"level":"ERROR","message":f"HTTP error response: 500 {request.method} {request.url.path} ({type(exc).__name__})",
                     "stack_trace":"","file_path":None,"line":None}
            try: await asyncio.to_thread(_send_event,endpoint,project_id,token,timeout,payload)
            except Exception: logging.getLogger("skyguard.runtime").warning("Could not forward HTTP 500 to SkyGuard")
            raise
        if response.status_code >= 400:
            level="ERROR" if response.status_code >= 500 else "WARNING"
            payload={"level":level,"message":f"HTTP error response: {response.status_code} {request.method} {request.url.path}",
                     "stack_trace":"","file_path":None,"line":None}
            try: await asyncio.to_thread(_send_event,endpoint,project_id,token,timeout,payload)
            except Exception: logging.getLogger("skyguard.runtime").warning("Could not forward HTTP error response to SkyGuard")
        return response

    return app
