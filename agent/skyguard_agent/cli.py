"""SkyGuard agent CLI: connect, scan, watch, and apply reviewed suggestions."""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .gemini import GeminiClient
from .report import build_report, render_html, render_terminal
from .scanner import EXCLUDED, EXTS, CONTEXT_EXTS, _project_files, scan_project, run_pytest


def _connection_options(parser):
    parser.add_argument("path", help="Local project directory")
    parser.add_argument("--api", default=None, help="SkyGuard API URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--project-id", help="Registered SkyGuard project ID")
    parser.add_argument("--token", help="Project connection token")


def _config_dir() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "SkyGuard" / "connections"


def _connection_file(root: Path) -> Path:
    identity = str(root.resolve()).casefold().encode("utf-8")
    return _config_dir() / (hashlib.sha256(identity).hexdigest() + ".json")


def _save_connection(root: Path, api: str, project_id: str, token: str) -> Path:
    path = _connection_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"path": str(root.resolve()), "api": api, "project_id": project_id, "token": token}, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _load_connection(root: Path) -> dict | None:
    path = _connection_file(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if Path(data.get("path", "")).resolve() == root.resolve() else None
    except (OSError, ValueError, TypeError):
        return None


def _upload(result, api, project_id, token):
    body = {"project_id": project_id, "findings": result["findings"], "files_scanned": result["scanned_files"]}
    response = requests.post(api.rstrip("/") + "/api/findings/bulk", json=body, headers={"Authorization": "Bearer " + token}, timeout=60)
    response.raise_for_status()
    return response.json()


def _upload_context(result, api, project_id, token):
    """Synchronize changed, redacted source context; .env values are excluded by scanner."""
    if not result.get("context_files") and not result.get("context_complete", False):
        return {"received": 0, "manifest_files": 0, "complete": bool(result.get("context_complete", False))}
    headers = {"Authorization": "Bearer " + token}
    base = api.rstrip("/") + f"/api/projects/{project_id}/context"
    known_response = requests.get(base + "/hashes", headers=headers, timeout=30)
    known_response.raise_for_status()
    known = known_response.json()
    files = []
    for item in result["context_files"]:
        digest = hashlib.sha256(item["content"].encode("utf-8")).hexdigest()
        if known.get(item["path"]) != digest:
            files.append({"path": item["path"], "content": item["content"], "sha256": digest})
    body = {"files": files, "paths": [item["path"] for item in result["context_files"]], "complete": result.get("context_complete", False)}
    response = requests.post(base, json=body, headers=headers, timeout=120)
    response.raise_for_status()
    return response.json()


def _clear_context(api, project_id, token):
    response = requests.delete(api.rstrip("/") + f"/api/projects/{project_id}/context", headers={"Authorization": "Bearer " + token}, timeout=30)
    response.raise_for_status()


def _snapshot(root):
    root = Path(root).resolve()
    state = {}
    for path in _project_files(root):
        if path.is_symlink() or not path.is_file() or any(part in EXCLUDED for part in path.parts):
            continue
        env_file = path.name.lower() == ".env" or path.name.lower().startswith(".env.")
        if (path.name.lower().startswith(".env") and not env_file) or (path.suffix.lower() not in CONTEXT_EXTS and path.suffix.lower() not in EXTS and path.name.lower() != "dockerfile" and not env_file):
            continue
        try:
            stat = path.stat()
            if stat.st_size <= 1_000_000:
                state[path.relative_to(root).as_posix()] = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            continue
    return state


def _emit_report(result, root, gemini_status, args):
    report = build_report(result, gemini_status)
    print(render_terminal(report))
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[SkyGuard] JSON report: {output.resolve()}")
    if getattr(args, "html", None):
        output = Path(args.html).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_html(report), encoding="utf-8")
        print(f"[SkyGuard] HTML report: {output.resolve()}")
    return report


def _scan_once(args, *, upload=True):
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory does not exist: {root}")
    print(f"[SkyGuard] Scanning and indexing {root} ...")
    result = scan_project(root)
    if getattr(args, "run_pytest", False):
        print("[SkyGuard] Running requested pytest checks...")
        result["findings"].extend(run_pytest(root, getattr(args, "pytest_python", None), timeout=max(1, min(getattr(args, "test_timeout", 120), 900))))
    print(f"[SkyGuard] Analyzing {result['scanned_files']} files...")

    api = getattr(args, "api", None) or "http://127.0.0.1:8000"
    project_id, token = getattr(args, "project_id", None), getattr(args, "token", None)
    if not getattr(args, "local_only", False) and (not project_id or not token):
        saved = _load_connection(root)
        if saved:
            api, project_id, token = saved["api"], saved["project_id"], saved["token"]
            print("[SkyGuard] Using saved connection credentials.")

    gemini_status = "disabled (local analysis only)"
    if getattr(args, "with_gemini", False):
        annotations, gemini_status = GeminiClient().explain_and_suggest(result["findings"], result.get("context_files", []), log=print)
        for index, finding in enumerate(result["findings"]):
            key = str(finding.get("fingerprint") or f"issue-{index + 1}")
            annotation = annotations.get(key, {})
            finding.update({k: annotation.get(k, "") for k in ("explanation", "suggested_fix_diff", "original_code", "fixed_code")})

    upload_error = None
    if upload and not getattr(args, "local_only", False):
        if not project_id or not token:
            upload_error = "No saved project connection. Run `skyguard connect <project_path> --project-id ... --token ...` or use --local-only."
        else:
            try:
                print("[SkyGuard] Uploading findings and redacted source index...")
                uploaded = _upload(result, api, project_id, token)
                if getattr(args, "no_context_upload", False):
                    _clear_context(api, project_id, token)
                    context = {"received": 0, "manifest_files": 0}
                else:
                    context = _upload_context(result, api, project_id, token)
                print(f"[SkyGuard] Uploaded {uploaded.get('inserted', 0)} new finding(s); indexed {context.get('manifest_files', 0)} codebase files (updated {context.get('received', 0)}).")
            except requests.RequestException as exc:
                upload_error = f"Upload failed: {exc}"

    _emit_report(result, root, gemini_status, args)
    if upload_error:
        print(f"[SkyGuard] ERROR: {upload_error}", file=sys.stderr)
        print("[SkyGuard] Local scan report is complete; backend synchronization failed.")
    else:
        print("[SkyGuard] Done.")
    return 3 if upload_error else 0


def _connect(args):
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory does not exist: {root}")
    if not args.project_id or not args.token:
        raise ValueError("connect requires --project-id and --token from the SkyGuard project settings")
    api = args.api or "http://127.0.0.1:8000"
    _save_connection(root, api, args.project_id, args.token)
    print(f"[SkyGuard] Connected {root} to project {args.project_id}.")
    return _scan_once(args)


def _watch(args):
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory does not exist: {root}")
    previous = None
    print(f"[SkyGuard] Watching {root} (poll every {args.interval}s). Press Ctrl+C to stop.")
    try:
        while True:
            current = _snapshot(root)
            if current != previous:
                if previous is not None:
                    print("[SkyGuard] Source changes detected; waiting for edits to settle...")
                    time.sleep(args.debounce)
                _scan_once(args)
                previous = _snapshot(root)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("[SkyGuard] Watch stopped.")
        return 0


def _serve(args):
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project directory does not exist: {root}")
    saved = _load_connection(root)
    args.api = args.api or (saved and saved["api"])
    args.project_id = args.project_id or (saved and saved["project_id"])
    args.token = args.token or (saved and saved["token"])
    if not args.project_id or not args.token:
        raise ValueError("No project credentials found. Run `skyguard connect <project_path> --project-id ... --token ...` first.")
    args.api = args.api or "http://127.0.0.1:8000"
    if args.project_id and args.token:
        _save_connection(root, args.api, args.project_id, args.token)

    def allowed_origin(origin):
        try:
            parsed = urlsplit(origin)
            return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"} and parsed.port is not None and 5173 <= parsed.port <= 5190
        except ValueError:
            return False

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status, payload, origin=None):
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(encoded)

        def _authorized_origin(self):
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            if host not in {"127.0.0.1:8765", "localhost:8765"} or not allowed_origin(origin):
                self._reply(403, {"detail": "Only the local SkyGuard dashboard may use this agent."})
                return None
            return origin

        def do_OPTIONS(self):
            origin = self._authorized_origin()
            if origin:
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SkyGuard-Request")
                self.send_header("Access-Control-Max-Age", "300")
                self.end_headers()

        def do_GET(self):
            origin = self._authorized_origin()
            if not origin:
                return
            if self.path != "/health":
                self._reply(404, {"detail": "Not found"}, origin)
                return
            self._reply(200, {"status": "ready", "project_id": args.project_id}, origin)

        def do_POST(self):
            origin = self._authorized_origin()
            if not origin:
                return
            if self.path != "/scan" or self.headers.get("X-SkyGuard-Request") != "1":
                self._reply(404, {"detail": "Not found"}, origin)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 4096:
                    self._reply(413, {"detail": "Request too large"}, origin)
                    return
                payload = json.loads(self.rfile.read(length) or b"{}")
                if payload.get("project_id") != args.project_id:
                    self._reply(403, {"detail": "Project does not match the connected local agent."}, origin)
                    return
                print("[SkyGuard] Dashboard requested a fresh local scan.", flush=True)
                status = _scan_once(args)
                self._reply(200 if status == 0 else 502, {"ok": status == 0, "detail": "Scan completed and findings synchronized." if status == 0 else "Scan completed locally, but synchronization failed."}, origin)
            except Exception as exc:
                self._reply(500, {"detail": str(exc)}, origin)

        def log_message(self, fmt, *values):
            print("[SkyGuard local agent] " + (fmt % values), flush=True)

    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print(f"[SkyGuard] Local refresh agent ready for {root} at http://127.0.0.1:8765", flush=True)
    print("[SkyGuard] Keep this terminal open. Dashboard Refresh now rescans this folder.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[SkyGuard] Local refresh agent stopped.")
    finally:
        server.server_close()
    return 0


def _apply(args):
    report_path = Path(args.report).expanduser().resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    root = Path(report["project_root"]).resolve()
    for issue in report.get("issues", []):
        old, new = issue.get("original_code"), issue.get("fixed_code")
        if not old or not new or not issue.get("absolute_path"):
            continue
        target = Path(issue["absolute_path"]).resolve()
        if root not in target.parents or target.name.lower().startswith(".env"):
            print(f"Skipped unsafe path: {target}")
            continue
        source = target.read_text(encoding="utf-8")
        if source.count(old) != 1:
            print(f"Skipped {target}: exact original text is missing or ambiguous.")
            continue
        print(f"Suggested fix for {target}:{issue.get('line')}\n{issue.get('suggested_fix_diff') or '(diff unavailable)'}")
        if input("Apply this change? [y/N] ").strip().lower() != "y":
            continue
        backup_dir = root / ".skyguard-backups"
        backup_dir.mkdir(exist_ok=True)
        backup = backup_dir / (target.name + "." + str(int(time.time())) + ".bak")
        backup.write_text(source, encoding="utf-8")
        target.write_text(source.replace(old, new, 1), encoding="utf-8")
        print(f"Applied; original saved to {backup}")


def main():
    parser = argparse.ArgumentParser(prog="skyguard", description="Scan and report project errors with SkyGuard")
    sub = parser.add_subparsers(dest="command", required=True)
    connect = sub.add_parser("connect", help="Save a project connection and run the first scan")
    _connection_options(connect)
    scan = sub.add_parser("scan", help="Run a scan (uses saved connection when available)")
    _connection_options(scan)
    watch = sub.add_parser("watch", help="Rescan and report whenever source files change")
    _connection_options(watch)
    serve = sub.add_parser("serve", help="Let the dashboard trigger a fresh local scan on Refresh")
    _connection_options(serve)
    apply = sub.add_parser("apply", help="Apply exact Gemini suggestions after per-change confirmation")
    apply.add_argument("report", help="JSON report created by scan --output")
    for command in (scan, connect):
        command.add_argument("--local-only", action="store_true", help="Do not upload findings or source context")
        command.add_argument("--output", help="Write a JSON report")
        command.add_argument("--html", help="Write a standalone HTML report")
        command.add_argument("--run-pytest", action="store_true", help="Explicitly execute project pytest tests")
        command.add_argument("--pytest-python", help="Python executable for pytest")
        command.add_argument("--test-timeout", type=int, default=120)
        command.add_argument("--no-context-upload", action="store_true", help="Clear server source context after scan")
        command.add_argument("--with-gemini", action="store_true", help="Opt in to Gemini explanations and fix suggestions")
    watch.add_argument("--interval", type=float, default=2.0)
    watch.add_argument("--debounce", type=float, default=1.0)
    watch.add_argument("--no-context-upload", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "connect":
            return _connect(args)
        if args.command == "scan":
            return _scan_once(args)
        if args.command == "watch":
            args.interval = max(1.0, args.interval)
            args.debounce = max(0.25, args.debounce)
            return _watch(args)
        if args.command == "serve":
            return _serve(args)
        if args.command == "apply":
            _apply(args)
            return 0
    except Exception as exc:
        print(f"[SkyGuard] ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
