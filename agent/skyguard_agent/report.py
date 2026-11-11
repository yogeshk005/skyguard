"""Terminal, JSON, and HTML reports for local SkyGuard scans."""
from __future__ import annotations

import html
import re
from pathlib import Path

from .scanner import _redact_source

KNOWN_TYPES = (
    "ZeroDivisionError", "FileNotFoundError", "NullPointerException", "StackOverflowError",
    "OutOfMemoryError", "SegmentationFault", "IndentationError", "SyntaxError", "RuntimeError",
    "LogicError", "TypeError", "ValueError", "NameError", "IndexError", "KeyError",
    "AttributeError", "CompilationError", "SemanticError", "LinkerError", "ArithmeticError",
    "IOError", "TimeoutError", "OverflowError", "ReferenceError", "AssertionError", "ParseError",
)


def classify_error(finding: dict) -> str:
    title = (finding.get("title") or "").lower()
    message = finding.get("message") or ""
    if "indent" in message.lower() and "syntax" in title:
        return "IndentationError"
    if "python syntax" in title or "javascript" in title and "syntax" in title or "java syntax" in title or "jsx syntax" in title:
        return "SyntaxError"
    if "python type error" in title or "typescript error" in title or "java compile/type" in title:
        return "TypeError"
    if "ruff f821" in (finding.get("analyzer") or "").lower() or "undefined name" in message.lower():
        return "NameError"
    if "no-undef" in (finding.get("analyzer") or "").lower():
        return "ReferenceError"
    if "test failure" in title:
        return "AssertionError" if "assert" in message.lower() else "LogicError"
    for error_type in KNOWN_TYPES:
        if re.search(rf"\b{re.escape(error_type)}\b", message):
            return error_type
    if finding.get("category") in {"RUNTIME_ERROR", "HTTP_ERROR"}:
        return "RuntimeError"
    if finding.get("category") in {"CONFIG_ERROR"} or "parser" in (finding.get("analyzer") or "").lower():
        return "ParseError"
    if finding.get("category") in {"PARSE_ERROR", "SYNTAX_ERROR"}:
        return "ParseError" if finding.get("category") == "PARSE_ERROR" else "SyntaxError"
    if finding.get("category") == "TYPE_ERROR":
        return "TypeError"
    if finding.get("category") in {"ACCESSIBILITY", "SECURITY", "STATIC_ANALYSIS"}:
        return "SemanticError"
    if finding.get("category") == "HTTP_ERROR":
        return "RuntimeError"
    if finding.get("category") == "ANALYZER_WARNING":
        return "AnalyzerUnavailable"
    return "LogicError" if finding.get("category") == "TEST_FAILURE" else (finding.get("category") or "SoftwareError")


def _offending_line(root: Path, finding: dict) -> str:
    relative = (finding.get("file_path") or "").replace("\\", "/")
    if Path(relative).name.lower() == ".env" or Path(relative).name.lower().startswith(".env."):
        return "[environment value withheld]"
    line_number = finding.get("line")
    if line_number and relative:
        source = root / relative
        try:
            line = source.read_text(encoding="utf-8", errors="replace").splitlines()[line_number - 1]
            return _redact_source(line).strip()[:1000] if line.strip() else "[blank source line]"
        except (OSError, IndexError, ValueError):
            if line_number:
                try:
                    if line_number > len(source.read_text(encoding="utf-8", errors="replace").splitlines()):
                        return "[end of file]"
                except OSError:
                    pass
    for line in (finding.get("code_snippet") or "").splitlines():
        match = re.match(r"\s*(\d+):\s?(.*)$", line)
        if match and (not line_number or int(match.group(1)) == line_number):
            return match.group(2)[:1000]
    return "[source line unavailable]"


def build_report(result: dict, gemini_status: str = "not_requested") -> dict:
    root = Path(result.get("root") or ".").expanduser().resolve()
    issues = []
    for finding in result.get("findings", []):
        relative = finding.get("file_path")
        full_path = str((root / relative).resolve()) if relative else None
        issues.append({
            **finding,
            "error_type": classify_error(finding),
            "absolute_path": full_path,
            "offending_code": _offending_line(root, finding),
            "short_description": finding.get("message") or finding.get("title") or "No description provided.",
            "explanation": finding.get("explanation") or "",
            "suggested_fix_diff": finding.get("suggested_fix_diff") or "",
            "original_code": finding.get("original_code") or "",
            "fixed_code": finding.get("fixed_code") or "",
        })
    counts = {}
    for issue in issues:
        counts[issue["error_type"]] = counts.get(issue["error_type"], 0) + 1
    return {
        "project_root": str(root),
        "files_scanned": result.get("scanned_files", 0),
        "files_skipped": result.get("skipped_files", 0),
        "context_files_indexed": len(result.get("context_files", [])),
        "context_complete": result.get("context_complete", False),
        "total_findings": len(issues),
        "counts_by_error_type": dict(sorted(counts.items())),
        "gemini_status": gemini_status,
        "limitations": result.get("limitations", ""),
        "issues": issues,
    }


def render_terminal(report: dict) -> str:
    lines = ["", "=" * 76, "SKYGUARD SCAN REPORT", "=" * 76,
             f"Project: {report['project_root']}",
             f"Files scanned: {report['files_scanned']} | skipped: {report['files_skipped']} | context indexed: {report['context_files_indexed']}"]
    if report["counts_by_error_type"]:
        lines.append("Findings by type:")
        for name, count in report["counts_by_error_type"].items():
            lines.append(f"  {name}: {count}")
    if not report["issues"]:
        lines.extend(["", "SUCCESS: No errors were detected by the available analyzers."])
    else:
        for number, issue in enumerate(report["issues"], 1):
            location = f"{issue['absolute_path'] or '[project]'}:{issue.get('line') or '?'}:{issue.get('column_no') or issue.get('column') or '?'}"
            lines.extend(["", f"[{number}] {issue['error_type']} - {issue.get('title', 'Finding')}",
                          f"Location: {location}", f"Offending code: {issue['offending_code']}",
                          f"Description: {issue['short_description']}"])
            if issue["explanation"]:
                lines.append(f"Explanation: {issue['explanation']}")
            if issue["suggested_fix_diff"]:
                lines.append("Suggested fix (diff):")
                lines.extend("  " + row for row in issue["suggested_fix_diff"].splitlines())
            elif report["gemini_status"] != "not_requested":
                lines.append("Suggested fix: unavailable; see Gemini status below.")
    lines.extend(["", f"Gemini: {report['gemini_status']}"])
    if report.get("limitations"):
        lines.append(f"Coverage: {report['limitations']}")
    lines.extend(["=" * 76, ""])
    return "\n".join(lines)


def render_html(report: dict) -> str:
    esc = html.escape
    cards = []
    for issue in report["issues"]:
        diff = f"<h4>Suggested fix</h4><pre>{esc(issue['suggested_fix_diff'])}</pre>" if issue["suggested_fix_diff"] else ""
        explanation = f"<p><b>Explanation:</b> {esc(issue['explanation'])}</p>" if issue["explanation"] else ""
        cards.append(f"<article><h2>{esc(issue['error_type'])}: {esc(issue.get('title','Finding'))}</h2><p><b>Location:</b> <code>{esc(issue.get('absolute_path') or '[project]')}:{esc(str(issue.get('line') or '?'))}</code></p><pre>{esc(issue['offending_code'])}</pre><p>{esc(issue['short_description'])}</p>{explanation}{diff}</article>")
    summary = " ".join(f"<li>{esc(name)}: {count}</li>" for name,count in report["counts_by_error_type"].items())
    empty = "<p class='success'>SUCCESS: No errors were detected by the available analyzers.</p>" if not cards else ""
    limitation = f"<p>{esc(report['limitations'])}</p>" if report["limitations"] else ""
    return ("<!doctype html><html><head><meta charset='utf-8'><title>SkyGuard report</title>"
            "<style>body{font:15px system-ui;max-width:1100px;margin:32px auto;padding:0 20px;color:#222}"
            "article{border:1px solid #ddd;border-radius:8px;padding:18px;margin:16px 0}"
            "pre{white-space:pre-wrap;background:#f5f5f3;padding:12px;overflow:auto}.success{color:#17663b;font-weight:bold}</style></head><body>"
            f"<h1>SkyGuard scan report</h1><p>{report['files_scanned']} files scanned; {report['total_findings']} findings; Gemini: {esc(report['gemini_status'])}</p>"
            f"<ul>{summary}</ul>{empty}{''.join(cards)}{limitation}</body></html>")
