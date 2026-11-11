import json

from skyguard_agent.report import build_report, classify_error, render_html, render_terminal
from skyguard_agent import cli


def test_report_includes_exact_source_line_and_location(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("x = 1\nprint(missing_name)\n", encoding="utf-8")
    result = {
        "root": str(tmp_path), "scanned_files": 1, "skipped_files": 0,
        "limitations": "Static checks only.", "findings": [{
            "fingerprint": "abc", "title": "Python undefined name", "message": "Undefined name `missing_name`.",
            "category": "STATIC_ERROR", "analyzer": "Ruff F821", "file_path": "sample.py", "line": 2,
        }],
    }
    report = build_report(result, "skipped: GEMINI_API_KEY is not set")
    assert report["counts_by_error_type"] == {"NameError": 1}
    assert report["issues"][0]["offending_code"] == "print(missing_name)"
    rendered = render_terminal(report)
    assert f"{source.resolve()}:2" in rendered
    assert "print(missing_name)" in rendered


def test_empty_report_has_explicit_success(tmp_path):
    report = build_report({"root": str(tmp_path), "findings": [], "scanned_files": 0, "skipped_files": 0})
    assert "SUCCESS: No errors" in render_terminal(report)
    assert "No errors" in render_html(report)


def test_html_escapes_source_and_report_is_json_serializable(tmp_path):
    result = {"root": str(tmp_path), "findings": [{
        "title": "HTML parse issue", "message": "bad <tag>", "category": "PARSE_ERROR",
        "file_path": "x.html", "line": 1, "code_snippet": "1: <script>alert(1)</script>",
    }]}
    report = build_report(result)
    html = render_html(report)
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    json.dumps(report)


def test_classifier_covers_common_language_errors():
    assert classify_error({"title": "Python syntax error", "message": "invalid syntax"}) == "SyntaxError"
    assert classify_error({"title": "Python type error", "message": "incompatible types"}) == "TypeError"


def test_connection_is_saved_outside_project_and_reloaded(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    config = tmp_path / "user-config"
    monkeypatch.setattr(cli, "_config_dir", lambda: config)
    saved = cli._save_connection(project, "http://localhost:8000", "prj_demo", "secret-token")
    assert project not in saved.parents
    if cli.os.name != "nt":
        assert saved.stat().st_mode & 0o077 == 0
    assert cli._load_connection(project)["project_id"] == "prj_demo"
