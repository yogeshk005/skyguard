from pathlib import Path
import json
from types import SimpleNamespace
from skyguard_agent.scanner import scan_project, run_pytest
import skyguard_agent.scanner as scanner

def test_detects_invalid_json_and_css(tmp_path):
    (tmp_path / "bad.json").write_text('{"x": 1,}', encoding="utf-8")
    (tmp_path / "bad.css").write_text(".x { color: red;", encoding="utf-8")
    result = scan_project(tmp_path)
    assert len(result["findings"]) == 2
    assert {x["file_path"] for x in result["findings"]} == {"bad.json", "bad.css"}

def test_normalizes_ruff_undefined_name(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print(missing_name)\n", encoding="utf-8")
    monkeypatch.setattr(scanner.importlib.util, "find_spec", lambda name: object() if name == "ruff" else None)
    diagnostic = [{"code":"F821","message":"Undefined name `missing_name`","location":{"row":1,"column":7}}]
    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1,stdout=json.dumps(diagnostic),stderr=""))
    result = scan_project(tmp_path)
    finding = next(item for item in result["findings"] if item["analyzer"] == "Ruff F821")
    assert finding["line"] == 1
    assert finding["severity"] == "HIGH"
    assert "missing_name" in finding["message"]

def test_normalizes_typescript_compiler_diagnostic(tmp_path, monkeypatch):
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{}}', encoding="utf-8")
    compiler=tmp_path / "node_modules" / "typescript" / "bin" / "tsc"
    compiler.parent.mkdir(parents=True)
    compiler.write_text("", encoding="utf-8")
    (tmp_path / "app.ts").write_text("const count: number = 'wrong';\n", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "node.exe" if name == "node" else None)
    output=f"{tmp_path / 'app.ts'}(1,7): error TS2322: Type 'string' is not assignable to type 'number'."
    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=2,stdout=output,stderr=""))
    result=scan_project(tmp_path)
    finding=next(item for item in result["findings"] if item["category"]=="TYPE_ERROR")
    assert finding["file_path"] == "app.ts"
    assert finding["line"] == 1 and finding["column"] == 7
    assert finding["analyzer"] == "TypeScript TS2322"

def test_normalizes_explicit_pytest_failure(tmp_path, monkeypatch):
    tests=tmp_path/"tests"; tests.mkdir()
    test_file=tests/"test_example.py"; test_file.write_text("def test_expected():\n    assert 1 == 2\n",encoding="utf-8")
    output="FAILED tests/test_example.py::test_expected - AssertionError: values differ\n1 failed"
    monkeypatch.setattr(scanner.subprocess,"run",lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout=output,stderr=""))
    results=run_pytest(tmp_path,python_executable="python")
    assert len(results)==1
    assert results[0]["category"]=="TEST_FAILURE"
    assert results[0]["file_path"]=="tests/test_example.py"
    assert "AssertionError" in results[0]["message"]

def test_real_yaml_sql_css_html_toml_and_xml_checks(tmp_path):
    import pytest
    for module in ("yaml","sqlglot","tinycss2","html5lib"):
        pytest.importorskip(module)
    (tmp_path/"bad.yaml").write_text("items: [unfinished\n",encoding="utf-8")
    (tmp_path/"bad.sql").write_text("SELECT FROM WHERE;",encoding="utf-8")
    (tmp_path/"bad.css").write_text(".card { color red; }",encoding="utf-8")
    (tmp_path/"bad.html").write_text("<!doctype html><html><head><title>x</title></head><body><img src='x.png'></body></html>",encoding="utf-8")
    (tmp_path/"bad.toml").write_text("value = [\n",encoding="utf-8")
    (tmp_path/"bad.xml").write_text("<root><item></root>",encoding="utf-8")
    findings=scan_project(tmp_path)["findings"]
    titles={item["title"] for item in findings}
    assert "YAML parsing error" in titles
    assert "SQL syntax error" in titles
    assert "CSS syntax error" in titles
    assert "Image missing alt text" in titles
    assert "Invalid TOML" in titles
    assert "Invalid XML" in titles

def test_normalizes_eslint_diagnostic(tmp_path,monkeypatch):
    source=tmp_path/"app.js"; source.write_text("console.log(missingName);\n",encoding="utf-8")
    eslint=tmp_path/"node_modules"/"eslint"/"bin"/"eslint.js"; eslint.parent.mkdir(parents=True); eslint.write_text("",encoding="utf-8")
    report=[{"filePath":str(source),"messages":[{"ruleId":"no-undef","severity":2,"message":"'missingName' is not defined.","line":1,"column":13}]}]
    monkeypatch.setattr(scanner.shutil,"which",lambda name:"node.exe" if name=="node" else None)
    monkeypatch.setattr(scanner.subprocess,"run",lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout=json.dumps(report),stderr=""))
    findings=scanner._eslint_findings(tmp_path,[source])
    assert len(findings)==1
    assert findings[0]["analyzer"]=="ESLint no-undef" and findings[0]["severity"]=="HIGH"
