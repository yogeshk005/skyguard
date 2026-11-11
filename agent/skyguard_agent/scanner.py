import ast, json, hashlib, re, subprocess, shutil, fnmatch, configparser, os, sys, importlib.util, tempfile, xml.etree.ElementTree as ET
from pathlib import Path
from html.parser import HTMLParser

EXCLUDED={".git",".hg",".svn",".aws",".ssh","node_modules",".venv","venv","env","__pycache__",".next","dist","build","coverage",".pytest_cache",".mypy_cache",".ruff_cache",".tox",".nox",".skyguard-backups"}
EXTS={".py",".java",".js",".mjs",".cjs",".jsx",".ts",".tsx",".json",".html",".htm",".css",".scss",".yaml",".yml",".sql",".toml",".xml",".ini",".cfg"}
CONTEXT_EXTS=EXTS | {".md",".mdx",".txt",".properties",".gradle",".kts",".sh",".bat"}
SENSITIVE={".env",".npmrc",".pypirc","id_rsa","id_ed25519","credentials.json"}
MAX_BYTES=1_000_000
MAX_FILES=12000
MAX_CONTEXT_FILES=5000
MAX_CONTEXT_BYTES=25_000_000

def _project_files(root):
    for current,dirs,files in os.walk(root):
        dirs[:]=sorted(name for name in dirs if name not in EXCLUDED and not (Path(current)/name).is_symlink())
        for name in sorted(files): yield Path(current)/name
def _finding(root,path,line,col,title,message,category,analyzer,lines,severity="HIGH"):
    rel=path.relative_to(root).as_posix()
    lo=max(1,(line or 1)-3); hi=min(len(lines),(line or 1)+3)
    def redact(value):
        return _redact_source(value)
    snippet="\n".join(f"{i}: {redact(lines[i-1].rstrip())}" for i in range(lo,hi))
    fp=hashlib.sha256(f"{rel}:{line}:{category}:{message}".encode()).hexdigest()
    return {"fingerprint":fp,"title":title,"severity":severity,"category":category,"message":message,
            "file_path":rel,"line":line,"column":col,"analyzer":analyzer,"code_snippet":snippet}

def _redact_source(text):
    """Redact common credential assignments before source context leaves the machine."""
    key=r'(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret|token)'
    quoted=re.compile(r'(?im)(\b'+key+r'\b["\']?\s*[:=]\s*)(["\'])(.*?)(["\'])(?=\s*[,;}#]|$)')
    text=quoted.sub(lambda m:m.group(1)+m.group(2)+"[REDACTED]"+m.group(4) if m.group(2)==m.group(4) else m.group(0),text)
    text=re.sub(r'(?im)(\b'+key+r'\b\s*[:=]\s*)(?!["\'])([^\s,;}#]+)',r'\1[REDACTED]',text)
    text=re.sub(r'(?im)(\bBearer\s+)[A-Za-z0-9._~+/=-]+',r'\1[REDACTED]',text)
    text=re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',text)
    return text

def _env_findings(root,path,text):
    """Check dotenv structure locally; never attach values or source snippets."""
    results=[]; seen=set(); lines=text.splitlines()
    for number,line in enumerate(lines,1):
        stripped=line.strip()
        if not stripped or stripped.startswith("#"): continue
        candidate=stripped[7:].lstrip() if stripped.startswith("export ") else stripped
        match=re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$",candidate)
        safe_lines=["[Environment file contents are withheld by SkyGuard]"]
        if not match:
            results.append(_finding(root,path,number,1,"Invalid environment variable assignment","Expected KEY=value syntax. The line value was not uploaded.","CONFIG_ERROR","SkyGuard dotenv parser",safe_lines,"MEDIUM")); continue
        key,value=match.groups()
        if key in seen:
            results.append(_finding(root,path,number,1,"Duplicate environment variable",f"Variable {key} is defined more than once. Values were not uploaded.","CONFIG_ERROR","SkyGuard dotenv parser",safe_lines,"MEDIUM"))
        seen.add(key)
        value=value.strip()
        if value and value[0] in {"'",'"'}:
            quote=value[0]; closing=None; escaped=False
            for index,char in enumerate(value[1:],1):
                if char==quote and not escaped: closing=index; break
                if char=="\\" and not escaped: escaped=True
                else: escaped=False
            trailing=value[closing+1:].strip() if closing is not None else ""
            if closing is None or (trailing and not trailing.startswith("#")):
                results.append(_finding(root,path,number,1,"Unclosed environment value quote","The environment variable value has an opening quote without a matching closing quote. The value was not uploaded.","CONFIG_ERROR","SkyGuard dotenv parser",safe_lines,"MEDIUM"))
    return results

def _java_syntax_findings(root,paths):
    javac=shutil.which("javac")
    if not paths: return []
    if not javac:
        path=paths[0]; lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
        return [_finding(root,path,1,1,"Java analyzer unavailable","Install a JDK with javac to enable Java syntax checks.","ANALYZER_WARNING","SkyGuard analyzer availability",lines,"LOW")]
    syntax=re.compile(r"(?i)(expected|illegal start|reached end of file|unclosed (?:string|text block)|not a statement|class, interface|orphaned case|else without if|identifier expected|illegal character|case, default)")
    type_error=re.compile(r"(?i)(incompatible types|bad operand types|cannot be applied to given types|no suitable method found|bad return type|inconvertible types|unexpected type|not abstract and does not override|has private access)")
    findings=[]
    with tempfile.TemporaryDirectory(prefix="skyguard-javac-") as output_dir:
        for start in range(0,len(paths),100):
            batch=paths[start:start+100]
            try:
                proc=subprocess.run([javac,"-proc:none","-Xmaxerrs","200","-d",output_dir,*map(str,batch)],cwd=root,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=45)
            except subprocess.TimeoutExpired:
                path=batch[0]; lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                findings.append(_finding(root,path,1,1,"Java analyzer timeout","javac exceeded its 45 second limit.","ANALYZER_WARNING","javac",lines,"LOW")); continue
            for raw in (proc.stderr+"\n"+proc.stdout).splitlines():
                match=re.match(r"(.+\.java):(\d+): error: (.+)",raw.strip())
                if not match: continue
                is_syntax=bool(syntax.search(match.group(3))); is_type=bool(type_error.search(match.group(3)))
                if not (is_syntax or is_type): continue
                target=Path(match.group(1)); target=target if target.is_absolute() else (root/target).resolve()
                try: target.relative_to(root)
                except ValueError: continue
                try: lines=target.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                except OSError: lines=[""]
                title="Java syntax error" if is_syntax else "Java compile/type error"
                category="SYNTAX_ERROR" if is_syntax else "TYPE_ERROR"
                findings.append(_finding(root,target,int(match.group(2)),1,title,match.group(3),category,"javac",lines,"HIGH"))
    return findings

def _ruff_findings(root,path,lines):
    """Run Ruff on one Python file; never run project-defined scripts."""
    if importlib.util.find_spec("ruff") is None: return []
    try:
        proc=subprocess.run([sys.executable,"-m","ruff","check","--output-format=json","--no-fix",str(path)],cwd=root,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=15)
    except subprocess.TimeoutExpired:
        return [_finding(root,path,1,1,"Ruff analyzer timeout","Ruff exceeded its 15 second limit.","ANALYZER_WARNING","Ruff",lines,"LOW")]
    try: diagnostics=json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [_finding(root,path,1,1,"Ruff analyzer error",(proc.stderr or "Could not read Ruff output")[:500],"ANALYZER_WARNING","Ruff",lines,"LOW")]
    results=[]
    for diagnostic in diagnostics:
        loc=diagnostic.get("location") or {}
        code=diagnostic.get("code") or "RUFF"
        severity="HIGH" if code in {"F821","E999"} else "MEDIUM"
        results.append(_finding(root,path,loc.get("row",1),loc.get("column",1),f"Python lint issue ({code})",diagnostic.get("message",code),"STATIC_ANALYSIS",f"Ruff {code}",lines,severity))
    return results

def _mypy_findings(root,paths):
    """Run the isolated mypy checker over Python files without project plugins/config execution."""
    if not paths or importlib.util.find_spec("mypy") is None: return []
    findings=[]; omitted=max(0,len(paths)-1000); paths=paths[:1000]
    with tempfile.TemporaryDirectory(prefix="skyguard-mypy-") as cache:
        for start in range(0,len(paths),100):
            batch=paths[start:start+100]
            try:
                proc=subprocess.run([sys.executable,"-m","mypy","--no-config","--no-incremental","--cache-dir",cache,"--show-column-numbers","--no-error-summary","--ignore-missing-imports","--follow-imports=silent",*map(str,batch)],cwd=root,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=60)
            except subprocess.TimeoutExpired:
                path=batch[0]; lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                findings.append(_finding(root,path,1,1,"Python type checker timeout","mypy exceeded its 60 second limit.","ANALYZER_WARNING","mypy",lines,"LOW")); continue
            for raw in (proc.stdout+"\n"+proc.stderr).splitlines():
                match=re.match(r"(.+\.py):(\d+)(?::(\d+))?: error: (.+?)(?:\s+\[[^]]+\])?$",raw.strip())
                if not match: continue
                raw_path,line,col,message=match.groups(); target=Path(raw_path)
                target=target if target.is_absolute() else (root/target).resolve()
                try: target.relative_to(root)
                except ValueError: continue
                try: lines=target.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                except OSError: lines=[""]
                findings.append(_finding(root,target,int(line),int(col or 1),"Python type error",message,"TYPE_ERROR","mypy",lines,"HIGH"))
    if omitted:
        path=paths[0]; lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
        findings.append(_finding(root,path,1,1,"Python type-check file limit reached",f"mypy checked the first 1,000 Python files and skipped {omitted} more to bound scan time.","ANALYZER_WARNING","mypy",lines,"LOW"))
    return findings

def _nearest_package(root,path):
    for base in (path.parent,*path.parent.parents):
        if base!=root and root not in base.parents: continue
        package=base/"package.json"
        if package.is_file():
            try:
                data=json.loads(package.read_text(encoding="utf-8"))
                deps={**data.get("dependencies",{}),**data.get("devDependencies",{})}
                if "react" in deps or "next" in deps: return data
            except (OSError,ValueError,TypeError): pass
        if base==root: break
    return None

def _nearest_node_module(root,path,relative):
    for base in (path.parent,*path.parent.parents):
        if base!=root and root not in base.parents: continue
        candidate=base/"node_modules"/Path(relative)
        if candidate.is_file(): return candidate
        if base==root: break
    return None

def _babel_findings(root,path,text,lines,typescript=False):
    parser=_nearest_node_module(root,path,"@babel/parser/lib/index.js")
    node=shutil.which("node")
    if not parser or not node: return None
    plugins=["jsx"]
    if typescript: plugins.append("typescript")
    script="const fs=require('fs'),p=require(process.env.SKYGUARD_BABEL_PARSER);let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{try{p.parse(s,{sourceType:'unambiguous',plugins:JSON.parse(process.env.SKYGUARD_BABEL_PLUGINS)})}catch(e){console.log(JSON.stringify({message:e.message,line:e.loc?.line||1,column:e.loc?.column+1||1}));process.exitCode=1}})"
    try:
        proc=subprocess.run([node,"-e",script],cwd=root,input=text,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=15,env={**os.environ,"SKYGUARD_BABEL_PARSER":str(parser),"SKYGUARD_BABEL_PLUGINS":json.dumps(plugins)})
    except subprocess.TimeoutExpired:
        return [_finding(root,path,1,1,"React/JavaScript parser timeout","Babel parsing exceeded its 15 second limit.","ANALYZER_WARNING","Babel parser",lines,"LOW")]
    if proc.returncode:
        try: issue=json.loads(proc.stdout.splitlines()[-1])
        except (json.JSONDecodeError,IndexError): issue={"message":(proc.stderr or proc.stdout)[:500],"line":1,"column":1}
        return [_finding(root,path,issue.get("line",1),issue.get("column",1),"JavaScript/JSX syntax error",issue.get("message","Invalid JavaScript/JSX syntax"),"SYNTAX_ERROR","Babel parser",lines)]
    return []

def _typescript_findings(root):
    """Run each local TypeScript project, including monorepo package configs."""
    configs=[]
    for current,dirs,files in os.walk(root):
        dirs[:]=[name for name in dirs if name not in EXCLUDED and not (Path(current)/name).is_symlink()]
        if "tsconfig.json" in files: configs.append(Path(current)/"tsconfig.json")
        if len(configs)>=50: break
    if not configs: return []
    results=[]; node=shutil.which("node")
    pattern=re.compile(r"^(.*)\((\d+),(\d+)\): error (TS\d+): (.*)$")
    for config in configs:
        compiler=_nearest_node_module(root,config,"typescript/bin/tsc")
        if not compiler or not node:
            lines=config.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
            results.append(_finding(root,config,1,1,"TypeScript compiler unavailable","A tsconfig.json exists, but a local TypeScript compiler and Node.js are required for type checking.","ANALYZER_WARNING","SkyGuard analyzer availability",lines,"LOW")); continue
        try:
            proc=subprocess.run([node,str(compiler),"--noEmit","--pretty","false","--project",str(config)],cwd=config.parent,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=45)
        except subprocess.TimeoutExpired:
            lines=config.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
            results.append(_finding(root,config,1,1,"TypeScript analyzer timeout","TypeScript exceeded its 45 second limit.","ANALYZER_WARNING","TypeScript",lines,"LOW")); continue
        start_count=len(results)
        for textline in (proc.stdout+"\n"+proc.stderr).splitlines():
            match=pattern.match(textline.strip())
            if not match: continue
            raw_path,line,col,code,message=match.groups(); target=Path(raw_path)
            if not target.is_absolute(): target=(config.parent/target).resolve()
            try: target.relative_to(root)
            except ValueError: continue
            try: lines=target.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
            except OSError: lines=[""]
            results.append(_finding(root,target,int(line),int(col),f"TypeScript error ({code})",message,"TYPE_ERROR",f"TypeScript {code}",lines,"HIGH"))
        if proc.returncode and len(results)==start_count:
            lines=config.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
            results.append(_finding(root,config,1,1,"TypeScript analyzer error",(proc.stderr or proc.stdout or "Compiler failed without diagnostics")[:500],"ANALYZER_WARNING","TypeScript",lines,"LOW"))
    return results

def _eslint_findings(root,paths):
    """Run package-local ESLint with fixed rules and no project config loading."""
    if not paths: return []
    node=shutil.which("node")
    if not node: return []
    groups={}
    for path in paths:
        eslint=_nearest_node_module(root,path,"eslint/bin/eslint.js")
        if eslint: groups.setdefault(eslint,[]).append(path)
    results=[]
    for eslint,batch_paths in groups.items():
        package_root=eslint.parents[3] if len(eslint.parents)>3 else root
        try:
            package=json.loads((package_root/"node_modules/eslint/package.json").read_text(encoding="utf-8"))
            major=int(str(package.get("version","8")).split(".")[0])
        except (OSError,ValueError,IndexError): major=8
        args=[node,str(eslint)]
        if major>=9: args.extend(["--no-config-lookup"])
        else: args.extend(["--no-eslintrc","--env","browser,es2021,node","--parser-options",'{"ecmaVersion":"latest","sourceType":"module","ecmaFeatures":{"jsx":true}}'])
        args.extend(["--format=json","--rule","no-undef:error","--rule","no-unused-vars:warn","--rule","no-unreachable:error","--rule","no-constant-condition:error","--global","require","--global","module","--global","process","--global","__dirname","--global","__filename","--global","console"])
        if (package_root/"node_modules/eslint-plugin-react/package.json").is_file():
            args.extend(["--plugin","react","--rule","react/jsx-uses-vars:error","--rule","react/jsx-uses-react:error","--rule","react/jsx-key:error","--rule","react/jsx-no-undef:error"])
        if (package_root/"node_modules/eslint-plugin-react-hooks/package.json").is_file():
            args.extend(["--plugin","react-hooks","--rule","react-hooks/rules-of-hooks:error","--rule","react-hooks/exhaustive-deps:warn"])
        for offset in range(0,len(batch_paths),100):
            batch=batch_paths[offset:offset+100]
            try: proc=subprocess.run(args+[str(p) for p in batch],cwd=package_root,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=45)
            except subprocess.TimeoutExpired:
                for path in batch:
                    lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                    results.append(_finding(root,path,1,1,"ESLint analyzer timeout","ESLint exceeded its 45 second limit.","ANALYZER_WARNING","ESLint",lines,"LOW"))
                continue
            try: reports=json.loads(proc.stdout or "[]")
            except json.JSONDecodeError:
                path=batch[0]; lines=path.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                results.append(_finding(root,path,1,1,"ESLint analyzer error",(proc.stderr or "Could not read ESLint JSON output")[:400],"ANALYZER_WARNING","ESLint",lines,"LOW")); continue
            for report in reports:
                target=Path(report.get("filePath", ""))
                try: target=target.resolve(); target.relative_to(root)
                except ValueError: continue
                try: lines=target.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
                except OSError: lines=[""]
                for message in report.get("messages",[]):
                    if message.get("fatal"): continue
                    rule=message.get("ruleId") or "ESLint"
                    severity="HIGH" if message.get("severity")==2 else "MEDIUM"
                    results.append(_finding(root,target,message.get("line",1),message.get("column",1),f"JavaScript lint issue ({rule})",message.get("message",rule),"STATIC_ANALYSIS",f"ESLint {rule}",lines,severity))
    return results

def _jsx_findings(root,path,text,lines):
    """Parse JSX/TSX with the project's existing esbuild, without executing source."""
    esbuild=_nearest_node_module(root,path,"esbuild/lib/main.js")
    node=shutil.which("node")
    if not esbuild or not node:
        parsed=_babel_findings(root,path,text,lines,typescript=path.suffix.lower()==".tsx")
        if parsed is not None: return parsed
        return [_finding(root,path,1,1,"JSX analyzer unavailable","Install project dependencies containing esbuild, or configure TypeScript for TSX checks.","ANALYZER_WARNING","SkyGuard analyzer availability",lines,"LOW")]
    loader="tsx" if path.suffix.lower()==".tsx" else "jsx"
    script="const e=require(process.env.SKYGUARD_ESBUILD);let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{try{e.transformSync(s,{loader:process.env.SKYGUARD_LOADER,logLevel:'silent'})}catch(x){console.error(x.message);process.exitCode=1}})"
    try:
        proc=subprocess.run([node,"-e",script],cwd=root,input=text,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=12,env={**os.environ,"SKYGUARD_LOADER":loader,"SKYGUARD_ESBUILD":str(esbuild)})
    except subprocess.TimeoutExpired:
        return [_finding(root,path,1,1,"JSX analyzer timeout","esbuild exceeded its 12 second limit.","ANALYZER_WARNING","esbuild",lines,"LOW")]
    if proc.returncode:
        message=(proc.stderr or proc.stdout).strip()
        loc=re.search(r":(\d+):(\d+):",message)
        line,col=(int(loc.group(1)),int(loc.group(2))) if loc else (1,1)
        return [_finding(root,path,line,col,"JSX syntax error",message[:500],"SYNTAX_ERROR","esbuild",lines)]
    return []

def _html_findings(root,path,text,lines):
    results=[]
    try:
        import html5lib
        parser=html5lib.HTMLParser(strict=True)
        try: parser.parse(text)
        except Exception as exc:
            position=parser.errors[-1][0] if parser.errors else getattr(exc,"position",(1,1))
            results.append(_finding(root,path,position[0],position[1],"HTML markup error",str(exc)[:400],"STATIC_ANALYSIS","html5lib",lines,"LOW"))
    except ImportError: pass
    except Exception: pass
    from html.parser import HTMLParser
    class AccessibilityParser(HTMLParser):
        def handle_starttag(self,tag,attrs):
            if tag.lower()=="img" and "alt" not in dict(attrs):
                line=self.getpos()[0]
                results.append(_finding(root,path,line,1,"Image missing alt text","Add an alt attribute, or alt=\"\" for decorative images.","ACCESSIBILITY","SkyGuard HTML check",lines,"LOW"))
    try: AccessibilityParser().feed(text)
    except Exception: pass
    return results

def _css_findings(root,path,text,lines):
    try: import tinycss2
    except ImportError: return []
    results=[]
    rules=tinycss2.parse_stylesheet(text,skip_whitespace=True,skip_comments=True)
    errors=[r for r in rules if getattr(r,"type",None)=="error"]
    for rule in rules:
        if getattr(rule,"type",None)=="qualified-rule" and rule.content is not None:
            errors.extend(x for x in tinycss2.parse_declaration_list(rule.content,skip_whitespace=True,skip_comments=True) if getattr(x,"type",None)=="error")
    for error in errors:
        results.append(_finding(root,path,getattr(error,"source_line",1),getattr(error,"source_column",1),"CSS syntax error",getattr(error,"message","Invalid CSS token")[:400],"SYNTAX_ERROR","tinycss2",lines,"MEDIUM"))
    return results

def _dockerfile_findings(root,path,text,lines):
    results=[]; instructions=[]
    for idx,line in enumerate(lines,1):
        stripped=line.strip()
        if not stripped or stripped.startswith("#"): continue
        head=stripped.split(None,1)[0].upper()
        if not re.fullmatch(r"[A-Z]+",head):
            results.append(_finding(root,path,idx,1,"Dockerfile instruction error","Dockerfile instruction must begin with a valid uppercase instruction keyword.","CONFIG_ERROR","SkyGuard Dockerfile check",lines,"MEDIUM"))
            continue
        instructions.append((head,idx,stripped))
    if instructions and not any(head=="FROM" for head,_,_ in instructions):
        results.append(_finding(root,path,instructions[0][1],1,"Dockerfile missing FROM","A Dockerfile needs a FROM base image instruction.","CONFIG_ERROR","SkyGuard Dockerfile check",lines))
    elif instructions and instructions[0][0] not in {"FROM","ARG"}:
        results.append(_finding(root,path,instructions[0][1],1,"Dockerfile instruction before FROM","FROM must be the first instruction, except for an ARG declaration.","CONFIG_ERROR","SkyGuard Dockerfile check",lines))
    for head,line,textline in instructions:
        if head in {"ARG","ENV"} and re.search(r"(?i)(password|secret|token|api[_-]?key)\s*[= ]\s*\S+",textline):
            results.append(_finding(root,path,line,1,"Possible secret in Dockerfile",f"Review {head} value; credentials should not be baked into image layers.","SECURITY","SkyGuard Dockerfile check",lines,"HIGH"))
    return results

def run_pytest(root,python_executable=None,timeout=120):
    """Explicit test execution helper. Call only when the CLI user opts in."""
    root=Path(root).expanduser().resolve(); python_executable=python_executable or sys.executable
    executable=Path(python_executable)
    if not executable.is_absolute():
        resolved=shutil.which(python_executable)
        if not resolved: raise ValueError(f"Python executable not found: {python_executable}")
        python_executable=resolved
    tests=list(root.glob("test_*.py"))
    if not tests and not (root/"tests").exists(): return []
    try:
        proc=subprocess.run([str(python_executable),"-m","pytest","-q","--maxfail=20"],cwd=root,capture_output=True,text=True,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout=exc.stdout.decode(errors="replace") if isinstance(exc.stdout,bytes) else (exc.stdout or "")
        stderr=exc.stderr.decode(errors="replace") if isinstance(exc.stderr,bytes) else (exc.stderr or "")
        test_output=stdout+stderr
        return [{"fingerprint":hashlib.sha256(f"pytest-timeout:{root}".encode()).hexdigest(),"title":"Pytest timed out","severity":"HIGH","category":"TEST_FAILURE","message":f"Pytest exceeded its {timeout} second limit. {test_output[-1000:]}","file_path":None,"line":None,"column":None,"analyzer":"pytest","code_snippet":None}]
    output=(proc.stdout+"\n"+proc.stderr).strip()
    if proc.returncode==0: return []
    summaries=[line.strip() for line in output.splitlines() if line.strip().startswith(("FAILED ","ERROR "))]
    if not summaries: summaries=[line.strip() for line in output.splitlines() if " failed" in line.lower() or " error" in line.lower()][-3:]
    if not summaries: summaries=[output[-1000:] or "pytest exited with a non-zero status"]
    findings=[]
    for summary in summaries[:20]:
        match=re.search(r"([\w./\\-]+\.py)(?:::(\S+))?",summary)
        target=None; rel=None; line=None; snippet=None
        if match:
            candidate=(root/match.group(1)).resolve()
            try:
                candidate.relative_to(root)
                if candidate.is_file():
                    target=candidate; rel=candidate.relative_to(root).as_posix()
                    source=candidate.read_text(encoding="utf-8",errors="replace").splitlines()
                    for trace_match in re.finditer(re.escape(match.group(1))+r":(\d+)",output): line=int(trace_match.group(1)); break
                    if source: snippet="\n".join(f"{i}: {source[i-1]}" for i in range(max(1,(line or 1)-2),min(len(source),(line or 1)+2)+1))
            except (ValueError,OSError): pass
        message=re.sub(r"(?i)(api[_-]?key|secret|password|token)(\s*[=:]\s*)(['\"]?)[^\s,'\";]+",r"\1\2\3[REDACTED]",summary)[:1500]
        fingerprint=hashlib.sha256(f"pytest:{summary}".encode()).hexdigest()
        findings.append({"fingerprint":fingerprint,"title":"Test failure: "+message[:180],"severity":"HIGH","category":"TEST_FAILURE","message":message,"file_path":rel,"line":line,"column":None,"analyzer":"pytest","code_snippet":snippet})
    return findings

def scan_project(root):
    root=Path(root).expanduser().resolve()
    if not root.is_dir(): raise ValueError(f"Project directory does not exist: {root}")
    findings=[]; scanned=0; skipped=0; jsx_paths=[]; js_paths=[]; java_paths=[]; python_paths=[]; has_typescript=False; first_python=None; first_html=None
    context_files=[]; context_bytes=0; context_complete=True
    ignore_file=root/".gitignore"
    try: ignore_patterns=[x.strip() for x in ignore_file.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
    except OSError: ignore_patterns=[]
    for path in _project_files(root):
        rel=path.relative_to(root).as_posix()
        if any(p in EXCLUDED for p in path.parts): continue
        if path.is_symlink(): continue
        env_file=path.name.lower()==".env" or path.name.lower().startswith(".env.")
        if (path.name.lower() in SENSITIVE and not env_file) or (path.name.lower().startswith(".env") and not env_file) or path.suffix.lower() in {".pem",".p12",".pfx",".key"}: continue
        if not env_file and any(fnmatch.fnmatch(rel,pat.lstrip("/")) or rel.startswith(pat.rstrip("/")+"/") for pat in ignore_patterns): continue
        is_dockerfile=path.name.lower()=="dockerfile"
        is_context_file=path.suffix.lower() in CONTEXT_EXTS or is_dockerfile
        if not path.is_file() or (path.suffix.lower() not in EXTS and not is_dockerfile and not is_context_file and not env_file): continue
        try:
            if path.stat().st_size>MAX_BYTES:
                skipped+=1
                if is_context_file: context_complete=False
                continue
            text=path.read_text(encoding="utf-8")
        except (OSError,UnicodeDecodeError):
            skipped+=1
            if is_context_file: context_complete=False
            continue
        scanned+=1
        lines=text.splitlines() or [""]
        ext=path.suffix.lower()
        if env_file:
            findings.extend(_env_findings(root,path,text))
            continue
        if is_context_file:
            clean=_redact_source(text)
            clean_bytes=len(clean.encode("utf-8"))
            if len(context_files)<MAX_CONTEXT_FILES and context_bytes+clean_bytes<=MAX_CONTEXT_BYTES:
                context_files.append({"path":rel,"content":clean})
                context_bytes+=clean_bytes
            else: context_complete=False
        if ext in {".ts",".tsx"}: has_typescript=True
        if ext in {".jsx",".tsx"}: jsx_paths.append(path)
        if ext in {".js",".mjs",".cjs"}: js_paths.append(path)
        if ext==".java": java_paths.append(path)
        if ext==".py":
            python_paths.append(path)
            if first_python is None: first_python=path
        if ext in {".html",".htm"} and first_html is None: first_html=path
        try:
            if ext==".py":
                try: ast.parse(text,filename=str(path))
                except SyntaxError as e:
                    findings.append(_finding(root,path,e.lineno or 1,e.offset or 1,"Python syntax error",e.msg,"SYNTAX_ERROR","Python AST",lines))
                else:
                    findings.extend(_ruff_findings(root,path,lines))
            elif ext==".json":
                try: json.loads(text)
                except json.JSONDecodeError as e:
                    findings.append(_finding(root,path,e.lineno,e.colno,"Invalid JSON",e.msg,"CONFIG_ERROR","Python json parser",lines))
            elif ext==".js" and _nearest_package(root,path):
                if path not in jsx_paths: jsx_paths.append(path)
            elif ext in {".js",".mjs",".cjs"} and shutil.which("node"):
                proc=subprocess.run(["node","--check",str(path)],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=12)
                if proc.returncode:
                    diagnostic=(proc.stderr or proc.stdout).strip()
                    m=re.search(re.escape(str(path))+r":(\d+)(?::(\d+))?",diagnostic) or re.search(r":(\d+)(?::(\d+))?",diagnostic)
                    ln=int(m.group(1)) if m else 1; col=int(m.group(2)) if m and m.group(2) else 1
                    excerpts=diagnostic.splitlines()
                    message="\n".join(excerpts[:6]+excerpts[-2:])[:800]
                    findings.append(_finding(root,path,ln,col,"JavaScript syntax error",message,"SYNTAX_ERROR","node --check",lines))
            elif ext in {".js",".mjs",".cjs"}:
                findings.append(_finding(root,path,1,1,"JavaScript analyzer unavailable","Install Node.js to enable JavaScript syntax checks.","ANALYZER_WARNING","SkyGuard analyzer availability",lines,"LOW"))
            elif ext in {".jsx",".tsx"}:
                findings.extend(_jsx_findings(root,path,text,lines))
            elif ext in {".yaml",".yml"}:
                try:
                    import yaml
                    list(yaml.safe_load_all(text))
                except ImportError: pass
                except Exception as e:
                    mark=getattr(e,"problem_mark",None); ln=(mark.line+1) if mark else 1
                    findings.append(_finding(root,path,ln,1,"YAML parsing error",str(e)[:500],"CONFIG_ERROR","PyYAML",lines))
            elif ext==".sql":
                try:
                    import sqlglot
                    sqlglot.parse(text)
                except ImportError:
                    findings.append(_finding(root,path,1,1,"SQL analyzer unavailable","Install the SkyGuard agent requirements to enable SQL parsing.","ANALYZER_WARNING","SkyGuard analyzer availability",lines,"LOW"))
                except Exception as e:
                    diag=(getattr(e,"errors",None) or [{}])[0]
                    findings.append(_finding(root,path,diag.get("line",1),diag.get("col",1),"SQL syntax error",str(e)[:500],"SYNTAX_ERROR","sqlglot",lines))
            elif ext in {".css",".scss"}:
                findings.extend(_css_findings(root,path,text,lines))
                if not any(f.get("file_path")==path.relative_to(root).as_posix() for f in findings) and text.count("{")!=text.count("}"):
                    findings.append(_finding(root,path,len(lines),1,"Unbalanced CSS braces","Opening and closing brace counts do not match.","STATIC_ANALYSIS","SkyGuard CSS structural check",lines,"MEDIUM"))
            elif ext in {".html",".htm"}:
                findings.extend(_html_findings(root,path,text,lines))
            elif ext==".toml":
                try:
                    try: import tomllib
                    except ImportError: import tomli as tomllib
                    tomllib.loads(text)
                except Exception as e:
                    findings.append(_finding(root,path,getattr(e,"lineno",1),getattr(e,"colno",1),"Invalid TOML",str(e)[:400],"CONFIG_ERROR","Python TOML parser",lines))
            elif ext==".xml":
                try: ET.fromstring(text)
                except ET.ParseError as e:
                    findings.append(_finding(root,path,e.position[0],e.position[1],"Invalid XML",str(e)[:400],"CONFIG_ERROR","Python XML parser",lines))
            elif ext in {".ini",".cfg"}:
                try:
                    parser=configparser.ConfigParser(allow_no_value=True); parser.read_string(text)
                except configparser.Error as e:
                    line=getattr(e,"lineno",1)
                    findings.append(_finding(root,path,line,1,"Invalid INI configuration",str(e)[:400],"CONFIG_ERROR","Python configparser",lines))
            elif is_dockerfile:
                findings.extend(_dockerfile_findings(root,path,text,lines))
        except subprocess.TimeoutExpired:
            findings.append(_finding(root,path,1,1,"Analyzer timeout","The language analyzer exceeded its time limit.","ANALYZER_WARNING","SkyGuard",lines,"LOW"))
        if scanned>=MAX_FILES: break
    if has_typescript: findings.extend(_typescript_findings(root))
    findings.extend(_java_syntax_findings(root,java_paths))
    findings.extend(_mypy_findings(root,python_paths))
    findings.extend(_eslint_findings(root,js_paths))
    if first_python and importlib.util.find_spec("ruff") is None:
        py_lines=first_python.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
        findings.append(_finding(root,first_python,1,1,"Python lint analyzer unavailable","Install the updated agent requirements to enable Ruff checks for undefined names and common lint issues.","ANALYZER_WARNING","SkyGuard analyzer availability",py_lines,"LOW"))
    if first_html:
        try: import html5lib
        except ImportError:
            html_lines=first_html.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
            findings.append(_finding(root,first_html,1,1,"HTML validator unavailable","Install the updated agent requirements to enable strict HTML validation.","ANALYZER_WARNING","SkyGuard analyzer availability",html_lines,"LOW"))
    for path in jsx_paths:
        if not (path.suffix.lower()==".tsx" and (root/"tsconfig.json").is_file()):
            text=path.read_text(encoding="utf-8",errors="replace")
            findings.extend(_jsx_findings(root,path,text,text.splitlines() or [""]))
    if first_python and importlib.util.find_spec("mypy") is None:
        py_lines=first_python.read_text(encoding="utf-8",errors="replace").splitlines() or [""]
        findings.append(_finding(root,first_python,1,1,"Python type checker unavailable","Install the updated SkyGuard agent requirements to enable mypy type checks.","ANALYZER_WARNING","SkyGuard analyzer availability",py_lines,"LOW"))
    if scanned>=MAX_FILES: context_complete=False
    return {"root":str(root),"scanned_files":scanned,"skipped_files":skipped,"findings":findings,
            "context_files":context_files,"context_complete":context_complete,"context_bytes":context_bytes,
            "limitations":"SkyGuard indexes redacted source context for supported text files and runs available syntax, lint, and type checks. Java syntax checks require a JDK; TypeScript/JSX checks require project tools/configuration. .env files are checked locally but their contents are never uploaded. Dynamic logic and runtime errors require tests, builds, or runtime monitoring. No scanner can identify every possible defect."}
