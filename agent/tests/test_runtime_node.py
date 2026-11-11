import json
import shutil
import subprocess
from pathlib import Path
import pytest

def test_node_express_404_middleware_forwards_event():
    node=shutil.which("node")
    if not node: pytest.skip("Node.js is not installed")
    module=Path(__file__).resolve().parents[1]/"skyguard_agent"/"runtime_node.cjs"
    script=f"""
const {{EventEmitter}}=require('node:events');
const {{configureSkyGuardNode}}=require({json.dumps(str(module))});
let sent;
global.fetch=async (url,options)=>{{sent={{url,payload:JSON.parse(options.body)}};return {{ok:true}}}};
const monitor=configureSkyGuardNode({{apiUrl:'http://127.0.0.1:8000',projectId:'prj_test',token:'sgp_test'}});
const req={{method:'GET',url:'/api/test/runtime-error'}};
const res=new EventEmitter();res.statusCode=404;
monitor.expressMiddleware(req,res,()=>{{}});res.emit('finish');
setTimeout(()=>console.log(JSON.stringify(sent)),30);
"""
    result=subprocess.run([node,"-e",script],capture_output=True,text=True,timeout=5)
    assert result.returncode == 0, result.stderr
    sent=json.loads(result.stdout)
    assert sent["payload"]["level"] == "WARNING"
    assert sent["payload"]["message"] == "HTTP error response: 404 GET /api/test/runtime-error"
