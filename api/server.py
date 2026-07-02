from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from mcp_tools.rule_tools import sync_misp_rules, validate_rules, deploy_rules, rollback_rules, rule_status
from dotenv import load_dotenv
import uvicorn, os

load_dotenv()
app = FastAPI(title="MISP→Wazuh API")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class SyncReq(BaseModel):
    since: Optional[str] = None
    misp_provider: str = "mock"

class ValidateReq(BaseModel):
    rule_dir: str

class DeployReq(BaseModel):
    dry_run: bool = True
    host_name: str = ""
    host_ip: str = ""
    ssh_user: str = ""
    ssh_key_path: str = ""
    rule_names: list[str] = []
    tags: list[str] = []

class RollbackReq(BaseModel):
    tag: str
    host_name: str = ""
    host_ip: str = ""
    ssh_user: str = ""
    ssh_key_path: str = ""

class StatusReq(BaseModel):
    manager_host: str
    host_ip: str = ""
    ssh_user: str = ""
    ssh_key_path: str = ""

@app.post("/sync")
def api_sync(req: SyncReq):
    r = sync_misp_rules(since=req.since, misp_provider=req.misp_provider)
    return vars(r)

@app.post("/validate")
def api_validate(req: ValidateReq):
    r = validate_rules(req.rule_dir)
    return vars(r)

@app.post("/deploy")
def api_deploy(req: DeployReq):
    r = deploy_rules(dry_run=req.dry_run, host_name=req.host_name,
                     host_ip=req.host_ip, ssh_user=req.ssh_user, ssh_key_path=req.ssh_key_path,
                     rule_names=req.rule_names or None, tags=req.tags or None)
    return vars(r)

@app.post("/rollback")
def api_rollback(req: RollbackReq):
    r = rollback_rules(tag=req.tag, host_name=req.host_name,
                       host_ip=req.host_ip, ssh_user=req.ssh_user, ssh_key_path=req.ssh_key_path)
    return vars(r)

@app.post("/status")
def api_status(req: StatusReq):
    r = rule_status(
        manager_host=req.manager_host,
        host_ip=req.host_ip,
        ssh_user=req.ssh_user,
        ssh_key_path=req.ssh_key_path
    )
    return vars(r)

# serve dashboard HTML
app.mount("/", StaticFiles(directory="dashboard", html=True), name="dashboard")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9640)
