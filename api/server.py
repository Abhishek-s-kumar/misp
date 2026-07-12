from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from mcp_tools.rule_tools import sync_misp_rules, validate_rules, deploy_rules, rollback_rules, rule_status, sync_github_rules, list_quarantine, promote_rule, reject_rule
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

@app.post("/sync-github")
def api_sync_github():
    r = sync_github_rules()
    return vars(r)

class PromoteReq(BaseModel):
    rule_name: str

class RejectReq(BaseModel):
    rule_name: str
    reason: str = ""

@app.get("/quarantine")
def api_list_quarantine():
    return list_quarantine()

@app.post("/quarantine/promote")
def api_promote_quarantine(req: PromoteReq):
    return promote_rule(rule_name=req.rule_name)

@app.post("/quarantine/reject")
def api_reject_quarantine(req: RejectReq):
    return reject_rule(rule_name=req.rule_name, reason=req.reason)

@app.post("/status")
def api_status(req: StatusReq):
    r = rule_status(
        manager_host=req.manager_host,
        host_ip=req.host_ip,
        ssh_user=req.ssh_user,
        ssh_key_path=req.ssh_key_path
    )
    return vars(r)


@app.get("/api/tags")
def api_tags():
    from mcp_tools.rule_tools import _resolve_rules_dir
    import json
    rules_dir = _resolve_rules_dir()
    metadata_dir = rules_dir.parent / "generated" / "metadata"
    counts = {}
    for rule_type in ("sigma", "wazuh", "yara"):
        type_dir = rules_dir / rule_type
        if not type_dir.exists():
            continue
        for f in type_dir.iterdir():
            if not f.is_file():
                continue
            meta_file = metadata_dir / f"{f.stem}.json"
            tags = []
            if meta_file.exists():
                try:
                    tags = json.loads(meta_file.read_text(encoding="utf-8")).get("tags", [])
                except Exception:
                    pass
            for t in tags:
                counts.setdefault(t, {"active_count": 0, "quarantine_count": 0})
                counts[t]["active_count"] += 1
    for entry in list_quarantine():
        for t in entry.get("tags", []):
            counts.setdefault(t, {"active_count": 0, "quarantine_count": 0})
            counts[t]["quarantine_count"] += 1
    return counts


@app.get("/api/rules")
def api_rules(tag: str = None):
    from mcp_tools.rule_tools import _resolve_rules_dir
    import json
    rules_dir = _resolve_rules_dir()
    metadata_dir = rules_dir.parent / "generated" / "metadata"
    out = []
    for rule_type in ("sigma", "wazuh", "yara"):
        type_dir = rules_dir / rule_type
        if not type_dir.exists():
            continue
        for f in type_dir.iterdir():
            if not f.is_file():
                continue
            meta_file = metadata_dir / f"{f.stem}.json"
            tags = []
            if meta_file.exists():
                try:
                    tags = json.loads(meta_file.read_text(encoding="utf-8")).get("tags", [])
                except Exception:
                    pass
            if tag and tag not in tags:
                continue
            status = "active"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    if meta.get("deployment_status") == "conversion_failed":
                        status = "conversion_failed"
                except Exception:
                    pass
            out.append({"name": f.name, "type": rule_type, "tags": tags, "status": status})
    for entry in list_quarantine():
        if tag and tag not in entry.get("tags", []):
            continue
        out.append({"name": entry.get("rule_name"), "type": entry.get("rule_type"),
                     "tags": entry.get("tags", []), "status": "quarantine"})
    return out


@app.post("/api/deploy-filtered")
def api_deploy_filtered(req: DeployReq):
    tags = req.tags or []
    if tags:
        q = list_quarantine()
        blocked = sorted({t for t in tags for e in q if t in e.get("tags", [])})
        if blocked:
            return {"error": "quarantined rules exist for these tags, resolve first", "blocked_tags": blocked}
    r = deploy_rules(dry_run=req.dry_run, host_name=req.host_name, host_ip=req.host_ip,
                      ssh_user=req.ssh_user, ssh_key_path=req.ssh_key_path,
                      rule_names=req.rule_names or None, tags=req.tags or None)
    return vars(r)

# serve dashboard HTML
app.mount("/", StaticFiles(directory="dashboard", html=True), name="dashboard")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9640)
