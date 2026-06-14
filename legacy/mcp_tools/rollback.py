import os
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from git import Repo
import structlog

log = structlog.get_logger()

def rollback_rules(
    target_tag: str,
    hosts: str = "all"
) -> Dict[str, Any]:
    """
    Restore IOC lists to a previous deploy tag and redeploy them.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    inventory = os.getenv("ANSIBLE_INVENTORY", "ansible/inventory.ini")
    vault_pass_file = os.getenv("ANSIBLE_VAULT_PASSWORD_FILE", "ansible/.vault_pass")
    
    is_local_mock = os.getenv("IS_LOCAL_MOCK", "true").lower() in ("true", "1")
    repo = Repo(repo_path)
    
    if target_tag not in repo.tags:
        raise ValueError(f"Target tag '{target_tag}' does not exist in repository")
        
    tag_ref = repo.tags[target_tag]
    target_commit = tag_ref.commit.hexsha
    
    metadata = {}
    try:
        if tag_ref.tag and tag_ref.tag.message:
            metadata = json.loads(tag_ref.tag.message.strip())
        else:
            show_output = repo.git.show(target_tag, "--format=%b", "-s")
            metadata = json.loads(show_output.strip())
    except Exception as e:
        log.warning("failed_to_parse_tag_metadata", tag=target_tag, error=str(e))
        
    log.info("preparing_rollback", target_tag=target_tag, target_commit=target_commit)
    
    cmd = [
        "ansible-playbook",
        "ansible/rollback.yml",
        "-i", inventory,
        "-e", f"rollback_tag={target_tag}",
        "-e", f"target_hosts={hosts}"
    ]
    
    if is_local_mock:
        mock_lists_dir = str(Path(repo_path).parent / "mock_wazuh" / "etc" / "lists")
        cmd.extend([
            "-e", "is_local_mock=true",
            "-e", f"wazuh_lists_dir={mock_lists_dir}"
        ])
    else:
        if Path(vault_pass_file).exists():
            cmd.extend(["--vault-password-file", vault_pass_file])
            
    log.info("running_ansible_rollback", command=" ".join(cmd))
    
    workspace_root = str(Path(repo_path).parent)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=workspace_root)
    
    if result.returncode != 0:
        log.error("ansible_rollback_failed", stdout=result.stdout, stderr=result.stderr)
        return {
            "status": "failed",
            "error": "Ansible rollback playbook failed",
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
    log.info("ansible_rollback_succeeded")
    
    repo.git.checkout("main")
    
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rollback_tag = f"rollback-to-{target_tag}-{timestamp_str}"
    
    rollback_metadata = {
        "type": "rollback",
        "rolled_back_to_tag": target_tag,
        "rolled_back_to_commit": target_commit,
        "rollback_reason": "mcp-triggered",
        "operator": "mcp",
        "hosts_succeeded": [hosts],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        repo.create_tag(rollback_tag, message=json.dumps(rollback_metadata))
        if repo.remotes:
            try:
                repo.remotes.origin.push(rollback_tag)
            except Exception as e:
                log.warning("git_push_rollback_tag_failed", error=str(e))
    except Exception as e:
        log.error("git_rollback_tag_creation_failed", error=str(e))
        
    return {
        "status": "ok",
        "rolled_back_to": target_tag,
        "target_commit": target_commit,
        "hosts_succeeded": [hosts],
        "hosts_failed": [],
        "rollback_tag": rollback_tag,
        "rollback_metadata": rollback_metadata
    }
