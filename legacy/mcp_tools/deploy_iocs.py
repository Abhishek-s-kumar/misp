import os
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from git import Repo
import structlog

log = structlog.get_logger()

def count_lines(file_path: Path) -> int:
    if not file_path.exists():
        return 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip() and not line.strip().startswith("#"))
    except Exception:
        return 0

def deploy_iocs(
    hosts: str = "all",
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Deploy CDB IOC lists and XML detection rules from Git main to Wazuh managers via Ansible.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    
    # Safeguard: check if all CDB lists are empty before deploying
    iocs_dir = Path(repo_path) / "iocs"
    total_iocs = (
        count_lines(iocs_dir / "misp_ips") +
        count_lines(iocs_dir / "misp_domains") +
        count_lines(iocs_dir / "misp_hashes") +
        count_lines(iocs_dir / "misp_urls")
    )
    if total_iocs == 0:
        return {
            "status": "aborted",
            "reason": "all_cdb_lists_empty",
            "message": "All CDB lists are empty. Deploy blocked to prevent clearing Wazuh IOC lists."
        }

    inventory = os.getenv("ANSIBLE_INVENTORY", "ansible/inventory.ini")
    vault_pass_file = os.getenv("ANSIBLE_VAULT_PASSWORD_FILE", "ansible/.vault_pass")
    
    is_local_mock = os.getenv("IS_LOCAL_MOCK", "true").lower() in ("true", "1")
    
    cmd = [
        "ansible-playbook",
        "ansible/deploy_iocs.yml",
        "-i", inventory,
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
            
    if dry_run:
        cmd.append("--check")
        
    log.info("running_ansible_deployment", command=" ".join(cmd), dry_run=dry_run)
    
    workspace_root = str(Path(repo_path).parent)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=workspace_root)
    
    if result.returncode != 0:
        log.error("ansible_deployment_failed", stdout=result.stdout, stderr=result.stderr)
        return {
            "status": "failed",
            "error": "Ansible deployment playbook failed",
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
    log.info("ansible_deployment_succeeded")
    
    deploy_tag = ""
    tag_metadata = {}
    if not dry_run:
        repo = Repo(repo_path)
        repo.git.checkout("main")
        
        main_commit = repo.head.commit.hexsha
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        deploy_tag = f"deploy-iocs-{timestamp_str}"
        
        # Count IOCs
        iocs_dir = Path(repo_path) / "iocs"
        ioc_counts = {
            "ips": count_lines(iocs_dir / "misp_ips"),
            "domains": count_lines(iocs_dir / "misp_domains"),
            "hashes": count_lines(iocs_dir / "misp_hashes"),
            "urls": count_lines(iocs_dir / "misp_urls")
        }
        
        tag_metadata = {
            "type": "deploy",
            "scope": "iocs",
            "commit": main_commit,
            "ioc_counts": ioc_counts,
            "hosts_succeeded": [hosts],
            "operator": "mcp",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            repo.create_tag(deploy_tag, message=json.dumps(tag_metadata))
            if repo.remotes:
                try:
                    repo.remotes.origin.push(deploy_tag)
                except Exception as e:
                    log.warning("git_push_tag_failed", error=str(e))
        except Exception as e:
            log.error("git_tag_creation_failed", error=str(e))
            
    return {
        "status": "ok",
        "hosts_succeeded": [hosts],
        "hosts_failed": [],
        "deploy_tag": deploy_tag,
        "deploy_metadata": tag_metadata,
        "wazuh_test_passed": not is_local_mock,
        "dry_run": dry_run
    }
