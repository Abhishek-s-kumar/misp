import os
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from git import Repo
import structlog

from collector.base import RawRule
from collector.misp_rules import get_rule_provider, MISPRuleCollector
from validators import RuleValidator
from processors import process_pending_rules

log = structlog.get_logger()

@dataclass
class SyncResult:
    status: str
    total_pulled: int
    approved: int
    rejected: int
    duplicated: int
    converted: int
    commit_sha: str

@dataclass
class RuleValidationDetail:
    rule_name: str
    rule_type: str
    valid: bool
    errors: List[str]
    warnings: List[str]

@dataclass
class ValidationReport:
    total_validated: int
    valid_count: int
    invalid_count: int
    details: List[RuleValidationDetail]

@dataclass
class DeployResult:
    status: str
    hosts_succeeded: List[str]
    hosts_failed: List[str]
    deploy_tag: str
    deploy_metadata: Dict[str, Any]
    dry_run: bool

@dataclass
class RollbackResult:
    status: str
    target_tag: str
    commit_sha: str
    revert_success: bool

@dataclass
class StatusReport:
    manager_host: str
    wazuh_running: bool
    yara_rules_count: int
    wazuh_rules_count: int
    last_deployment_tag: str


def count_files_in_dir(directory: Path, glob_pattern: str = "*") -> int:
    if not directory.exists():
        return 0
    return sum(1 for f in directory.glob(glob_pattern) if f.is_file() and not f.name.startswith("."))


def sync_misp_rules(since: Optional[str] = None) -> SyncResult:
    """
    Pull latest detection rules from MISP, validate, process, and commit to main.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    repo_dir = Path(repo_path)
    state_file = repo_dir / ".sync_state.json"
    rules_dir = repo_dir / "rules"

    provider = get_rule_provider()
    collector = MISPRuleCollector(provider, state_file)

    log.info("sync_misp_rules_started", since=since)
    
    # Parse explicit 'since' datetime if provided
    dt_since = None
    if since:
        try:
            dt_since = datetime.fromisoformat(since)
        except ValueError as e:
            log.error("invalid_since_timestamp", error=str(e))
            return SyncResult(
                status="error: invalid timestamp",
                total_pulled=0, approved=0, rejected=0, duplicated=0, converted=0, commit_sha=""
            )

    # Ingest rules
    raw_rules = collector.pull(
        rule_types=["yara", "sigma", "wazuh"],
        tags=["tlp:white"],
        full_pull=False,
        since_override=dt_since
    )
    
    if not raw_rules:
        # Check current HEAD commit sha
        repo = Repo(repo_dir)
        commit_sha = repo.head.commit.hexsha
        return SyncResult(
            status="no_changes",
            total_pulled=0, approved=0, rejected=0, duplicated=0, converted=0, commit_sha=commit_sha
        )

    # Process rules (validation, deduplication, conversion, state promotion, metadata)
    stats = process_pending_rules(raw_rules, rules_dir=rules_dir)

    # Git commit
    repo = Repo(repo_dir)
    repo.git.checkout("main")
    
    # Track the sync state file and rules directory changes safely
    files_to_add = []
    if rules_dir.exists():
        files_to_add.append("rules/")
    if state_file.exists():
        files_to_add.append(".sync_state.json")
        
    if files_to_add:
        repo.git.add(files_to_add)


    if repo.is_dirty(untracked_files=True) or len(repo.index.diff("HEAD")) > 0:
        commit_msg = (
            f"sync: rules [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}] "
            f"pulled={stats['total']} approved={stats['approved']} converted={stats['converted']}"
        )
        commit = repo.index.commit(commit_msg)
        commit_sha = commit.hexsha
        try:
            if repo.remotes:
                repo.remotes.origin.push("main")
        except Exception as e:
            log.warning("git_push_rules_failed", error=str(e))
        status = "committed"
    else:
        commit_sha = repo.head.commit.hexsha
        status = "no_changes"

    return SyncResult(
        status=status,
        total_pulled=stats["total"],
        approved=stats["approved"],
        rejected=stats["rejected"],
        duplicated=stats["duplicated"],
        converted=stats["converted"],
        commit_sha=commit_sha
    )


def validate_rules(rule_dir: str) -> ValidationReport:
    """
    Validate all rule files in a given directory using the RuleValidator dispatcher.
    """
    target_path = Path(rule_dir)
    if not target_path.exists():
        return ValidationReport(total_validated=0, valid_count=0, invalid_count=0, details=[])

    validator = RuleValidator()
    details: List[RuleValidationDetail] = []
    
    # Process all files in the directory
    for file_path in target_path.rglob("*"):
        if not file_path.is_file() or file_path.name.startswith("."):
            continue

        ext = file_path.suffix.lower()
        rule_type = None
        if ext in (".yar", ".yara"):
            rule_type = "yara"
        elif ext in (".yml", ".yaml"):
            rule_type = "sigma"
        elif ext == ".xml":
            rule_type = "wazuh"

        if not rule_type:
            continue

        content = file_path.read_text(encoding="utf-8")
        dummy_rule = RawRule(
            rule_type=rule_type,
            name=file_path.name,
            content=content,
            event_id=0,
            event_uuid="0",
            misp_timestamp=datetime.now(timezone.utc),
            tags=[]
        )
        
        result = validator.validate(dummy_rule)
        details.append(
            RuleValidationDetail(
                rule_name=file_path.name,
                rule_type=rule_type,
                valid=result.valid,
                errors=result.errors,
                warnings=result.warnings
            )
        )

    total = len(details)
    valid_count = sum(1 for d in details if d.valid)
    invalid_count = total - valid_count

    return ValidationReport(
        total_validated=total,
        valid_count=valid_count,
        invalid_count=invalid_count,
        details=details
    )


def deploy_rules(dry_run: bool = False) -> DeployResult:
    """
    Deploy validated rules to Wazuh managers via Ansible.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    approved_dir = Path(repo_path) / "rules" / "approved"

    # Safeguard: Check if approved/wazuh and approved/yara are empty
    wazuh_rules_count = count_files_in_dir(approved_dir / "wazuh")
    yara_rules_count = count_files_in_dir(approved_dir / "yara")

    if wazuh_rules_count == 0 and yara_rules_count == 0:
        log.warning("deploy_blocked_empty_approved_rules")
        return DeployResult(
            status="aborted: empty approved rules",
            hosts_succeeded=[], hosts_failed=[], deploy_tag="", deploy_metadata={}, dry_run=dry_run
        )

    inventory = os.getenv("ANSIBLE_INVENTORY", "ansible/inventory.ini")
    vault_pass_file = os.getenv("ANSIBLE_VAULT_PASSWORD_FILE", "ansible/.vault_pass")
    is_local_mock = os.getenv("IS_LOCAL_MOCK", "true").lower() in ("true", "1")

    cmd = [
        "ansible-playbook",
        "ansible/deploy_rules.yml",
        "-i", inventory
    ]

    if is_local_mock:
        cmd.extend(["-e", "is_local_mock=true"])
    else:
        if Path(vault_pass_file).exists():
            cmd.extend(["--vault-password-file", vault_pass_file])

    if dry_run:
        cmd.append("--check")

    log.info("running_ansible_rules_deployment", command=" ".join(cmd), dry_run=dry_run)
    workspace_root = str(Path(repo_path).parent)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=workspace_root)

    if result.returncode != 0:
        log.error("ansible_rules_deployment_failed", stdout=result.stdout, stderr=result.stderr)
        return DeployResult(
            status="failed",
            hosts_succeeded=[],
            hosts_failed=["all"],
            deploy_tag="",
            deploy_metadata={"stdout": result.stdout, "stderr": result.stderr},
            dry_run=dry_run
        )

    log.info("ansible_rules_deployment_succeeded")

    deploy_tag = ""
    tag_metadata = {}

    if not dry_run:
        repo = Repo(repo_path)
        repo.git.checkout("main")
        main_commit = repo.head.commit.hexsha
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        deploy_tag = f"deploy-rules-{timestamp_str}"

        # Write deployment manifest
        manifests_dir = Path(repo_path) / "rules" / "manifests"
        manifests_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = manifests_dir / f"{deploy_tag}.json"

        tag_metadata = {
            "type": "deploy",
            "scope": "rules",
            "commit": main_commit,
            "rule_counts": {
                "wazuh_xml": wazuh_rules_count,
                "yara": yara_rules_count
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": "mcp"
        }

        manifest_file.write_text(json.dumps(tag_metadata, indent=2), encoding="utf-8")

        # Add manifest to Git repository
        repo.git.add(f"rules/manifests/{deploy_tag}.json")
        repo.index.commit(f"manifest: record rule deployment {deploy_tag}")
        
        # Re-get the commit hash for the tag
        main_commit = repo.head.commit.hexsha
        tag_metadata["commit"] = main_commit

        try:
            repo.create_tag(deploy_tag, message=json.dumps(tag_metadata))
            if repo.remotes:
                try:
                    repo.remotes.origin.push("main")
                    repo.remotes.origin.push(deploy_tag)
                except Exception as e:
                    log.warning("git_push_rules_tag_failed", error=str(e))
        except Exception as e:
            log.error("git_rules_tag_creation_failed", error=str(e))

    return DeployResult(
        status="ok",
        hosts_succeeded=["all"],
        hosts_failed=[],
        deploy_tag=deploy_tag,
        deploy_metadata=tag_metadata,
        dry_run=dry_run
    )


def rollback_rules(tag: str) -> RollbackResult:
    """
    Rollback approved rules to a previous deployment tag.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    repo = Repo(repo_path)
    
    log.info("starting_rules_rollback", tag=tag)

    try:
        repo.git.checkout("main")
        
        # Revert rules directory from the tag
        repo.git.checkout(tag, "--", "rules/")
        
        # Commit the reverted files to main
        commit_msg = f"rollback: rules reverted to tag {tag}"
        repo.index.add(["rules/"])
        commit = repo.index.commit(commit_msg)
        commit_sha = commit.hexsha

        if repo.remotes:
            try:
                repo.remotes.origin.push("main")
            except Exception as e:
                log.warning("git_push_rollback_failed", error=str(e))

        # Deploy the reverted rules
        deploy_res = deploy_rules(dry_run=False)
        revert_success = deploy_res.status == "ok"

        return RollbackResult(
            status="ok" if revert_success else "rollback_deploy_failed",
            target_tag=tag,
            commit_sha=commit_sha,
            revert_success=revert_success
        )

    except Exception as e:
        log.error("rules_rollback_failed", error=str(e))
        return RollbackResult(
            status=f"error: {str(e)}",
            target_tag=tag,
            commit_sha="",
            revert_success=False
        )


def rule_status(manager_host: str) -> StatusReport:
    """
    Check the rules status of a given manager.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")
    repo = Repo(repo_path)

    # Retrieve last deployment tag
    last_deployment_tag = ""
    try:
        tags = sorted(repo.tags, key=lambda t: t.commit.committed_datetime)
        rule_tags = [t for t in tags if t.name.startswith("deploy-rules-")]
        if rule_tags:
            last_deployment_tag = rule_tags[-1].name
    except Exception as e:
        log.warning("get_last_tag_failed", error=str(e))

    is_local_mock = os.getenv("IS_LOCAL_MOCK", "true").lower() in ("true", "1")

    wazuh_rules_count = 0
    yara_rules_count = 0
    wazuh_running = False

    if is_local_mock:
        mock_wazuh_dir = Path(repo_path).parent / "mock_wazuh"
        wazuh_rules_count = count_files_in_dir(mock_wazuh_dir / "etc" / "rules")
        yara_rules_count = count_files_in_dir(mock_wazuh_dir / "opt" / "yara-rules")
        wazuh_running = True
    else:
        # Run local wazuh-control check or remotely via SSH if config supports it
        try:
            status_res = subprocess.run(
                ["/var/ossec/bin/wazuh-control", "status"],
                capture_output=True, text=True, timeout=10
            )
            wazuh_running = status_res.returncode == 0
        except Exception:
            wazuh_running = False

        wazuh_rules_count = count_files_in_dir(Path("/var/ossec/etc/rules"))
        yara_rules_count = count_files_in_dir(Path("/opt/yara-rules"))

    return StatusReport(
        manager_host=manager_host,
        wazuh_running=wazuh_running,
        yara_rules_count=yara_rules_count,
        wazuh_rules_count=wazuh_rules_count,
        last_deployment_tag=last_deployment_tag
    )
