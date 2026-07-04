import os
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from git import Repo
import structlog

from collector.base import RawRule
from collector.misp_rules import get_rule_provider, MISPRuleCollector
from validators import RuleValidator
from processors import process_pending_rules, list_quarantined_rules, promote_quarantined_rule, reject_quarantined_rule
from processors.git_ops import commit_and_push_to_dev, get_or_create_pr
from collector.github_provider import GitHubRepoSource

log = structlog.get_logger()

def _write_dynamic_inventory(host: str, ip: str, user: str, key_path: str) -> str:
    """Write a temp inventory file for one host. Returns path."""
    content = f"""[wazuh_managers]
{host} ansible_host={ip} ansible_user={user}

[wazuh_managers:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_private_key_file={key_path}
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
"""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name

@dataclass
class SyncResult:
    status: str
    total_pulled: int
    approved: int
    rejected: int
    duplicated: int
    converted: int
    commit_sha: str
    pr_url: str = ""

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
    try:
        if not directory.exists():
            return 0
        return sum(1 for f in directory.glob(glob_pattern) if f.is_file() and not f.name.startswith("."))
    except PermissionError:
        return 0


def sync_misp_rules(
    since: Optional[str] = None,
    misp_provider: str = "",
) -> SyncResult:
    """
    Pull latest detection rules from MISP, validate, process, and commit to main.
    """
    repo_path = os.getenv("TI_REPO_PATH", "repository")
    repo_dir = Path(repo_path)
    state_file = repo_dir / ".sync_state.json"

    dac_repo_path_str = os.getenv("DAC_REPO_PATH", "")
    separate_dac_repo = bool(dac_repo_path_str) and Path(dac_repo_path_str) != repo_dir

    if separate_dac_repo:
        rules_dir = Path(dac_repo_path_str) / "rules"
    else:
        rules_dir = repo_dir / "rules"

    provider = get_rule_provider(provider_override=misp_provider)
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

    commit_msg = (
        f"sync: rules [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}] "
        f"pulled={stats['total']} approved={stats['approved']} converted={stats['converted']}"
    )

    commit_sha = ""
    pr_url = ""

    if separate_dac_repo:
        # ── Two-repo mode ──────────────────────────────────────────────────────
        # Push to the DaC repo's dev branch, then open / reuse a PR.
        dac_repo_path = Path(dac_repo_path_str)
        commit_sha = commit_and_push_to_dev(dac_repo_path, commit_msg) or ""

        # Also commit the pipeline repo's state file on main
        try:
            repo = Repo(repo_dir)
            repo.git.checkout("main")
            if state_file.exists():
                repo.git.add([".sync_state.json"])
            if repo.is_dirty(untracked_files=False):
                pipeline_commit = repo.index.commit(f"state: {commit_msg}")
                commit_sha = commit_sha or pipeline_commit.hexsha
                if repo.remotes:
                    repo.remotes.origin.push("main")
        except Exception as e:
            log.warning("git_push_pipeline_state_failed", error=str(e))

        # Open or reuse the DaC PR (best-effort; gh CLI may be absent in CI)
        if commit_sha:
            pr_result = get_or_create_pr(
                dac_repo_path,
                pr_title=f"sync: MISP rules update [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}]",
                pr_body=(
                    f"Automated MISP rules synchronization.\n\n"
                    f"- Rules pulled: {stats['total']}\n"
                    f"- Approved: {stats['approved']}\n"
                    f"- Converted: {stats['converted']}\n"
                    f"- Rejected: {stats['rejected']}\n"
                ),
            )
            pr_url = pr_result.get("url") or ""
            log.info("pr_status", action=pr_result.get("action"), pr_url=pr_url)

    else:
        # ── Single-repo mode (default / tests) ────────────────────────────────
        # Commit rules/ and generated/ directly to main, no PR created.
        repo = Repo(repo_dir)
        repo.git.checkout("main")
        files_to_add = []
        if rules_dir.exists():
            files_to_add.append("rules/")
        generated_dir = repo_dir / "generated"
        if generated_dir.exists():
            files_to_add.append("generated/")
        if state_file.exists():
            files_to_add.append(".sync_state.json")
        if files_to_add:
            repo.git.add(files_to_add)
        if repo.is_dirty(untracked_files=True) or len(repo.index.diff("HEAD")) > 0:
            commit = repo.index.commit(commit_msg)
            commit_sha = commit.hexsha
            try:
                if repo.remotes:
                    repo.remotes.origin.push("main")
            except Exception as e:
                log.warning("git_push_rules_failed", error=str(e))

    status = "committed" if commit_sha else "no_changes"


    return SyncResult(
        status=status,
        total_pulled=stats["total"],
        approved=stats["approved"],
        rejected=stats["rejected"],
        duplicated=stats["duplicated"],
        converted=stats["converted"],
        commit_sha=commit_sha,
        pr_url=pr_url,
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


def deploy_rules(
    dry_run: bool = False,
    host_name: str = "",
    host_ip: str = "",
    ssh_user: str = "",
    ssh_key_path: str = "",
    rule_names=None,
    tags=None,
    source: str = "local",
) -> DeployResult:
    """
    Deploy validated rules to Wazuh managers via Ansible.
    source="local" (default): deploy from TI_REPO_PATH, as before.
    source="public": deploy from the public DAC_REPO_PATH repo instead — fetches and
      hard-resets that clone to origin/main first, so what's deployed is exactly what's
      merged/reviewed on GitHub, not anything stray sitting locally.
    """
    local_repo_path = os.getenv("TI_REPO_PATH", "repository")

    if source == "public":
        dac_repo_path_str = os.getenv("DAC_REPO_PATH", "")
        if not dac_repo_path_str:
            log.warning("deploy_blocked_no_dac_repo_path")
            return DeployResult(
                status="aborted: DAC_REPO_PATH not set",
                hosts_succeeded=[], hosts_failed=[], deploy_tag="", deploy_metadata={}, dry_run=dry_run
            )
        dac_path = Path(dac_repo_path_str)
        try:
            dac_repo = Repo(dac_path)
            dac_repo.git.fetch("origin")
            dac_repo.git.checkout("main")
            dac_repo.git.reset("--hard", "origin/main")
        except Exception as e:
            log.error("deploy_public_repo_sync_failed", error=str(e))
            return DeployResult(
                status=f"aborted: failed to sync public repo: {e}",
                hosts_succeeded=[], hosts_failed=[], deploy_tag="", deploy_metadata={}, dry_run=dry_run
            )
        active_repo_path = dac_path
        public_commit_sha = dac_repo.head.commit.hexsha
        from processors.xml_merger import rebuild_local_rules
        try:
            rebuild_local_rules(dac_path / "rules")
        except Exception as e:
            log.error("deploy_public_repo_compile_failed", error=str(e))
            return DeployResult(
                status=f"aborted: failed to compile public repo rules: {e}",
                hosts_succeeded=[], hosts_failed=[], deploy_tag="", deploy_metadata={}, dry_run=dry_run
            )
    else:
        active_repo_path = Path(local_repo_path)
        public_commit_sha = ""

    rules_dir = active_repo_path / "rules"

    # Safeguard: Check if rules/wazuh and rules/yara are empty (checked against the ACTIVE source)
    wazuh_rules_count = count_files_in_dir(rules_dir / "wazuh")
    yara_rules_count = count_files_in_dir(rules_dir / "yara")

    if wazuh_rules_count == 0 and yara_rules_count == 0:
        log.warning("deploy_blocked_empty_rules", source=source)
        return DeployResult(
            status="aborted: no rules to deploy",
            hosts_succeeded=[], hosts_failed=[], deploy_tag="", deploy_metadata={}, dry_run=dry_run
        )

    inventory = ""
    is_dynamic = False
    try:
        if host_name and host_ip and ssh_key_path:
            inventory = _write_dynamic_inventory(host_name, host_ip, ssh_user or "root", ssh_key_path)
            is_dynamic = True
        else:
            inventory = os.getenv("ANSIBLE_INVENTORY", "ansible/inventory.ini")

        vault_pass_file = os.getenv("ANSIBLE_VAULT_PASSWORD_FILE", "ansible/.vault_pass")
        is_local_mock = os.getenv("IS_LOCAL_MOCK", "true").lower() in ("true", "1")

        deploy_src_file = active_repo_path.resolve() / "generated" / "local_rules.xml"
        if rule_names or tags:
            from processors.xml_merger import build_filtered_rules_xml
            filtered_xml = build_filtered_rules_xml(rules_dir, rule_names=set(rule_names) if rule_names else None, tags=set(tags) if tags else None)
            deploy_src_file = active_repo_path.resolve() / "generated" / "deploy_filtered.xml"
            deploy_src_file.write_text(filtered_xml, encoding="utf-8")

        cmd = [
            "ansible-playbook",
            "ansible/deploy_rules_docker.yml",
            "-i", inventory,
            "-e", f"local_rules_src={deploy_src_file}"
        ]

        if is_local_mock:
            cmd.extend(["-e", "is_local_mock=true"])
        else:
            if Path(vault_pass_file).exists():
                cmd.extend(["--vault-password-file", vault_pass_file])

        if dry_run:
            cmd.append("--check")

        log.info("running_ansible_rules_deployment", command=" ".join(cmd), dry_run=dry_run, source=source)
        workspace_root = str(Path(local_repo_path).parent)
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
            # Deploy tag/manifest always recorded on the local pipeline repo — this is the
            # pipeline's own deployment audit trail, regardless of which source was deployed.
            repo = Repo(local_repo_path)
            repo.git.checkout("main")
            main_commit = repo.head.commit.hexsha
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            deploy_tag = f"deploy-rules-{timestamp_str}"

            manifests_dir = Path(local_repo_path) / "generated" / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            manifest_file = manifests_dir / f"{deploy_tag}.json"

            tag_metadata = {
                "type": "deploy",
                "scope": "rules",
                "source": source,
                "commit": main_commit,
                "public_repo_commit": public_commit_sha,
                "rule_counts": {
                    "wazuh_xml": wazuh_rules_count,
                    "yara": yara_rules_count
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operator": os.getenv("OPERATOR_NAME", "dashboard")
            }
            manifest_file.write_text(json.dumps(tag_metadata, indent=2), encoding="utf-8")
            repo.git.add(f"generated/manifests/{deploy_tag}.json")
            repo.index.commit(f"manifest: record rule deployment {deploy_tag}")
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
    finally:
        if is_dynamic and inventory and os.path.exists(inventory):
            try:
                os.unlink(inventory)
            except Exception as e:
                log.warning("failed_to_delete_temp_inventory", path=inventory, error=str(e))


def rollback_rules(
    tag: str,
    host_name: str = "",
    host_ip: str = "",
    ssh_user: str = "",
    ssh_key_path: str = "",
) -> RollbackResult:
    """
    Rollback approved rules to a previous deployment tag.
    """
    repo_path = os.getenv("TI_REPO_PATH", "repository")
    repo = Repo(repo_path)
    
    log.info("starting_rules_rollback", tag=tag)

    try:
        repo.git.checkout("main")

        # Revert rules and generated/ directories from the tag
        repo.git.checkout(tag, "--", "rules/")
        try:
            repo.git.checkout(tag, "--", "generated/")
        except Exception:
            pass  # generated/ may not exist in older tags

        # Commit the reverted files to main
        commit_msg = f"rollback: rules reverted to tag {tag}"
        repo.index.add(["rules/"])
        try:
            repo.index.add(["generated/"])
        except Exception:
            pass
        commit = repo.index.commit(commit_msg)
        commit_sha = commit.hexsha

        if repo.remotes:
            try:
                repo.remotes.origin.push("main")
            except Exception as e:
                log.warning("git_push_rollback_failed", error=str(e))

        # Deploy the reverted rules
        deploy_res = deploy_rules(
            dry_run=False,
            host_name=host_name,
            host_ip=host_ip,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
        )
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


def rule_status(
    manager_host: str,
    host_ip: str = "",
    ssh_user: str = "",
    ssh_key_path: str = "",
) -> StatusReport:
    """
    Check the rules status of a given manager.
    """
    repo_path = os.getenv("TI_REPO_PATH", "repository")
    repo = Repo(repo_path)

    inventory = ""
    is_dynamic = False
    try:
        if manager_host and host_ip and ssh_key_path:
            inventory = _write_dynamic_inventory(manager_host, host_ip, ssh_user or "root", ssh_key_path)
            is_dynamic = True
        else:
            inventory = os.getenv("ANSIBLE_INVENTORY", "ansible/inventory.ini")

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
            container_name = os.getenv("WAZUH_CONTAINER_NAME", "multi-node-wazuh.master-1")
            def _remote(cmd):
                return subprocess.run(
                    ["ansible", "wazuh_managers", "-i", inventory,
                     "-m", "ansible.builtin.shell",
                     "-a", f"docker exec {container_name} {cmd}"],
                    capture_output=True, text=True, timeout=30
                )
            try:
                r = _remote("/var/ossec/bin/wazuh-control status")
                wazuh_running = "wazuh-analysisd is running" in r.stdout
            except Exception:
                wazuh_running = False
            try:
                r = _remote('sh -c \'ls /var/ossec/etc/rules | wc -l\'')
                wazuh_rules_count = int(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 else 0
            except Exception:
                wazuh_rules_count = 0
            try:
                r = _remote('sh -c \'ls /var/ossec/etc/yara-rules | wc -l\'')
                yara_rules_count = int(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 else 0
            except Exception:
                yara_rules_count = 0

        return StatusReport(
            manager_host=manager_host,
            wazuh_running=wazuh_running,
            yara_rules_count=yara_rules_count,
            wazuh_rules_count=wazuh_rules_count,
            last_deployment_tag=last_deployment_tag
        )
    finally:
        if is_dynamic and inventory and os.path.exists(inventory):
            try:
                os.unlink(inventory)
            except Exception:
                pass


def _load_github_state(repo_path: Path) -> dict:
    state_file = repo_path / ".sync_state.json"
    if not state_file.exists():
        return {}
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f).get("github_sources", {})
    except Exception as e:
        log.warning("failed_to_load_github_state", error=str(e))
        return {}


def _save_github_state(repo_path: Path, github_sources: dict) -> None:
    state_file = repo_path / ".sync_state.json"
    existing = {}
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}
    existing["github_sources"] = github_sources
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(existing, f)
    except Exception as e:
        log.error("failed_to_save_github_state", error=str(e))


def sync_github_rules() -> SyncResult:
    """Pull Sigma/YARA rules from configured external GitHub repos (pinned ref, manual bump).
    Supports two-repo mode via DAC_REPO_PATH, same as sync_misp_rules: pushes to the
    public repo's dev branch and opens/reuses a PR, instead of committing straight to
    the local repository's main.
    """
    repo_path = os.getenv("TI_REPO_PATH", "repository")
    repo_dir = Path(repo_path)

    dac_repo_path_str = os.getenv("DAC_REPO_PATH", "")
    separate_dac_repo = bool(dac_repo_path_str) and Path(dac_repo_path_str) != repo_dir

    if separate_dac_repo:
        rules_dir = Path(dac_repo_path_str) / "rules"
    else:
        rules_dir = repo_dir / "rules"

    token = os.getenv("GITHUB_TOKEN", "")
    extra_tags = [t.strip() for t in os.getenv("GITHUB_RULE_TAGS", "").split(",") if t.strip()]
    sources = []
    sigma_repo = os.getenv("GITHUB_SIGMA_REPO", "")
    if sigma_repo:
        sources.append(GitHubRepoSource(
            repo=sigma_repo,
            ref=os.getenv("GITHUB_SIGMA_REF", "main"),
            path=os.getenv("GITHUB_SIGMA_PATH", ""),
            token=token,
            extra_tags=extra_tags,
        ))
    yara_repo = os.getenv("GITHUB_YARA_REPO", "")
    if yara_repo:
        sources.append(GitHubRepoSource(
            repo=yara_repo,
            ref=os.getenv("GITHUB_YARA_REF", "main"),
            path=os.getenv("GITHUB_YARA_PATH", ""),
            token=token,
            extra_tags=extra_tags,
        ))
    if not sources:
        return SyncResult(status="no_sources_configured", total_pulled=0, approved=0, rejected=0, duplicated=0, converted=0, commit_sha="")

    github_state = _load_github_state(repo_dir)
    all_raw_rules = []
    for src in sources:
        last_sha = github_state.get(src.repo)
        raw_rules, head_sha, changed = src.fetch(last_synced_sha=last_sha)
        github_state[src.repo] = head_sha
        all_raw_rules.extend(raw_rules)

    if not all_raw_rules:
        repo = Repo(repo_dir)
        _save_github_state(repo_dir, github_state)
        return SyncResult(status="no_changes", total_pulled=0, approved=0, rejected=0, duplicated=0, converted=0, commit_sha=repo.head.commit.hexsha)

    stats = process_pending_rules(all_raw_rules, rules_dir=rules_dir)

    commit_msg = (
        f"sync: github rules [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}] "
        f"pulled={stats['total']} approved={stats['approved']} converted={stats['converted']}"
    )

    commit_sha = ""
    pr_url = ""

    if separate_dac_repo:
        # ── Two-repo mode ──────────────────────────────────────────────────────
        dac_repo_path = Path(dac_repo_path_str)
        commit_sha = commit_and_push_to_dev(dac_repo_path, commit_msg) or ""

        # Also persist github sync state on the pipeline repo's main
        try:
            repo = Repo(repo_dir)
            repo.git.checkout("main")
            _save_github_state(repo_dir, github_state)
            if (repo_dir / ".sync_state.json").exists():
                repo.git.add([".sync_state.json"])
            if repo.is_dirty(untracked_files=False):
                pipeline_commit = repo.index.commit(f"state: {commit_msg}")
                commit_sha = commit_sha or pipeline_commit.hexsha
                if repo.remotes:
                    repo.remotes.origin.push("main")
        except Exception as e:
            log.warning("git_push_github_state_failed", error=str(e))

        if commit_sha:
            pr_result = get_or_create_pr(
                dac_repo_path,
                pr_title=f"sync: GitHub rules update [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}]",
                pr_body=(
                    f"Automated GitHub external rule source synchronization.\n\n"
                    f"- Rules pulled: {stats['total']}\n"
                    f"- Approved: {stats['approved']}\n"
                    f"- Converted: {stats['converted']}\n"
                    f"- Rejected: {stats['rejected']}\n"
                    f"- Sources: {', '.join(s.repo for s in sources)}\n"
                ),
            )
            pr_url = pr_result.get("url") or ""
            log.info("github_pr_status", action=pr_result.get("action"), pr_url=pr_url)

    else:
        # ── Single-repo mode (default / tests) ────────────────────────────────
        repo = Repo(repo_dir)
        repo.git.checkout("main")
        files_to_add = []
        if rules_dir.exists():
            files_to_add.append("rules/")
        if (repo_dir / "generated").exists():
            files_to_add.append("generated/")
        _save_github_state(repo_dir, github_state)
        if (repo_dir / ".sync_state.json").exists():
            files_to_add.append(".sync_state.json")
        if files_to_add:
            repo.git.add(files_to_add)
        if repo.is_dirty(untracked_files=True) or len(repo.index.diff("HEAD")) > 0:
            commit = repo.index.commit(commit_msg)
            commit_sha = commit.hexsha
            try:
                if repo.remotes:
                    repo.remotes.origin.push("main")
            except Exception as e:
                log.warning("git_push_github_rules_failed", error=str(e))

    return SyncResult(
        status="committed" if commit_sha else "no_changes",
        total_pulled=stats["total"],
        approved=stats["approved"],
        rejected=stats["rejected"],
        duplicated=stats["duplicated"],
        converted=stats["converted"],
        commit_sha=commit_sha,
        pr_url=pr_url,
    )

def _resolve_rules_dir() -> Path:
    """Same repo-selection logic as sync_misp_rules/sync_github_rules: respect
    two-repo mode (DAC_REPO_PATH) so quarantine ops target the same rules/
    directory the sync path writes into."""
    repo_path = os.getenv("TI_REPO_PATH", "repository")
    repo_dir = Path(repo_path)
    dac_repo_path_str = os.getenv("DAC_REPO_PATH", "")
    if dac_repo_path_str and Path(dac_repo_path_str) != repo_dir:
        return Path(dac_repo_path_str) / "rules"
    return repo_dir / "rules"


def list_quarantine() -> List[Dict[str, Any]]:
    """List all rules currently sitting in quarantine, with metadata."""
    return list_quarantined_rules(_resolve_rules_dir())


def promote_rule(rule_name: str) -> Dict[str, Any]:
    """Approve a quarantined rule: move it into the real rules dir, assign
    IDs, rebuild generated/local_rules.xml."""
    return promote_quarantined_rule(rule_name, _resolve_rules_dir())


def reject_rule(rule_name: str, reason: str = "") -> Dict[str, Any]:
    """Reject a quarantined rule: delete it, keep a rejected metadata record."""
    return reject_quarantined_rule(rule_name, _resolve_rules_dir(), reason=reason)

