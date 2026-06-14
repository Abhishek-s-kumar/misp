import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from git import Repo
import structlog
from collector.misp_iocs import MISPIOCCollector, get_provider
from ioc_validators.ioc_validator import IOCValidator

log = structlog.get_logger()

def sync_misp_iocs(
    tags: List[str] = ["tlp:white"],
    ioc_types: List[str] = ["ip-src", "ip-dst", "domain", "md5", "sha256", "url"],
    full_pull: bool = False
) -> Dict[str, Any]:
    """
    Pull latest IOCs from MISP, validate them, and write CDB files directly to Git main branch.
    """
    repo_path = os.getenv("TI_REPO_PATH", "/home/kali/Desktop/misp/repository")

    provider = get_provider()
    state_file = Path(repo_path) / ".sync_state.json"
    collector = MISPIOCCollector(provider, state_file)
    raw_iocs = collector.pull(ioc_types=ioc_types, tags=tags, full_pull=full_pull)

    validator = IOCValidator()
    valid_iocs, stats = validator.validate_batch(raw_iocs)

    if not valid_iocs:
        return {
            "status": "aborted",
            "reason": "all_iocs_empty",
            "message": "No valid IOCs after validation. Nothing committed.",
            "total_pulled": len(raw_iocs),
            "total_valid": 0
        }

    repo_dir = Path(repo_path)
    iocs_dir = repo_dir / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)

    grouped = {"ip": [], "domain": [], "hash": [], "url": []}
    for ioc in valid_iocs:
        if ioc.normalized_type in grouped:
            grouped[ioc.normalized_type].append(ioc)

    file_map = {
        "ip": iocs_dir / "misp_ips",
        "domain": iocs_dir / "misp_domains",
        "hash": iocs_dir / "misp_hashes",
        "url": iocs_dir / "misp_urls"
    }

    for name, iocs in grouped.items():
        file_path = file_map[name]
        lines = sorted(set(f"{ioc.value}:malicious" for ioc in iocs))
        file_path.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")

    repo = Repo(repo_dir)
    repo.git.checkout("main")

    files_to_add = [
        "iocs/misp_ips",
        "iocs/misp_domains",
        "iocs/misp_hashes",
        "iocs/misp_urls",
        ".sync_state.json"
    ]
    existing_files = [f for f in files_to_add if (repo_dir / f).exists()]
    repo.index.add(existing_files)

    if repo.is_dirty(untracked_files=True) or len(repo.index.diff("HEAD")) > 0:
        commit_msg = f"sync: iocs main [{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}] pulled={len(raw_iocs)} valid={len(valid_iocs)}"
        commit = repo.index.commit(commit_msg)
        commit_sha = commit.hexsha
        try:
            if repo.remotes:
                repo.remotes.origin.push("main")
        except Exception as e:
            log.warning("git_push_failed", error=str(e))
        status = "committed"
    else:
        commit_sha = repo.head.commit.hexsha
        status = "no_changes"

    return {
        "status": status,
        "total_pulled": len(raw_iocs),
        "total_valid": len(valid_iocs),
        "rejected": stats["rejected"],
        "commit": commit_sha,
        "next_step": "call deploy_iocs to push to Wazuh managers"
    }
