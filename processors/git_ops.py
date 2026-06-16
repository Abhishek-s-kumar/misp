"""
processors/git_ops.py — Git and GitHub PR operations for the DaC repository.

Responsibilities:
  - Commit and push rule changes to the `dev` branch of the DaC repo.
  - Check whether an open PR already exists from dev→main.
  - Create a new PR if none exists; reuse the existing one if it does.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import structlog
from git import Repo, InvalidGitRepositoryError

log = structlog.get_logger()


def _run(cmd: list, cwd: str = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess command, returning the CompletedProcess result."""
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=check)


def commit_and_push_to_dev(
    repo_path: Path,
    commit_msg: str,
) -> Optional[str]:
    """
    Stage all changes in the DaC repo, commit them to the `dev` branch,
    and push to origin.

    Returns the commit SHA on success, or None if there was nothing to commit.
    """
    repo = Repo(repo_path)

    # Ensure we are on the dev branch; create it if absent
    try:
        repo.git.checkout("dev")
    except Exception:
        try:
            repo.git.checkout("-b", "dev")
        except Exception as e:
            log.error("failed_to_checkout_dev", error=str(e))
            return None

    # Stage everything
    repo.git.add("-A")

    if not repo.is_dirty(index=True) and not repo.untracked_files:
        log.info("commit_and_push_dev_nothing_to_commit")
        return None

    commit = repo.index.commit(commit_msg)
    sha = commit.hexsha
    log.info("committed_to_dev", sha=sha, message=commit_msg)

    # Push to origin/dev
    try:
        if repo.remotes:
            repo.remotes.origin.push("dev")
            log.info("pushed_to_origin_dev")
    except Exception as e:
        log.warning("push_to_dev_failed", error=str(e))

    return sha


def get_or_create_pr(
    repo_path: Path,
    pr_title: str = "sync: automated MISP rules update",
    pr_body: str = "Automated synchronization of MISP detection rules into the DaC repository.",
) -> dict:
    """
    Check for an existing open PR from dev→main.
    If one exists, return its number and URL (reuse it).
    If none exists, create a new one via `gh pr create`.

    Returns a dict with keys: number, url, action ('reused' | 'created' | 'error').

    Requires the `gh` CLI to be authenticated and available on PATH.
    The GH_TOKEN or GITHUB_TOKEN environment variable must be set.
    """
    cwd = str(repo_path)

    # Check for an existing open PR from dev→main
    try:
        result = _run(
            ["gh", "pr", "list",
             "--head", "dev",
             "--base", "main",
             "--state", "open",
             "--json", "number,url,title"],
            cwd=cwd,
            check=True,
        )
        prs = json.loads(result.stdout or "[]")
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        log.error("gh_pr_list_failed", error=str(e))
        return {"number": None, "url": None, "action": "error", "error": str(e)}

    if prs:
        pr = prs[0]
        log.info("reusing_existing_pr", number=pr["number"], url=pr["url"])
        return {"number": pr["number"], "url": pr["url"], "action": "reused"}

    # No existing PR — create one
    try:
        result = _run(
            ["gh", "pr", "create",
             "--title", pr_title,
             "--body", pr_body,
             "--base", "main",
             "--head", "dev"],
            cwd=cwd,
            check=True,
        )
        # gh pr create outputs the PR URL on stdout
        pr_url = result.stdout.strip()
        log.info("created_new_pr", url=pr_url)
        return {"number": None, "url": pr_url, "action": "created"}
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.error("gh_pr_create_failed", error=str(e))
        return {"number": None, "url": None, "action": "error", "error": str(e)}
