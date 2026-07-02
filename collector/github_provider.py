"""
collector/github_provider.py — Pulls Sigma/YARA rule files from external GitHub repos.

Incrementality is commit-SHA based, not datetime-based:
  - Each source (repo + pinned ref + optional subfolder path) resolves to a commit SHA
    on every sync call. If it matches the last-synced SHA, nothing is fetched (no-op) —
    that's the pin: nothing new comes in until the ref is bumped manually.
  - If the SHA differs, the GitHub Compare API fetches only changed files.
  - First-ever sync of a source does one full recursive tree walk, scoped to path.
"""

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import requests
import structlog

from collector.base import RawRule

log = structlog.get_logger()

GITHUB_API = "https://api.github.com"

EXTENSION_MAP = {
    ".yar": "yara",
    ".yara": "yara",
    ".yml": "sigma",
    ".yaml": "sigma",
}


class GitHubRepoSource:
    def __init__(
        self,
        repo: str,
        ref: str,
        path: str = "",
        token: str = "",
        extra_tags: Optional[List[str]] = None,
    ):
        self.repo = repo
        self.ref = ref
        self.path = path.strip("/")
        self.token = token
        self.extra_tags = extra_tags or []

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _resolve_ref_sha(self) -> str:
        url = f"{GITHUB_API}/repos/{self.repo}/commits/{self.ref}"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()["sha"]

    def _in_scope(self, file_path: str) -> bool:
        if self.path and not (file_path == self.path or file_path.startswith(self.path + "/")):
            return False
        return Path(file_path).suffix.lower() in EXTENSION_MAP

    def _list_tree_files(self, sha: str) -> List[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/git/trees/{sha}"
        resp = requests.get(url, params={"recursive": "1"}, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
        return [e["path"] for e in tree if e.get("type") == "blob" and self._in_scope(e["path"])]

    def _list_changed_files(self, base_sha: str, head_sha: str) -> List[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/compare/{base_sha}...{head_sha}"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        out = []
        for f in resp.json().get("files", []):
            if f.get("status") not in ("added", "modified", "renamed"):
                continue
            if self._in_scope(f["filename"]):
                out.append(f["filename"])
        return out

    def _fetch_file_content(self, path: str, ref: str) -> Optional[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/contents/{path}"
        resp = requests.get(url, params={"ref": ref}, headers=self._headers(), timeout=30)
        if resp.status_code != 200:
            log.warning("github_file_fetch_failed", path=path, status=resp.status_code)
            return None
        data = resp.json()
        if data.get("encoding") == "base64" and data.get("content"):
            try:
                return base64.b64decode(data["content"]).decode("utf-8")
            except Exception as e:
                log.warning("github_file_decode_failed", path=path, error=str(e))
                return None
        return data.get("content")

    def fetch(self, last_synced_sha: Optional[str]) -> Tuple[List[RawRule], str, bool]:
        head_sha = self._resolve_ref_sha()

        if last_synced_sha == head_sha:
            log.info("github_source_unchanged", repo=self.repo, ref=self.ref, sha=head_sha)
            return [], head_sha, False

        if last_synced_sha:
            file_paths = self._list_changed_files(last_synced_sha, head_sha)
            log.info("github_incremental_pull", repo=self.repo, count=len(file_paths))
        else:
            file_paths = self._list_tree_files(head_sha)
            log.info("github_full_pull", repo=self.repo, path=self.path, count=len(file_paths))

        raw_rules: List[RawRule] = []
        now = datetime.now(timezone.utc)
        for p in file_paths:
            content = self._fetch_file_content(p, head_sha)
            if not content:
                continue
            rule_type = EXTENSION_MAP.get(Path(p).suffix.lower())
            if not rule_type:
                continue
            raw_rules.append(
                RawRule(
                    rule_type=rule_type,
                    name=Path(p).name,
                    content=content,
                    event_id=0,
                    event_uuid=f"github:{self.repo}@{head_sha[:12]}",
                    misp_timestamp=now,
                    tags=["source:github", f"repo:{self.repo}"] + self.extra_tags,
                )
            )
        return raw_rules, head_sha, True
