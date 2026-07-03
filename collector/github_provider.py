"""
collector/github_provider.py — Pulls Sigma/YARA rule files from external GitHub repos.

Incrementality is commit-SHA based, not datetime-based:
  - Each source (repo + pinned ref + optional subfolder path) resolves to a commit SHA
    on every sync call. If it matches the last-synced SHA, nothing is fetched (no-op) —
    that's the pin: nothing new comes in until the ref is bumped manually.
  - If the SHA differs and this is the FIRST sync of that source (no stored SHA yet),
    the whole repo is downloaded as a single tarball at that commit (one API call,
    regardless of file count) and the scoped subfolder is read off disk. This avoids
    making one Contents-API call per file, which is fine for a handful of files but
    blows through rate limits and takes minutes on folders with 1000+ files.
  - If the SHA differs and there IS a stored last-synced SHA, the GitHub Compare API
    fetches only the files that changed since then (typically a small number), and
    those are fetched individually via the Contents API — a full tarball re-download
    isn't worth it for a small diff.
"""

import base64
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import requests
import structlog

from collector.base import RawRule

log = structlog.get_logger()

GITHUB_API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"

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

    def _list_changed_files(self, base_sha: str, head_sha: str) -> List[str]:
        """GitHub Compare API — only files added/modified/renamed between base and head."""
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

    def _fetch_files_individually(self, file_paths: List[str], ref: str) -> List[RawRule]:
        raw_rules: List[RawRule] = []
        now = datetime.now(timezone.utc)
        for p in file_paths:
            content = self._fetch_file_content(p, ref)
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
                    event_uuid=f"github:{self.repo}@{ref[:12]}",
                    misp_timestamp=now,
                    tags=["source:github", f"repo:{self.repo}"] + self.extra_tags,
                )
            )
        return raw_rules

    def _full_pull_via_tarball(self, head_sha: str) -> List[RawRule]:
        """One-shot tarball download + local extraction, scoped to self.path."""
        url = f"{CODELOAD}/{self.repo}/tar.gz/{head_sha}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        raw_rules: List[RawRule] = []
        now = datetime.now(timezone.utc)

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "repo.tar.gz"
            resp = requests.get(url, headers=headers, stream=True, timeout=180)
            resp.raise_for_status()
            with open(tar_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    f.write(chunk)

            extract_dir = Path(tmpdir) / "extracted"
            extract_dir.mkdir()
            with tarfile.open(tar_path, "r:gz") as tar:
                try:
                    tar.extractall(extract_dir, filter="data")
                except TypeError:
                    # Python < 3.12 doesn't support the filter= kwarg
                    tar.extractall(extract_dir)

            roots = [p for p in extract_dir.iterdir() if p.is_dir()]
            if not roots:
                log.warning("github_tarball_empty", repo=self.repo)
                return []
            root_dir = roots[0]
            scope_dir = (root_dir / self.path) if self.path else root_dir
            if not scope_dir.exists():
                log.warning("github_tarball_scope_missing", repo=self.repo, path=self.path)
                return []

            for file_path in scope_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                rule_type = EXTENSION_MAP.get(file_path.suffix.lower())
                if not rule_type:
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8")
                except Exception as e:
                    log.warning("github_tarball_file_read_failed", path=str(file_path), error=str(e))
                    continue
                raw_rules.append(
                    RawRule(
                        rule_type=rule_type,
                        name=file_path.name,
                        content=content,
                        event_id=0,
                        event_uuid=f"github:{self.repo}@{head_sha[:12]}",
                        misp_timestamp=now,
                        tags=["source:github", f"repo:{self.repo}"] + self.extra_tags,
                    )
                )

        log.info("github_full_pull_tarball", repo=self.repo, path=self.path, count=len(raw_rules))
        return raw_rules

    def fetch(self, last_synced_sha: Optional[str]) -> Tuple[List[RawRule], str, bool]:
        """
        Returns (raw_rules, resolved_head_sha, changed).
        changed=False means the pinned ref is unchanged since last sync — nothing pulled.
        """
        head_sha = self._resolve_ref_sha()

        if last_synced_sha == head_sha:
            log.info("github_source_unchanged", repo=self.repo, ref=self.ref, sha=head_sha)
            return [], head_sha, False

        if last_synced_sha:
            file_paths = self._list_changed_files(last_synced_sha, head_sha)
            log.info("github_incremental_pull", repo=self.repo, count=len(file_paths))
            raw_rules = self._fetch_files_individually(file_paths, head_sha)
        else:
            raw_rules = self._full_pull_via_tarball(head_sha)

        return raw_rules, head_sha, True
