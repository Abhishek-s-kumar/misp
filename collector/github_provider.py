"""
GitHub rule source for mcp_tools.rule_tools.sync_github_rules().

GitHubRepoSource wraps a single GitHub repo/ref/path as a pull source.
Incremental sync is commit-SHA based: fetch() resolves `ref` to its
current HEAD SHA and compares against `last_synced_sha` (persisted by
the caller in .sync_state.json under "github_sources"). If unchanged,
returns immediately with zero tree/blob API calls. If changed, does a
full re-fetch of all in-scope files at the new HEAD -- this is repo-level
granularity, not per-file diffing, which is a deliberate simplification:
cheap (one extra API call per source per sync when nothing changed) and
avoids the complexity of tracking per-file state, at the cost of
re-downloading unchanged files within a repo that had ANY change.
Reasonable for the file counts involved here (~1000s, not 100,000s).

RawRule's event_id / event_uuid / misp_timestamp fields are MISP-shaped
concepts with no GitHub equivalent -- synthesized:
  - event_id: stable hash of "owner/repo".
  - event_uuid: the file's git blob SHA (real, content-addressed).
  - misp_timestamp: fetch time (GitHub tree listing has no per-file
    commit date without one extra API call per file).
"""

import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import requests
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from collector.base import RawRule

log = structlog.get_logger()

EXTENSION_MAP = {
    ".yml": "sigma",
    ".yaml": "sigma",
    ".yar": "yara",
    ".yara": "yara",
}

GITHUB_API = "https://api.github.com"


class GitHubRepoSource:
    def __init__(self, repo: str, ref: str, path: str, token: str, extra_tags: List[str]):
        self.repo = repo
        self.ref = ref
        self.path = path
        self.token = token
        self.extra_tags = extra_tags
        if not token:
            log.warning(
                "github_source_no_token",
                repo=repo,
                message="GITHUB_TOKEN not set -- limited to 60 req/hr",
            )

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _resolve_head_sha(self) -> str:
        url = f"{GITHUB_API}/repos/{self.repo}/commits/{self.ref}"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()["sha"]

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _fetch_tree(self, commit_sha: str) -> List[dict]:
        url = f"{GITHUB_API}/repos/{self.repo}/git/trees/{commit_sha}?recursive=1"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get("truncated"):
            log.warning(
                "github_tree_truncated",
                repo=self.repo,
                message="repo tree exceeds GitHub's single-response limit, some files were not listed",
            )
        return data.get("tree", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _fetch_blob_content(self, blob_url: str) -> str:
        resp = requests.get(blob_url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content", "")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _fetch_raw_content(self, path: str, ref: str) -> str:
        """Fetch file content via raw.githubusercontent.com CDN instead of the
        git/blobs REST API -- avoids GitHub's secondary rate limit on repeated
        blob API calls, which the retry/backoff alone could not survive."""
        url = f"https://raw.githubusercontent.com/{self.repo}/{ref}/{path}"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.text

    @staticmethod
    def _get_extension(filename: str) -> str:
        dot_idx = filename.rfind(".")
        return filename[dot_idx:].lower() if dot_idx != -1 else ""

    def fetch(self, last_synced_sha: Optional[str] = None) -> Tuple[List[RawRule], str, bool]:
        """
        Returns (raw_rules, head_sha, changed).
        changed=False means head_sha == last_synced_sha, raw_rules is empty,
        no tree/blob calls were made.
        """
        head_sha = self._resolve_head_sha()

        if last_synced_sha is not None and last_synced_sha == head_sha:
            log.info("github_source_unchanged", repo=self.repo, sha=head_sha[:12])
            return [], head_sha, False

        tree = self._fetch_tree(head_sha)
        event_id = abs(hash(self.repo)) % (2**31)

        in_scope = []
        for entry in tree:
            if entry.get("type") != "blob":
                continue
            path = entry["path"]
            if self.path and not path.startswith(self.path):
                continue
            ext = self._get_extension(path)
            if ext not in EXTENSION_MAP:
                continue
            in_scope.append(entry)

        log.info(
            "github_source_scope_resolved",
            repo=self.repo,
            file_count=len(in_scope),
            head_sha=head_sha[:12],
        )

        raw_rules: List[RawRule] = []

        def _fetch_one(entry):
            try:
                return entry, self._fetch_raw_content(entry["path"], head_sha), None
            except Exception as e:
                return entry, None, e

        BATCH_SIZE = 40
        BATCH_DELAY_SECONDS = 2.0
        MAX_WORKERS = 4

        for batch_start in range(0, len(in_scope), BATCH_SIZE):
            batch = in_scope[batch_start:batch_start + BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = [pool.submit(_fetch_one, e) for e in batch]
                for future in as_completed(futures):
                    entry, content, err = future.result()
                    if err is not None:
                        log.warning("github_blob_fetch_failed", path=entry["path"], error=str(err))
                        continue
                    ext = self._get_extension(entry["path"])
                    raw_rules.append(
                        RawRule(
                            rule_type=EXTENSION_MAP[ext],
                            name=entry["path"].replace("/", "__"),
                            content=content,
                            event_id=event_id,
                            event_uuid=entry["sha"],
                            misp_timestamp=datetime.now(timezone.utc),
                            tags=list(self.extra_tags) + [f"repo:{self.repo}"],
                        )
                    )
            done = min(batch_start + BATCH_SIZE, len(in_scope))
            log.info("github_source_fetch_progress", repo=self.repo, done=done, total=len(in_scope))
            if done < len(in_scope):
                time.sleep(BATCH_DELAY_SECONDS)

        log.info("github_source_rules_fetched", repo=self.repo, count=len(raw_rules))
        return raw_rules, head_sha, True
