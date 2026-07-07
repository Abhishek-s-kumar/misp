#!/usr/bin/env python3
"""Patch collector/github_provider.py: fetch content via raw.githubusercontent.com
instead of the git/blobs REST API, which is hitting secondary rate limits.
Run from repo root. Assumes patch_github_throttle.py already applied."""
import sys, pathlib

f = pathlib.Path("collector/github_provider.py")
s = f.read_text(encoding="utf-8")

OLD_METHOD = '''    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _fetch_blob_content(self, blob_url: str) -> str:
        resp = requests.get(blob_url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content", "")'''

NEW_METHOD = '''    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
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
        return resp.text'''

OLD_FETCH_ONE = '''        def _fetch_one(entry):
            try:
                return entry, self._fetch_blob_content(entry["url"]), None
            except Exception as e:
                return entry, None, e'''

NEW_FETCH_ONE = '''        def _fetch_one(entry):
            try:
                return entry, self._fetch_raw_content(entry["path"], head_sha), None
            except Exception as e:
                return entry, None, e'''

if OLD_METHOD not in s:
    sys.exit("_fetch_blob_content anchor not found, abort")
if OLD_FETCH_ONE not in s:
    sys.exit("_fetch_one anchor not found, abort")

s = s.replace(OLD_METHOD, NEW_METHOD, 1)
s = s.replace(OLD_FETCH_ONE, NEW_FETCH_ONE, 1)

f.write_text(s, encoding="utf-8")
print("patched collector/github_provider.py: content fetch now uses raw.githubusercontent.com")
