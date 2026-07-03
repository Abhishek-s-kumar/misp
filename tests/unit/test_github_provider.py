import io
import tarfile
from unittest.mock import MagicMock, patch
from collector.github_provider import GitHubRepoSource


def _mk_resp(json_data=None, status=200, content=None):
    r = MagicMock()
    r.status_code = status
    if json_data is not None:
        r.json.return_value = json_data
    r.raise_for_status = MagicMock() if status == 200 else MagicMock(side_effect=Exception("http err"))
    if content is not None:
        r.iter_content = MagicMock(return_value=[content])
    return r


def _mk_tarball(files: dict, root: str = "repo-abc123") -> bytes:
    """files: {relative_path: content_str} — builds a gzip tarball in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{root}/{rel_path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@patch("collector.github_provider.requests.get")
def test_first_sync_full_pull_uses_tarball(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules")
    tarball_bytes = _mk_tarball({
        "rules/a.yml": "title: test",
        "rules/b.yar": "rule test {}",
        "other/c.txt": "not a rule",
    })
    mock_get.side_effect = [
        _mk_resp({"sha": "headsha123"}),  # resolve ref
        _mk_resp(content=tarball_bytes),  # tarball download
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha=None)
    assert changed is True
    assert head_sha == "headsha123"
    assert len(rules) == 2
    assert {r.rule_type for r in rules} == {"sigma", "yara"}


@patch("collector.github_provider.requests.get")
def test_pinned_ref_unchanged_is_noop(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="v1.0", path="rules")
    mock_get.return_value = _mk_resp({"sha": "samesha"})
    rules, head_sha, changed = src.fetch(last_synced_sha="samesha")
    assert changed is False
    assert rules == []
    assert head_sha == "samesha"


@patch("collector.github_provider.requests.get")
def test_incremental_uses_compare_api_not_tarball(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules")
    mock_get.side_effect = [
        _mk_resp({"sha": "newsha"}),
        _mk_resp({"files": [
            {"filename": "rules/new.yml", "status": "added"},
            {"filename": "rules/x.yar", "status": "modified"},
            {"filename": "other/skip.txt", "status": "added"},
        ]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IG5ldw=="}),
        _mk_resp({"encoding": "base64", "content": "cnVsZSBuZXcge30="}),
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha="oldsha")
    assert changed is True
    assert head_sha == "newsha"
    assert len(rules) == 2
    assert all(r.event_uuid.startswith("github:org/repo@") for r in rules)
    # only 4 calls: resolve, compare, 2x content — no tarball download call
    assert mock_get.call_count == 4


def test_out_of_scope_path_filtered():
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules/windows")
    assert src._in_scope("rules/windows/a.yml") is True
    assert src._in_scope("rules/linux/b.yml") is False
    assert src._in_scope("rules/windows/readme.md") is False
