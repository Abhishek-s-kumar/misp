from unittest.mock import MagicMock, patch
from collector.github_provider import GitHubRepoSource

def _mk_resp(json_data, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data
    r.raise_for_status = MagicMock() if status == 200 else MagicMock(side_effect=Exception("http err"))
    return r

@patch("collector.github_provider.requests.get")
def test_first_sync_full_tree_walk(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules")
    mock_get.side_effect = [
        _mk_resp({"sha": "headsha123"}),
        _mk_resp({"tree": [{"type": "blob", "path": "rules/a.yml"}, {"type": "blob", "path": "rules/b.yar"}, {"type": "blob", "path": "other/c.txt"}]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IHRlc3Q="}),
        _mk_resp({"encoding": "base64", "content": "cnVsZSB0ZXN0IHt9"}),
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
def test_incremental_uses_compare_api(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules")
    mock_get.side_effect = [
        _mk_resp({"sha": "newsha"}),
        _mk_resp({"files": [{"filename": "rules/new.yml", "status": "added"}, {"filename": "rules/x.yar", "status": "modified"}, {"filename": "other/skip.txt", "status": "added"}]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IG5ldw=="}),
        _mk_resp({"encoding": "base64", "content": "cnVsZSBuZXcge30="}),
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha="oldsha")
    assert changed is True
    assert head_sha == "newsha"
    assert len(rules) == 2
    assert all(r.event_uuid.startswith("github:org/repo@") for r in rules)

@patch("collector.github_provider.requests.get")
def test_out_of_scope_path_filtered(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules/windows")
    assert src._in_scope("rules/windows/a.yml") is True
    assert src._in_scope("rules/linux/b.yml") is False
    assert src._in_scope("rules/windows/readme.md") is False
