from unittest.mock import MagicMock, patch
from collector.github_provider import GitHubRepoSource


def _mk_resp(json_data=None, status=200):
    r = MagicMock()
    r.status_code = status
    if json_data is not None:
        r.json.return_value = json_data
    r.raise_for_status = MagicMock() if status == 200 else MagicMock(side_effect=Exception("http err"))
    return r


@patch("collector.github_provider.requests.get")
def test_first_sync_full_pull(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules", token="", extra_tags=[])
    mock_get.side_effect = [
        _mk_resp({"sha": "headsha123"}),  # resolve head
        _mk_resp({"tree": [  # tree listing
            {"type": "blob", "path": "rules/a.yml", "sha": "blobsha1", "url": "https://api.github.com/blob1"},
            {"type": "blob", "path": "rules/b.yar", "sha": "blobsha2", "url": "https://api.github.com/blob2"},
            {"type": "blob", "path": "other/c.txt", "sha": "blobsha3", "url": "https://api.github.com/blob3"},
        ]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IHRlc3Q="}),  # a.yml content
        _mk_resp({"encoding": "base64", "content": "cnVsZSB0ZXN0IHt9"}),  # b.yar content
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha=None)
    assert changed is True
    assert head_sha == "headsha123"
    assert len(rules) == 2
    assert {r.rule_type for r in rules} == {"sigma", "yara"}
    assert all(r.event_uuid in ("blobsha1", "blobsha2") for r in rules)


@patch("collector.github_provider.requests.get")
def test_pinned_ref_unchanged_is_noop(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="v1.0", path="rules", token="", extra_tags=[])
    mock_get.return_value = _mk_resp({"sha": "samesha"})
    rules, head_sha, changed = src.fetch(last_synced_sha="samesha")
    assert changed is False
    assert rules == []
    assert head_sha == "samesha"
    # only the ref-resolve call — no tree or blob calls when unchanged
    assert mock_get.call_count == 1


@patch("collector.github_provider.requests.get")
def test_fetch_scopes_by_path_and_extension(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules/windows", token="", extra_tags=[])
    mock_get.side_effect = [
        _mk_resp({"sha": "newsha"}),
        _mk_resp({"tree": [
            {"type": "blob", "path": "rules/windows/a.yml", "sha": "s1", "url": "u1"},
            {"type": "blob", "path": "rules/linux/b.yml", "sha": "s2", "url": "u2"},  # out of path scope
            {"type": "blob", "path": "rules/windows/readme.md", "sha": "s3", "url": "u3"},  # wrong extension
            {"type": "tree", "path": "rules/windows/subdir", "sha": "s4", "url": "u4"},  # not a blob
        ]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IHdpbg=="}),
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha="oldsha")
    assert changed is True
    assert len(rules) == 1
    assert rules[0].name == "rules__windows__a.yml"


@patch("collector.github_provider.requests.get")
def test_extra_tags_and_repo_tag_applied(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules", token="", extra_tags=["external", "unverified"])
    mock_get.side_effect = [
        _mk_resp({"sha": "sha1"}),
        _mk_resp({"tree": [
            {"type": "blob", "path": "rules/a.yml", "sha": "s1", "url": "u1"},
        ]}),
        _mk_resp({"encoding": "base64", "content": "dGl0bGU6IHRlc3Q="}),
    ]
    rules, head_sha, changed = src.fetch(last_synced_sha=None)
    assert len(rules) == 1
    assert "external" in rules[0].tags
    assert "unverified" in rules[0].tags
    assert "repo:org/repo" in rules[0].tags


def test_get_extension():
    assert GitHubRepoSource._get_extension("rules/a.yml") == ".yml"
    assert GitHubRepoSource._get_extension("rules/b.YAR") == ".yar"
    assert GitHubRepoSource._get_extension("noextension") == ""


@patch("collector.github_provider.requests.get")
def test_token_sets_auth_header(mock_get):
    src = GitHubRepoSource(repo="org/repo", ref="main", path="rules", token="fake-token-123", extra_tags=[])
    mock_get.return_value = _mk_resp({"sha": "samesha"})
    src.fetch(last_synced_sha="samesha")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer fake-token-123"
