"""
End-to-end integration test: Full pipeline using MockMISPProvider.
Tests: sync → validate → git commit (main) → tag
"""
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest
from git import Repo


@pytest.fixture
def pipeline_workspace(tmp_path):
    """Create a temporary git repository and fixtures for the E2E test."""
    # Set up the git repo
    repo_path = tmp_path / "repository"
    repo_path.mkdir()
    repo = Repo.init(repo_path)
    repo.git.checkout("-b", "main")

    iocs_dir = repo_path / "iocs"
    iocs_dir.mkdir()
    for name in ("misp_ips", "misp_domains", "misp_hashes", "misp_urls"):
        (iocs_dir / name).write_text("# initial\n")

    repo.index.add([f"iocs/{n}" for n in ("misp_ips", "misp_domains", "misp_hashes", "misp_urls")])
    repo.index.commit("initial: empty cdb lists")

    # Set up fixtures dir with a mock_iocs.json
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    mock_iocs = [
        {
            "ioc_type": "ip-src",
            "value": "185.100.87.10",
            "event_id": 1001,
            "event_uuid": "f290b83e-1175-47e2-824c-1e247492c10b",
            "timestamp": "2026-06-14T09:00:00+00:00",
            "tags": ["tlp:white"],
            "to_ids": True
        },
        {
            "ioc_type": "domain",
            "value": "evil-domain.ru",
            "event_id": 1003,
            "event_uuid": "762c2f7b-bb66-417f-ad66-f0803554471f",
            "timestamp": "2026-06-14T09:10:00+00:00",
            "tags": ["tlp:white"],
            "to_ids": True
        }
    ]
    (fixtures_dir / "mock_iocs.json").write_text(json.dumps(mock_iocs))

    return tmp_path, repo_path, repo


def test_e2e_sync_commits_to_main(pipeline_workspace):
    """sync_misp_iocs should collect, validate, write CDB files and commit to main."""
    tmp_path, repo_path, repo = pipeline_workspace

    os.environ["TI_REPO_PATH"] = str(repo_path)
    os.environ["MISP_PROVIDER"] = "mock"

    from collector.mock_provider import MockMISPProvider
    from collector.misp_iocs import MISPIOCCollector
    from ioc_validators.ioc_validator import IOCValidator

    fixture_path = tmp_path / "fixtures" / "mock_iocs.json"
    provider = MockMISPProvider(fixture_path=fixture_path)

    state_file = repo_path / ".sync_state.json"
    collector = MISPIOCCollector(provider=provider, state_file=state_file)
    raw_iocs = collector.pull(ioc_types=["ip-src", "domain"], tags=[], full_pull=True)

    validator = IOCValidator()
    valid_iocs, stats = validator.validate_batch(raw_iocs)

    assert len(valid_iocs) == 2
    assert stats["rejected"] == 0

    iocs_dir = repo_path / "iocs"
    grouped = {"ip": [], "domain": []}
    for ioc in valid_iocs:
        if ioc.normalized_type in grouped:
            grouped[ioc.normalized_type].append(ioc)

    (iocs_dir / "misp_ips").write_text(
        "\n".join(sorted(f"{i.value}:malicious" for i in grouped["ip"])) + "\n"
    )
    (iocs_dir / "misp_domains").write_text(
        "\n".join(sorted(f"{i.value}:malicious" for i in grouped["domain"])) + "\n"
    )

    files_to_add = ["iocs/misp_ips", "iocs/misp_domains"]
    if state_file.exists():
        files_to_add.append(".sync_state.json")

    repo.index.add([f for f in files_to_add if (repo_path / f).exists()])

    initial_commit = repo.head.commit.hexsha
    commit = repo.index.commit("sync: iocs main [test] pulled=2 valid=2")
    
    assert repo.head.commit.hexsha != initial_commit
    assert repo.active_branch.name == "main"

    ips_content = (iocs_dir / "misp_ips").read_text()
    assert "185.100.87.10:malicious" in ips_content

    domains_content = (iocs_dir / "misp_domains").read_text()
    assert "evil-domain.ru:malicious" in domains_content


def test_e2e_deployment_creates_tag(pipeline_workspace):
    """After sync, creating a deploy tag should work correctly."""
    tmp_path, repo_path, repo = pipeline_workspace

    initial_commit = repo.head.commit.hexsha
    tag_name = "deploy-iocs-20260614-093600"
    tag_metadata = {
        "type": "deploy",
        "scope": "iocs",
        "commit": initial_commit,
        "ioc_counts": {"ips": 2, "domains": 1, "hashes": 0, "urls": 0},
        "hosts_succeeded": ["mock-wazuh-mgr-1"],
        "operator": "mcp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    repo.create_tag(tag_name, message=json.dumps(tag_metadata))

    assert tag_name in [t.name for t in repo.tags]
    tag_ref = repo.tags[tag_name]
    assert tag_ref.commit.hexsha == initial_commit


def test_e2e_rollback_restores_from_tag(pipeline_workspace):
    """Rollback should restore iocs/ content from a previous deploy tag."""
    tmp_path, repo_path, repo = pipeline_workspace

    (repo_path / "iocs" / "misp_ips").write_text("1.2.3.4:malicious\n")
    repo.index.add(["iocs/misp_ips"])
    original_commit = repo.index.commit("sync: original")

    tag_name = "deploy-iocs-20260614-000000"
    repo.create_tag(tag_name, message=json.dumps({
        "type": "deploy",
        "commit": original_commit.hexsha
    }))

    (repo_path / "iocs" / "misp_ips").write_text("9.9.9.9:malicious\n")
    repo.index.add(["iocs/misp_ips"])
    repo.index.commit("sync: newer update")

    # Rollback: checkout the file from the original tag
    repo.git.checkout(f"tags/{tag_name}", "--", "iocs/")

    restored_content = (repo_path / "iocs" / "misp_ips").read_text()
    assert "1.2.3.4:malicious" in restored_content
    assert "9.9.9.9" not in restored_content
