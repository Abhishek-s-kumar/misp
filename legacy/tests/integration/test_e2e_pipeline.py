import os
import json
import shutil
import pytest
from pathlib import Path
from git import Repo
from mcp_tools.sync_iocs import sync_misp_iocs
from mcp_tools.deploy_iocs import deploy_iocs
from mcp_tools.status import check_wazuh_status

@pytest.fixture
def e2e_env(tmp_path, monkeypatch):
    # 1. Initialize temporary git repo on 'main' branch
    repo_path = tmp_path / "repository"
    repo_path.mkdir()
    repo = Repo.init(repo_path)
    repo.git.checkout("-b", "main")
    
    # Create empty CDB stub files
    iocs_dir = repo_path / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    for name in ("misp_ips", "misp_domains", "misp_hashes", "misp_urls"):
        (iocs_dir / name).write_text("# stub\n", encoding="utf-8")
        
    repo.index.add([f"iocs/{name}" for name in ("misp_ips", "misp_domains", "misp_hashes", "misp_urls")])
    repo.index.commit("Initial commit with stubs")
    
    # Copy ansible folder to tmp_path
    shutil.copytree("/home/kali/Desktop/misp/ansible", tmp_path / "ansible")
    
    # Create fixtures/mock_iocs.json with at least 2 valid IOCs
    temp_fixture = tmp_path / "fixtures" / "mock_iocs.json"
    temp_fixture.parent.mkdir(parents=True, exist_ok=True)
    mock_data = [
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
            "event_id": 1002,
            "event_uuid": "762c2f7b-bb66-417f-ad66-f0803554471f",
            "timestamp": "2026-06-14T09:10:00+00:00",
            "tags": ["tlp:white"],
            "to_ids": True
        }
    ]
    temp_fixture.write_text(json.dumps(mock_data), encoding="utf-8")
    
    # Ensure mock_wazuh/etc/lists/ exists
    mock_wazuh_lists = tmp_path / "mock_wazuh" / "etc" / "lists"
    mock_wazuh_lists.mkdir(parents=True, exist_ok=True)
    
    # Set environment variables
    monkeypatch.setenv("TI_REPO_PATH", str(repo_path))
    monkeypatch.setenv("IS_LOCAL_MOCK", "true")
    monkeypatch.setenv("MISP_PROVIDER", "mock")
    monkeypatch.setenv("ANSIBLE_INVENTORY", str(tmp_path / "ansible" / "inventory.ini"))
    
    # Prepend virtual env bin directory to PATH so subprocess can find ansible-playbook
    venv_bin = str(Path("/home/kali/Desktop/misp/.venv/bin"))
    monkeypatch.setenv("PATH", f"{venv_bin}:{os.environ.get('PATH', '')}")
    
    # Patch MockMISPProvider to use our temp fixture
    monkeypatch.setattr(
        "collector.mock_provider.MockMISPProvider.__init__",
        lambda self, fixture_path=temp_fixture: setattr(self, "fixture_path", fixture_path)
    )
    
    return tmp_path, repo_path, repo

def test_sync_commits_valid_iocs_to_main(e2e_env):
    tmp_path, repo_path, repo = e2e_env
    
    initial_commit = repo.head.commit.hexsha
    
    res = sync_misp_iocs(tags=["tlp:white"], full_pull=True)
    
    assert res["status"] == "committed"
    assert res["total_valid"] > 0
    assert repo.head.commit.hexsha != initial_commit
    
    misp_ips_file = repo_path / "iocs" / "misp_ips"
    assert misp_ips_file.exists()
    content = misp_ips_file.read_text(encoding="utf-8")
    assert "185.100.87.10:malicious" in content

def test_deploy_runs_ansible_in_mock_mode(e2e_env):
    tmp_path, repo_path, repo = e2e_env
    
    # First sync to populate lists
    sync_res = sync_misp_iocs(tags=["tlp:white"], full_pull=True)
    assert sync_res["status"] == "committed"
    
    # Then deploy
    deploy_res = deploy_iocs(dry_run=False)
    
    assert deploy_res["status"] == "ok"
    assert deploy_res["deploy_tag"] != ""
    assert deploy_res["deploy_tag"] in [t.name for t in repo.tags]
    
    mock_ips_file = tmp_path / "mock_wazuh" / "etc" / "lists" / "misp_ips"
    assert mock_ips_file.exists()
    assert "185.100.87.10:malicious" in mock_ips_file.read_text(encoding="utf-8")

def test_check_wazuh_status_mock_returns_ok(e2e_env):
    tmp_path, repo_path, repo = e2e_env
    
    res = check_wazuh_status()
    
    assert res["status"] == "ok"
    assert len(res["results"]) > 0
    assert any(info["running"] for info in res["results"].values())

def test_deploy_blocked_when_all_lists_empty(e2e_env):
    tmp_path, repo_path, repo = e2e_env
    
    # CDB lists are empty (only contain '# stub')
    deploy_res = deploy_iocs(dry_run=False)
    
    assert deploy_res["status"] == "aborted"
    assert deploy_res["reason"] == "all_cdb_lists_empty"
