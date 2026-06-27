import os
import json
import shutil
import pytest
from pathlib import Path
from git import Repo
from unittest.mock import MagicMock

from mcp_tools.rule_tools import sync_misp_rules, deploy_rules, rollback_rules, rule_status

@pytest.fixture(autouse=True)
def mock_subprocess_run(monkeypatch):
    import subprocess
    original_run = subprocess.run

    def mock_run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and len(cmd) > 0:
            first = str(cmd[0])
            if "yara" in first or "sigma" in first or "wazuh-analysisd" in first:
                mock_res = MagicMock()
                mock_res.returncode = 0
                mock_res.stdout = "<group name='converted'><rule id='100201'></rule></group>" if "convert" in cmd else ""
                mock_res.stderr = ""
                return mock_res
        return original_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", mock_run)

@pytest.fixture
def e2e_rules_env(tmp_path, monkeypatch):
    # 1. Initialize temporary Git repo on 'main' branch
    repo_path = tmp_path / "repository"
    repo_path.mkdir()
    repo = Repo.init(repo_path)
    repo.git.checkout("-b", "main")

    # Create directory structure for rules (new flat layout)
    rules_dir = repo_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("sigma", "yara", "wazuh"):
        (rules_dir / sub).mkdir(parents=True, exist_ok=True)
    # Also create generated/ layout
    generated_dir = repo_path / "generated"
    for sub in ("pending", "metadata", "conversion_cache", "manifests"):
        (generated_dir / sub).mkdir(parents=True, exist_ok=True)

    # Put a dummy file and commit so we have a valid HEAD
    readme = repo_path / "README.md"
    readme.write_text("# Threat Intel Repo", encoding="utf-8")
    repo.index.add(["README.md"])
    repo.index.commit("Initial commit")

    # Create tag for rollback tests
    repo.create_tag("last_known_good", message="Baseline valid ruleset")

    # Copy ansible folder to tmp_path
    shutil.copytree("/home/kali/Desktop/misp/ansible", tmp_path / "ansible")

    # Override inventory to use localhost with local connection to avoid SSH timeouts
    inventory_path = tmp_path / "ansible" / "inventory.ini"
    inventory_path.write_text(
        "[wazuh_managers]\nwazuh-mgr-1 ansible_host=localhost ansible_connection=local\n",
        encoding="utf-8"
    )

    # Create fixtures/mock_rules.json with a valid YARA and Sigma rule
    temp_fixture = tmp_path / "fixtures" / "mock_rules.json"
    temp_fixture.parent.mkdir(parents=True, exist_ok=True)
    mock_data = [
        {
            "rule_type": "yara",
            "name": "e2e_suspicious_powershell.yar",
            "content": "rule e2e_susp_powershell {\n    strings:\n        $a = \"powershell.exe\"\n    condition:\n        $a\n}",
            "event_id": 2001,
            "event_uuid": "3e9b1da9-f81d-44a5-9263-d1f86f99cf2a",
            "timestamp": "2026-06-14T10:00:00+00:00",
            "tags": ["tlp:white"]
        },
        {
            "rule_type": "sigma",
            "name": "e2e_win_encoded_cmd.yml",
            "content": "title: Encoded Command Execution\nid: 762c2f7b-bb66-417f-ad66-f0803554471f\nlogsource:\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: '-encodedcommand'\n    condition: selection",
            "event_id": 2002,
            "event_uuid": "3e9b1da9-f81d-44a5-9263-d1f86f99cf2b",
            "timestamp": "2026-06-14T10:05:00+00:00",
            "tags": ["tlp:white"]
        }
    ]
    temp_fixture.write_text(json.dumps(mock_data), encoding="utf-8")

    # Ensure mock_wazuh folders exist
    (tmp_path / "mock_wazuh" / "etc" / "rules").mkdir(parents=True, exist_ok=True)
    (tmp_path / "mock_wazuh" / "opt" / "yara-rules").mkdir(parents=True, exist_ok=True)

    # Set environment variables
    monkeypatch.setenv("TI_REPO_PATH", str(repo_path))
    monkeypatch.setenv("IS_LOCAL_MOCK", "true")
    monkeypatch.setenv("MISP_PROVIDER", "mock")
    monkeypatch.setenv("ANSIBLE_INVENTORY", str(tmp_path / "ansible" / "inventory.ini"))

    # Prepend virtual env bin directory to PATH for subprocess calls to ansible-playbook
    venv_bin = "/home/kali/Desktop/misp/.venv/bin"
    monkeypatch.setenv("PATH", f"{venv_bin}:{os.environ.get('PATH', '')}")

    # Patch MockMISPRuleProvider to point to our temp fixture
    monkeypatch.setattr(
        "collector.mock_provider.MockMISPRuleProvider.__init__",
        lambda self, fixture_path=temp_fixture: setattr(self, "fixture_path", fixture_path)
    )

    return tmp_path, repo_path, repo

def test_sync_rules_commits_to_main(e2e_rules_env):
    tmp_path, repo_path, repo = e2e_rules_env

    initial_commit = repo.head.commit.hexsha

    res = sync_misp_rules(since=None)

    assert res.status == "committed"
    assert res.total_pulled == 2
    assert res.approved == 2
    assert res.converted == 1  # 1 Sigma ID assigned
    assert repo.head.commit.hexsha != initial_commit

    # Verify YARA was saved to rules/yara/
    yara_file = repo_path / "rules" / "yara" / "e2e_suspicious_powershell.yar"
    assert yara_file.exists()

    # Verify Sigma was saved to rules/sigma/ with wazuh_rule_id persisted
    sigma_file = repo_path / "rules" / "sigma" / "e2e_win_encoded_cmd.yml"
    assert sigma_file.exists()
    import yaml
    sigma_data = yaml.safe_load(sigma_file.read_text())
    assert "custom" in sigma_data
    assert "wazuh_rule_id" in sigma_data["custom"]
    assert 200000 <= sigma_data["custom"]["wazuh_rule_id"] <= 299999

    # Verify generated/local_rules.xml was created
    local_rules = repo_path / "generated" / "local_rules.xml"
    assert local_rules.exists()

    # Verify metadata was created
    metadata_file = repo_path / "generated" / "metadata" / "e2e_win_encoded_cmd.json"
    assert metadata_file.exists()
    meta_data = json.loads(metadata_file.read_text(encoding="utf-8"))
    assert meta_data["validation_status"] == "passed"
    assert meta_data["conversion_status"] == "converted"

def test_deploy_rules_mock(e2e_rules_env):
    tmp_path, repo_path, repo = e2e_rules_env

    # 1. Sync rules
    sync_res = sync_misp_rules(since=None)
    assert sync_res.status == "committed"

    # 2. Deploy rules
    deploy_res = deploy_rules(dry_run=False)
    assert deploy_res.status == "ok"
    assert deploy_res.deploy_tag.startswith("deploy-rules-")
    assert deploy_res.deploy_tag in [t.name for t in repo.tags]

    # Verify files were copied to mock_wazuh targets
    mock_rules_dir = tmp_path / "mock_wazuh" / "etc" / "rules"
    mock_yara_dir = tmp_path / "mock_wazuh" / "opt" / "yara-rules"

    assert (mock_yara_dir / "e2e_suspicious_powershell.yar").exists()
    # Ansible copies generated/local_rules.xml -> target_rules_dir/local_rules.xml
    assert (mock_rules_dir / "local_rules.xml").exists()

def test_deploy_rules_blocked_if_empty(e2e_rules_env):
    tmp_path, repo_path, repo = e2e_rules_env

    # Try deploying directly (rules directory contains no rules yet)
    deploy_res = deploy_rules(dry_run=False)
    assert deploy_res.status.startswith("aborted")

def test_rule_status_mock(e2e_rules_env):
    tmp_path, repo_path, repo = e2e_rules_env

    # Pre-deployment status
    report = rule_status("localhost")
    assert report.wazuh_running is True
    assert report.yara_rules_count == 0
    assert report.wazuh_rules_count == 0

    # Sync and Deploy
    sync_misp_rules(since=None)
    deploy_rules(dry_run=False)

    # Post-deployment status
    report = rule_status("localhost")
    assert report.yara_rules_count == 1
    assert report.wazuh_rules_count == 1
    assert report.last_deployment_tag.startswith("deploy-rules-")

def test_rollback_rules_mock(e2e_rules_env):
    tmp_path, repo_path, repo = e2e_rules_env

    # Sync and Deploy to create a tag
    sync_misp_rules(since=None)
    deploy_res = deploy_rules(dry_run=False)
    tag_name = deploy_res.deploy_tag

    # Modify the rule file locally to simulate bad changes
    yara_file = repo_path / "rules" / "yara" / "e2e_suspicious_powershell.yar"
    yara_file.write_text("bad content modifications", encoding="utf-8")
    repo.index.add([str(yara_file)])
    repo.index.commit("Bad commit")

    # Run Rollback to the previous deploy tag
    rollback_res = rollback_rules(tag=tag_name)
    assert rollback_res.status == "ok"
    assert rollback_res.revert_success is True

    # Check that YARA content has been restored
    content = yara_file.read_text(encoding="utf-8")
    assert "e2e_susp_powershell" in content

def test_sync_rules_two_repo_mode(e2e_rules_env, monkeypatch):
    tmp_path, repo_path, repo = e2e_rules_env

    # 1. Set up a separate DaC repo
    dac_path = tmp_path / "dac_repository"
    dac_path.mkdir()
    dac_repo = Repo.init(dac_path)
    dac_repo.git.checkout("-b", "main")

    # Put a dummy file and commit so main branch has a commit history
    readme = dac_path / "README.md"
    readme.write_text("# DaC Repo", encoding="utf-8")
    dac_repo.index.add(["README.md"])
    dac_repo.index.commit("Initial commit")

    # Create directory structure in DaC repo
    for sub in ("rules", "rules/yara", "rules/sigma", "rules/wazuh", "generated"):
        (dac_path / sub).mkdir(parents=True, exist_ok=True)

    # 2. Configure E2E env to use separate DaC repo
    monkeypatch.setenv("DAC_REPO_PATH", str(dac_path))

    # Mock the github PR creation/reuse logic to avoid gh CLI subprocess call
    from unittest.mock import patch
    with patch("mcp_tools.rule_tools.get_or_create_pr") as mock_pr:
        mock_pr.return_value = {
            "number": 42,
            "url": "https://github.com/mock/DaC/pull/42",
            "action": "created"
        }

        # 3. Sync rules
        res = sync_misp_rules(since=None)

        # Assert status and PR URL
        assert res.status == "committed"
        assert res.pr_url == "https://github.com/mock/DaC/pull/42"
        assert res.total_pulled == 2
        assert res.approved == 2

        # 4. Verify rules were committed to the dev branch in the separate DaC repo
        assert dac_repo.active_branch.name == "dev"
        
        yara_file = dac_path / "rules" / "yara" / "e2e_suspicious_powershell.yar"
        assert yara_file.exists()

        sigma_file = dac_path / "rules" / "sigma" / "e2e_win_encoded_cmd.yml"
        assert sigma_file.exists()

        local_rules = dac_path / "generated" / "local_rules.xml"
        assert local_rules.exists()

