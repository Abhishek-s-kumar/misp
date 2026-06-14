"""Integration test: Ansible dry-run against mock_wazuh directory."""
import os
import shutil
import subprocess
from pathlib import Path
import pytest

REPO_PATH = Path(os.environ.get("TI_REPO_PATH", "/home/kali/Desktop/misp/repository"))
WORKSPACE_ROOT = REPO_PATH.parent
ANSIBLE_DIR = WORKSPACE_ROOT / "ansible"
INVENTORY_FILE = ANSIBLE_DIR / "inventory.ini"

# Resolve ansible-playbook from .venv or PATH
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook") or str(WORKSPACE_ROOT / ".venv/bin/ansible-playbook")
ansible_available = Path(ANSIBLE_PLAYBOOK).exists()

pytestmark = pytest.mark.skipif(
    not ansible_available,
    reason="ansible-playbook not found — install ansible-core in .venv to run this test"
)


@pytest.fixture(autouse=True)
def ensure_cdb_stubs():
    """Create stub CDB files in repository/iocs/ so the playbook has files to copy."""
    iocs_dir = REPO_PATH / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    for name in ("misp_ips", "misp_domains", "misp_hashes", "misp_urls"):
        stub = iocs_dir / name
        if not stub.exists():
            stub.write_text("# stub for dry-run test\n")


def test_ansible_dry_run_deploy_playbook():
    """Deploy playbook should pass --check (dry-run) without errors in mock mode."""
    mock_lists = str(WORKSPACE_ROOT / "mock_wazuh" / "etc" / "lists")

    cmd = [
        ANSIBLE_PLAYBOOK,
        str(ANSIBLE_DIR / "deploy_iocs.yml"),
        "-i", str(INVENTORY_FILE),
        "-e", "is_local_mock=true",
        "-e", f"wazuh_lists_dir={mock_lists}",
        "--check"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(WORKSPACE_ROOT)
    )

    # Ansible --check may return 0 or non-zero depending on state;
    # we check for no FAILED task lines in output.
    assert "ERROR!" not in result.stdout, f"Ansible ERROR:\n{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, (
        f"Ansible dry-run failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
