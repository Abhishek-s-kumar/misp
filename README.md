# MISP Detection Rule Pipeline — Complete Production Setup

**Date:** 2026-06-18  
**Environment:** Raspberry Pi (Debian Trixie) + Remote Wazuh Docker  
**Project Path:** `/home/rpi/misp`  
**GitHub Repo:** `https://github.com/Abhishek-s-kumar/misp.git`

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [MISP Docker Deployment](#2-misp-docker-deployment)
3. [Pipeline Environment Setup](#3-pipeline-environment-setup)
4. [MISP Connectivity & Test Data](#4-misp-connectivity--test-data)
5. [Pipeline Fixes Applied](#5-pipeline-fixes-applied)
6. [GitHub Integration](#6-github-integration)
7. [Wazuh Docker Deployment](#7-wazuh-docker-deployment)
8. [Production Configuration](#8-production-configuration)
9. [Verification & Testing](#9-verification--testing)
10. [Troubleshooting](#10-troubleshooting)
11. [Next Steps](#11-next-steps)

---

## 1. Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MISP Docker   │────▶│  Pipeline (Pi)   │────▶│  Wazuh Docker   │
│  (localhost)    │     │  (/home/rpi/misp)│     │ (10.21.232.220) │
│                 │     │                  │     │                 │
│ • Event ID 1    │     │ • Collect rules  │     │ • local_rules   │
│ • YARA attr     │     │ • Validate       │     │ • YARA rules    │
│ • Sigma attr    │     │ • Convert        │     │ • Container     │
│ • tlp:white     │     │ • Git commit     │     │   restart       │
└─────────────────┘     │ • Ansible deploy │     └─────────────────┘
                        └──────────────────┘
                                   │
                                   ▼
                        ┌──────────────────┐
                        │  GitHub Repo     │
                        │  (deploy key)    │
                        └──────────────────┘
```

---

## 2. MISP Docker Deployment

### 2.1 Clone Repository
```bash
cd ~
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
```

### 2.2 Create `.env` File
```bash
cp template.env .env
nano .env
```

```env
# Required Build Tags
CORE_TAG=v2.4.198
MODULES_TAG=v2.4.198
GUARD_TAG=v2.4.198
PHP_TAG=8.2

# Required Runtime Variables
BASE_URL=http://localhost
ADMIN_EMAIL=admin@admin.test
ADMIN_PASSWORD=ChangeMe123!
ADMIN_ORG=ORGNAME
ADMIN_ORG_UUID=5e335b0a-0aef-4f55-900e-abcdef123456
ENCRYPTION_KEY=ChangeMeEncryptionKey12345678901234567890
SALT=ChangeMeSalt123456789012345678901234567890
UUID=5e335b0a-0aef-4f55-900e-abcdef123456

# Database
MYSQL_HOST=db
MYSQL_DATABASE=misp
MYSQL_USER=misp
MYSQL_PASSWORD=ChangeMeDB123!
MYSQL_ROOT_PASSWORD=ChangeMeRoot123!

# Redis
REDIS_HOST=redis
REDIS_PASSWORD=ChangeMeRedis123!

# Optional
INIT=true
DISABLE_SSL_REDIRECT=true
```

### 2.3 Start Containers
```bash
docker compose up -d
```

**Containers:**
| Container | Image | Ports | Status |
|-----------|-------|-------|--------|
| `misp-core` | `ghcr.io/misp/misp-docker/misp-core:latest` | 80, 443 | ✅ Healthy |
| `misp-modules` | `ghcr.io/misp/misp-docker/misp-modules:latest` | — | ✅ Healthy |
| `db` | `mariadb:10.11` | 3306 | ✅ Healthy |
| `redis` | `valkey/valkey:7.2` | 6379 | ✅ Healthy |
| `mail` | `ghcr.io/egos-tech/smtp:1.1.3` | 25 | ✅ Running |

### 2.4 Generate API Key
```bash
docker exec misp-docker-misp-core-1 bash -c \
  '/var/www/MISP/app/Console/cake User change_authkey admin@admin.test'
```

**API Key:** `BUXC1zOMA0iScGVhcQwPFLtaI0xdhlEzL8ZgYvPG`

### 2.5 Resource Requirements

| Resource | Minimum | Recommended | Production |
|----------|---------|-------------|------------|
| **CPU** | 2 cores | 4 cores | 8+ cores |
| **RAM** | 4 GB | 8 GB | 16+ GB |
| **Disk** | 50 GB | 100 GB SSD | 500 GB+ SSD |
| **Network** | 100 Mbps | 1 Gbps | 1 Gbps+ |

**Note:** Raspberry Pi is sufficient for dev/testing but not recommended for production MISP.

---

## 3. Pipeline Environment Setup

### 3.1 Project Structure
```
/home/rpi/misp/
├── .env                          # Environment variables
├── .venv/                        # Python virtual environment
├── ansible/
│   ├── deploy_rules.yml          # Bare-metal deploy playbook
│   ├── deploy_rules_docker.yml   # Docker-aware deploy playbook
│   ├── group_vars/
│   │   └── all.yml
│   └── inventory.ini
├── collector/                    # MISP rule ingestion
│   ├── base.py
│   ├── misp_rules.py
│   ├── mock_provider.py
│   └── pymisp_provider.py
├── fixtures/
│   └── mock_rules.json
├── mcp_tools/                    # MCP server & tools
│   ├── rule_tools.py
│   └── server.py
├── processors/                   # Rule processing pipeline
│   ├── __init__.py
│   ├── deduplicator.py
│   ├── git_ops.py
│   ├── metadata_writer.py
│   ├── sigma_converter.py
│   └── xml_merger.py
├── repository/                   # Git artifact store
│   ├── iocs/
│   ├── rules/
│   │   ├── sigma/
│   │   ├── wazuh/
│   │   └── yara/
│   └── generated/
│       ├── conversion_cache/
│       ├── manifests/
│       ├── metadata/
│       └── pending/
├── scheduler/
│   └── hourly_sync.py
├── validators/                   # Rule validation engines
│   ├── sigma_validator.py
│   ├── wazuh_validator.py
│   └── yara_validator.py
├── github_deploy_key             # GitHub deploy key (private)
├── github_deploy_key.pub         # GitHub deploy key (public)
├── wazuh_ansible_key             # Wazuh SSH key (private)
├── wazuh_ansible_key.pub         # Wazuh SSH key (public)
└── requirements.txt
```

### 3.2 `.env` Configuration
```env
# MISP Connection
MISP_URL=http://localhost
MISP_API_KEY=BUXC1zOMA0iScGVhcQwPFLtaI0xdhlEzL8ZgYvPG
MISP_VERIFY_SSL=false
MISP_PROVIDER=real

# Git Repository
TI_REPO_PATH=/home/rpi/misp/repository
GIT_REMOTE=origin
GIT_BRANCH=main

# Ansible
ANSIBLE_INVENTORY=/home/rpi/misp/ansible/inventory.ini
ANSIBLE_VAULT_PASSWORD_FILE=/home/rpi/misp/.vault_pass

# Mock mode — DISABLE for production
IS_LOCAL_MOCK=false

# Scheduler
ENABLE_SCHEDULER=true
SCHEDULER_INTERVAL_HOURS=1

# Fix for Ansible locale
LC_ALL=C.UTF-8
LANG=C.UTF-8
```

### 3.3 Install Dependencies
```bash
cd /home/rpi/misp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pysigma  # Fallback for Sigma validation
```

### 3.4 Install System Binaries
```bash
sudo apt update
sudo apt install yara
```

### 3.5 Create Directory Structure
```bash
cd /home/rpi/misp
mkdir -p repository/rules/{yara,sigma,wazuh}
mkdir -p repository/generated/{pending,metadata,conversion_cache,manifests}
mkdir -p mock_wazuh/etc/rules
mkdir -p mock_wazuh/opt/yara-rules

cd repository
git init
git checkout -b main
git add .
git commit -m "Initial structure"
```

---

## 4. MISP Connectivity & Test Data

### 4.1 Verify Connection
```python
from pymisp import PyMISP
misp = PyMISP('http://localhost', 'BUXC1zOMA0iScGVhcQwPFLtaI0xdhlEzL8ZgYvPG', ssl=False)
user = misp.get_user()
print('Connected as:', user['User']['email'])
# Connected as: admin@admin.test
```

### 4.2 Create Test Event
```python
from pymisp import PyMISP, MISPEvent

misp = PyMISP('http://localhost', 'BUXC1zOMA0iScGVhcQwPFLtaI0xdhlEzL8ZgYvPG', ssl=False)

# Create event
event = MISPEvent()
event.info = 'Test Detection Rules Pipeline'
event.distribution = 0
event.add_tag('tlp:white')

# Add YARA attribute
yara_rule = 'rule test_misp_connection {
    meta:
        description = "Test rule from MISP pipeline"
    strings:
        $a = "powershell.exe" nocase
    condition:
        $a
}'
event.add_attribute(type='yara', value=yara_rule)
event.attributes[0].add_tag('tlp:white')

# Add Sigma attribute
sigma_rule = 'title: Test Sigma Rule
id: 762c2f7b-bb66-417f-ad66-f0803554471f
status: experimental
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
level: high'
event.add_attribute(type='sigma', value=sigma_rule)
event.attributes[1].add_tag('tlp:white')

result = misp.add_event(event)
print('Event ID:', result['Event']['id'])
# Event ID: 1
```

**Event UUID:** `023143ce-0ee0-45c0-8565-3ce4be41d669`

---

## 5. Pipeline Fixes Applied

### 5.1 Sigma Validator — CLI Command Update
**File:** `validators/sigma_validator.py`

**Problem:** `sigma validate` command removed in sigma-cli v3.x  
**Fix:** Changed to `sigma check` with pySigma fallback

```python
# Before (broken)
result = subprocess.run(["sigma", "validate", str(tmp_path)], ...)

# After (working)
result = subprocess.run(["sigma", "check", str(tmp_path)], ...)
```

### 5.2 YARA Validator — Command Syntax Update
**File:** `validators/yara_validator.py`

**Problem:** `yara -C` in v4.5.2 requires target file argument  
**Fix:** Use `yara -p 0 <rule> <dummy_file>`

```python
# Before (broken)
result = subprocess.run(["yara", "-C", str(tmp_path)], ...)

# After (working)
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as dummy:
    dummy.write("dummy")
    dummy_path = Path(dummy.name)
result = subprocess.run(["yara", "-p", "0", str(tmp_path), str(dummy_path)], ...)
```

### 5.3 Rule ID Range — Conflict Avoidance
**File:** `processors/xml_merger.py`

**Problem:** Default range 100000-199999 conflicts with existing Wazuh rules (100100, 100200, 101100-101902)  
**Fix:** Changed to 200000-299999

```python
# Before
for rid in range(100000, 200000):

# After
for rid in range(200000, 300000):
```

### 5.4 Sigma Converter — Missing Wazuh Backend
**File:** `processors/sigma_converter.py`

**Problem:** `sigma convert --target wazuh` fails — Wazuh backend plugin not in sigma-cli v3.x  
**Status:** Falls back to `_mock_sigma_to_wazuh()` which generates valid Wazuh XML skeleton  
**Note:** For real conversion, install `sigma-cli` with Wazuh backend plugin

---

## 6. GitHub Integration

### 6.1 Generate Deploy Key
```bash
cd /home/rpi/misp
ssh-keygen -t ed25519 -a 100 -f github_deploy_key -N "" -C "misp-pipeline-deploy@$(hostname)"
```

### 6.2 Add to GitHub
- URL: `https://github.com/Abhishek-s-kumar/misp/settings/keys`
- Title: `misp-pipeline-deploy`
- Key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXHM56pYC1UHK8eWy+0RN5QxLAlbWHujnBHtvepGD1T misp-pipeline-deploy@rpi`
- ✅ Allow write access

### 6.3 SSH Config
```bash
mkdir -p ~/.ssh
cat >> ~/.ssh/config << 'EOF'
Host github-misp
    HostName github.com
    User git
    IdentityFile /home/rpi/misp/github_deploy_key
    IdentitiesOnly yes
    StrictHostKeyChecking no
EOF
chmod 600 ~/.ssh/config
```

### 6.4 Git Remote & Push
```bash
cd /home/rpi/misp
git remote add origin git@github-misp:Abhishek-s-kumar/misp.git
git add .
git commit -m "feat: deploy MISP rules to Wazuh Docker"
git push origin main
```

---

## 7. Wazuh Docker Deployment

### 7.1 Wazuh Server Details
- **Host:** `waserver@10.21.232.220`
- **Password:** `Wh$rver@12`
- **Docker Dir:** `~/wazuh-docker/multi-node`
- **Container:** `multi-node-wazuh.master-1`
- **Rules Volume:** `./config/wazuh_manager/rules:/var/ossec/etc/rules`

### 7.2 Set Up SSH Key for Ansible
```bash
cd /home/rpi/misp
ssh-keygen -t ed25519 -f wazuh_ansible_key -N "" -C "ansible-wazuh@rpi"
ssh-copy-id -i wazuh_ansible_key.pub waserver@10.21.232.220
# Enter password: Wh$rver@12

# Test
ssh -i wazuh_ansible_key waserver@10.21.232.220
```

### 7.3 Ansible Inventory
**File:** `ansible/inventory.ini`
```ini
[wazuh_managers]
wazuh-mgr-1 ansible_host=10.21.232.220 ansible_user=waserver

[wazuh_managers:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_private_key_file=/home/rpi/misp/wazuh_ansible_key
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
```

### 7.4 Ansible Group Variables
**File:** `ansible/group_vars/all.yml`
```yaml
---
# Wazuh Manager Configuration
wazuh_rules_dir: /var/ossec/etc/rules
yara_rules_dir: /opt/yara-rules
wazuh_bin: /var/ossec/bin
wazuh_file_owner: root
wazuh_file_group: wazuh
wazuh_file_mode: "0640"
wazuh_dir_mode: "0750"

# Production — disable mock
is_local_mock: false
```

### 7.5 Docker-Aware Playbook
**File:** `ansible/deploy_rules_docker.yml`
```yaml
---
- name: Deploy Detection Rules to Wazuh Docker
  hosts: wazuh_managers
  serial: 1
  vars:
    wazuh_docker_dir: "~/wazuh-docker/multi-node"
    wazuh_rules_host_dir: "{{ wazuh_docker_dir }}/config/wazuh_manager/rules"
    wazuh_yara_host_dir: "{{ wazuh_docker_dir }}/config/wazuh_manager/yara-rules"
    container_name: "multi-node-wazuh.master-1"

  tasks:
    - name: Ensure rules directory exists on host
      file:
        path: "{{ wazuh_rules_host_dir }}"
        state: directory
        mode: "0755"

    - name: Ensure YARA directory exists on host
      file:
        path: "{{ wazuh_yara_host_dir }}"
        state: directory
        mode: "0755"

    - name: Sync compiled Wazuh rules to host volume
      copy:
        src: ../repository/generated/local_rules.xml
        dest: "{{ wazuh_rules_host_dir }}/local_rules.xml"
        mode: "0644"
      register: copy_wazuh_rules

    - name: Sync YARA rules to host volume
      copy:
        src: ../repository/rules/yara/
        dest: "{{ wazuh_yara_host_dir }}/"
        mode: "0644"
      register: copy_yara_rules

    - name: Restart Wazuh master container
      command: "docker restart {{ container_name }}"
      when: copy_wazuh_rules.changed or copy_yara_rules.changed

    - name: Verify container is running after restart
      command: "docker ps --filter name={{ container_name }} --format '{% raw %}{{ .Status }}{% endraw %}'"
      register: container_status
      retries: 5
      delay: 10
      until: "'Up' in container_status.stdout"
      when: copy_wazuh_rules.changed or copy_yara_rules.changed

    - name: Show container status
      debug:
        msg: "Wazuh master container status: {{ container_status.stdout }}"
      when: copy_wazuh_rules.changed or copy_yara_rules.changed
```

### 7.6 Deploy Commands
```bash
cd /home/rpi/misp
source .venv/bin/activate
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Dry run
ansible-playbook -i ansible/inventory.ini ansible/deploy_rules_docker.yml --check

# Real deploy
ansible-playbook -i ansible/inventory.ini ansible/deploy_rules_docker.yml
```

### 7.7 Deploy Result
```
PLAY RECAP
wazuh-mgr-1 | ok=8 | changed=6 | unreachable=0 | failed=0 | skipped=0

Container status: Up Less than a second
```

---

## 8. Production Configuration

### 8.1 Systemd Service for Scheduler
**File:** `/etc/systemd/system/misp-sync.service`
```ini
[Unit]
Description=MISP Detection Rule Sync
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=rpi
WorkingDirectory=/home/rpi/misp
Environment=PATH=/home/rpi/misp/.venv/bin:/usr/bin
EnvironmentFile=/home/rpi/misp/.env
ExecStart=/home/rpi/misp/.venv/bin/python scheduler/hourly_sync.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable misp-sync
sudo systemctl start misp-sync
sudo systemctl status misp-sync
```

### 8.2 Firewall Hardening (MISP)
```bash
sudo ufw allow 22/tcp                    # SSH
sudo ufw allow from <pipeline-ip> to any port 80
sudo ufw allow from <pipeline-ip> to any port 443
sudo ufw default deny incoming
sudo ufw enable
```

### 8.3 SSL for MISP (Production)
Set up reverse proxy (nginx/traefik) with Let's Encrypt or internal CA. Currently running HTTP only.

---

## 9. Verification & Testing

### 9.1 Pipeline Sync Test
```bash
cd /home/rpi/misp
source .venv/bin/activate
python3 -c "
from dotenv import load_dotenv
load_dotenv('/home/rpi/misp/.env')
from mcp_tools.rule_tools import sync_misp_rules
result = sync_misp_rules()
print(f'Status: {result.status}')
print(f'Pulled: {result.total_pulled}')
print(f'Approved: {result.approved}')
print(f'Rejected: {result.rejected}')
print(f'Converted: {result.converted}')
print(f'Commit: {result.commit_sha}')
"
```

**Expected Output:**
```
Status: committed
Pulled: 2
Approved: 2
Rejected: 0
Converted: 1
Commit: 227a5aca2d65431cefc434c9720cebb518de845d
```

### 9.2 Deploy Test
```bash
ansible-playbook -i ansible/inventory.ini ansible/deploy_rules_docker.yml
```

**Expected Output:**
```
wazuh-mgr-1 | ok=8 | changed=6 | failed=0
```

### 9.3 Verify on Wazuh Server
```bash
ssh waserver@10.21.232.220
cat ~/wazuh-docker/multi-node/config/wazuh_manager/rules/local_rules.xml
```

**Expected Content:**
```xml
<group name="misp,">
  <rule id="200000" level="10">
    <description>Test Sigma Rule [Sigma converted]</description>
  </rule>
</group>
```

### 9.4 Verify YARA Rules
```bash
ls -la ~/wazuh-docker/multi-node/config/wazuh_manager/yara-rules/
cat ~/wazuh-docker/multi-node/config/wazuh_manager/yara-rules/*.yar
```

---

## 10. Troubleshooting

### 10.1 Ansible Locale Error
```bash
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
```

### 10.2 MISP Redirect Loop
```bash
docker exec misp-docker-misp-core-1 bash -c \
  '/var/www/MISP/app/Console/cake Admin setSetting Security.force_https false'
docker restart misp-docker-misp-core-1
```

### 10.3 Sigma CLI Missing Command
```bash
sigma --help
# Use 'check' instead of 'validate'
```

### 10.4 YARA Syntax Error
```bash
# Test YARA syntax
yara -p 0 /tmp/test.yar /tmp/dummy.txt
```

### 10.5 Rule ID Conflicts
```bash
# Check existing rules on Wazuh server
ssh waserver@10.21.232.220
cat ~/wazuh-docker/multi-node/config/custom_rules/local_rules.xml | grep 'id='
```

---

## 11. Next Steps

1. [ ] **Add more MISP events** with real detection rules (YARA, Sigma, Wazuh XML)
2. [ ] **Install Wazuh Sigma backend** for real conversion instead of mock fallback
3. [ ] **Enable systemd scheduler** for hourly auto-sync
4. [ ] **Set up SSL** for MISP (Let's Encrypt or internal CA)
5. [ ] **Multi-node deployment** — extend playbook to deploy to worker nodes
6. [ ] **Monitoring & alerting** — add webhook notifications for failures
7. [ ] **Backup strategy** — backup MISP database and Git repository
8. [ ] **API key rotation** — rotate `MISP_API_KEY` every 90 days

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `.env` | Environment variables (MISP, Git, Ansible) |
| `validators/sigma_validator.py` | Sigma rule validation (`sigma check`) |
| `validators/yara_validator.py` | YARA rule validation (`yara -p 0`) |
| `processors/xml_merger.py` | Rule ID allocation (200000-299999 range) |
| `ansible/inventory.ini` | Wazuh server SSH config |
| `ansible/deploy_rules_docker.yml` | Docker-aware deployment playbook |
| `mcp_tools/rule_tools.py` | Main pipeline functions (sync, deploy, rollback) |
| `scheduler/hourly_sync.py` | Background scheduler for auto-sync |

---

## Commands Cheat Sheet

```bash
# === MISP ===
docker ps | grep misp
docker logs misp-docker-misp-core-1 --tail 50
docker restart misp-docker-misp-core-1

# === Pipeline ===
cd /home/rpi/misp && source .venv/bin/activate
export LC_ALL=C.UTF-8 && export LANG=C.UTF-8

# Sync
python3 -c "from mcp_tools.rule_tools import sync_misp_rules; print(sync_misp_rules())"

# Deploy
ansible-playbook -i ansible/inventory.ini ansible/deploy_rules_docker.yml

# Status
python3 -c "from mcp_tools.rule_tools import rule_status; print(rule_status('localhost'))"

# === Git ===
git add . && git commit -m "update" && git push origin main

# === Wazuh Server ===
ssh waserver@10.21.232.220
cat ~/wazuh-docker/multi-node/config/wazuh_manager/rules/local_rules.xml
docker ps | grep wazuh.master
```

---

*End of Document*
