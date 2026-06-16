# Threat Intel Artifact Repository

## Environment Variable Clarification

Two separate variables control mock mode:

| Variable | Type | Controls |
|----------|------|----------|
| `IS_LOCAL_MOCK` | Env var (uppercase) | Python MCP tools (deploy_iocs.py, rollback.py, status.py) |
| `is_local_mock` | Ansible extra-var (lowercase) | Ansible playbooks — passed via `-e "is_local_mock=true"` |

These are independent. Both must be set correctly for local mock mode to work end-to-end.
