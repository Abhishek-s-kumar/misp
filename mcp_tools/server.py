import os
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(parent_dir, ".env"))

# Initialize FastMCP
mcp = FastMCP(
    "wazuh-detection-pipeline",
    title="Wazuh Detection Rule Automation",
    description="MISP to Wazuh Detection Rules Automation via MCP"
)

# Import tool functions
from mcp_tools.rule_tools import (
    sync_misp_rules,
    validate_rules,
    deploy_rules,
    rollback_rules,
    rule_status,
    sync_github_rules,
    list_quarantine,
    promote_rule,
    reject_rule
)

# Register tools
mcp.add_tool(sync_misp_rules)
mcp.add_tool(validate_rules)
mcp.add_tool(deploy_rules)
mcp.add_tool(rollback_rules)
mcp.add_tool(rule_status)
mcp.add_tool(sync_github_rules)
mcp.add_tool(list_quarantine)
mcp.add_tool(promote_rule)
mcp.add_tool(reject_rule)

if __name__ == "__main__":
    mcp.run()
