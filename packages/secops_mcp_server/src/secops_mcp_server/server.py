"""GitGuardian MCP server for SecOps teams with incident management tools."""

import json
import logging
import os
from typing import Any, Literal

from developer_mcp_server.register_tools import register_developer_tools
from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_secops_scopes, validate_scopes, set_secops_scopes
from gg_api_core.host import is_self_hosted_instance
from pydantic import BaseModel, Field
from fastmcp.exceptions import ToolError

from gg_api_core.tools.assign_incident import assign_incident
from gg_api_core.tools.create_code_fix_request import create_code_fix_request
from gg_api_core.tools.list_users import list_users
from gg_api_core.tools.manage_incident import manage_private_incident, update_incident_status
from gg_api_core.tools.read_custom_tags import read_custom_tags
from gg_api_core.tools.revoke_secret import revoke_secret
from gg_api_core.tools.write_custom_tags import write_custom_tags, update_or_create_incident_custom_tags

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)


# ===== Pydantic Models for Tool Parameters =====

class GenerateHoneytokenParams(BaseModel):
    """Parameters for generating a honeytoken."""
    name: str = Field(description="Name for the honeytoken")
    description: str = Field(default="", description="Description of what the honeytoken is used for")


class ListIncidentsParams(BaseModel):
    """Parameters for listing incidents."""
    severity: str | None = Field(
        default=None, description="Filter incidents by severity (critical, high, medium, low)"
    )
    status: str | None = Field(
        default=None, description="Filter incidents by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)"
    )
    from_date: str | None = Field(
        default=None, description="Filter incidents created after this date (ISO format: YYYY-MM-DD)"
    )
    to_date: str | None = Field(
        default=None, description="Filter incidents created before this date (ISO format: YYYY-MM-DD)"
    )
    assignee_email: str | None = Field(default=None, description="Filter incidents assigned to this email")
    assignee_id: str | int | None = Field(default=None, description="Filter incidents assigned to this user id")
    validity: str | None = Field(
        default=None, description="Filter incidents by validity (valid, invalid, failed_to_check, no_checker, unknown)"
    )
    ordering: Literal["date", "-date", "resolved_at", "-resolved_at", "ignored_at", "-ignored_at"] | None = Field(
        default=None,
        description="Sort field and direction (prefix with '-' for descending order). If you need to get the latest incidents, use '-date'.",
    )
    per_page: int = Field(default=20, description="Number of results per page (1-100)")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")
    mine: bool = Field(default=False, description="If True, fetch incidents assigned to the current user")


class ListHoneytokensParams(BaseModel):
    """Parameters for listing honeytokens."""
    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)")
    search: str | None = Field(default=None, description="Search string to filter results by name or description")
    ordering: str | None = Field(
        default=None, description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')"
    )
    show_token: bool = Field(default=False, description="Whether to include token details in the response")
    creator_id: str | int | None = Field(default=None, description="Filter by creator ID")
    creator_api_token_id: str | int | None = Field(default=None, description="Filter by creator API token ID")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")
    mine: bool = Field(default=False, description="If True, fetch honeytokens created by the current user")


# ===== End of Pydantic Models =====

set_secops_scopes()

SECOPS_INSTRUCTIONS = """
# GitGuardian SecOps Tools

This server provides comprehensive GitGuardian security tools through MCP.
Each tool requires specific API token scopes to function correctly.

If you receive an error when calling a tool, it may be because your API token does not have the required scopes.
Check the required scopes for each tool below and don't use another tool instead of the one that requires the missing scope.

Available capabilities:

1. Honeytoken Management:
   - Generate honeytokens
   - List and manage existing honeytokens
   - Get detailed information about tokens

2. Incident Management:
   - List and filter incidents by various criteria
   - Manage incidents (assign, resolve, ignore)
   - Update incident status and add custom tags

3. Repository Analysis:
   - List incidents by repository
   - Get detailed information about repository security status

IMPORTANT:
- If a prompt is asking to filter results for the current user, you MUST use the mine parameter.
- For example, if a prompt is asking: "list incidents assigned to me", or "list my incident", or "list my honeytokens", you MUST use the `mine` parameter.
"""

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian SecOps",
    log_level="DEBUG",
    instructions=SECOPS_INSTRUCTIONS,
)
logger.debug("Created SecOps GitGuardianFastMCP instance")

register_developer_tools(mcp)


@mcp.tool(
    description="Get information about the current API token ",
    required_scopes=["api_tokens:read"],
)
async def get_current_token_info() -> dict[str, Any]:
    """
    Get information about the current API token.

    Returns comprehensive information including:
    - Token details (name, ID, creation date, expiration)
    - Token scopes and permissions
    - Associated member information

    Returns:
        Token information dictionary
    """
    client = mcp.get_client()
    logger.debug("Getting current token information")

    try:
        result = await client.get_current_token_info()
        logger.debug(f"Retrieved token info for token ID: {result.get('id')}")
        return result
    except Exception as e:
        logger.error(f"Error getting token info: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


mcp.tool(
    update_or_create_incident_custom_tags,
    description="Update or create custom tags for a secret incident",
    required_scopes=["incidents:write", "custom_tags:write"],
)

mcp.tool(
    update_incident_status,
    description="Update a secret incident with status",
    required_scopes=["incidents:write"],
)

mcp.tool(
    read_custom_tags,
    description="Read custom tags from the GitGuardian dashboard.",
    required_scopes=["custom_tags:read"],
)

mcp.tool(
    write_custom_tags,
    description="Create or delete custom tags in the GitGuardian dashboard.",
    required_scopes=["custom_tags:write"],
)

mcp.tool(
    manage_private_incident,
    description="Manage a secret incident (assign, unassign, resolve, ignore, reopen)",
    required_scopes=["incidents:write"],
)

mcp.tool(list_users,
             description="List users on the workspace/account",
             required_scopes=["members:read"], )

mcp.tool(
    revoke_secret,
    description="Revoke a secret by its ID through the GitGuardian API",
    required_scopes=["write:secret"],
)

mcp.tool(
    assign_incident,
    description="Assign a secret incident to a specific member or to the current user",
    required_scopes=["incidents:write"],
)

mcp.add_tool(
    create_code_fix_request,
    description="Create code fix requests for multiple secret incidents with their locations. This will generate pull requests to automatically remediate the detected secrets.",
    required_scopes=["incidents:write"],
)

# Register common tools for user information and token management
try:
    from gg_api_core.mcp_server import register_common_tools

    register_common_tools(mcp)
except Exception as e:
    logger.error(f"Failed to register common tools: {str(e)}")
    import traceback

    logger.error(f"Traceback: {traceback.format_exc()}")


def run_mcp_server():
    logger.info("Starting SecOps MCP server...")

    # Check if HTTP/SSE transport is requested via environment variables
    mcp_port = os.environ.get("MCP_PORT")
    mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")

    if mcp_port:
        # Use HTTP/SSE transport
        import uvicorn

        logger.info(f"Starting MCP server with HTTP/SSE transport on {mcp_host}:{mcp_port}")
        uvicorn.run(mcp.sse_app(), host=mcp_host, port=int(mcp_port))
    else:
        # Use default stdio transport
        logger.info("Starting MCP server with stdio transport (default)")
        mcp.run()


if __name__ == "__main__":
    run_mcp_server()
