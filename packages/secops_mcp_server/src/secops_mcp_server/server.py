"""GitGuardian MCP server for SecOps teams with incident management tools."""

import logging
import os

# Declare this process's profile before anything in gg_api_core reads Settings.
# Used by ``Settings.effective_scopes`` to cap the OAuth scope set.
os.environ.setdefault("SERVER_PROFILE", "secops")

from typing import Any, Literal  # noqa: E402

from developer_mcp_server.add_health_check import add_health_check  # noqa: E402
from developer_mcp_server.register_tools import register_developer_tools  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402
from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES  # noqa: E402
from gg_api_core.mcp_server import get_mcp_server, register_common_tools  # noqa: E402
from gg_api_core.prompts.register_prompts import register_hil_prompts  # noqa: E402
from gg_api_core.tools.assign_incident import assign_incident  # noqa: E402
from gg_api_core.tools.assign_public_incident import assign_public_incident  # noqa: E402
from gg_api_core.tools.create_code_fix_request import create_code_fix_request  # noqa: E402
from gg_api_core.tools.manage_incident import (  # noqa: E402
    manage_private_incident,
    update_incident_status,
)
from gg_api_core.tools.read_custom_tags import read_custom_tags  # noqa: E402
from gg_api_core.tools.revoke_secret import revoke_secret  # noqa: E402
from gg_api_core.tools.update_public_incident_status import update_public_incident_status  # noqa: E402
from gg_api_core.tools.write_custom_tags import (  # noqa: E402
    update_or_create_incident_custom_tags,
    write_custom_tags,
)
from pydantic import BaseModel, Field  # noqa: E402

from secops_mcp_server.register_hil import register_hil_tools  # noqa: E402

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)


# ===== Pydantic Models for Tool Parameters =====


class GenerateHoneytokenParams(BaseModel):
    """Parameters for generating a honeytoken."""

    name: str = Field(description="Name for the honeytoken")
    description: str = Field(default="", description="Description of what the honeytoken is used for")


class ListIncidentsParams(BaseModel):
    """Parameters for listing incidents."""

    severity: str | None = Field(
        default=None,
        description="Filter incidents by severity (critical, high, medium, low)",
    )
    status: str | None = Field(
        default=None,
        description="Filter incidents by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)",
    )
    from_date: str | None = Field(
        default=None,
        description="Filter incidents created after this date (ISO format: YYYY-MM-DD)",
    )
    to_date: str | None = Field(
        default=None,
        description="Filter incidents created before this date (ISO format: YYYY-MM-DD)",
    )
    assignee_email: str | None = Field(default=None, description="Filter incidents assigned to this email")
    assignee_id: str | int | None = Field(default=None, description="Filter incidents assigned to this user id")
    validity: str | None = Field(
        default=None,
        description="Filter incidents by validity (valid, invalid, failed_to_check, no_checker, unknown)",
    )
    ordering: Literal["date", "-date", "resolved_at", "-resolved_at", "ignored_at", "-ignored_at"] | None = Field(
        default=None,
        description="Sort field and direction (prefix with '-' for descending order). If you need to get the latest incidents, use '-date'.",
    )
    per_page: int = Field(default=20, description="Number of results per page (1-100)")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch incidents assigned to the current user",
    )


class ListHoneytokensParams(BaseModel):
    """Parameters for listing honeytokens."""

    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)")
    search: str | None = Field(
        default=None,
        description="Search string to filter results by name or description",
    )
    ordering: str | None = Field(
        default=None,
        description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')",
    )
    show_token: bool = Field(default=False, description="Whether to include token details in the response")
    creator_id: str | int | None = Field(default=None, description="Filter by creator ID")
    creator_api_token_id: str | int | None = Field(default=None, description="Filter by creator API token ID")
    per_page: int = Field(
        default=20,
        description="Number of results per page (default: 20, min: 1, max: 100)",
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch honeytokens created by the current user",
    )


# ===== End of Pydantic Models =====

SECOPS_INSTRUCTIONS = """
# GitGuardian SecOps Tools

This server provides comprehensive GitGuardian security tools through MCP.
Each tool requires specific API token scopes to function correctly.

If you receive an error when calling a tool, it may be because your API token does not have the required scopes.
Check the required scopes for each tool below and don't use another tool instead of the one that requires the missing scope.

## Two incident categories — pick the right tool

GitGuardian surfaces two distinct, non-overlapping categories of secret incidents:

- **Internal incidents** — detected in sources the workspace has explicitly integrated:
  private/org Git repos, Slack, Jira, Confluence, container registries, SharePoint, etc.
  Identified by a `source_id`. Default category for most customer workflows.
  Read tools: `list_incidents`, `count_incidents`, `get_incident`, `list_repo_occurrences`,
  `remediate_secret_incidents`, `list_sources`, `find_current_source_id`.
  Write tools: `manage_private_incident`, `update_incident_status`, `assign_incident`,
  `update_or_create_incident_custom_tags`, `create_code_fix_request`.
- **Public incidents** — detected by GitGuardian Public Monitoring on the worldwide public
  perimeter: public GitHub repos/gists, Docker Hub, etc. Not linked to a workspace source.
  Read tools: `list_public_incidents`, `get_public_incident`, `list_public_occurrences`.
  Write tools: `assign_public_incident`, `update_public_incident_status`.

Incident IDs are **not** interchangeable between the two categories. If the user's intent is
about leaks "on public GitHub / outside the org / on Docker Hub / found by Public Monitoring",
use the `list_public_*` tools. Otherwise default to the internal tools. Invoking an internal
write tool with a public incident ID (or vice versa) will silently 404.

Available capabilities:

1. Honeytoken Management:
   - Generate honeytokens
   - List and manage existing honeytokens
   - Get detailed information about tokens

2. Incident Management:
   - List and filter incidents by various criteria (internal and public)
   - Manage internal incidents (assign, resolve, ignore)
   - Update internal incident status and add custom tags

3. Repository Analysis:
   - List incidents by repository (internal)
   - Get detailed information about repository security status

IMPORTANT:
- If a prompt is asking to filter results for the current user, you MUST use the mine parameter.
- For example, if a prompt is asking: "list incidents assigned to me", or "list my incident", or "list my honeytokens", you MUST use the `mine` parameter.
"""

# Use our custom GitGuardianFastMCP from the core package
mcp = get_mcp_server(
    "GitGuardian SecOps",
    instructions=SECOPS_INSTRUCTIONS,
)

register_developer_tools(mcp)
add_health_check(mcp)


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
    client = await mcp.get_client()
    logger.debug("Getting current token information")

    try:
        result = await client.get_current_token_info()
        assert isinstance(result, dict)
        logger.debug(f"Retrieved token info for token ID: {result.get('id')}")
        return result
    except Exception as e:
        logger.exception(f"Error getting token info: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


mcp.tool(
    update_or_create_incident_custom_tags,
    description="(Internal sources only) Update or create custom tags for an internal secret incident. "
    "Does not work on public-monitoring incident IDs.",
    required_scopes=["incidents:write", "custom_tags:write"],
)

mcp.tool(
    update_incident_status,
    description="(Internal sources only) Update an internal secret incident with status. "
    "Does not work on public-monitoring incident IDs.",
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
    description="(Internal sources only) Manage an internal secret incident (assign, unassign, resolve, ignore, reopen). "
    "Does not work on public-monitoring incident IDs.",
    required_scopes=["incidents:write"],
)

mcp.tool(
    revoke_secret,
    description="Revoke a secret by its ID through the GitGuardian API. Operates on a secret_id regardless of whether "
    "the incident surfaced on an internal source or via Public Monitoring.",
    required_scopes=["write:secret"],
)

mcp.tool(
    assign_incident,
    description="(Internal sources only) Assign an internal secret incident to a specific member or to the current user. "
    "Does not work on public-monitoring incident IDs.",
    required_scopes=["incidents:write"],
)

mcp.tool(
    assign_public_incident,
    description="(Public Monitoring only — for internal sources use assign_incident) "
    "Assign a public secret incident detected by GitGuardian Public Monitoring to a specific "
    "member or to the current user. Public incident IDs are NOT interchangeable with internal "
    "incident IDs.",
    required_scopes=["incidents:write"],
)

mcp.tool(
    update_public_incident_status,
    description="(Public Monitoring only — for internal sources use manage_private_incident) "
    "Update the status of a public secret incident (resolve, ignore, reopen) detected by "
    "GitGuardian Public Monitoring. Public incident IDs are NOT interchangeable with internal "
    "incident IDs.",
    required_scopes=["incidents:write"],
)

mcp.tool(
    create_code_fix_request,
    description="(Internal sources only) Create code fix requests for multiple internal secret incidents with their "
    "locations. This will generate pull requests to automatically remediate detected secrets in the repositories the "
    "workspace monitors. Does not apply to public-monitoring incidents.",
    required_scopes=["incidents:write"],
)

register_common_tools(mcp)

# HIL (High Impact Leak) capabilities — atomic tools + orchestration prompts.
register_hil_tools(mcp)
register_hil_prompts(mcp)

logger.info("SecOps MCP server instance created and configured")
