"""GitGuardian MCP server for SecOps teams with incident management tools."""

import json
import logging
import os
from typing import Any, Literal

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_secops_scopes, validate_scopes
from gg_api_core.host import is_self_hosted_instance
from mcp.server.fastmcp import ToolError
from pydantic import BaseModel, Field

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


class ManageIncidentParams(BaseModel):
    """Parameters for managing an incident."""
    incident_id: str | int = Field(description="ID of the secret incident to manage")
    action: Literal["assign", "unassign", "resolve", "ignore", "reopen"] = Field(
        description="Action to perform on the incident"
    )
    assignee_id: str | int | None = Field(
        default=None, description="ID of the member to assign the incident to (required for 'assign' action)"
    )
    ignore_reason: str | None = Field(
        default=None,
        description="Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)",
    )
    mine: bool = Field(default=False, description="If True, use the current user's ID for the assignee_id")


class UpdateOrCreateIncidentCustomTagsParams(BaseModel):
    """Parameters for updating or creating incident custom tags."""
    incident_id: str | int = Field(description="ID of the secret incident")
    custom_tags: list[str | dict[str, str]] = Field(description="List of custom tags to apply to the incident")


class UpdateIncidentStatusParams(BaseModel):
    """Parameters for updating incident status."""
    incident_id: str | int = Field(description="ID of the secret incident")
    status: str = Field(description="New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)")


class ReadCustomTagsParams(BaseModel):
    """Parameters for reading custom tags."""
    action: Literal["list_tags", "get_tag"] = Field(description="Action to perform related to reading custom tags")
    tag_id: str | int | None = Field(
        default=None, description="ID of the custom tag to retrieve (used with 'get_tag' action)"
    )


class WriteCustomTagsParams(BaseModel):
    """Parameters for writing custom tags."""
    action: Literal["create_tag", "delete_tag"] = Field(description="Action to perform related to writing custom tags")
    key: str | None = Field(default=None, description="Key for the new tag (used with 'create_tag' action)")
    value: str | None = Field(default=None, description="Value for the new tag (used with 'create_tag' action)")
    tag_id: str | int | None = Field(
        default=None, description="ID of the custom tag to delete (used with 'delete_tag' action)"
    )


# ===== End of Pydantic Models =====

# Log environment variables
gitguardian_url = os.environ.get("GITGUARDIAN_URL")

logger.info("Starting GitGuardian MCP Server")
logger.debug(f"GitGuardian URL: {gitguardian_url or 'Using default'}")

# Set specific environment variable for this server to request only SecOps-specific scopes
# Use dynamic scope detection based on instance type (self-hosted vs SaaS)
# But respect user-specified scopes if they exist
is_self_hosted = is_self_hosted_instance(gitguardian_url)

# Only override scopes if user hasn't specified them
if not os.environ.get("GITGUARDIAN_SCOPES"):
    secops_scopes = get_secops_scopes(gitguardian_url)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(secops_scopes)
    logger.debug(f"Auto-detected scopes for instance type: {'Self-hosted' if is_self_hosted else 'SaaS'}")
    if is_self_hosted:
        logger.info("Self-hosted instance detected - honeytokens:write scope omitted to avoid permission issues")
else:
    # Validate user-specified scopes
    try:
        user_scopes_str = os.environ.get("GITGUARDIAN_SCOPES")
        validated_scopes = validate_scopes(user_scopes_str)
        os.environ["GITGUARDIAN_SCOPES"] = ",".join(validated_scopes)
        logger.info(f"Using validated user-specified scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")
    except ValueError as e:
        logger.error(f"Invalid scopes configuration: {e}")
        logger.error("Please check your GITGUARDIAN_SCOPES environment variable")
        raise

logger.debug(f"Final scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian SecOps",
    log_level="DEBUG",
    instructions="""
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
    """,
)
logger.debug("Created SecOps GitGuardianFastMCP instance")


@mcp.tool(
    description="Generate an AWS GitGuardian honeytoken and get injection recommendations",
    required_scopes=["honeytokens:write"],
)
async def generate_honeytoken(params: GenerateHoneytokenParams) -> dict[str, Any]:
    """
    Generate an AWS GitGuardian honeytoken and get injection recommendations.

    Args:
        params: GenerateHoneytokenParams model containing honeytoken configuration

    Returns:
        Honeytoken data and injection recommendations
    """
    client = mcp.get_client()
    logger.debug(f"Generating honeytoken with name: {params.name}")

    try:
        # Generate the honeytoken
        result = await client.generate_honeytoken(name=params.name, description=params.description)
        logger.debug(f"Generated honeytoken with ID: {result.get('id')}")
        return result
    except Exception as e:
        logger.error(f"Error generating honeytoken: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="List secret incidents detected by the GitGuardian dashboard. When you need to retrieve personal incidents (mine, me or my), set the mine parameter to True.",
    required_scopes=["incidents:read"],
)
async def list_incidents(params: ListIncidentsParams) -> list[dict[str, Any]]:
    """
    List secret incidents detected by the GitGuardian dashboard.

    Args:
        params: ListIncidentsParams model containing filtering options

    Returns:
        List of incidents matching the specified criteria
    """
    client = mcp.get_client()
    logger.debug("Listing incidents with filters")

    # Build filters dictionary
    filters = {
        "severity": params.severity,
        "status": params.status,
        "from_date": params.from_date,
        "to_date": params.to_date,
        "assignee_email": params.assignee_email,
        "assignee_id": params.assignee_id,
        "validity": params.validity,
        "per_page": params.per_page,
        "ordering": params.ordering,
        "get_all": params.get_all,
        "mine": params.mine,
    }

    logger.debug(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

    try:
        result = await client.list_incidents(**filters)

        # Handle both response formats: either a dict with 'incidents' key or a list directly
        if isinstance(result, dict):
            incidents = result.get("incidents", [])
        else:
            # If the result is already a list, use it directly
            incidents = result

        logger.debug(f"Found {len(incidents)} incidents")
        return incidents
    except Exception as e:
        logger.error(f"Error listing incidents: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


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


@mcp.tool(
    description="List honeytokens from the GitGuardian dashboard with filtering options",
    required_scopes=["honeytokens:read"],
)
async def list_honeytokens(params: ListHoneytokensParams) -> list[dict[str, Any]]:
    """
    List honeytokens from the GitGuardian dashboard with filtering options.

    Args:
        params: ListHoneytokensParams model containing filtering options

    Returns:
        List of honeytokens matching the specified criteria
    """
    client = mcp.get_client()
    logger.debug("Listing honeytokens with filters")

    # Build filters dictionary, removing None values
    filters = {
        "status": params.status,
        "search": params.search,
        "ordering": params.ordering,
        "show_token": params.show_token,
        "creator_id": params.creator_id,
        "creator_api_token_id": params.creator_api_token_id,
        "per_page": params.per_page,
        "get_all": params.get_all,
        "mine": params.mine,
    }

    logger.debug(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

    try:
        result = await client.list_honeytokens(**filters)

        # Handle both response formats: either a dict with 'honeytokens' key or a list directly
        if isinstance(result, dict):
            honeytokens = result.get("honeytokens", [])
        else:
            # If the result is already a list, use it directly
            honeytokens = result

        logger.debug(f"Found {len(honeytokens)} honeytokens")
        return honeytokens
    except Exception as e:
        logger.error(f"Error listing honeytokens: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Manage a secret incident (assign, unassign, resolve, ignore, reopen)",
    required_scopes=["incidents:write"],
)
async def manage_incident(params: ManageIncidentParams) -> dict[str, Any]:
    """
    Manage a secret incident (assign, unassign, resolve, ignore, reopen).

    Args:
        params: ManageIncidentParams model containing incident management configuration

    Returns:
        Updated incident data
    """
    client = mcp.get_client()
    logger.debug(f"Managing incident {params.incident_id} with action: {params.action}")

    try:
        # Make the API call
        result = await client.manage_incident(
            incident_id=params.incident_id,
            action=params.action,
            assignee_id=params.assignee_id,
            ignore_reason=params.ignore_reason,
            mine=params.mine,
        )

        logger.debug(f"Managed incident {params.incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error managing incident: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Update or create custom tags for a secret incident",
    required_scopes=["incidents:write", "custom_tags:write"],
)
async def update_or_create_incident_custom_tags(params: UpdateOrCreateIncidentCustomTagsParams) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.
    If a custom tag is a String, a label is created. For example "MCP": None will create a label "MCP" without a value.

    Args:
        params: UpdateOrCreateIncidentCustomTagsParams model containing custom tags configuration

    Returns:
        Updated incident data
    """
    client = mcp.get_client()
    logger.debug(f"Updating custom tags for incident {params.incident_id}")

    try:
        # Make the API call
        result = await client.update_or_create_incident_custom_tags(
            incident_id=params.incident_id,
            custom_tags=params.custom_tags,
        )

        logger.debug(f"Updated custom tags for incident {params.incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error updating custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Update a secret incident with status",
    required_scopes=["incidents:write"],
)
async def update_incident_status(params: UpdateIncidentStatusParams) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.

    Args:
        params: UpdateIncidentStatusParams model containing status update configuration

    Returns:
        Updated incident data
    """
    client = mcp.get_client()
    logger.debug(f"Updating incident {params.incident_id} status to {params.status}")

    try:
        result = await client.update_incident_status(incident_id=params.incident_id, status=params.status)
        logger.debug(f"Updated incident {params.incident_id} status to {params.status}")
        return result
    except Exception as e:
        logger.error(f"Error updating incident status: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Read custom tags from the GitGuardian dashboard.",
    required_scopes=["custom_tags:read"],
)
async def read_custom_tags(params: ReadCustomTagsParams):
    """
    Read custom tags from the GitGuardian dashboard.

    Args:
        params: ReadCustomTagsParams model containing custom tags query configuration

    Returns:
        Custom tag data based on the action performed
    """
    try:
        client = mcp.get_client()

        if params.action == "list_tags":
            logger.debug("Listing all custom tags")
            return await client.custom_tags_list()
        elif params.action == "get_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'get_tag'")
            logger.debug(f"Getting custom tag with ID: {params.tag_id}")
            return await client.custom_tags_get(params.tag_id)
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['list_tags', 'get_tag']")
    except Exception as e:
        logger.error(f"Error reading custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Create or delete custom tags in the GitGuardian dashboard.",
    required_scopes=["custom_tags:write"],
)
async def write_custom_tags(params: WriteCustomTagsParams):
    """
    Create or delete custom tags in the GitGuardian dashboard.

    Args:
        params: WriteCustomTagsParams model containing custom tags write configuration

    Returns:
        Result based on the action performed
    """
    try:
        client = mcp.get_client()

        if params.action == "create_tag":
            if not params.key:
                raise ValueError("key is required when action is 'create_tag'")

            # Value is optional for label-only tags
            logger.debug(f"Creating custom tag with key: {params.key}, value: {params.value or 'None (label only)'}")
            return await client.custom_tags_create(params.key, params.value)

        elif params.action == "delete_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'delete_tag'")

            logger.debug(f"Deleting custom tag with ID: {params.tag_id}")
            return await client.custom_tags_delete(params.tag_id)
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['create_tag', 'delete_tag']")
    except Exception as e:
        logger.error(f"Error writing custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


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
        # Get the SSE ASGI app from FastMCP
        uvicorn.run(mcp.sse_app(), host=mcp_host, port=int(mcp_port))
    else:
        # Use default stdio transport
        logger.info("Starting MCP server with stdio transport (default)")
        mcp.run()


if __name__ == "__main__":
    run_mcp_server()
