"""GitGuardian MCP server for SecOps with comprehensive security tools."""

import json
import logging
import os
from typing import Any, Literal

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import SECOPS_SCOPES
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables (without exposing the full API key)
gitguardian_api_key = os.environ.get("GITGUARDIAN_API_KEY")
gitguardian_api_url = os.environ.get("GITGUARDIAN_API_URL")

logger.info("Starting SecOps MCP Server")
logger.info(f"GitGuardian API Key present: {bool(gitguardian_api_key)}")
logger.info(f"GitGuardian API URL: {gitguardian_api_url or 'Using default'}")

# Set specific environment variable for this server to request full SecOps scopes
os.environ["GITGUARDIAN_SCOPES"] = ",".join(SECOPS_SCOPES)
logger.info(f"Requesting scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

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
logger.info("Created SecOps GitGuardianFastMCP instance")


@mcp.tool(
    description="Generate an AWS GitGuardian honeytoken and get injection recommendations",
    required_scopes=["honeytokens:write"],
)
async def generate_honeytoken(
    name: str = Field(description="Name for the honeytoken"),
    description: str = Field(default="", description="Description of what the honeytoken is used for"),
) -> dict[str, Any]:
    """
    Generate an AWS GitGuardian honeytoken and get injection recommendations.

    Args:
        name: Name for the honeytoken
        description: Description of what the honeytoken is used for

    Returns:
        dict[str, Any]: Dictionary containing:
            - id: ID of the created honeytoken
            - name: Name of the honeytoken
            - description: Description of the honeytoken
            - token: The generated honeytoken value
            - created_at: Creation timestamp
            - expires_at: Expiration timestamp
            - type: Type of honeytoken (e.g., 'aws')
            - injection_help: Suggestions for injecting the honeytoken
    """
    client = mcp.get_client()
    logger.info(f"Generating honeytoken with name: {name}")

    try:
        result = await client.generate_honeytoken(name=name, description=description)
        logger.info(f"Successfully generated honeytoken with ID: {result.get('id')}")
        return result
    except Exception as e:
        logger.error(f"Error generating honeytoken: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="List secret incidents detected by the GitGuardian dashboard. When you need to retrieve personal incidents (mine, me or my), set the mine parameter to True.",
    required_scopes=["incidents:read"],
)
async def list_incidents(
    severity: str | None = Field(
        default=None, description="Filter incidents by severity (critical, high, medium, low)"
    ),
    status: str | None = Field(
        default=None, description="Filter incidents by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)"
    ),
    from_date: str | None = Field(
        default=None, description="Filter incidents created after this date (ISO format: YYYY-MM-DD)"
    ),
    to_date: str | None = Field(
        default=None, description="Filter incidents created before this date (ISO format: YYYY-MM-DD)"
    ),
    assignee_email: str | None = Field(default=None, description="Filter incidents assigned to this email"),
    assignee_id: str | None = Field(default=None, description="Filter incidents assigned to this user id"),
    validity: str | None = Field(
        default=None, description="Filter incidents by validity (valid, invalid, failed_to_check, no_checker, unknown)"
    ),
    ordering: Literal["date", "-date", "resolved_at", "-resolved_at", "ignored_at", "-ignored_at"] | None = Field(
        default=None,
        description="Sort field and direction (prefix with '-' for descending order). If you need to get the latest incidents, use '-date'.",
    ),
    per_page: int = Field(default=20, description="Number of results per page (1-100)"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(default=False, description="If True, fetch incidents assigned to the current user"),
) -> list[dict[str, Any]]:
    """
    List secret incidents detected by the GitGuardian dashboard with filtering options.

    Args:
        severity: Filter by severity level (critical, high, medium, low)
        status: Filter by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)
        from_date: Filter incidents created after this date (ISO format: YYYY-MM-DD)
        to_date: Filter incidents created before this date (ISO format: YYYY-MM-DD)
        assignee_email: Filter incidents assigned to a specific email address
        assignee_id: Filter incidents assigned to a specific member ID
        validity: Filter by validity status (valid, invalid, failed_to_check, no_checker, unknown)
        ordering: Sort field (Enum: date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at)
                Default is ASC, DESC if preceded by '-'
        per_page: Number of results per page (default: 20, min: 1, max: 100)
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True, fetch incidents assigned to the current user

    Returns:
        List of incidents matching the specified criteria
    """
    client = mcp.get_client()
    logger.info("Listing incidents with filters")

    try:
        # Log the filter values
        filters = {
            "severity": severity,
            "status": status,
            "from_date": from_date,
            "to_date": to_date,
            "assignee_email": assignee_email,
            "assignee_id": assignee_id,
            "validity": validity,
            "ordering": ordering,
            "per_page": per_page,
            "get_all": get_all,
            "mine": mine,
        }

        logger.info(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

        # Make the API call
        result = await client.list_incidents(
            severity=severity,
            status=status,
            from_date=from_date,
            to_date=to_date,
            assignee_email=assignee_email,
            assignee_id=assignee_id,
            validity=validity,
            ordering=ordering,
            per_page=per_page,
            get_all=get_all,
            mine=mine,
        )

        incidents = result.get("incidents", [])
        logger.info(f"Found {len(incidents)} incidents")

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
    Get information about the current API token. Use this to get information about current user token information.

    Args:
        None

    Returns:
        dict[str, Any]: Dictionary containing token information including:
            - id: ID of the API token
            - name: Name of the token
            - scopes: List of scopes the token has access to
            - member_id: ID of the member who owns the token
            - created_at: Creation timestamp
            - expiration_date: When the token expires (if applicable)
    """
    client = mcp.get_client()
    logger.info("Getting current token info")

    try:
        result = await client.get_current_token_info()
        logger.info(f"Successfully retrieved token info for token ID: {result.get('id')}")
        return result
    except Exception as e:
        logger.error(f"Error getting token info: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="List honeytokens from the GitGuardian dashboard with filtering options",
    required_scopes=["honeytokens:read"],
)
async def list_honeytokens(
    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)"),
    search: str | None = Field(default=None, description="Search string to filter results by name or description"),
    ordering: str | None = Field(
        default=None, description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')"
    ),
    show_token: bool = Field(default=False, description="Whether to include token details in the response"),
    creator_id: str | None = Field(default=None, description="Filter by creator ID"),
    creator_api_token_id: str | None = Field(default=None, description="Filter by creator API token ID"),
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(default=False, description="If True, fetch honeytokens created by the current user"),
) -> list[dict[str, Any]]:
    """
    List honeytokens from the GitGuardian dashboard with filtering options.
    This can be used to get a honeytoken and inject it in the codebase.

    Args:
        status: Filter by status (ACTIVE or REVOKED)
        search: Search string to filter results by name or description
        ordering: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
        show_token: Whether to include token details in the response
        creator_id: Filter by creator ID
        creator_api_token_id: Filter by creator API token ID
        per_page: Number of results per page (default: 20)
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True, fetch honeytokens created by the current user
    Returns:
        List of honeytokens matching the specified criteria
    """
    client = mcp.get_client()
    logger.info("Listing honeytokens with filters")

    try:
        # Log the filter values
        filters = {
            "status": status,
            "search": search,
            "ordering": ordering,
            "show_token": show_token,
            "creator_id": creator_id,
            "creator_api_token_id": creator_api_token_id,
            "per_page": per_page,
            "get_all": get_all,
            "mine": mine,
        }

        logger.info(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

        # Make the API call
        result = await client.list_honeytokens(
            status=status,
            search=search,
            ordering=ordering,
            show_token=show_token,
            creator_id=creator_id,
            creator_api_token_id=creator_api_token_id,
            per_page=per_page,
            get_all=get_all,
            mine=mine,
        )

        honeytokens = result.get("honeytokens", [])
        logger.info(f"Found {len(honeytokens)} honeytokens")

        return honeytokens
    except Exception as e:
        logger.error(f"Error listing honeytokens: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Manage a secret incident (assign, unassign, resolve, ignore, reopen)",
    required_scopes=["incidents:write"],
)
async def manage_incident(
    incident_id: str = Field(description="ID of the secret incident to manage"),
    action: Literal["assign", "unassign", "resolve", "ignore", "reopen"] = Field(
        description="Action to perform on the incident"
    ),
    assignee_id: str | None = Field(
        default=None, description="ID of the member to assign the incident to (required for 'assign' action)"
    ),
    ignore_reason: str | None = Field(
        default=None,
        description="Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)",
    ),
    mine: bool = Field(default=False, description="If True, use the current user's ID for the assignee_id"),
) -> dict[str, Any]:
    """
    Manage a secret incident with various actions.

    Args:
        incident_id: ID of the secret incident to manage
        action: Action to perform on the incident (assign, unassign, resolve, ignore, reopen)
        assignee_id: ID of the member to assign the incident to (required for 'assign' action)
        ignore_reason: Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)
        mine: If True, use the current user's ID for the assignee_id
    Returns:
        Status of the operation
    """
    client = mcp.get_client()
    logger.info(f"Managing incident {incident_id} with action: {action}")

    try:
        # If 'mine' is True and this is an 'assign' action, we need to get the current user's ID
        if mine and action == "assign" and not assignee_id:
            logger.info("Getting current token info to use current user's ID")
            token_info = await client.get_current_token_info()
            assignee_id = token_info.get("member_id")
            logger.info(f"Using current user's ID for assignment: {assignee_id}")

        # Validate required parameters
        if action == "assign" and not assignee_id:
            error_msg = "assignee_id is required for 'assign' action"
            logger.error(error_msg)
            raise ToolError(error_msg)

        if action == "ignore" and not ignore_reason:
            logger.warning("No ignore_reason provided for 'ignore' action")

        # Make the API call
        result = await client.manage_incident(
            incident_id=incident_id,
            action=action,
            assignee_id=assignee_id,
            ignore_reason=ignore_reason,
        )

        logger.info(f"Successfully managed incident {incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error managing incident: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Update or create custom tags for a secret incident",
    required_scopes=["incidents:write", "custom_tags:write"],
)
async def update_or_create_incident_custom_tags(
    incident_id: str = Field(description="ID of the secret incident"),
    custom_tags: list[str | dict[str, str]] = Field(description="List of custom tags to apply to the incident"),
) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.
    If a custom tag is a String, a label is created. For example "MCP": None will create a label "MCP" without a value.

    Args:
        incident_id: ID of the secret incident
        custom_tags: List of custom tags to apply to the incident
                     Format: [{"key": "key1"}, "label"]

    Returns:
        Updated incident data
    """
    client = mcp.get_client()
    logger.info(f"Updating custom tags for incident {incident_id}")

    try:
        # Make the API call
        result = await client.update_or_create_incident_custom_tags(
            incident_id=incident_id,
            custom_tags=custom_tags,
        )

        logger.info(f"Successfully updated custom tags for incident {incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error updating custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Update a secret incident with status",
    required_scopes=["incidents:write"],
)
async def update_incident_status(
    incident_id: str = Field(description="ID of the secret incident"),
    status: str = Field(description="New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)"),
) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.

    Args:
        incident_id: ID of the secret incident
        status: New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)

    Returns:
        Updated incident data
    """
    client = mcp.get_client()
    logger.info(f"Updating incident {incident_id} status to {status}")

    try:
        result = await client.update_incident_status(incident_id=incident_id, status=status)
        logger.info(f"Successfully updated incident {incident_id} status to {status}")
        return result
    except Exception as e:
        logger.error(f"Error updating incident status: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Read custom tags from the GitGuardian dashboard.",
    required_scopes=["custom_tags:read"],
)
async def read_custom_tags(
    action: Literal["list_tags", "get_tag"] = Field(description="Action to perform related to reading custom tags"),
    tag_id: str | None = Field(
        default=None, description="ID of the custom tag to retrieve (used with 'get_tag' action)"
    ),
):
    """
    Read custom tags from the GitGuardian dashboard.

    Args:
        action: Action to perform (list_tags, get_tag)
        tag_id: ID of the custom tag to retrieve (used with 'get_tag' action)

    Returns:
        Custom tag data based on the action performed
    """
    try:
        client = mcp.get_client()

        if action == "list_tags":
            logger.info("Listing all custom tags")
            return await client.custom_tags_list()
        elif action == "get_tag":
            if not tag_id:
                raise ValueError("tag_id is required when action is 'get_tag'")
            logger.info(f"Getting custom tag with ID: {tag_id}")
            return await client.custom_tags_get(tag_id)
        else:
            raise ValueError(f"Invalid action: {action}. Must be one of ['list_tags', 'get_tag']")
    except Exception as e:
        logger.error(f"Error reading custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


@mcp.tool(
    description="Create or delete custom tags in the GitGuardian dashboard.",
    required_scopes=["custom_tags:write"],
)
async def write_custom_tags(
    action: Literal["create_tag", "delete_tag"] = Field(description="Action to perform related to writing custom tags"),
    key: str | None = Field(default=None, description="Key for the new tag (used with 'create_tag' action)"),
    value: str | None = Field(default=None, description="Value for the new tag (used with 'create_tag' action)"),
    tag_id: str | None = Field(
        default=None, description="ID of the custom tag to delete (used with 'delete_tag' action)"
    ),
):
    """
    Create or delete custom tags in the GitGuardian dashboard.

    Args:
        action: Action to perform (create_tag, delete_tag)
        key: Key for the new tag (used with 'create_tag' action)
        value: Value for the new tag (used with 'create_tag' action)
        tag_id: ID of the custom tag to delete (used with 'delete_tag' action)

    Returns:
        Result based on the action performed
    """
    try:
        client = mcp.get_client()

        if action == "create_tag":
            if not key:
                raise ValueError("key is required when action is 'create_tag'")

            # Value is optional for label-only tags
            logger.info(f"Creating custom tag with key: {key}, value: {value or 'None (label only)'}")
            return await client.custom_tags_create(key, value)

        elif action == "delete_tag":
            if not tag_id:
                raise ValueError("tag_id is required when action is 'delete_tag'")

            logger.info(f"Deleting custom tag with ID: {tag_id}")
            return await client.custom_tags_delete(tag_id)
        else:
            raise ValueError(f"Invalid action: {action}. Must be one of ['create_tag', 'delete_tag']")
    except Exception as e:
        logger.error(f"Error writing custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


if __name__ == "__main__":
    # Register common tools for user information and token management
    logger.info("About to register common tools...")
    try:
        from gg_api_core.mcp_server import register_common_tools

        logger.info("Successfully imported register_common_tools")
        register_common_tools(mcp)
        logger.info("Successfully called register_common_tools")
    except Exception as e:
        logger.error(f"Failed to register common tools: {str(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")

    # Log all registered tools
    logger.info("Starting SecOps MCP server...")
    mcp.run()


# Register common tools for user information and token management
logger.info("About to register common tools...")
try:
    from gg_api_core.mcp_server import register_common_tools

    logger.info("Successfully imported register_common_tools")
    register_common_tools(mcp)
    logger.info("Successfully called register_common_tools")
except Exception as e:
    logger.error(f"Failed to register common tools: {str(e)}")
    import traceback

    logger.error(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    # Log all registered tools
    logger.info("Starting SecOps MCP server...")
    mcp.run()
