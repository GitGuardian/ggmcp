import json
import logging
import os
from typing import Any, Literal

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

from gg_api_mcp_server.mcp_server import GitGuardianFastMCP

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables (without exposing the full API key)
gitguardian_api_key = os.environ.get("GITGUARDIAN_API_KEY")
gitguardian_api_url = os.environ.get("GITGUARDIAN_API_URL")

logger.info("Starting MCP Server")
logger.info(f"GitGuardian API Key present: {bool(gitguardian_api_key)}")
logger.info(f"GitGuardian API URL: {gitguardian_api_url or 'Using default'}")

# Use our custom GitGuardianFastMCP instead of the base FastMCP
mcp = GitGuardianFastMCP(
    "GitGuardian",
    log_level="DEBUG",
    instructions="""
    # GitGuardian API Tools

    This server provides access to GitGuardian API functionality through MCP tools.
    Each tool requires specific API token scopes to function correctly.
    If you receive an error when calling a tool, it may be because your API token does not have the required scopes.
    Check the required scopes for each tool below and don't use another tool instead of the one that requires the missing scope.

    If not specified, try to reuse an existing active honeytoken instead of generating a new one.

    1. Add honeytoken in code:
        - Use list_honeytokens with status=ACTIVE to get existing honeytokens
        - Always filter by creator_id=member_id when user is asking about their own honeytokens
        - You can use also use parameters like search or ordering to filter the results
        - You MUST use show_token=True to get the token value
        - When you retrieve the honeytoken, try to hide it in the codebase
        - It must seem like a real token that was leaked by mistake
        - Do not directly mention GitGuardian in the generated code
        - Do not mention the honeytoken in the codebase
    2. Generate a new honeytoken:
        - Use generate_honeytoken to generate a new honeytoken
        - when you retrieve the honeytoken, try to hide it in the codebase
        - It must seem like a real token that was leaked by mistake.
        - Do not directly mention GitGuardian in the generated code.
        - Do not mention the honeytoken in the codebase
    3. List incidents:
        - Use list_incidents to list incidents
        - you can use also use parameters like severity, status, from_date, to_date, assignee_email, assignee_id, per_page, page to filter the results
        - try to summarize the results in a few sentences

      """,
)
logger.info("Created GitGuardianFastMCP instance")

# Register the GitGuardian tools if API key is available


@mcp.tool(
    name="generate_honeytoken",
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
            - token: The honeytoken value
            - created_at: Creation timestamp
            - status: Current status
            - type: Always "AWS"
            - injection_recommendations: dict containing:
                - instructions: Usage instructions
    """
    logger.info(f"Received generate_honeytoken request with name={name}")
    try:
        logger.debug("Using GitGuardian client from MCP instance")
        client = mcp.get_client()
        logger.info("Successfully initialized GitGuardian client")
        logger.debug("Calling create_honeytoken API")
        custom_tags = [
            {"key": "source", "value": "auto-generated"},
            {"key": "type", "value": "aws"},
        ]
        result = await client.create_honeytoken(name=name, description=description, custom_tags=custom_tags)
        logger.debug("got response from server %s", json.dumps(result, indent=2))
        honeytoken_id = result.get("id")
        if not honeytoken_id:
            logger.error("Failed to get honeytoken ID from GitGuardian API")
            raise ToolError("Failed to get honeytoken ID from GitGuardian API")
        logger.info(f"Successfully created honeytoken with ID: {honeytoken_id}")
        return {
            "id": honeytoken_id,
            "name": result.get("name"),
            "token": result.get("token"),
            "created_at": result.get("created_at"),
            "status": result.get("status"),
            "type": result.get("type"),
            "injection_recommendations": {
                "instructions": """Add the above generated token in the current codebase.
                It should look like a real leaked token and don't mention that it's a honeytoken or a fake token.
                It should really look like a real token that was leaked by mistake.
                Do not directly mention GitGuardian in the generated code."""
            },
        }

    except Exception as e:
        logger.exception(f"Error in generate_honeytoken: {str(e)}")
        raise ToolError(f"Failed to generate honeytoken: {str(e)}")


@mcp.tool(
    name="list_incidents",
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
        default=None, description="Sort field and direction (prefix with '-' for descending order)"
    ),
    per_page: int = Field(default=20, description="Number of results per page (1-100)"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(default=False, description="If True, fetch incidents assigned to the current user"),
):
    """List secret incidents detected by the GitGuardian dashboard with filtering options.

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

    if mine:
        assignee_id = mcp.get_token_info().get("member_id")

    # Build parameters
    params = {}
    if severity:
        params["severity"] = severity
    if status:
        params["status"] = status
    if from_date:
        params["from_date"] = from_date
    if to_date:
        params["to_date"] = to_date
    if assignee_email:
        params["assignee_email"] = assignee_email
    if assignee_id:
        params["assignee_id"] = assignee_id
    if validity:
        params["validity"] = validity
    if ordering:
        params["ordering"] = ordering
    if per_page:
        params["per_page"] = str(per_page)

    # Use the client's list_incidents method directly if not fetching all pages
    if not get_all:
        return await client.list_incidents(**params)

    # Use the client's paginate_all method when get_all=True
    endpoint = "/incidents/secrets"
    return await client.paginate_all(endpoint, params)


@mcp.tool(
    name="search_team",
    description="Search for teams and team members",
    required_scopes=["teams:read"],
)
async def search_team(
    action: Literal["list_teams", "search_team", "list_members", "search_member"] = Field(
        description="Action to perform related to teams"
    ),
    team_name: str | None = Field(
        default=None, description="The name of the team to search for (used with 'search_team' action)"
    ),
    member_name: str | None = Field(
        default=None, description="The name of the member to search for (used with 'search_member' action)"
    ),
):
    """Search for teams and team members.

    Args:
        action: Action to perform (list_teams, search_team, list_members, search_member)
        team_name: The name of the team to search for (used with 'search_team' action)
        member_name: The name of the member to search for (used with 'search_member' action)

    Returns:
        Results based on the action performed
    """
    logger.info(f"Searching team with action: {action}")

    try:
        client = mcp.get_client()

        if action == "list_teams":
            return await client.list_teams()

        elif action == "search_team":
            if not team_name:
                raise ToolError("team_name is required for 'search_team' action")
            return await client.list_teams(search=team_name)

        elif action == "list_members":
            return await client.list_members()

        elif action == "search_member":
            if not member_name:
                raise ToolError("member_name is required for 'search_member' action")
            return await client.list_members(search=member_name)

        else:
            raise ToolError(
                f"Invalid action: {action}. Must be one of: list_teams, search_team, list_members, search_member"
            )

    except Exception as e:
        logger.exception(f"Error searching team: {str(e)}")
        raise ToolError(f"Failed to search team: {str(e)}")


@mcp.tool(
    name="add_member_to_team",
    description="Add a member to a team",
    required_scopes=["teams:write"],
)
async def add_member_to_team(
    team_id: str = Field(description="ID of the team to add the member to"),
    member_id: str = Field(description="ID of the member to add to the team"),
):
    """Add a member to a team.

    Args:
        team_id: ID of the team to add the member to
        member_id: ID of the member to add to the team

    Returns:
        Status of the operation
    """
    logger.info(f"Adding member {member_id} to team {team_id}")

    try:
        client = mcp.get_client()
        return await client.add_member_to_team(team_id=team_id, member_id=member_id)
    except Exception as e:
        logger.exception(f"Error adding member to team: {str(e)}")
        raise ToolError(f"Failed to add member to team: {str(e)}")


@mcp.tool(
    name="get_current_token_info",
    description="Get information about the current API token ",
    required_scopes=["api_tokens:read"],
)
async def get_current_token_info() -> dict[str, Any]:
    """Get information about the current API token. Use this to get information about current user token information.

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
    logger.info("Received get_current_token_info request")
    # Check if we already have the token info stored in the MCP instance
    token_info = mcp.get_token_info()
    if token_info:
        logger.info("Returning cached token info")
        response = {
            "id": token_info.get("id"),
            "name": token_info.get("name"),
            "scopes": token_info.get("scopes", []),
            "member_id": token_info.get("member_id", {}),
            "created_at": token_info.get("created_at"),
            "expiration_date": token_info.get("expiration_date"),
        }
        return response

    # Otherwise, fetch the token info
    client = mcp.get_client()
    result = await client.get_current_token_info()

    response = {
        "id": result.get("id"),
        "name": result.get("name"),
        "scopes": result.get("scopes", []),
        "member_id": result.get("member_id", {}),
        "created_at": result.get("created_at"),
        "expiration_date": result.get("expiration_date"),
    }

    return response


@mcp.tool(
    name="list_honeytokens",
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
):
    """List honeytokens from the GitGuardian dashboard with filtering options.
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
    logger.info(
        f"Listing honeytokens with filters: status={status}, search={search}, ordering={ordering}, creator_id={creator_id}, creator_api_token_id={creator_api_token_id}"
    )
    client = mcp.get_client()

    if mine:
        creator_id = mcp.get_token_info().get("member_id")

    # Build parameters
    params = {}
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    if ordering:
        params["ordering"] = ordering
    if show_token is not None:
        params["show_token"] = str(show_token).lower()
    if creator_id:
        params["creator_id"] = creator_id
    if creator_api_token_id:
        params["creator_api_token_id"] = creator_api_token_id
    if per_page:
        params["per_page"] = str(per_page)

    # Use the client's list_honeytokens method directly if not fetching all pages
    if not get_all:
        return await client.list_honeytokens(**params)

    # Use the client's paginate_all method when get_all=True
    endpoint = "/honeytokens"
    return await client.paginate_all(endpoint, params)


# Secret Incident Management Tools
@mcp.tool(
    name="manage_incident",
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
):
    """Manage a secret incident with various actions.

    Args:
        incident_id: ID of the secret incident to manage
        action: Action to perform on the incident (assign, unassign, resolve, ignore, reopen)
        assignee_id: ID of the member to assign the incident to (required for 'assign' action)
        ignore_reason: Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)

    Returns:
        Status of the operation
    """
    logger.info(f"Managing incident {incident_id} with action: {action}")

    try:
        client = mcp.get_client()

        if action == "assign":
            if not assignee_id:
                raise ToolError("assignee_id is required for 'assign' action")
            return await client.assign_incident(incident_id=incident_id, assignee_id=assignee_id)

        elif action == "unassign":
            return await client.unassign_incident(incident_id=incident_id)

        elif action == "resolve":
            return await client.resolve_incident(incident_id=incident_id)

        elif action == "ignore":
            return await client.ignore_incident(incident_id=incident_id, ignore_reason=ignore_reason)

        elif action == "reopen":
            return await client.reopen_incident(incident_id=incident_id)

        else:
            raise ToolError(f"Invalid action: {action}. Must be one of: assign, unassign, resolve, ignore, reopen")

    except Exception as e:
        logger.exception(f"Error managing incident: {str(e)}")
        raise ToolError(f"Failed to manage incident: {str(e)}")


@mcp.tool(
    name="update_or_create_incident_custom_tags",
    description="Update or create custom tags for a secret incident",
    required_scopes=["incidents:write"],
)
async def update_or_create_incident_custom_tags(
    incident_id: str = Field(description="ID of the secret incident"),
    custom_tags: list[str | dict[str, str]] = Field(description="List of custom tags to apply to the incident"),
):
    """Update a secret incident with status and/or custom tags.
    If a custom tag is a String, a label is created. For example "MCP": None will create a label "MCP" without a value.

    Args:
        incident_id: ID of the secret incident
        custom_tags: List of custom tags to apply to the incident
                     Format: [{"key": "key1"}, "label"]

    Returns:
        Updated incident data
    """
    if not custom_tags:
        raise ToolError("At least one of status or custom_tags must be provided")

    logger.info(f"Updating incident {incident_id} with custom_tags={custom_tags}")
    try:
        client = mcp.get_client()
        tags = []
        for tag in custom_tags:
            if isinstance(tag, str):
                tags.append({"key": tag, "value": None})
            else:
                tags.append(tag)
        return await client.update_incident(incident_id=incident_id, custom_tags=tags)
    except Exception as e:
        logger.exception(f"Error updating incident: {str(e)}")
        raise ToolError(f"Failed to update incident: {str(e)}")


@mcp.tool(
    name="update_incident_status",
    description="Update a secret incident with status",
    required_scopes=["incidents:write"],
)
async def update_incident_status(
    incident_id: str = Field(description="ID of the secret incident"),
    status: str = Field(description="New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)"),
):
    """Update a secret incident with status and/or custom tags.

    Args:
        incident_id: ID of the secret incident
        status: New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)

    Returns:
        Updated incident data
    """
    if not status:
        raise ToolError("Status must be provided")

    logger.info(f"Updating incident {incident_id} with status={status}")
    try:
        client = mcp.get_client()
        return await client.update_incident(incident_id=incident_id, status=status)
    except Exception as e:
        logger.exception(f"Error updating incident: {str(e)}")
        raise ToolError(f"Failed to update incident: {str(e)}")


@mcp.tool(
    name="read_custom_tags",
    description="Read custom tags from the GitGuardian dashboard",
    required_scopes=["custom_tags:read"],
)
async def read_custom_tags(
    action: Literal["list_tags", "get_tag"] = Field(description="Action to perform related to reading custom tags"),
    tag_id: str | None = Field(
        default=None, description="ID of the custom tag to retrieve (used with 'get_tag' action)"
    ),
):
    """Read custom tags from the GitGuardian dashboard.

    Args:
        action: Action to perform (list_tags, get_tag)
        tag_id: ID of the custom tag to retrieve (used with 'get_tag' action)

    Returns:
        Custom tag data based on the action performed
    """
    logger.info(f"Reading custom tags with action: {action}")

    try:
        client = mcp.get_client()

        if action == "list_tags":
            return await client.list_custom_tags()

        elif action == "get_tag":
            if not tag_id:
                raise ToolError("tag_id is required for 'get_tag' action")
            return await client.get_custom_tag(tag_id=tag_id)

        else:
            raise ToolError(f"Invalid action: {action}. Must be one of: list_tags, get_tag")

    except Exception as e:
        logger.exception(f"Error reading custom tags: {str(e)}")
        raise ToolError(f"Failed to read custom tags: {str(e)}")


@mcp.tool(
    name="write_custom_tags",
    description="Create or delete custom tags in the GitGuardian dashboard",
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
    """Create or delete custom tags in the GitGuardian dashboard.

    Args:
        action: Action to perform (create_tag, delete_tag)
        key: Key for the new tag (used with 'create_tag' action)
        value: Value for the new tag (used with 'create_tag' action)
        tag_id: ID of the custom tag to delete (used with 'delete_tag' action)

    Returns:
        Result based on the action performed
    """
    logger.info(f"Writing custom tags with action: {action}")

    try:
        client = mcp.get_client()

        if action == "create_tag":
            if not key:
                raise ToolError("key is required for 'create_tag' action")
            if not value:
                raise ToolError("value is required for 'create_tag' action")
            return await client.create_custom_tag(key=key, value=value)

        elif action == "delete_tag":
            if not tag_id:
                raise ToolError("tag_id is required for 'delete_tag' action")
            return await client.delete_custom_tag(tag_id=tag_id)

        else:
            raise ToolError(f"Invalid action: {action}. Must be one of: create_tag, delete_tag")

    except Exception as e:
        logger.exception(f"Error writing custom tags: {str(e)}")
        raise ToolError(f"Failed to write custom tags: {str(e)}")


@mcp.tool(
    name="scan_secrets",
    description="Scan multiple content items for secrets and policy breaks",
    required_scopes=["scan"],
)
async def scan_secrets(
    documents: list[dict[str, str]] = Field(
        description="List of documents to scan, each with 'document' and optional 'filename'. Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]"
    ),
) -> dict[str, Any]:
    """Scan multiple content items for secrets and policy breaks.

    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.

    Args:
        documents: List of documents to scan, each with 'document' and optional 'filename'
                  Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]

    Returns:
        Scan results for all documents, including any detected secrets or policy breaks
    """
    logger.info(f"Received scan_secrets request for {len(documents)} documents")

    try:
        # Validate input format
        for i, doc in enumerate(documents):
            if "document" not in doc:
                error_msg = f"Document at index {i} is missing required 'document' field"
                logger.error(error_msg)
                raise ToolError(error_msg)

        client = mcp.get_client()
        result = await client.multiple_scan(documents)

        logger.info(f"Successfully scanned {len(documents)} documents")
        return result

    except Exception as e:
        logger.exception(f"Error in scan_secrets: {str(e)}")
        raise ToolError(f"Failed to scan documents: {str(e)}")


if __name__ == "__main__":
    # Log all registered tools
    logger.info("Starting MCP server...")
    mcp.run()
