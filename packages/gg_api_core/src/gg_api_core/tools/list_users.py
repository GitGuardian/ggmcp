import json
import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListUsersParams(BaseModel):
    """Parameters for listing workspace members/users."""

    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    role: str | None = Field(
        default=None,
        description="Filter members based on their role (owner, manager, member, restricted). Deprecated - use access_level instead",
    )
    access_level: str | None = Field(
        default=None, description="Filter members based on their access level (owner, manager, member, restricted)"
    )
    active: bool | None = Field(default=None, description="Filter members based on their active status")
    search: str | None = Field(default=None, description="Search members based on their name or email")
    ordering: str | None = Field(
        default=None,
        description="Sort results by field (created_at, -created_at, last_login, -last_login). Use '-' prefix for descending order",
    )
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")


class ListUsersResult(BaseModel):
    """Result from listing workspace members/users."""

    members: list[dict[str, Any]] = Field(description="List of workspace member objects")
    total_count: int = Field(description="Total number of members returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")


async def list_users(params: ListUsersParams) -> ListUsersResult:
    """
    List members/users in the GitGuardian workspace.

    Returns information about workspace members including their ID, name, email, role,
    access level, active status, creation date, and last login.

    Args:
        params: ListUsersParams model containing all filtering and pagination options

    Returns:
        ListUsersResult: Pydantic model containing:
            - members: List of member objects with user information
            - total_count: Total number of members returned
            - next_cursor: Pagination cursor for next page (if applicable)

    Raises:
        ToolError: If the listing operation fails
    """
    client = get_client()
    logger.debug("Listing workspace members")

    # Build query parameters
    query_params = {}

    if params.cursor:
        query_params["cursor"] = params.cursor
    if params.per_page:
        query_params["per_page"] = params.per_page
    if params.role:
        query_params["role"] = params.role
    if params.access_level:
        query_params["access_level"] = params.access_level
    if params.active is not None:
        query_params["active"] = "true" if params.active else "false"
    if params.search:
        query_params["search"] = params.search
    if params.ordering:
        query_params["ordering"] = params.ordering

    logger.debug(f"Query parameters: {json.dumps(query_params)}")

    try:
        if params.get_all:
            # Use paginate_all for fetching all results
            members = await client.paginate_all("/members", query_params)
            logger.debug(f"Retrieved all {len(members)} members using pagination")
            return ListUsersResult(members=members, total_count=len(members), next_cursor=None)
        else:
            # Single page request
            result, headers = await client.list_members(params=query_params)

            # Handle response format
            if isinstance(result, dict):
                members = result.get("results", result.get("data", []))
                next_cursor = client._extract_next_cursor(headers) if headers else None
            elif isinstance(result, list):
                members = result
                next_cursor = None
            else:
                logger.error(f"Unexpected result type: {type(result)}")
                raise ToolError(f"Unexpected response format: {type(result).__name__}")

            logger.debug(f"Found {len(members)} members")
            return ListUsersResult(members=members, total_count=len(members), next_cursor=next_cursor)

    except Exception as e:
        logger.error(f"Error listing workspace members: {str(e)}")
        raise ToolError(str(e))
