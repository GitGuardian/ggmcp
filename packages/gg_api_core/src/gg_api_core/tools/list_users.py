import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
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
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListUsersResult(BaseModel):
    """Result from listing workspace members/users."""

    members: list[dict[str, Any]] = Field(description="List of workspace member objects")
    total_count: int = Field(description="Total number of members returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")
    has_more: bool = Field(default=False, description="True if more results exist (use next_cursor to fetch)")


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
    client = await get_client()
    logger.debug("Listing workspace members")

    # Build query parameters
    query_params: dict[str, Any] = {}

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

    if params.get_all:
        # Use paginate_all for fetching all results (capped at DEFAULT_PAGINATION_MAX_BYTES)
        result = await client.paginate_all("/members", query_params)
        logger.debug(f"Retrieved {len(result['data'])} members using pagination (has_more={result['has_more']})")
        return ListUsersResult(
            members=result["data"],
            total_count=len(result["data"]),
            next_cursor=result["cursor"],
            has_more=result["has_more"],
        )
    else:
        # Single page request
        result = await client.list_members(params=query_params)
        logger.debug(f"Found {len(result['data'])} members")
        return ListUsersResult(members=result["data"], total_count=len(result["data"]), next_cursor=result["cursor"])
