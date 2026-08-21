import json
import logging
from typing import Annotated, Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListIncidentMembersParams(BaseModel):
    """Parameters for listing members with access to a secret incident."""

    incident_id: int = Field(description="The ID of the secret incident to retrieve members for")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    per_page: int = Field(
        default=20,
        description="Number of results per page (default: 20, min: 1, max: 100)",
    )
    access_level: str | None = Field(
        default=None,
        description="Filter members based on their access level (owner, manager, member, restricted)",
    )
    search: str | None = Field(default=None, description="Search members based on their name or email")
    ordering: str | None = Field(
        default=None,
        description="Sort results by field (created_at, -created_at, last_login, -last_login). Use '-' prefix for descending order",
    )
    direct_access: bool | None = Field(
        default=None,
        description="Filter on direct or indirect accesses",
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListIncidentMembersResult(BaseModel):
    """Result from listing members with access to a secret incident."""

    members: list[dict[str, Any]] = Field(description="List of member objects with access to the incident")
    total_count: int = Field(description="Total number of members returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")
    has_more: bool = Field(
        default=False,
        description="True if more results exist (use next_cursor to fetch)",
    )


async def list_incident_members(
    incident_id: Annotated[int, Field(description="The ID of the secret incident to retrieve members for")],
    cursor: Annotated[
        str | None, Field(default=None, description="Pagination cursor for fetching next page of results")
    ] = None,
    per_page: Annotated[
        int,
        Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    ] = 20,
    access_level: Annotated[
        str | None,
        Field(
            default=None,
            description="Filter members based on their access level (owner, manager, member, restricted)",
        ),
    ] = None,
    search: Annotated[
        str | None, Field(default=None, description="Search members based on their name or email")
    ] = None,
    ordering: Annotated[
        str | None,
        Field(
            default=None,
            description="Sort results by field (created_at, -created_at, last_login, -last_login). Use '-' prefix for descending order",
        ),
    ] = None,
    direct_access: Annotated[
        bool | None,
        Field(default=None, description="Filter on direct or indirect accesses"),
    ] = None,
    get_all: Annotated[
        bool,
        Field(
            default=False,
            description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
        ),
    ] = False,
) -> ListIncidentMembersResult:
    """
    List members with access to a secret incident.

    Returns information about members who have access to a specific secret incident,
    including their ID, name, email, role, access level, active status, creation date,
    and last login.

    Args:
        incident_id: The ID of the secret incident to retrieve members for
        cursor: Pagination cursor
        per_page: Number of results per page (default: 20)
        access_level: Filter by access level
        search: Search members by name/email
        ordering: Sort field
        direct_access: Filter on direct or indirect accesses
        get_all: If True, fetch all pages

    Returns:
        ListIncidentMembersResult: Pydantic model containing:
            - members: List of member objects with access information
            - total_count: Total number of members returned
            - next_cursor: Pagination cursor for next page (if applicable)
            - has_more: Whether more results are available

    Raises:
        ToolError: If the listing operation fails
    """
    params = ListIncidentMembersParams(
        incident_id=incident_id,
        cursor=cursor,
        per_page=per_page,
        access_level=access_level,
        search=search,
        ordering=ordering,
        direct_access=direct_access,
        get_all=get_all,
    )
    client = await get_client()
    logger.debug(f"Listing members with access to incident {params.incident_id}")

    # Build query parameters
    query_params: dict[str, Any] = {}

    if params.cursor:
        query_params["cursor"] = params.cursor
    if params.per_page:
        query_params["per_page"] = params.per_page
    if params.access_level:
        query_params["access_level"] = params.access_level
    if params.search:
        query_params["search"] = params.search
    if params.ordering:
        query_params["ordering"] = params.ordering
    if params.direct_access is not None:
        query_params["direct_access"] = "true" if params.direct_access else "false"

    logger.debug(f"Query parameters: {json.dumps(query_params)}")

    result = await client.list_incident_members(
        incident_id=params.incident_id,
        params=query_params,
        get_all=params.get_all,
    )

    logger.debug(f"Found {len(result['data'])} members (has_more={result['has_more']})")
    return ListIncidentMembersResult(
        members=result["data"],
        total_count=len(result["data"]),
        next_cursor=result["cursor"],
        has_more=result["has_more"],
    )
