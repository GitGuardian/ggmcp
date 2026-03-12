import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListIncidentTeamsParams(BaseModel):
    """Parameters for listing teams with access to a secret incident."""

    incident_id: int = Field(description="The ID of the secret incident to retrieve teams for")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    per_page: int = Field(
        default=20,
        description="Number of results per page (default: 20, min: 1, max: 100)",
    )
    search: str | None = Field(default=None, description="Search teams based on their name and/or description")
    direct_access: bool | None = Field(
        default=None,
        description="Filter on direct or indirect accesses",
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListIncidentTeamsResult(BaseModel):
    """Result from listing teams with access to a secret incident."""

    teams: list[dict[str, Any]] = Field(description="List of team objects with access to the incident")
    total_count: int = Field(description="Total number of teams returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")
    has_more: bool = Field(
        default=False,
        description="True if more results exist (use next_cursor to fetch)",
    )


async def list_incident_teams(params: ListIncidentTeamsParams) -> ListIncidentTeamsResult:
    """
    List teams with access to a secret incident.

    Returns information about teams who have access to a specific secret incident,
    including their ID, name, description, global status, GitGuardian URL, and external provider ID.

    Args:
        params: ListIncidentTeamsParams model containing incident ID and filtering/pagination options

    Returns:
        ListIncidentTeamsResult: Pydantic model containing:
            - teams: List of team objects with access information
            - total_count: Total number of teams returned
            - next_cursor: Pagination cursor for next page (if applicable)
            - has_more: Whether more results are available

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug(f"Listing teams with access to incident {params.incident_id}")

    # Build query parameters
    query_params: dict[str, Any] = {}

    if params.cursor:
        query_params["cursor"] = params.cursor
    if params.per_page:
        query_params["per_page"] = params.per_page
    if params.search:
        query_params["search"] = params.search
    if params.direct_access is not None:
        query_params["direct_access"] = "true" if params.direct_access else "false"

    logger.debug(f"Query parameters: {json.dumps(query_params)}")

    result = await client.list_incident_teams(
        incident_id=params.incident_id,
        params=query_params,
        get_all=params.get_all,
    )

    logger.debug(f"Found {len(result['data'])} teams (has_more={result['has_more']})")
    return ListIncidentTeamsResult(
        teams=result["data"],
        total_count=len(result["data"]),
        next_cursor=result["cursor"],
        has_more=result["has_more"],
    )
