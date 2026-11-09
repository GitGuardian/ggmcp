from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.incident_filters import (
    IncidentFilters,
    build_filter_info,
    build_incident_query,
    resolve_assignee,
)
from gg_api_core.utils import get_client


class CountIncidentsParams(IncidentFilters):
    """Parameters for counting incidents using the MCP-optimized count endpoint.

    Accepts the same filters as list_incidents but returns only a count.
    """


class CountIncidentsResult(BaseModel):
    """Result from counting incidents."""

    count: int = Field(description="Total number of matching incidents")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


# Stays in the tool's return type so its output schema, and the result wrapper
# that schema implies, are unchanged. The tool raises instead of returning it.
class CountIncidentsError(BaseModel):
    """Error result from counting incidents."""

    error: str = Field(description="Error message")


async def count_incidents(
    params: CountIncidentsParams = CountIncidentsParams(),
) -> CountIncidentsResult | CountIncidentsError:
    """Count secret incidents matching the given filters.

    Args:
        params: CountIncidentsParams model containing all filtering options.
    """
    client = await get_client()

    assignee_id, conflict = await resolve_assignee(client, params)
    if conflict:
        raise ToolError(conflict)

    response = await client.count_incidents_for_mcp(build_incident_query(params, assignee_id))

    return CountIncidentsResult(
        count=response["count"],
        applied_filters=build_filter_info(params),
    )
