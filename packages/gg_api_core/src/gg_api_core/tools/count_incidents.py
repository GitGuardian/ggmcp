import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.incident_filters import (
    IncidentFilterParams,
    build_api_params,
    build_filter_info,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class CountIncidentsParams(IncidentFilterParams):
    """Parameters for counting incidents using the MCP-optimized count endpoint.

    Accepts the same filters as list_incidents but returns only a count.
    """


class CountIncidentsResult(BaseModel):
    """Result from counting incidents."""

    count: int = Field(description="Total number of matching incidents")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


class CountIncidentsError(BaseModel):
    """Error result from counting incidents."""

    error: str = Field(description="Error message")


async def count_incidents(
    params: CountIncidentsParams = CountIncidentsParams(),
) -> CountIncidentsResult | CountIncidentsError:
    """
    Count secret incidents matching the given filters.

    Returns the total number of matching incidents without fetching the full list.
    This is useful to get an overview of incident volume, check filter results
    before paginating, or build dashboards.

    Accepts the same filters as list_incidents (status, severity, detector type,
    source, tags, etc.) but returns only the count.

    Args:
        params: CountIncidentsParams model containing all filtering options.

    Returns:
        CountIncidentsResult: Pydantic model containing:
            - count: Total number of matching incidents
            - applied_filters: Dictionary of filters that were applied

        CountIncidentsError: Pydantic model with error message if the operation fails
    """
    client = await get_client()

    try:
        api_params: dict[str, Any] = {}

        # Handle 'mine' parameter
        if params.mine:
            member = await client.get_current_member()
            current_user_id = member["id"]
            if params.assignee_id is not None and params.assignee_id != current_user_id:
                return CountIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                    f"but assignee_id={params.assignee_id} was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_id', not both."
                )
            api_params["assignee_id"] = current_user_id
        elif params.assignee_id is not None:
            api_params["assignee_id"] = params.assignee_id

        api_params.update(build_api_params(params))

        response = await client.count_incidents_for_mcp(**api_params)

        return CountIncidentsResult(
            count=response["count"],
            applied_filters=build_filter_info(params),
        )

    except Exception as e:
        logger.exception(f"Error counting incidents: {str(e)}")
        return CountIncidentsError(error=f"Failed to count incidents: {str(e)}")
