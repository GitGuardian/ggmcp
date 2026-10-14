import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, MAX_PAGINATION_PAGES
from gg_api_core.incident_filters import (
    DEFAULT_EXCLUDED_TAGS,
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    IncidentFilterParams,
    build_api_params,
    build_filter_info,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_EXCLUDED_TAGS",
    "DEFAULT_SEVERITIES",
    "DEFAULT_STATUSES",
    "DEFAULT_VALIDITIES",
]


def _build_suggestion(params: "ListIncidentsParams", incidents_count: int) -> str:
    """Build a suggestion message based on applied filters and results."""
    suggestions = []

    if params.mine:
        suggestions.append("Incidents are filtered to show only those assigned to current user")
    if params.assignee_id is not None:
        if params.assignee_id == 0:
            suggestions.append("Incidents are filtered to show only unassigned incidents")
        else:
            suggestions.append(f"Incidents are filtered by assignee ID: {params.assignee_id}")

    if params.status:
        suggestions.append(f"Filtered by status: {', '.join(params.status)}")

    if params.severity:
        suggestions.append(f"Filtered by severity: {', '.join(str(s) for s in params.severity)}")

    if params.validity:
        suggestions.append(f"Filtered by validity: {', '.join(params.validity)}")

    if params.source_criticality:
        suggestions.append(f"Filtered by source criticality: {', '.join(params.source_criticality)}")

    if params.opened_for_days:
        suggestions.append(f"Filtered to incidents open for at least {params.opened_for_days} days")

    if params.public_exposure:
        suggestions.append(f"Filtered by public exposure: {', '.join(params.public_exposure)}")

    if incidents_count == 0 and suggestions:
        suggestions.append(
            "No incidents matched the applied filters. Try adjusting filters such as status, severity, or assignee."
        )

    return "\n".join(suggestions) if suggestions else ""


class ListIncidentsParams(IncidentFilterParams):
    """Parameters for listing incidents using the MCP-optimized endpoint."""

    # Pagination
    page: int = Field(default=1, description="Page number (1-indexed)", ge=1)
    page_size: int = Field(
        default=20,
        description="Number of results per page (default: 20, max: 100)",
        ge=1,
        le=100,
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' to see if results were truncated)",
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
    )


class ListIncidentsResult(BaseModel):
    """Result from listing incidents."""

    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of incident objects")
    page: int = Field(description="Current page number (last page fetched when get_all=True)")
    page_size: int = Field(description="Number of results per page")
    has_next: bool = Field(default=False, description="True if there are more pages available")
    has_previous: bool = Field(default=False, description="True if there are previous pages")
    has_more: bool = Field(
        default=False,
        description="True if results were truncated due to size limit (only relevant when get_all=True)",
    )
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


class ListIncidentsError(BaseModel):
    """Error result from listing incidents."""

    error: str = Field(description="Error message")


async def list_incidents(
    params: ListIncidentsParams = ListIncidentsParams(),
) -> ListIncidentsResult | ListIncidentsError:
    """
    List secret incidents with enhanced filtering using the MCP-optimized endpoint.

    This endpoint provides filtering options including detector type, secret category,
    source criticality, public exposure, and more. It uses page-based pagination.

    Features:
    - Page-based pagination
    - Status values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED
    - Rich filtering options for detector types, secret categories, and public exposure
    - Returns detailed incident data including custom tags, vault metadata, and similar issue counts

    Args:
        params: ListIncidentsParams model containing all filtering options.

    Returns:
        ListIncidentsResult: Pydantic model containing:
            - incidents: List of incident objects with detailed information
            - page: Current page number
            - page_size: Results per page
            - has_next/has_previous: Pagination indicators
            - applied_filters: Dictionary of filters that were applied
            - suggestion: Suggestions for interpreting or modifying the results

        ListIncidentsError: Pydantic model with error message if the operation fails
    """
    client = await get_client()

    try:
        api_params: dict[str, Any] = {}

        # Handle 'mine' parameter - get current user's member ID
        if params.mine:
            member = await client.get_current_member()
            current_user_id = member["id"]
            if params.assignee_id is not None and params.assignee_id != current_user_id:
                return ListIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                    f"but assignee_id={params.assignee_id} was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_id', not both."
                )
            api_params["assignee_id"] = current_user_id
        elif params.assignee_id is not None:
            api_params["assignee_id"] = params.assignee_id

        api_params.update(build_api_params(params))

        if params.get_all:
            # Fetch all pages with byte limit protection and hard page cap.
            all_incidents: list[dict[str, Any]] = []
            current_page = 1
            total_bytes = 0
            has_more = False

            while True:
                if current_page > MAX_PAGINATION_PAGES:
                    logger.warning(f"get_all pagination stopped: reached max page limit ({MAX_PAGINATION_PAGES})")
                    has_more = True
                    break

                response = await client.list_incidents_for_mcp(
                    page=current_page,
                    page_size=params.page_size,
                    ordering=params.ordering,
                    **api_params,
                )

                page_incidents = response.get("results", [])
                has_next_page = response.get("next") is not None

                # Empty page means no more matching results
                if not page_incidents:
                    break

                # Check byte limit before adding results
                page_bytes = len(json.dumps(page_incidents))
                if total_bytes + page_bytes > DEFAULT_PAGINATION_MAX_BYTES and all_incidents:
                    # Would exceed limit, stop here
                    has_more = True
                    break

                all_incidents.extend(page_incidents)
                total_bytes += page_bytes

                if not has_next_page:
                    break

                current_page += 1

            return ListIncidentsResult(
                incidents=all_incidents,
                page=current_page,
                page_size=params.page_size,
                has_next=has_more,
                has_previous=False,
                has_more=has_more,
                applied_filters=build_filter_info(params),
                suggestion=_build_suggestion(params, len(all_incidents)),
            )
        else:
            # Single page request
            response = await client.list_incidents_for_mcp(
                page=params.page,
                page_size=params.page_size,
                ordering=params.ordering,
                **api_params,
            )

            # Parse the response
            incidents_data = response.get("results", [])
            has_next = response.get("next") is not None
            has_previous = response.get("previous") is not None

            return ListIncidentsResult(
                incidents=incidents_data,
                page=params.page,
                page_size=params.page_size,
                has_next=has_next,
                has_previous=has_previous,
                has_more=False,
                applied_filters=build_filter_info(params),
                suggestion=_build_suggestion(params, len(incidents_data)),
            )

    except Exception as e:
        logger.exception(f"Error listing incidents: {str(e)}")
        return ListIncidentsError(error=f"Failed to list incidents: {str(e)}")
