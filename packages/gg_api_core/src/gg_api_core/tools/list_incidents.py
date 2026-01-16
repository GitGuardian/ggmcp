import logging
from typing import Any, cast

from pydantic import BaseModel, Field

from gg_api_core.client import (
    DEFAULT_PAGINATION_MAX_BYTES,
    IncidentSeverity,
    IncidentStatus,
    IncidentValidity,
    TagNames,
)
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

DEFAULT_EXCLUDED_TAGS = [
    TagNames.TEST_FILE,
    TagNames.FALSE_POSITIVE,
    TagNames.CHECK_RUN_SKIP_FALSE_POSITIVE,
    TagNames.CHECK_RUN_SKIP_LOW_RISK,
    TagNames.CHECK_RUN_SKIP_TEST_CRED,
]
DEFAULT_SEVERITIES = [
    IncidentSeverity.CRITICAL,
    IncidentSeverity.HIGH,
    IncidentSeverity.MEDIUM,
    IncidentSeverity.UNKNOWN,
]  # We exclude LOW and INFO
DEFAULT_STATUSES = [
    IncidentStatus.TRIGGERED,
    IncidentStatus.ASSIGNED,
    IncidentStatus.RESOLVED,
]  # We exclude "IGNORED" ones
DEFAULT_VALIDITIES = [
    IncidentValidity.VALID,
    IncidentValidity.FAILED_TO_CHECK,
    IncidentValidity.NO_CHECKER,
    IncidentValidity.UNKNOWN,
]  # We exclude "INVALID" ones


def _build_filter_info(params: "ListIncidentsParams") -> dict[str, Any]:
    """Build a dictionary describing the filters applied to the query."""
    filters: dict[str, Any] = {}

    # Include all active filters
    if params.from_date:
        filters["from_date"] = params.from_date
    if params.to_date:
        filters["to_date"] = params.to_date
    if params.presence:
        filters["presence"] = params.presence
    if params.tags:
        filters["tags_include"] = [tag.value if hasattr(tag, "value") else tag for tag in params.tags]
    if params.exclude_tags:
        filters["exclude_tags"] = [tag.value if hasattr(tag, "value") else tag for tag in params.exclude_tags]
    if params.status:
        filters["status"] = [st.value if hasattr(st, "value") else st for st in params.status]
    if params.severity:
        filters["severity"] = [sev.value if hasattr(sev, "value") else sev for sev in params.severity]
    if params.validity:
        filters["validity"] = [v.value if hasattr(v, "value") else v for v in params.validity]
    if params.assignee_id:
        filters["assignee_id"] = params.assignee_id
    if params.assignee_email:
        filters["assignee_email"] = params.assignee_email

    return filters


def _build_suggestion(params: "ListIncidentsParams", incidents_count: int) -> str:
    """Build a suggestion message based on applied filters and results."""
    suggestions = []

    # Explain what's being filtered
    if params.mine:
        suggestions.append("Incidents are filtered to show only those assigned to current user")
    if params.assignee_id:
        suggestions.append(f"Incidents are filtered by assignee ID: {params.assignee_id}")
    if params.assignee_email:
        suggestions.append(f"Incidents are filtered by assignee email: {params.assignee_email}")

    if params.exclude_tags:
        excluded_tag_names = [tag.name if hasattr(tag, "name") else tag for tag in params.exclude_tags]
        suggestions.append(f"Incidents are filtered to exclude tags: {', '.join(excluded_tag_names)}")

    if params.status:
        status_names = [st.name if hasattr(st, "name") else st for st in params.status]
        suggestions.append(f"Filtered by status: {', '.join(status_names)}")

    if params.severity:
        sev_names = [sev.name if hasattr(sev, "name") else sev for sev in params.severity]
        suggestions.append(f"Filtered by severity: {', '.join(sev_names)}")

    if params.validity:
        val_names = [v.name if hasattr(v, "name") else v for v in params.validity]
        suggestions.append(f"Filtered by validity: {', '.join(val_names)}")

    # If no results, suggest how to get more
    if incidents_count == 0 and suggestions:
        suggestions.append(
            "No incidents matched the applied filters. Try with mine=False, exclude_tags=[], or different status/severity/validity filters to see all incidents."
        )

    return "\n".join(suggestions) if suggestions else ""


class ListIncidentsParams(BaseModel):
    """Parameters for listing repository incidents."""

    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Pass the current repository name if not provided. Not required if source_id is provided.",
    )
    source_id: str | int | None = Field(
        default=None,
        description="The GitGuardian source ID to filter by. Can be obtained using find_current_source_id. If provided, repository_name is not required.",
    )
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}; check 'has_more' and use cursor to continue)",
    )

    # Filters
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    )
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    )
    presence: str | None = Field(default=None, description="Filter by presence status")
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)")
    exclude_tags: list[str | TagNames] | None = Field(
        default=cast(list[str | TagNames], DEFAULT_EXCLUDED_TAGS), description="Exclude incidents with these tag names."
    )
    status: list[str | IncidentStatus] | None = Field(
        default=cast(list[str | IncidentStatus], DEFAULT_STATUSES),
        description="Filter by status (list of status names)",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )
    assignee_id: int | None = Field(
        default=None,
        description="Filter by assignee member ID. Cannot be used together with 'mine'.",
    )
    assignee_email: str | None = Field(
        default=None,
        description="Filter by assignee email address. Cannot be used together with 'mine'.",
    )
    severity: list[str | IncidentSeverity] | None = Field(
        default=cast(list[str | IncidentSeverity], DEFAULT_SEVERITIES),
        description="Filter by severity (list of severity names)",
    )
    validity: list[str | IncidentValidity] | None = Field(
        default=cast(list[str | IncidentValidity], DEFAULT_VALIDITIES),
        description="Filter by validity (list of validity names)",
    )


class ListIncidentsResult(BaseModel):
    """Result from listing repository incidents."""

    source_id: str | int | None = Field(default=None, description="Source ID of the repository")
    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of incident objects")
    total_count: int = Field(description="Total number of incidents")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")
    has_more: bool = Field(default=False, description="True if more results exist (use next_cursor to fetch)")


class ListIncidentsError(BaseModel):
    """Error result from listing repository incidents."""

    error: str = Field(description="Error message")


async def list_incidents(params: ListIncidentsParams) -> ListIncidentsResult | ListIncidentsError:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to remove this filter
    By default, incidents tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        params: ListIncidentsParams model containing all filtering options.
            If repository_name or source_id is provided, only the incidents for the corresponding source are returned.
            If not, this tool offers a global view of incidents.

    Returns:
        ListIncidentsResult: Pydantic model containing:
            - source_id: Source ID of the repository
            - incidents: List of incident objects
            - total_count: Total number of incidents
            - next_cursor: Pagination cursor (if applicable)
            - applied_filters: Dictionary of filters that were applied
            - suggestion: Suggestions for interpreting or modifying results

        ListIncidentsError: Pydantic model with error message if the operation fails
    """
    client = await get_client()

    # Use the new direct approach using the GitGuardian Sources API
    try:
        # If source_id or repository_name is provided, use them to filter by source_id
        api_params: dict[str, Any] = {}
        if params.source_id:
            api_params["source_id"] = params.source_id
        elif params.repository_name:
            result = await find_current_source_id(params.repository_name)
            if hasattr(result, "error"):
                # Handle error case from find_current_source_id
                return ListIncidentsError(error=result.error)
            api_params["source_id"] = result.source_id

        if params.mine:
            member = await client.get_current_member()
            current_user_email = member["email"]
            if params.assignee_email and params.assignee_email != current_user_email:
                return ListIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_email='{current_user_email}', "
                    f"but assignee_email='{params.assignee_email}' was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_email', not both with different values."
                )
            api_params["assignee_email"] = current_user_email
        if params.assignee_id:
            api_params["assignee_id"] = params.assignee_id
        if params.assignee_email and not params.mine:
            api_params["assignee_email"] = params.assignee_email

        if params.from_date:
            api_params["date_after"] = params.from_date
        if params.to_date:
            api_params["date_before"] = params.to_date
        if params.presence:
            api_params["presence"] = params.presence
        if params.tags:
            api_params["tags"] = ",".join(params.tags) if isinstance(params.tags, list) else params.tags
        if params.per_page:
            api_params["per_page"] = params.per_page
        if params.cursor:
            api_params["cursor"] = params.cursor
        if params.ordering:
            api_params["ordering"] = params.ordering
        if params.severity:
            api_params["severity"] = ",".join(params.severity) if isinstance(params.severity, list) else params.severity
        if params.status:
            api_params["status"] = ",".join(params.status) if isinstance(params.status, list) else params.status
        if params.validity:
            api_params["validity"] = ",".join(params.validity) if isinstance(params.validity, list) else params.validity
        if params.get_all:
            api_params["get_all"] = params.get_all

        # Get incidents using list_incidents which returns ListResponse or PaginatedResult
        response = await client.list_incidents(**api_params)
        incidents_data = response["data"]
        next_cursor = response["cursor"]

        count = len(incidents_data)
        return ListIncidentsResult(
            source_id=params.source_id,
            incidents=incidents_data,
            total_count=count,
            next_cursor=next_cursor,
            applied_filters=_build_filter_info(params),
            suggestion=_build_suggestion(params, count),
            has_more=response.get("has_more", False),
        )

    except Exception as e:
        logger.exception(f"Error listing repository incidents: {str(e)}")
        return ListIncidentsError(error=f"Failed to list repository incidents: {str(e)}")
