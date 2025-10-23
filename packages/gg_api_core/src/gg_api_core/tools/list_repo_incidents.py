from typing import Any
import logging

from pydantic import BaseModel, Field

from gg_api_core.client import IncidentSeverity, IncidentStatus, IncidentValidity, TagNames
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
]
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


def _build_filter_info(params: "ListRepoIncidentsParams") -> dict[str, Any]:
    """Build a dictionary describing the filters applied to the query."""
    filters = {}

    # Include all active filters
    if params.from_date:
        filters["from_date"] = params.from_date
    if params.to_date:
        filters["to_date"] = params.to_date
    if params.presence:
        filters["presence"] = params.presence
    if params.tags:
        filters["tags_include"] = [tag.value if hasattr(tag, 'value') else tag for tag in params.tags]
    if params.exclude_tags:
        filters["exclude_tags"] = [tag.value if hasattr(tag, 'value') else tag for tag in params.exclude_tags]
    if params.status:
        filters["status"] = [st.value if hasattr(st, 'value') else st for st in params.status]
    if params.severity:
        filters["severity"] = [sev.value if hasattr(sev, 'value') else sev for sev in params.severity]
    if params.validity:
        filters["validity"] = [v.value if hasattr(v, 'value') else v for v in params.validity]
    if not params.mine:
        filters["assigned_to_me"] = False

    return filters


def _build_suggestion(params: "ListRepoIncidentsParams", incidents_count: int) -> str:
    """Build a suggestion message based on applied filters and results."""
    suggestions = []

    # Explain what's being filtered
    if params.mine:
        suggestions.append("Filtering to incidents assigned to current user")

    if params.exclude_tags:
        excluded_tag_names = [tag.name if hasattr(tag, 'name') else tag for tag in params.exclude_tags]
        suggestions.append(f"Incidents are filtered to exclude tags: {', '.join(excluded_tag_names)}")

    if params.status:
        status_names = [st.name if hasattr(st, 'name') else st for st in params.status]
        suggestions.append(f"Filtered by status: {', '.join(status_names)}")

    if params.severity:
        sev_names = [sev.name if hasattr(sev, 'name') else sev for sev in params.severity]
        suggestions.append(f"Filtered by severity: {', '.join(sev_names)}")

    if params.validity:
        val_names = [v.name if hasattr(v, 'name') else v for v in params.validity]
        suggestions.append(f"Filtered by validity: {', '.join(val_names)}")

    # If no results, suggest how to get more
    if incidents_count == 0 and suggestions:
        suggestions.append("No incidents matched the applied filters. Try with mine=False, exclude_tags=[], or different status/severity/validity filters to see all incidents.")

    return "\n".join(suggestions) if suggestions else ""


class ListRepoIncidentsParams(BaseModel):
    """Parameters for listing repository incidents."""
    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Pass the current repository name if not provided. Not required if source_id is provided."
    )
    source_id: str | None = Field(
        default=None,
        description="The GitGuardian source ID to filter by. Can be obtained using find_current_source_id. If provided, repository_name is not required."
    )
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")

    # Filters
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    )
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    )
    presence: str | None = Field(default=None, description="Filter by presence status")
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)")
    exclude_tags: list[str] | None = Field(
        default=DEFAULT_EXCLUDED_TAGS,
        description="Exclude incidents with these tag names."
    )
    status: list[str] | None = Field(default=DEFAULT_STATUSES, description="Filter by status (list of status names)")
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )
    severity: list[str] | None = Field(default=DEFAULT_SEVERITIES, description="Filter by severity (list of severity names)")
    validity: list[str] | None = Field(default=DEFAULT_VALIDITIES, description="Filter by validity (list of validity names)")


class ListRepoIncidentsResult(BaseModel):
    """Result from listing repository incidents."""
    source_id: str | None = Field(default=None, description="Source ID of the repository")
    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of incident objects")
    total_count: int = Field(description="Total number of incidents")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


class ListRepoIncidentsError(BaseModel):
    """Error result from listing repository incidents."""
    error: str = Field(description="Error message")


async def list_repo_incidents(params: ListRepoIncidentsParams) -> ListRepoIncidentsResult | ListRepoIncidentsError:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.
    By default, incidents tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        params: ListRepoIncidentsParams model containing all filtering options

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = get_client()

    # Validate that at least one of repository_name or source_id is provided
    if not params.repository_name and not params.source_id:
        return ListRepoIncidentsError(error="Either repository_name or source_id must be provided")

    logger.debug(f"Listing incidents with repository_name={params.repository_name}, source_id={params.source_id}")

    # Use the new direct approach using the GitGuardian Sources API
    try:
        # If source_id is provided, use it directly; otherwise use repository_name lookup
        if params.source_id:
            # Prepare parameters for the API call
            api_params = {"with_sources": "false"}
            if params.from_date:
                api_params["from_date"] = params.from_date
            if params.to_date:
                api_params["to_date"] = params.to_date
            if params.presence:
                api_params["presence"] = params.presence
            if params.tags:
                api_params["tags"] = ",".join(params.tags) if isinstance(params.tags, list) else params.tags
            if params.exclude_tags:
                api_params["exclude_tags"] = ",".join(params.exclude_tags) if isinstance(params.exclude_tags, list) else params.exclude_tags
            if params.per_page:
                api_params["per_page"] = params.per_page
            if params.cursor:
                api_params["cursor"] = params.cursor
            if params.ordering:
                api_params["ordering"] = params.ordering
            if params.mine:
                api_params["assigned_to_me"] = "true"
            if params.severity:
                api_params["severity"] = ",".join(params.severity) if isinstance(params.severity, list) else params.severity
            if params.status:
                api_params["status"] = ",".join(params.status) if isinstance(params.status, list) else params.status
            if params.validity:
                api_params["validity"] = ",".join(params.validity) if isinstance(params.validity, list) else params.validity

            # Get incidents directly using source_id
            if params.get_all:
                incidents_result = await client.paginate_all(f"/sources/{params.source_id}/incidents/secrets", api_params)
                if isinstance(incidents_result, list):
                    count = len(incidents_result)
                    return ListRepoIncidentsResult(
                        source_id=params.source_id,
                        incidents=incidents_result,
                        total_count=count,
                        applied_filters=_build_filter_info(params),
                        suggestion=_build_suggestion(params, count),
                    )
                elif isinstance(incidents_result, dict):
                    count = incidents_result.get("total_count", len(incidents_result.get("data", [])))
                    return ListRepoIncidentsResult(
                        source_id=params.source_id,
                        incidents=incidents_result.get("data", []),
                        total_count=count,
                        applied_filters=_build_filter_info(params),
                        suggestion=_build_suggestion(params, count),
                    )
                else:
                    # Fallback for unexpected types
                    return ListRepoIncidentsError(
                        error=f"Unexpected response type: {type(incidents_result).__name__}",
                    )
            else:
                incidents_result = await client.list_source_incidents(params.source_id, **api_params)
                if isinstance(incidents_result, dict):
                    count = incidents_result.get("total_count", 0)
                    return ListRepoIncidentsResult(
                        source_id=params.source_id,
                        incidents=incidents_result.get("data", []),
                        next_cursor=incidents_result.get("next_cursor"),
                        total_count=count,
                        applied_filters=_build_filter_info(params),
                        suggestion=_build_suggestion(params, count),
                    )
                elif isinstance(incidents_result, list):
                    # Handle case where API returns a list directly
                    count = len(incidents_result)
                    return ListRepoIncidentsResult(
                        source_id=params.source_id,
                        incidents=incidents_result,
                        total_count=count,
                        applied_filters=_build_filter_info(params),
                        suggestion=_build_suggestion(params, count),
                    )
                else:
                    # Fallback for unexpected types
                    return ListRepoIncidentsError(
                        error=f"Unexpected response type: {type(incidents_result).__name__}",
                    )
        else:
            # Use repository_name lookup (legacy path)
            result = await client.list_repo_incidents_directly(
                repository_name=params.repository_name,
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                mine=params.mine,
            )

            # Enrich result with filter info and convert to Pydantic model
            if isinstance(result, dict):
                count = result.get("total_count", len(result.get("incidents", [])))
                return ListRepoIncidentsResult(
                    source_id=result.get("source_id"),
                    incidents=result.get("incidents", []),
                    total_count=count,
                    next_cursor=result.get("next_cursor"),
                    applied_filters=_build_filter_info(params),
                    suggestion=_build_suggestion(params, count),
                )
            else:
                return ListRepoIncidentsError(error="Unexpected result format from legacy path")

    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        return ListRepoIncidentsError(error=f"Failed to list repository incidents: {str(e)}")
