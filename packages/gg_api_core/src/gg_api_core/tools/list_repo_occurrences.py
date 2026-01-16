import logging
from typing import Any

from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import (
    DEFAULT_PAGINATION_MAX_BYTES,
    IncidentSeverity,
    IncidentStatus,
    IncidentValidity,
    TagNames,
)
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


class ListRepoOccurrencesFilters(BaseModel):
    """Filters for listing repository occurrences."""

    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    )
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    )
    presence: str | None = Field(default=None, description="Filter by presence status")
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)")
    exclude_tags: list[TagNames] | None = Field(
        default=DEFAULT_EXCLUDED_TAGS,
        description="Exclude occurrences with these tag names. Pass empty list to disable filtering.",
    )
    status: list[IncidentStatus] | None = Field(
        default=DEFAULT_STATUSES, description="Filter by status (list of status names)"
    )
    severity: list[IncidentSeverity] | None = Field(
        default=DEFAULT_SEVERITIES, description="Filter by severity (list of severity names)"
    )
    validity: list[IncidentValidity] | None = Field(
        default=DEFAULT_VALIDITIES, description="Filter by validity (list of validity names)"
    )
    mine: bool = Field(
        default=False, description="If True, fetch occurrences related to issues assigned to the current user"
    )
    member_assignee_id: int | None = Field(default=None, description="Filter by the member the incident is assigned to")

    @model_validator(mode="after")
    def validate_exactly_one_assignee_option(self):
        """Validate that exactly one of member_assignee_id, or mine is provided."""
        if self.member_assignee_id is not None and self.mine:
            raise ValueError("Only one of assignee_member_id, or mine should be provided")


class ListRepoOccurrencesBaseParams(BaseModel):
    """Parameters for listing repository occurrences."""

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
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListRepoOccurrencesParams(ListRepoOccurrencesFilters, ListRepoOccurrencesBaseParams):
    pass


class ListRepoOccurrencesResult(BaseModel):
    """Result from listing repository occurrences."""

    repository: str | None = Field(default=None, description="Repository name")
    occurrences_count: int = Field(description="Number of occurrences returned")
    occurrences: list[dict[str, Any]] = Field(default_factory=list, description="List of occurrence objects")
    cursor: str | None = Field(default=None, description="Pagination cursor for next page")
    has_more: bool = Field(default=False, description="True if more results exist (use cursor to fetch)")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


class ListRepoOccurrencesError(BaseModel):
    """Error result from listing repository occurrences."""

    error: str = Field(description="Error message")


def _build_filter_info(params: ListRepoOccurrencesParams) -> dict[str, Any]:
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
        filters["tags"] = [tag.value if hasattr(tag, "value") else tag for tag in params.tags]
    if params.exclude_tags:
        filters["exclude_tags"] = [tag.value if hasattr(tag, "value") else tag for tag in params.exclude_tags]
    if params.status:
        filters["status"] = [st.value if hasattr(st, "value") else st for st in params.status]
    if params.severity:
        filters["severity"] = [sev.value if hasattr(sev, "value") else sev for sev in params.severity]
    if params.validity:
        filters["validity"] = [v.value if hasattr(v, "value") else v for v in params.validity]
    if params.mine:
        filters["mine"] = params.mine
    if params.member_assignee_id:
        filters["member_assignee_id"] = params.member_assignee_id

    return filters


def _build_suggestion(params: ListRepoOccurrencesParams, occurrences_count: int) -> str:
    """Build a suggestion message based on applied filters and results."""
    suggestions = []

    # Explain what's being filtered
    if params.exclude_tags:
        excluded_tag_names = [tag.name if hasattr(tag, "name") else tag for tag in params.exclude_tags]
        suggestions.append(f"Occurrences were filtered to exclude tags: {', '.join(excluded_tag_names)}")

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
    if occurrences_count == 0 and suggestions:
        suggestions.append(
            "No occurrences matched the applied filters. Try with exclude_tags=[] or different status/severity/validity filters to see all occurrences."
        )

    return "\n".join(suggestions) if suggestions else ""


async def list_repo_occurrences(
    params: ListRepoOccurrencesParams,
) -> ListRepoOccurrencesResult | ListRepoOccurrencesError:
    """
    List secret occurrences for a specific repository using the GitGuardian v1/occurrences/secrets API.

    This tool returns detailed occurrence data with EXACT match locations, including:
    - File path where the secret was found
    - Line number in the file
    - Start and end character indices of the match
    - The type of secret detected
    - Match context and patterns

    This is particularly useful for automated remediation workflows where the agent needs to:
    1. Locate the exact position of secrets in files
    2. Read the surrounding code context
    3. Make precise edits to remove or replace secrets
    4. Verify that secrets have been properly removed

    Use list_incidents for a higher-level view of incidents grouped by secret type.

    By default, occurrences tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        params: ListRepoOccurrencesParams model containing all filtering options.
               Optionally filter by repository_name or source_id.

    Returns:
        ListRepoOccurrencesResult: Pydantic model containing:
            - repository: Repository name
            - occurrences_count: Number of occurrences returned
            - occurrences: List of occurrence objects with exact match locations
            - cursor: Pagination cursor (if applicable)
            - has_more: Whether more results are available
            - applied_filters: Dictionary of filters that were applied
            - suggestion: Suggestions for interpreting or modifying results

        ListRepoOccurrencesError: Pydantic model with error message if the operation fails
    """
    client = await get_client()
    logger.debug(f"Listing occurrences with repository_name={params.repository_name}, source_id={params.source_id}")

    # Filter by assigned member
    member_assignee_id = params.member_assignee_id
    if params.mine:
        member = await client.get_current_member()
        member_assignee_id = member["id"]

    try:
        # Call the list_occurrences method with appropriate filter
        if params.source_id:
            # Use source_id directly
            result = await client.list_occurrences(
                source_id=str(params.source_id) if params.source_id is not None else None,
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                status=params.status,
                severity=params.severity,
                validity=params.validity,
                member_assignee_id=member_assignee_id,
                with_sources=False,
            )
        else:
            # Use source_name (legacy path)
            source_name = params.repository_name.strip() if params.repository_name is not None else None
            result = await client.list_occurrences(
                source_name=source_name,
                source_type="github",  # Default to github, could be made configurable
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                status=params.status,
                severity=params.severity,
                validity=params.validity,
                member_assignee_id=member_assignee_id,
                with_sources=False,
            )

        # Extract data from ListResponse or PaginatedResult
        occurrences_data = result["data"]
        next_cursor = result["cursor"]
        has_more = result.get("has_more", False)

        count = len(occurrences_data)
        return ListRepoOccurrencesResult(
            repository=params.repository_name,
            occurrences_count=count,
            occurrences=occurrences_data,
            cursor=next_cursor,
            has_more=has_more,
            applied_filters=_build_filter_info(params),
            suggestion=_build_suggestion(params, count),
        )

    except Exception as e:
        logger.exception(f"Error listing repository occurrences: {str(e)}")
        return ListRepoOccurrencesError(error=f"Failed to list repository occurrences: {str(e)}")
