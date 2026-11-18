from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import (
    IncidentSeverity,
    IncidentStatus,
    IncidentValidity,
    TagNames,
)
from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PageOfResults,
    page_fields,
)
from gg_api_core.utils import get_client

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
]  # We exclude "INVALID" ones. Note: /occurrences/secrets uses "unknown" not "not_checked"


class ListRepoOccurrencesFilters(BaseModel):
    """Filters for listing repository occurrences."""

    incident_id: int | None = Field(
        default=None,
        ge=1,
        description="Filter occurrences by incident ID. Omit source_id to query across sources. "
        "Other filters still apply; pass [] for tags, exclude_tags, status, severity, and validity "
        "to enumerate all known occurrences of that incident.",
    )
    date_after: str | None = Field(
        default=None,
        description="Occurrences found after this date (ISO datetime, e.g. 2025-01-31T00:00:00Z)",
    )
    date_before: str | None = Field(
        default=None,
        description="Occurrences found before this date (ISO datetime, e.g. 2025-01-31T00:00:00Z)",
    )
    presence: Literal["present", "removed"] | None = Field(
        default=None, description="Occurrences still present in their source, or removed from it"
    )
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)")
    exclude_tags: list[TagNames] | None = Field(
        default=DEFAULT_EXCLUDED_TAGS,
        description="Exclude occurrences with these tag names. Pass empty list to disable filtering.",
    )
    status: list[IncidentStatus] | None = Field(
        default=DEFAULT_STATUSES, description="Filter by status (list of status names)"
    )
    severity: list[IncidentSeverity] | None = Field(
        default=DEFAULT_SEVERITIES,
        description="Filter by severity (list of severity names)",
    )
    validity: list[IncidentValidity] | None = Field(
        default=DEFAULT_VALIDITIES,
        description="Filter by validity (list of validity names)",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch occurrences related to issues assigned to the current user",
    )
    assignee_id: NumericId | None = Field(
        default=None, description="Occurrences whose incident is assigned to this member ID. Cannot be used with mine."
    )

    @model_validator(mode="after")
    def validate_one_assignee_option(self):
        """Refuse assignee_id together with mine."""
        if self.assignee_id is not None and self.mine:
            raise ValueError("give assignee_id or mine, not both")
        return self


class ListRepoOccurrencesBaseParams(BaseModel):
    """Parameters for listing repository occurrences."""

    source_id: NumericId | None = Field(
        default=None,
        description="The GitGuardian source ID to filter by. Can be obtained using the list_sources tool.",
    )
    ordering: Literal["date", "-date"] | None = Field(
        default=None,
        description="Sort order: date, or -date for newest first. Unset, occurrences come in the order the API "
        "returns them, by ID",
    )
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListRepoOccurrencesParams(ListRepoOccurrencesFilters, ListRepoOccurrencesBaseParams):
    pass


class ListRepoOccurrencesResult(PageOfResults):
    """Result from listing repository occurrences."""

    occurrences: list[dict[str, Any]] = Field(default_factory=list, description="List of occurrence objects")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


def _build_filter_info(params: ListRepoOccurrencesParams) -> dict[str, Any]:
    """Build a dictionary describing the filters applied to the query."""
    filters: dict[str, Any] = {}

    # Include all active filters
    if params.incident_id is not None:
        filters["incident_id"] = params.incident_id
    if params.date_after:
        filters["date_after"] = params.date_after
    if params.date_before:
        filters["date_before"] = params.date_before
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
    if params.assignee_id:
        filters["assignee_id"] = params.assignee_id

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


async def list_internal_occurrences(
    params: ListRepoOccurrencesParams = ListRepoOccurrencesParams(),
) -> ListRepoOccurrencesResult:
    """List secret occurrences for a repository or incident using the GitGuardian v1/occurrences/secrets API.

    Args:
        params: ListRepoOccurrencesParams model containing all filtering options.
               Optionally filter by source_id.
    """
    client = await get_client()

    assignee_id = params.assignee_id
    if params.mine:
        # Token info provides the member ID without requiring members:read.
        # Fail before querying occurrences if the caller cannot be identified.
        token_info = await client.get_current_token_info()
        assignee_id = token_info.get("member_id")
        if assignee_id is None:
            raise ToolError(
                "mine=True requires a personal token with a member_id. "
                "Use assignee_id to select an assignee with a service token."
            )

    result = await client.list_occurrences(
        incident_id=params.incident_id,
        source_id=str(params.source_id) if params.source_id is not None else None,
        date_after=params.date_after,
        date_before=params.date_before,
        presence=params.presence,
        tags=params.tags,
        exclude_tags=params.exclude_tags,
        per_page=params.page_size,
        cursor=params.cursor,
        ordering=params.ordering,
        get_all=params.get_all,
        status=params.status,
        severity=params.severity,
        validity=params.validity,
        assignee_id=assignee_id,
        with_sources=False,
    )

    return ListRepoOccurrencesResult(
        occurrences=result["data"],
        applied_filters=_build_filter_info(params),
        suggestion=_build_suggestion(params, len(result["data"])),
        **page_fields(params, result),
    )
