import logging
from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.generated_filter_vocabulary import (
    IncidentSeverityFilter,
    IncidentStatusFilter,
    IncidentValidityFilter,
)
from gg_api_core.incident_filters import coerce_to_list
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListPublicOccurrencesParams(BaseModel):
    """Parameters for listing occurrences of a public secret incident."""

    incident_id: int = Field(
        description="The id of the public secret incident to list occurrences for",
    )

    # Pagination
    per_page: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Number of results per page (default: 20, max: 100)",
    )
    cursor: str | None = Field(
        default=None,
        description="Pagination cursor for fetching the next page of results",
    )
    get_all: bool = Field(
        default=False,
        description=(
            f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; "
            "check 'has_more' and use cursor to continue)"
        ),
    )

    # Date filters
    date_before: str | None = Field(
        default=None,
        description="Entries found before this date (ISO datetime, e.g. 2025-01-31T00:00:00Z)",
    )
    date_after: str | None = Field(
        default=None,
        description="Entries found after this date (ISO datetime)",
    )

    # Source / location filters
    source_id: int | None = Field(
        default=None,
        description="Filter occurrences belonging to this source ID",
    )
    presence: str | None = Field(
        default=None,
        description="Filter by presence status (present, removed)",
    )
    sha: str | None = Field(
        default=None,
        min_length=3,
        description="Filter by commit sha (>=3 characters)",
    )
    filepath: str | None = Field(
        default=None,
        min_length=3,
        description="Filter by filepath (>=3 characters)",
    )
    attachment_reason: str | None = Field(
        default=None,
        description=(
            "Filter by attachment reason. Comma-separated values allowed. "
            "Options: by_dev_from_perimeter, on_github_org_in_perimeter, from_secret_grasper"
        ),
    )

    # Related-incident filters
    severity: list[IncidentSeverityFilter] | None = Field(
        default=None,
        description="Filter occurrences by related incident severity.",
    )
    status: list[IncidentStatusFilter] | None = Field(
        default=None,
        description="Filter occurrences by related incident status.",
    )
    validity: list[IncidentValidityFilter] | None = Field(
        default=None,
        description="Filter occurrences by related secret validity.",
    )
    tags: str | None = Field(
        default=None,
        description=(
            "Filter by tags. Comma-separated list of tag names. Use 'NONE' to filter occurrences with no tags."
        ),
    )

    # Ordering
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: id, -id, date, -date",
    )

    @field_validator("severity", "status", "validity", mode="before")
    @classmethod
    def coerce_to_list(cls, value: Any) -> list[Any] | None:
        """Accept a single value, a list, or a comma-separated string, and normalize to a list."""
        return coerce_to_list(value)


class ListPublicOccurrencesResult(BaseModel):
    """Result from listing public secret occurrences."""

    occurrences_count: int = Field(description="Number of occurrences returned")
    occurrences: list[dict[str, Any]] = Field(default_factory=list, description="List of public occurrence objects")
    cursor: str | None = Field(default=None, description="Pagination cursor for next page")
    has_more: bool = Field(default=False, description="True if more results exist (use cursor to fetch)")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


class ListPublicOccurrencesError(BaseModel):
    """Error result from listing public secret occurrences."""

    error: str = Field(description="Error message")


def _build_filter_info(params: ListPublicOccurrencesParams) -> dict[str, Any]:
    filters: dict[str, Any] = {"incident_id": params.incident_id}
    if params.date_before:
        filters["date_before"] = params.date_before
    if params.date_after:
        filters["date_after"] = params.date_after
    if params.source_id is not None:
        filters["source_id"] = params.source_id
    if params.presence:
        filters["presence"] = params.presence
    if params.sha:
        filters["sha"] = params.sha
    if params.filepath:
        filters["filepath"] = params.filepath
    if params.attachment_reason:
        filters["attachment_reason"] = params.attachment_reason
    if params.severity:
        filters["severity"] = params.severity
    if params.status:
        filters["status"] = params.status
    if params.validity:
        filters["validity"] = params.validity
    if params.tags:
        filters["tags"] = params.tags
    return filters


async def list_public_occurrences(
    incident_id: Annotated[
        int,
        Field(description="The id of the public secret incident to list occurrences for"),
    ],
    per_page: Annotated[
        int,
        Field(default=20, ge=1, le=100, description="Number of results per page (default: 20, max: 100)"),
    ] = 20,
    cursor: Annotated[
        str | None, Field(default=None, description="Pagination cursor for fetching the next page of results")
    ] = None,
    get_all: Annotated[
        bool,
        Field(
            default=False,
            description=(
                f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; "
                "check 'has_more' and use cursor to continue)"
            ),
        ),
    ] = False,
    date_before: Annotated[
        str | None,
        Field(default=None, description="Entries found before this date (ISO datetime, e.g. 2025-01-31T00:00:00Z)"),
    ] = None,
    date_after: Annotated[
        str | None, Field(default=None, description="Entries found after this date (ISO datetime)")
    ] = None,
    source_id: Annotated[
        int | None, Field(default=None, description="Filter occurrences belonging to this source ID")
    ] = None,
    presence: Annotated[
        str | None, Field(default=None, description="Filter by presence status (present, removed)")
    ] = None,
    sha: Annotated[
        str | None, Field(default=None, min_length=3, description="Filter by commit sha (>=3 characters)")
    ] = None,
    filepath: Annotated[
        str | None, Field(default=None, min_length=3, description="Filter by filepath (>=3 characters)")
    ] = None,
    attachment_reason: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Filter by attachment reason. Comma-separated values allowed. "
                "Options: by_dev_from_perimeter, on_github_org_in_perimeter, from_secret_grasper"
            ),
        ),
    ] = None,
    severity: Annotated[
        list[IncidentSeverityFilter] | IncidentSeverityFilter | None,
        Field(default=None, description="Filter occurrences by related incident severity."),
    ] = None,
    status: Annotated[
        list[IncidentStatusFilter] | IncidentStatusFilter | None,
        Field(default=None, description="Filter occurrences by related incident status."),
    ] = None,
    validity: Annotated[
        list[IncidentValidityFilter] | IncidentValidityFilter | None,
        Field(default=None, description="Filter occurrences by related secret validity."),
    ] = None,
    tags: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Filter by tags. Comma-separated list of tag names. Use 'NONE' to filter occurrences with no tags."
            ),
        ),
    ] = None,
    ordering: Annotated[
        str | None,
        Field(
            default="-date",
            description="Sort field with optional '-' prefix for descending. Options: id, -id, date, -date",
        ),
    ] = "-date",
) -> ListPublicOccurrencesResult | ListPublicOccurrencesError:
    """List occurrences of a public secret incident detected by GitGuardian Public Monitoring.

    Returns occurrence-level details for a single public incident, including filepath,
    commit sha, source repository, actor, and attachment reasons. Use this after
    `list_public_incidents` to drill into a specific public incident.

    Wraps GET /v1/public-incidents/secrets/{incident_id}/occurrences and uses cursor-based pagination.

    Args:
        incident_id: The id of the public secret incident to list occurrences for
        per_page: Number of results per page (default: 20, max: 100)
        cursor: Pagination cursor
        get_all: If True, fetch all pages
        date_before: Entries found before this date
        date_after: Entries found after this date
        source_id: Filter occurrences belonging to this source ID
        presence: Filter by presence status
        sha: Filter by commit sha (>=3 characters)
        filepath: Filter by filepath (>=3 characters)
        attachment_reason: Filter by attachment reason
        severity: Filter by severity of related incident
        status: Filter by status of related incident
        validity: Filter by validity of related secret
        tags: Filter by tags
        ordering: Sort field

    Returns:
        ListPublicOccurrencesResult with the occurrences page, or
        ListPublicOccurrencesError on failure.
    """
    params = ListPublicOccurrencesParams(
        incident_id=incident_id,
        per_page=per_page,
        cursor=cursor,
        get_all=get_all,
        date_before=date_before,
        date_after=date_after,
        source_id=source_id,
        presence=presence,
        sha=sha,
        filepath=filepath,
        attachment_reason=attachment_reason,
        severity=severity,
        status=status,
        validity=validity,
        tags=tags,
        ordering=ordering,
    )
    client = await get_client()

    try:
        result = await client.list_public_occurrences(
            incident_id=params.incident_id,
            cursor=params.cursor,
            per_page=params.per_page,
            date_before=params.date_before,
            date_after=params.date_after,
            source_id=params.source_id,
            presence=params.presence,
            sha=params.sha,
            filepath=params.filepath,
            attachment_reason=params.attachment_reason,
            severity=params.severity,
            status=params.status,
            validity=params.validity,
            tags=params.tags,
            ordering=params.ordering,
            get_all=params.get_all,
        )

        occurrences_data = result["data"]
        next_cursor = result["cursor"]
        has_more = result.get("has_more", False)

        return ListPublicOccurrencesResult(
            occurrences_count=len(occurrences_data),
            occurrences=occurrences_data,
            cursor=next_cursor,
            has_more=has_more,
            applied_filters=_build_filter_info(params),
        )

    except Exception as e:
        logger.exception(f"Error listing public occurrences: {str(e)}")
        return ListPublicOccurrencesError(error=f"Failed to list public occurrences: {str(e)}")
