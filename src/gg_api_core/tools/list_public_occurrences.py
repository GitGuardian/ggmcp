from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PageOfResults,
    page_fields,
)
from gg_api_core.utils import get_client


class ListPublicOccurrencesParams(BaseModel):
    """Parameters for listing occurrences of a public secret incident."""

    incident_id: NumericId = Field(
        description="The id of the public secret incident to list occurrences for",
    )

    # Pagination
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)

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
    source_id: NumericId | None = Field(
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
    severity: str | None = Field(
        default=None,
        description=(
            "Filter occurrences by the severity of their related incident. "
            "Comma-separated values allowed (e.g. 'critical,high'). "
            "Options: critical, high, medium, low, info, unknown"
        ),
    )
    status: str | None = Field(
        default=None,
        description=(
            "Filter occurrences by the status of their related incident. "
            "Comma-separated values allowed (e.g. 'TRIGGERED,ASSIGNED'). "
            "Options: IGNORED, TRIGGERED, ASSIGNED, RESOLVED"
        ),
    )
    validity: str | None = Field(
        default=None,
        description=(
            "Filter occurrences by the validity of their related secret. "
            "Comma-separated values allowed. "
            "Options: valid, invalid, failed_to_check, no_checker, unknown"
        ),
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


class ListPublicOccurrencesResult(PageOfResults):
    """Result from listing public secret occurrences."""

    occurrences: list[dict[str, Any]] = Field(default_factory=list, description="List of public occurrence objects")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


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
    params: ListPublicOccurrencesParams,
) -> ListPublicOccurrencesResult:
    """List occurrences of a public secret incident detected by GitGuardian Public Monitoring.

    Args:
        params: ListPublicOccurrencesParams model containing the incident_id and all filters.
    """
    client = await get_client()

    result = await client.list_public_occurrences(
        incident_id=params.incident_id,
        cursor=params.cursor,
        per_page=params.page_size,
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

    return ListPublicOccurrencesResult(
        occurrences=result["data"],
        applied_filters=_build_filter_info(params),
        **page_fields(params, result),
    )
