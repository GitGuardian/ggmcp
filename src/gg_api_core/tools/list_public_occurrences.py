from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from gg_api_core.client import IncidentSeverity, IncidentStatus, IncidentValidity, _serialize_enum_filter
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
    presence: Literal["present", "removed"] | None = Field(
        default=None,
        description="Occurrences still present in their source, or removed from it",
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
    attachment_reason: (
        list[Literal["by_dev_from_perimeter", "on_github_org_in_perimeter", "from_secret_grasper"]] | None
    ) = Field(default=None, description="Occurrences attached to the incident for any of these reasons")

    # Related-incident filters
    severity: list[IncidentSeverity] | None = Field(
        default=None, description="Occurrences whose incident has any of these severities"
    )
    status: list[IncidentStatus] | None = Field(
        default=None, description="Occurrences whose incident has any of these statuses"
    )
    validity: list[IncidentValidity] | None = Field(
        default=None, description="Occurrences whose secret has any of these validities"
    )
    tags: list[str] | None = Field(
        default=None, description="Occurrences with any of these tags. Use ['NONE'] for occurrences with no tag."
    )

    @field_validator("attachment_reason", "severity", "status", "validity", "tags", mode="before")
    @classmethod
    def coerce_to_list(cls, v: Any) -> list[Any] | None:
        """Accept a single value where a list is expected."""
        if v is None or isinstance(v, list):
            return v
        return [v]

    # Ordering
    ordering: Literal["date", "-date", "id", "-id"] = Field(
        default="-date", description="Sort order: a field, prefixed with '-' for descending"
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
        filters["severity"] = [value.value for value in params.severity]
    if params.status:
        filters["status"] = [value.value for value in params.status]
    if params.validity:
        filters["validity"] = [value.value for value in params.validity]
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
        attachment_reason=_serialize_enum_filter(params.attachment_reason) if params.attachment_reason else None,
        severity=_serialize_enum_filter(params.severity) if params.severity else None,
        status=_serialize_enum_filter(params.status) if params.status else None,
        validity=_serialize_enum_filter(params.validity) if params.validity else None,
        tags=_serialize_enum_filter(params.tags) if params.tags else None,
        ordering=params.ordering,
        get_all=params.get_all,
    )

    return ListPublicOccurrencesResult(
        occurrences=result["data"],
        applied_filters=_build_filter_info(params),
        **page_fields(params, result),
    )
