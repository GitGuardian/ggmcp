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


# Default filters mirror list_incidents to keep the two tools behaviorally consistent:
# hide IGNORED statuses, LOW/INFO severities, and INVALID validity out of the box.
DEFAULT_STATUSES: list[IncidentStatusFilter] = [
    "TRIGGERED",
    "ASSIGNED",
    "RESOLVED",
]
DEFAULT_SEVERITIES: list[IncidentSeverityFilter] = [
    "critical",
    "high",
    "medium",
    "unknown",
]
# /public-incidents/secrets validity enum uses 'unknown' (not 'not_checked' like /incidents-for-mcp).
DEFAULT_VALIDITIES: list[IncidentValidityFilter] = [
    "valid",
    "failed_to_check",
    "no_checker",
    "unknown",
]


class ListPublicIncidentsParams(BaseModel):
    """Parameters for listing public secret incidents.

    Public incidents are incidents detected by GitGuardian on public sources
    (e.g. public GitHub repositories), as opposed to internal sources monitored
    by the workspace.
    """

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
    triggered_at_before: str | None = Field(
        default=None,
        description="Incidents triggered before this date (ISO datetime)",
    )
    triggered_at_after: str | None = Field(
        default=None,
        description="Incidents triggered after this date (ISO datetime)",
    )

    # Assignment filters
    assignee_email: str | None = Field(
        default=None,
        description="Filter by assignee email",
    )
    assignee_id: int | None = Field(
        default=None,
        description="Filter by assignee user id",
    )

    # Status / severity / validity
    status: list[IncidentStatusFilter] | None = Field(
        default=DEFAULT_STATUSES,
        description=(
            "Filter by incident status. Values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED. "
            "Accepts a single value or a list. Default excludes IGNORED."
        ),
    )
    severity: list[IncidentSeverityFilter] | None = Field(
        default=DEFAULT_SEVERITIES,
        description=(
            "Filter by severity. Values: critical, high, medium, low, info, unknown. "
            "Accepts a single value or a list. Default excludes LOW and INFO."
        ),
    )
    validity: list[IncidentValidityFilter] | None = Field(
        default=DEFAULT_VALIDITIES,
        description=(
            "Filter by validity. Values: valid, invalid, failed_to_check, no_checker, unknown. "
            "Accepts a single value or a list. Default excludes INVALID."
        ),
    )

    # Tags
    tags: str | None = Field(
        default=None,
        description=(
            "Filter by tags. Comma-separated list of tag names (e.g. "
            "'FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED'). Use 'NONE' to filter incidents with no tags."
        ),
    )
    custom_tags: str | None = Field(
        default=None,
        description="Comma-separated list of custom tag UUIDs to filter by",
    )
    custom_tag_key: str | None = Field(
        default=None,
        description="Filter incidents that have a custom tag with this key",
    )
    custom_tag_value: str | None = Field(
        default=None,
        description="Filter incidents that have a custom tag with this value",
    )

    # Ordering
    ordering: str | None = Field(
        default="-date",
        description=(
            "Sort field with optional '-' prefix for descending. Options: date, -date, "
            "resolved_at, -resolved_at, ignored_at, -ignored_at, risk_score, -risk_score"
        ),
    )

    # Detector / actor filters
    detector_group_name: str | None = Field(
        default=None,
        description="Filter by detector group name (e.g. 'slackbot_token')",
    )
    ignorer_id: int | None = Field(
        default=None,
        description="Filter incidents ignored by this user id",
    )
    ignorer_api_token_id: str | None = Field(
        default=None,
        description="Filter incidents ignored by this API token id",
    )
    resolver_id: int | None = Field(
        default=None,
        description="Filter incidents resolved by this user id",
    )
    resolver_api_token_id: str | None = Field(
        default=None,
        description="Filter incidents resolved by this API token id",
    )

    # Boolean / declarative filters
    feedback: bool | None = Field(
        default=None,
        description="Filter to incidents with (True) or without (False) feedback",
    )
    declarative_secret_status: str | None = Field(
        default=None,
        description=(
            "Filter by declarative secret status (revoked, active, test_credential, false_positive, low_risk)"
        ),
    )

    # Risk score
    risk_score_min: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Filter incidents with risk score >= this value (0-100)",
    )
    risk_score_max: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Filter incidents with risk score <= this value (0-100)",
    )

    # Coerce a single enum/string into a list so LLM callers can pass either shape.
    @field_validator("status", "severity", "validity", mode="before")
    @classmethod
    def coerce_to_list(cls, v: Any) -> list[Any] | None:
        return coerce_to_list(v)


class ListPublicIncidentsResult(BaseModel):
    """Result from listing public secret incidents."""

    incidents_count: int = Field(description="Number of incidents returned")
    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of public incident objects")
    cursor: str | None = Field(default=None, description="Pagination cursor for next page")
    has_more: bool = Field(default=False, description="True if more results exist (use cursor to fetch)")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


class ListPublicIncidentsError(BaseModel):
    """Error result from listing public secret incidents."""

    error: str = Field(description="Error message")


def _build_filter_info(params: ListPublicIncidentsParams) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    if params.date_before:
        filters["date_before"] = params.date_before
    if params.date_after:
        filters["date_after"] = params.date_after
    if params.triggered_at_before:
        filters["triggered_at_before"] = params.triggered_at_before
    if params.triggered_at_after:
        filters["triggered_at_after"] = params.triggered_at_after
    if params.assignee_email:
        filters["assignee_email"] = params.assignee_email
    if params.assignee_id is not None:
        filters["assignee_id"] = params.assignee_id
    if params.status:
        filters["status"] = params.status
    if params.severity:
        filters["severity"] = params.severity
    if params.validity:
        filters["validity"] = params.validity
    if params.tags:
        filters["tags"] = params.tags
    if params.custom_tags:
        filters["custom_tags"] = params.custom_tags
    if params.custom_tag_key:
        filters["custom_tag_key"] = params.custom_tag_key
    if params.custom_tag_value:
        filters["custom_tag_value"] = params.custom_tag_value
    if params.detector_group_name:
        filters["detector_group_name"] = params.detector_group_name
    if params.ignorer_id is not None:
        filters["ignorer_id"] = params.ignorer_id
    if params.ignorer_api_token_id:
        filters["ignorer_api_token_id"] = params.ignorer_api_token_id
    if params.resolver_id is not None:
        filters["resolver_id"] = params.resolver_id
    if params.resolver_api_token_id:
        filters["resolver_api_token_id"] = params.resolver_api_token_id
    if params.feedback is not None:
        filters["feedback"] = params.feedback
    if params.declarative_secret_status:
        filters["declarative_secret_status"] = params.declarative_secret_status
    if params.risk_score_min is not None:
        filters["risk_score_min"] = params.risk_score_min
    if params.risk_score_max is not None:
        filters["risk_score_max"] = params.risk_score_max
    return filters


async def list_public_incidents(
    per_page: Annotated[int, Field(default=20, ge=1, le=100, description='Number of results per page (default: 20, max: 100)')] = 20,
    cursor: Annotated[str | None, Field(default=None, description='Pagination cursor for fetching the next page of results')] = None,
    get_all: Annotated[bool, Field(default=False, description="If True, fetch all pages (capped at ~20.0KB; check 'has_more' and use cursor to continue)")] = False,
    date_before: Annotated[str | None, Field(default=None, description='Entries found before this date (ISO datetime, e.g. 2025-01-31T00:00:00Z)')] = None,
    date_after: Annotated[str | None, Field(default=None, description='Entries found after this date (ISO datetime)')] = None,
    triggered_at_before: Annotated[str | None, Field(default=None, description='Incidents triggered before this date (ISO datetime)')] = None,
    triggered_at_after: Annotated[str | None, Field(default=None, description='Incidents triggered after this date (ISO datetime)')] = None,
    assignee_email: Annotated[str | None, Field(default=None, description='Filter by assignee email')] = None,
    assignee_id: Annotated[int | None, Field(default=None, description='Filter by assignee user id')] = None,
    status: Annotated[list[IncidentStatus] | IncidentStatus | None, Field(default=['TRIGGERED', 'ASSIGNED', 'RESOLVED'], description='Filter by incident status. Values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED. Accepts a single value or a list. Default excludes IGNORED.')] = ['TRIGGERED', 'ASSIGNED', 'RESOLVED'],
    severity: Annotated[list[IncidentSeverity] | IncidentSeverity | None, Field(default=['critical', 'high', 'medium', 'unknown'], description='Filter by severity. Values: critical, high, medium, low, info, unknown. Accepts a single value or a list. Default excludes LOW and INFO.')] = ['critical', 'high', 'medium', 'unknown'],
    validity: Annotated[list[IncidentValidity] | IncidentValidity | None, Field(default=['valid', 'failed_to_check', 'no_checker', 'unknown'], description='Filter by validity. Values: valid, invalid, failed_to_check, no_checker, unknown. Accepts a single value or a list. Default excludes INVALID.')] = ['valid', 'failed_to_check', 'no_checker', 'unknown'],
    tags: Annotated[str | None, Field(default=None, description="Filter by tags. Comma-separated list of tag names (e.g. 'FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED'). Use 'NONE' to filter incidents with no tags.")] = None,
    custom_tags: Annotated[str | None, Field(default=None, description='Comma-separated list of custom tag UUIDs to filter by')] = None,
    custom_tag_key: Annotated[str | None, Field(default=None, description='Filter incidents that have a custom tag with this key')] = None,
    custom_tag_value: Annotated[str | None, Field(default=None, description='Filter incidents that have a custom tag with this value')] = None,
    ordering: Annotated[str | None, Field(default='-date', description="Sort field with optional '-' prefix for descending. Options: date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at, risk_score, -risk_score")] = '-date',
    detector_group_name: Annotated[str | None, Field(default=None, description="Filter by detector group name (e.g. 'slackbot_token')")] = None,
    ignorer_id: Annotated[int | None, Field(default=None, description='Filter incidents ignored by this user id')] = None,
    ignorer_api_token_id: Annotated[str | None, Field(default=None, description='Filter incidents ignored by this API token id')] = None,
    resolver_id: Annotated[int | None, Field(default=None, description='Filter incidents resolved by this user id')] = None,
    resolver_api_token_id: Annotated[str | None, Field(default=None, description='Filter incidents resolved by this API token id')] = None,
    feedback: Annotated[bool | None, Field(default=None, description='Filter to incidents with (True) or without (False) feedback')] = None,
    declarative_secret_status: Annotated[str | None, Field(default=None, description='Filter by declarative secret status (revoked, active, test_credential, false_positive, low_risk)')] = None,
    risk_score_min: Annotated[int | None, Field(default=None, ge=0, le=100, description='Filter incidents with risk score >= this value (0-100)')] = None,
    risk_score_max: Annotated[int | None, Field(default=None, ge=0, le=100, description='Filter incidents with risk score <= this value (0-100)')] = None,
) -> ListPublicIncidentsResult | ListPublicIncidentsError:
    """
    List public secret incidents detected by GitGuardian on public sources (e.g. public GitHub).

        Public incidents differ from internal incidents: they correspond to secrets leaked outside the
        organization perimeter and surfaced via GitGuardian Public Monitoring (Explore). Use this tool
        instead of `list_incidents` when investigating leaks on public sources.

        Wraps GET /v1/public-incidents/secrets and uses cursor-based pagination.

        Args:
            params: ListPublicIncidentsParams model containing all filtering options.

        Returns:
            ListPublicIncidentsResult with the public incidents page, or
            ListPublicIncidentsError on failure.

    """
    params = ListPublicIncidentsParams(
        per_page=per_page,
        cursor=cursor,
        get_all=get_all,
        date_before=date_before,
        date_after=date_after,
        triggered_at_before=triggered_at_before,
        triggered_at_after=triggered_at_after,
        assignee_email=assignee_email,
        assignee_id=assignee_id,
        status=status,
        severity=severity,
        validity=validity,
        tags=tags,
        custom_tags=custom_tags,
        custom_tag_key=custom_tag_key,
        custom_tag_value=custom_tag_value,
        ordering=ordering,
        detector_group_name=detector_group_name,
        ignorer_id=ignorer_id,
        ignorer_api_token_id=ignorer_api_token_id,
        resolver_id=resolver_id,
        resolver_api_token_id=resolver_api_token_id,
        feedback=feedback,
        declarative_secret_status=declarative_secret_status,
        risk_score_min=risk_score_min,
        risk_score_max=risk_score_max,
    )

    client = await get_client()

    try:
        result = await client.list_public_incidents(
            cursor=params.cursor,
            per_page=params.per_page,
            date_before=params.date_before,
            date_after=params.date_after,
            triggered_at_before=params.triggered_at_before,
            triggered_at_after=params.triggered_at_after,
            assignee_email=params.assignee_email,
            assignee_id=params.assignee_id,
            status=params.status,
            severity=params.severity,
            validity=params.validity,
            tags=params.tags,
            custom_tags=params.custom_tags,
            custom_tag_key=params.custom_tag_key,
            custom_tag_value=params.custom_tag_value,
            ordering=params.ordering,
            detector_group_name=params.detector_group_name,
            ignorer_id=params.ignorer_id,
            ignorer_api_token_id=params.ignorer_api_token_id,
            resolver_id=params.resolver_id,
            resolver_api_token_id=params.resolver_api_token_id,
            feedback=params.feedback,
            declarative_secret_status=params.declarative_secret_status,
            risk_score_min=params.risk_score_min,
            risk_score_max=params.risk_score_max,
            get_all=params.get_all,
        )

        incidents_data = result["data"]
        next_cursor = result["cursor"]
        has_more = result.get("has_more", False)

        return ListPublicIncidentsResult(
            incidents_count=len(incidents_data),
            incidents=incidents_data,
            cursor=next_cursor,
            has_more=has_more,
            applied_filters=_build_filter_info(params),
        )

    except Exception as e:
        logger.exception(f"Error listing public incidents: {str(e)}")
        return ListPublicIncidentsError(error=f"Failed to list public incidents: {str(e)}")
