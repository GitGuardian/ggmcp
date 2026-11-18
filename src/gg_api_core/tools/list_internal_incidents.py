import json
import logging
import re
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, MAX_PAGINATION_PAGES
from gg_api_core.tools.incident_filters import (
    DEFAULT_STATUSES,
    STATUS_DESCRIPTION,
    IncidentFilters,
    Status,
    build_filter_info,
    build_incident_query,
    resolve_assignee,
)
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PageOfResults,
    StopReason,
    next_arguments_for,
    stop_reason_of,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# get_all fetches pages this small: about 16 KB of summaries each, so it stops near its size
# budget instead of returning one oversized page whole, and the next page at this page size
# resumes exactly where its result stops.
GET_ALL_PAGE_SIZE = 5

# The endpoint pages by number, so a cursor names a page and the page size it counts in.
_CURSOR = re.compile(r"(\d+):(\d+)")


def _cursor(page: int, page_size: int) -> str:
    return f"{page}:{page_size}"


def _read_cursor(cursor: str) -> tuple[int, int]:
    """The page and page size a cursor names."""
    match = _CURSOR.fullmatch(cursor)
    if match is None or int(match[1]) < 1 or not 1 <= int(match[2]) <= 100:
        raise ToolError("cursor is not one this tool returned; pass next_arguments from a previous result as given")
    return int(match[1]), int(match[2])


def _get_all_page_size(page_size: int) -> int:
    """The largest page size up to GET_ALL_PAGE_SIZE that divides the requested one.

    The requested page, counted in pages of the requested size, then starts exactly on a
    page boundary at the smaller size.
    """
    return max(size for size in range(1, GET_ALL_PAGE_SIZE + 1) if page_size % size == 0)


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


class _Pagination(BaseModel):
    """Pagination fields, declared first so list_internal_incidents' schema lists them first."""

    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(
        default=False, description=f"{GET_ALL_DESCRIPTION}. get_all fetches pages of at most {GET_ALL_PAGE_SIZE}"
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
    )


class ListIncidentsParams(IncidentFilters, _Pagination):
    """Parameters for listing incidents using the MCP-optimized endpoint."""

    status: list[Status] | None = Field(
        default=DEFAULT_STATUSES,
        description=f"{STATUS_DESCRIPTION} Note that OPENED is not a valid status but means 'TRIGGERED OR ASSIGNED'.",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Overrides assignee_id.",
    )

    score_min: int | None = Field(
        default=None,
        description="Filter incidents with a score greater than or equal to this value (0-100). Higher scores indicate higher priority incidents.",
        ge=0,
        le=100,
    )


# A listed incident keeps every top-level field, but its secret and displayed occurrence
# are cut to what triage reads: they are most of an incident's size, and a page of full
# incidents outgrows what clients accept as tool output. get_internal_incident gives an incident's full details.
_SECRET_FIELDS = (
    "id",
    "status",
    "validity_status",
    "validity_status_override",
    "category",
    "family",
    "provider",
    "analyzer_status",
    "publicly_leaked_count",
)
_DETECTOR_FIELDS = (
    "name",
    "display_name",
    "detector_group_name",
    "detector_group_display_name",
    "category",
    "family",
    "provider",
    "nature",
)
_OCCURRENCE_FIELDS = (
    "id",
    "kind",
    "element",
    "element_type",
    "url",
    "filepath",
    "filename",
    "presence",
    "date",
    "author_name",
)
_SOURCE_FIELDS = ("id", "type", "display_name", "url", "source_criticality", "visibility")
_MATCH_FIELDS = ("name", "pre_line_start", "pre_line_end", "post_line_start", "post_line_end")


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def summarize_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """An incident as listed: its secret and displayed occurrence cut to the fields triage reads."""
    summary = dict(incident)
    secret = incident.get("secret")
    if isinstance(secret, dict):
        summary["secret"] = _pick(secret, _SECRET_FIELDS)
        if isinstance(secret.get("detector"), dict):
            summary["secret"]["detector"] = _pick(secret["detector"], _DETECTOR_FIELDS)
    occurrence = incident.get("displayed_occurrence")
    if isinstance(occurrence, dict):
        summary["displayed_occurrence"] = _pick(occurrence, _OCCURRENCE_FIELDS)
        if isinstance(occurrence.get("source"), dict):
            summary["displayed_occurrence"]["source"] = _pick(occurrence["source"], _SOURCE_FIELDS)
        if isinstance(occurrence.get("matches"), list):
            summary["displayed_occurrence"]["matches"] = [
                _pick(match, _MATCH_FIELDS) for match in occurrence["matches"] if isinstance(match, dict)
            ]
    return summary


class ListIncidentsResult(PageOfResults):
    """Result from listing incidents."""

    incidents: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Incidents. Each one's secret and displayed_occurrence are summarized (validity, detector, "
        "source, file and lines); call get_internal_incident for an incident's full details.",
    )
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


async def list_internal_incidents(
    params: ListIncidentsParams = ListIncidentsParams(),
) -> ListIncidentsResult:
    """List secret incidents with enhanced filtering using the MCP-optimized endpoint.

    Args:
        params: ListIncidentsParams model containing all filtering options.
    """
    client = await get_client()

    assignee_id, conflict = await resolve_assignee(client, params)
    if conflict:
        raise ToolError(conflict)
    query = build_incident_query(params, assignee_id)
    page, page_size = _read_cursor(params.cursor) if params.cursor else (1, params.page_size)

    if not params.get_all:
        response = await client.list_incidents_for_mcp(query, page=page, page_size=page_size, ordering=params.ordering)
        incidents = [summarize_incident(incident) for incident in response.get("results", [])]
        has_more = response.get("next") is not None
        return _result(params, incidents, page_size, has_more, _cursor(page + 1, page_size) if has_more else None)

    # Fetch pages with a byte budget and a page cap, in pages small enough to stop near
    # the budget, starting at the same first incident the cursor's page starts at.
    get_all_size = _get_all_page_size(page_size)
    current_page = (page - 1) * page_size // get_all_size + 1
    all_incidents: list[dict[str, Any]] = []
    total_bytes = 0
    stopped_by: StopReason | None = None
    pages_fetched = 0

    while True:
        if pages_fetched >= MAX_PAGINATION_PAGES:
            logger.warning(f"get_all pagination stopped: reached max page limit ({MAX_PAGINATION_PAGES})")
            stopped_by = "page_limit"
            break

        response = await client.list_incidents_for_mcp(
            query, page=current_page, page_size=get_all_size, ordering=params.ordering
        )
        pages_fetched += 1
        page_incidents = [summarize_incident(incident) for incident in response.get("results", [])]
        if not page_incidents:
            break

        page_bytes = len(json.dumps(page_incidents))
        if total_bytes + page_bytes > DEFAULT_PAGINATION_MAX_BYTES and all_incidents:
            stopped_by = "size_budget"
            break

        all_incidents.extend(page_incidents)
        total_bytes += page_bytes
        if response.get("next") is None:
            break
        current_page += 1
        # The next page is not in the result yet: a stop from here resumes at it.

    has_more = stopped_by is not None
    next_cursor = _cursor(current_page, get_all_size) if has_more else None
    return _result(params, all_incidents, get_all_size, has_more, next_cursor, stopped_by)


def _result(
    params: ListIncidentsParams,
    incidents: list[dict[str, Any]],
    page_size: int,
    has_more: bool,
    next_cursor: str | None,
    stopped_by: StopReason | None = None,
) -> ListIncidentsResult:
    return ListIncidentsResult(
        incidents=incidents,
        page_size=page_size,
        has_more=has_more,
        stop_reason=stop_reason_of(has_more, params.get_all, stopped_by),
        next_arguments=next_arguments_for(params, next_cursor, page_size),
        applied_filters=build_filter_info(params),
        suggestion=_build_suggestion(params, len(incidents)),
    )
