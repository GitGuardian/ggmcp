import json
import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, MAX_PAGINATION_PAGES
from gg_api_core.tools.incident_filters import (
    DEFAULT_STATUSES,
    IncidentFilters,
    build_filter_info,
    build_incident_query,
    resolve_assignee,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# get_all fetches pages this small: about 16 KB of summaries each, so it stops near its size
# budget instead of returning one oversized page whole, and page + 1 at this page size
# resumes exactly where its result stops.
GET_ALL_PAGE_SIZE = 5


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
    """Pagination fields, declared first so list_incidents' schema lists them first."""

    page: int = Field(default=1, description="Page number (1-indexed)", ge=1)
    page_size: int = Field(
        default=20,
        description="Number of results per page (default: 20, max: 100)",
        ge=1,
        le=100,
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch pages of up to {GET_ALL_PAGE_SIZE} incidents, starting where page starts, until about "
        f"{DEFAULT_PAGINATION_MAX_BYTES // 1000} KB of results. When has_more is true, call again with page + 1 "
        "and the page_size returned.",
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
    )


class ListIncidentsParams(IncidentFilters, _Pagination):
    """Parameters for listing incidents using the MCP-optimized endpoint."""

    status: list[str] | None = Field(
        default=DEFAULT_STATUSES,
        description="Filter by status. Values: TRIGGERED (unassigned active), ASSIGNED (assigned active), RESOLVED, IGNORED. Default excludes IGNORED. Note that OPENED is not a valid status but means 'TRIGGERED OR ASSIGNED'.",
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
# incidents outgrows what clients accept as tool output. get_incident gives an incident's full details.
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


class ListIncidentsResult(BaseModel):
    """Result from listing incidents."""

    incidents: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Incidents. Each one's secret and displayed_occurrence are summarized (validity, detector, "
        "source, file and lines); call get_incident for an incident's full details.",
    )
    page: int = Field(
        description="Current page number. With get_all=True, the last page whose incidents are included: "
        "when has_more is true, continue with page + 1."
    )
    page_size: int = Field(
        description=f"Number of results per page. With get_all=True, at most {GET_ALL_PAGE_SIZE}, whatever was "
        "requested: continue with this page_size."
    )
    has_next: bool = Field(default=False, description="True if there are more pages available")
    has_previous: bool = Field(default=False, description="True if there are previous pages")
    has_more: bool = Field(
        default=False,
        description="True if more incidents match than this result holds: continue with page + 1 and the "
        "page_size returned.",
    )
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


# Stays in the tool's return type so its output schema, and the result wrapper
# that schema implies, are unchanged. The tool raises instead of returning it.
class ListIncidentsError(BaseModel):
    """Error result from listing incidents."""

    error: str = Field(description="Error message")


async def list_incidents(
    params: ListIncidentsParams = ListIncidentsParams(),
) -> ListIncidentsResult | ListIncidentsError:
    """List secret incidents with enhanced filtering using the MCP-optimized endpoint.

    Args:
        params: ListIncidentsParams model containing all filtering options.
    """
    client = await get_client()

    assignee_id, conflict = await resolve_assignee(client, params)
    if conflict:
        raise ToolError(conflict)
    query = build_incident_query(params, assignee_id)

    if params.get_all:
        # Fetch pages from params.page with a byte budget and a page cap.
        page_size = _get_all_page_size(params.page_size)
        # The same first incident the requested page starts at, in pages of page_size.
        start_page = (params.page - 1) * params.page_size // page_size + 1
        all_incidents: list[dict[str, Any]] = []
        current_page = start_page
        # Last page whose incidents are in the result. Pages dropped by the size or
        # page cap are not, so a caller resuming at last_included_page + 1 sees them.
        last_included_page = 0
        total_bytes = 0
        has_more = False
        pages_fetched = 0

        while True:
            if pages_fetched >= MAX_PAGINATION_PAGES:
                logger.warning(f"get_all pagination stopped: reached max page limit ({MAX_PAGINATION_PAGES})")
                has_more = True
                break

            response = await client.list_incidents_for_mcp(
                query, page=current_page, page_size=page_size, ordering=params.ordering
            )
            pages_fetched += 1

            page_incidents = [summarize_incident(incident) for incident in response.get("results", [])]
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
            last_included_page = current_page

            if not has_next_page:
                break

            current_page += 1

        return ListIncidentsResult(
            incidents=all_incidents,
            page=last_included_page or start_page,
            page_size=page_size,
            has_next=has_more,
            has_previous=params.page > 1,
            has_more=has_more,
            applied_filters=build_filter_info(params),
            suggestion=_build_suggestion(params, len(all_incidents)),
        )
    else:
        # Single page request
        response = await client.list_incidents_for_mcp(
            query, page=params.page, page_size=params.page_size, ordering=params.ordering
        )

        # Parse the response
        incidents_data = [summarize_incident(incident) for incident in response.get("results", [])]
        has_next = response.get("next") is not None
        has_previous = response.get("previous") is not None

        return ListIncidentsResult(
            incidents=incidents_data,
            page=params.page,
            page_size=params.page_size,
            has_next=has_next,
            has_previous=has_previous,
            # Same meaning as in the other list tools: more incidents match.
            has_more=has_next,
            applied_filters=build_filter_info(params),
            suggestion=_build_suggestion(params, len(incidents_data)),
        )
