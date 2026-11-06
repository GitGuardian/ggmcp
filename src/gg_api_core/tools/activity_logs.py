"""Tools for listing the activity log of a secret incident.

An incident's activity log is the full, chronological record of everything that
happened to it: user notes (free-form comments) AND system actions (status
changes, assignments, severity edits, new locations detected, etc.). The public
API exposes it under ``.../activity-logs`` and each entry carries a ``content``
discriminated union — ``{"type": "note", "comment": ...}`` for a comment or
``{"type": "action", "content_key": ..., "data": ...}`` for a system action.

This is broader than the notes-only listing (``list_incident_comments``): use
the activity log to reconstruct an incident's full timeline. Internal incidents
and Public Monitoring incidents have separate, non-interchangeable activity
logs, so each perimeter gets its own dedicated tool — mirroring the split used
elsewhere (e.g. ``assign_incident`` vs ``assign_public_incident``).
"""

import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, ListResponse
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListActivityLogsParams(BaseModel):
    """Parameters for listing the activity log of a secret incident."""

    incident_id: int = Field(description="ID of the secret incident whose activity log to list")
    content_key: str | None = Field(
        default=None,
        description="Filter to a single system-action type (e.g. 'TRIGGER', 'RESOLVE', 'ASSIGN', 'SET_SEVERITY'). "
        "Omit to return notes and every action type.",
    )
    member_id: int | None = Field(
        default=None,
        description="Filter to entries authored by a specific member (by member ID)",
    )
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching the next page of results")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListActivityLogsResult(BaseModel):
    """Result from listing the activity log of a secret incident."""

    activity_logs: list[dict[str, Any]] = Field(
        description="List of activity log entries (notes and system actions) attached to the incident"
    )
    total_count: int = Field(description="Total number of entries returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")
    has_more: bool = Field(default=False, description="True if more results exist (use next_cursor to fetch)")


def _build_query_params(params: ListActivityLogsParams) -> dict[str, Any]:
    """Build the query parameters dict from the tool params, dropping unset filters."""
    query_params: dict[str, Any] = {"per_page": params.per_page}
    if params.cursor:
        query_params["cursor"] = params.cursor
    if params.content_key:
        query_params["content_key"] = params.content_key
    if params.member_id is not None:
        query_params["member_id"] = params.member_id
    return query_params


def _build_list_result(result: ListResponse) -> ListActivityLogsResult:
    """Adapt a client ListResponse into a ListActivityLogsResult."""
    return ListActivityLogsResult(
        activity_logs=result["data"],
        total_count=len(result["data"]),
        next_cursor=result["cursor"],
        has_more=result["has_more"],
    )


async def list_incident_activity_logs(params: ListActivityLogsParams) -> ListActivityLogsResult:
    """
    List the full activity log of an internal secret incident.

    Returns both user notes (comments) and system actions (status changes,
    assignments, severity edits, new locations detected, etc.) in one timeline.
    Use this to reconstruct what happened to an incident and when. To read only
    the comments use `list_incident_comments`; for Public Monitoring incidents
    use `list_public_incident_activity_logs` instead.

    Args:
        params: ListActivityLogsParams with the incident ID, optional filters and pagination options

    Returns:
        ListActivityLogsResult with the entries, total_count, next_cursor, and has_more

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug(f"Listing activity logs for incident {params.incident_id}")

    try:
        result = await client.list_incident_activity_logs(
            incident_id=params.incident_id,
            params=_build_query_params(params),
            get_all=params.get_all,
        )
        return _build_list_result(result)
    except Exception as e:
        logger.exception(f"Error listing activity logs for incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


async def list_public_incident_activity_logs(params: ListActivityLogsParams) -> ListActivityLogsResult:
    """
    List the full activity log of a public secret incident.

    Public incidents are surfaced by GitGuardian Public Monitoring (public GitHub
    repos/gists, Docker Hub, etc.). Returns both user notes (comments) and system
    actions (status changes, assignments, severity edits, etc.) in one timeline.
    To read only the comments use `list_public_incident_comments`; for internal
    incidents use `list_incident_activity_logs` instead. Public incident IDs are
    NOT interchangeable with internal incident IDs.

    Args:
        params: ListActivityLogsParams with the public incident ID, optional filters and pagination options

    Returns:
        ListActivityLogsResult with the entries, total_count, next_cursor, and has_more

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug(f"Listing activity logs for public incident {params.incident_id}")

    try:
        result = await client.list_public_incident_activity_logs(
            incident_id=params.incident_id,
            params=_build_query_params(params),
            get_all=params.get_all,
        )
        return _build_list_result(result)
    except Exception as e:
        logger.exception(f"Error listing activity logs for public incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
