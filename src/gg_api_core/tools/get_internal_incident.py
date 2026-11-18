import asyncio
import logging
from typing import Any

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import GitGuardianClient
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# Most incidents have a short history; this many entries keeps the result small.
HISTORY_LIMIT = 50


class GetIncidentParams(BaseModel):
    """Parameters for retrieving a specific incident."""

    incident_id: int = Field(description="The ID of the incident to retrieve")
    with_occurrences: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Number of occurrences to retrieve (0-100, default: 20)",
    )
    with_history: bool = Field(
        default=False,
        description="If True, also return the incident's history: its comments and its system actions, such as "
        f"status changes and assignments. The {HISTORY_LIMIT} most recent entries, newest first.",
    )


class IncidentHistory(BaseModel):
    """An incident's activity log, or why it could not be read."""

    entries: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Activity log entries, newest first. content.type 'note' is a comment; content.type 'action' "
        "is a system action, named by content.content_key (for example TRIGGER, ASSIGN, UNASSIGN, RESOLVE, "
        "UNRESOLVE, IGNORE, UNIGNORE).",
    )
    has_more: bool = Field(
        default=False,
        description=f"True when the incident has more than the {HISTORY_LIMIT} entries returned; the oldest are "
        "left out",
    )
    unavailable_reason: str | None = Field(
        default=None,
        description="Why the history could not be read. The incident itself is still returned.",
    )


class GetIncidentResult(BaseModel):
    """Result from retrieving a specific incident."""

    incident: dict[str, Any] = Field(description="Detailed incident data including occurrences")
    history: IncidentHistory | None = Field(
        default=None,
        exclude_if=lambda history: history is None,
        description="The incident's history, present only when with_history is True",
    )


async def _incident_history(client: GitGuardianClient, incident_id: int) -> IncidentHistory:
    """The incident's activity log, or the reason it could not be read.

    A 401 is raised, so that the client is asked to authenticate again; any other
    failure leaves the incident readable and is reported in unavailable_reason.
    """
    try:
        page = await client.list_incident_activity_logs(incident_id, per_page=HISTORY_LIMIT)
    except httpx.HTTPStatusError as e:
        return IncidentHistory(unavailable_reason=f"The history could not be read: {e}")
    except httpx.RequestError as e:
        return IncidentHistory(unavailable_reason=f"The history could not be read: {type(e).__name__}")
    return IncidentHistory(entries=page["data"], has_more=page["has_more"])


async def get_internal_incident(params: GetIncidentParams) -> GetIncidentResult:
    """Retrieve a specific secret incident by its ID.

    Args:
        params: GetIncidentParams model containing:
            - incident_id: The ID of the incident to retrieve
            - with_occurrences: Number of occurrences to include (0-100)
            - with_history: Whether to include the incident's activity log
    """
    client = await get_client()

    try:
        if not params.with_history:
            incident = await client.get_incident(
                incident_id=params.incident_id,
                with_occurrences=params.with_occurrences,
            )
            return GetIncidentResult(incident=incident)

        incident, history = await asyncio.gather(
            client.get_incident(incident_id=params.incident_id, with_occurrences=params.with_occurrences),
            _incident_history(client, params.incident_id),
        )
        return GetIncidentResult(incident=incident, history=history)
    except Exception as e:
        raise ToolError(str(e))
