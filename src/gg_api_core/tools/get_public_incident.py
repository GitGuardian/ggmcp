import asyncio
import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.get_internal_incident import HISTORY_LIMIT, IncidentHistory, incident_history
from gg_api_core.tools.ids import NumericId
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GetPublicIncidentParams(BaseModel):
    """Parameters for retrieving a public secret incident."""

    incident_id: NumericId = Field(description="The id of the public secret incident to retrieve")
    with_history: bool = Field(
        default=False,
        description="If True, also return the incident's history: its comments and its system actions, such as "
        f"status changes and assignments. The {HISTORY_LIMIT} most recent entries, newest first.",
    )


class GetPublicIncidentResult(BaseModel):
    """Result from retrieving a public secret incident."""

    incident: dict[str, Any] = Field(description="Detailed public incident data")
    history: IncidentHistory | None = Field(
        default=None,
        exclude_if=lambda history: history is None,
        description="The incident's history, present only when with_history is True",
    )


async def get_public_incident(params: GetPublicIncidentParams) -> GetPublicIncidentResult:
    """Retrieve a single public secret incident detected by GitGuardian Public Monitoring.

    Args:
        params: GetPublicIncidentParams model containing the incident_id and with_history.
    """
    client = await get_client()

    try:
        if not params.with_history:
            return GetPublicIncidentResult(incident=await client.get_public_incident(incident_id=params.incident_id))
        incident, history = await asyncio.gather(
            client.get_public_incident(incident_id=params.incident_id),
            incident_history(
                lambda: client.list_public_incident_activity_logs(params.incident_id, per_page=HISTORY_LIMIT)
            ),
        )
        return GetPublicIncidentResult(incident=incident, history=history)
    except Exception as e:
        raise ToolError(str(e))
