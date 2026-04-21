import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GetPublicIncidentParams(BaseModel):
    """Parameters for retrieving a public secret incident."""

    incident_id: int = Field(description="The id of the public secret incident to retrieve")


class GetPublicIncidentResult(BaseModel):
    """Result from retrieving a public secret incident."""

    incident: dict[str, Any] = Field(description="Detailed public incident data")


async def get_public_incident(params: GetPublicIncidentParams) -> GetPublicIncidentResult:
    """Retrieve a single public secret incident detected by GitGuardian Public Monitoring.

    Public incidents live on public sources (public GitHub repos/gists, Docker Hub, etc.) and
    have their own id namespace — incident ids are NOT interchangeable with internal incident
    ids. Use this tool instead of `get_incident` when drilling into a leak surfaced by
    `list_public_incidents`.

    Wraps GET /v1/public-incidents/secrets/{incident_id}.

    Args:
        params: GetPublicIncidentParams model containing the incident_id.

    Returns:
        GetPublicIncidentResult: Pydantic model containing:
            - incident: Detailed public incident data (detector, status, severity, validity,
              risk_score, tags, custom_tags, timestamps, assignee, share_url, etc.)

    Raises:
        ToolError: If the retrieval operation fails (e.g. unknown id, API error).
    """
    client = await get_client()
    logger.debug(f"Retrieving public incident {params.incident_id}")

    try:
        response = await client.get_public_incident(incident_id=params.incident_id)
        return GetPublicIncidentResult(incident=response)
    except Exception as e:
        logger.exception(f"Error retrieving public incident {params.incident_id}: {str(e)}")
        raise ToolError(str(e))
