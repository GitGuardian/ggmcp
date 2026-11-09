import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GetIncidentParams(BaseModel):
    """Parameters for retrieving a specific incident."""

    incident_id: int = Field(description="The ID of the incident to retrieve")
    with_occurrences: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Number of occurrences to retrieve (0-100, default: 20)",
    )


class GetIncidentResult(BaseModel):
    """Result from retrieving a specific incident."""

    incident: dict[str, Any] = Field(description="Detailed incident data including occurrences")


async def get_incident(params: GetIncidentParams) -> GetIncidentResult:
    """Retrieve a specific secret incident by its ID.

    Args:
        params: GetIncidentParams model containing:
            - incident_id: The ID of the incident to retrieve
            - with_occurrences: Number of occurrences to include (0-100)
    """
    client = await get_client()

    try:
        response = await client.get_incident(
            incident_id=params.incident_id,
            with_occurrences=params.with_occurrences,
        )

        return GetIncidentResult(incident=response)
    except Exception as e:
        logger.exception(f"Error retrieving incident {params.incident_id}: {str(e)}")
        raise ToolError(str(e))
