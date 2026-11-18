import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import PathId
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ManageIncidentParams(BaseModel):
    """Parameters for managing an incident."""

    incident_id: PathId = Field(description="ID of the secret incident to manage")
    action: Literal["unassign"] = Field(description="Action to perform: 'unassign' removes any assigned member")


async def manage_private_incident(params: ManageIncidentParams) -> dict[str, Any]:
    """Unassign an internal secret incident.

    Args:
        params: ManageIncidentParams containing:
            - incident_id: The ID of the incident to manage
            - action: 'unassign'
    """
    client = await get_client()

    try:
        return await client.unassign_incident(incident_id=str(params.incident_id))
    except Exception as e:
        raise ToolError(f"Error: {str(e)}")
