from typing import Literal, Any

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client
import logging

logger = logging.getLogger(__name__)


class ManageIncidentParams(BaseModel):
    """Parameters for managing an incident."""
    incident_id: str | int = Field(description="ID of the secret incident to manage")
    action: Literal["assign", "unassign", "resolve", "ignore", "reopen"] = Field(
        description="Action to perform on the incident"
    )
    assignee_id: str | int | None = Field(
        default=None, description="ID of the member to assign the incident to (required for 'assign' action)"
    )
    ignore_reason: str | None = Field(
        default=None,
        description="Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)",
    )
    mine: bool = Field(default=False, description="If True, use the current user's ID for the assignee_id")


async def manage_incident(params: ManageIncidentParams) -> dict[str, Any]:
    """
    Manage a secret incident (assign, unassign, resolve, ignore, reopen).

    Args:
        params: ManageIncidentParams model containing incident management configuration

    Returns:
        Updated incident data
    """
    client = get_client()
    logger.debug(f"Managing incident {params.incident_id} with action: {params.action}")

    try:
        # Make the API call
        result = await client.manage_incident(
            incident_id=params.incident_id,
            action=params.action,
            assignee_id=params.assignee_id,
            ignore_reason=params.ignore_reason,
            mine=params.mine,
        )

        logger.debug(f"Managed incident {params.incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error managing incident: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


class UpdateIncidentStatusParams(BaseModel):
    """Parameters for updating incident status."""
    incident_id: str | int = Field(description="ID of the secret incident")
    status: str = Field(description="New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)")


async def update_incident_status(params: UpdateIncidentStatusParams) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.

    Args:
        params: UpdateIncidentStatusParams model containing status update configuration

    Returns:
        Updated incident data
    """
    client = get_client()
    logger.debug(f"Updating incident {params.incident_id} status to {params.status}")

    try:
        result = await client.update_incident_status(incident_id=params.incident_id, status=params.status)
        logger.debug(f"Updated incident {params.incident_id} status to {params.status}")
        return result
    except Exception as e:
        logger.error(f"Error updating incident status: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
