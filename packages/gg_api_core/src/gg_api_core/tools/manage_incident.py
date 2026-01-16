import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ManageIncidentParams(BaseModel):
    """Parameters for managing an incident."""

    incident_id: str | int = Field(description="ID of the secret incident to manage")
    action: Literal["unassign", "resolve", "ignore", "reopen"] = Field(
        description="Action to perform on the incident: 'unassign' removes any assigned member, 'resolve' marks the incident as resolved, 'ignore' marks as ignored (use with ignore_reason), 'reopen' reopens a resolved or ignored incident"
    )
    ignore_reason: Literal["test_credential", "false_positive", "low_risk", "invalid"] | None = Field(
        default=None,
        description="Reason for ignoring the incident. Only used with 'ignore' action. Options: 'test_credential' (secret is for testing), 'false_positive' (not a real secret), 'low_risk' (secret poses minimal risk), 'invalid' (secret is invalid/inactive)",
    )


async def manage_private_incident(params: ManageIncidentParams) -> dict[str, Any]:
    """
    Perform lifecycle management actions on a secret incident.

    This tool allows you to change the state of a secret incident through various actions:
    - 'unassign': Remove the assigned member from an incident (useful when reassigning or leaving unassigned)
    - 'resolve': Mark an incident as resolved (typically after the secret has been rotated/revoked)
    - 'ignore': Mark an incident as ignored with a reason (test_credential, false_positive, low_risk, or invalid)
    - 'reopen': Reopen a previously resolved or ignored incident

    Note: To assign an incident to a member, use the dedicated 'assign_incident' tool instead.

    Args:
        params: ManageIncidentParams containing:
            - incident_id: The ID of the incident to manage
            - action: The lifecycle action to perform (unassign, resolve, ignore, or reopen)
            - ignore_reason: Required when action is 'ignore'. One of: test_credential, false_positive, low_risk, invalid

    Returns:
        Dictionary containing the updated incident data from the API

    Raises:
        ToolError: If the action fails or if an invalid action is provided
    """
    client = await get_client()
    logger.debug(f"Managing incident {params.incident_id} with action: {params.action}")

    try:
        # Route the action to the appropriate client method
        if params.action == "unassign":
            result = await client.unassign_incident(incident_id=str(params.incident_id))

        elif params.action == "resolve":
            result = await client.resolve_incident(incident_id=str(params.incident_id))

        elif params.action == "ignore":
            result = await client.ignore_incident(
                incident_id=str(params.incident_id), ignore_reason=params.ignore_reason
            )

        elif params.action == "reopen":
            result = await client.reopen_incident(incident_id=str(params.incident_id))

        else:
            raise ToolError(f"Unknown action: {params.action}")

        logger.debug(f"Successfully managed incident {params.incident_id} with action: {params.action}")
        return result
    except ToolError:
        raise
    except Exception as e:
        logger.exception(f"Error managing incident: {str(e)}")
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
    client = await get_client()
    logger.debug(f"Updating incident {params.incident_id} status to {params.status}")

    try:
        result = await client.update_incident(incident_id=str(params.incident_id), status=params.status)
        logger.debug(f"Updated incident {params.incident_id} status to {params.status}")
        return result
    except Exception as e:
        logger.exception(f"Error updating incident status: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
