import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


PublicResolveReason = Literal["revoked", "dmca_request", "source_deleted"]
PublicIgnoreReason = Literal[
    "test_credential",
    "false_positive",
    "low_risk",
    "invalid",
    "ignore_actor",
    "ignore_secret",
]


class UpdatePublicIncidentStatusParams(BaseModel):
    """Parameters for updating a public secret incident status."""

    incident_id: int = Field(description="ID of the public secret incident to update")
    action: Literal["resolve", "ignore", "reopen"] = Field(
        description="Action to perform on the public incident: 'resolve' marks the incident "
        "as resolved (use with resolve_reason), 'ignore' marks as ignored (use with "
        "ignore_reason), 'reopen' reopens a previously resolved or ignored incident"
    )
    resolve_reason: PublicResolveReason | None = Field(
        default=None,
        description="Reason for resolving the public incident. Required when action is "
        "'resolve'. Must be explicitly provided by the user. Options: 'revoked' (the secret "
        "has been revoked/rotated), 'dmca_request' (resolved via DMCA takedown), "
        "'source_deleted' (the public source hosting the secret has been deleted)",
    )
    ignore_reason: PublicIgnoreReason | None = Field(
        default=None,
        description="Reason for ignoring the public incident. Required when action is "
        "'ignore'. Must be explicitly provided by the user. Options: 'test_credential' "
        "(secret is for testing), 'false_positive' (not a real secret), 'low_risk' (secret "
        "poses minimal risk), 'invalid' (secret is invalid/inactive), 'ignore_actor' "
        "(ignore based on the leaking actor), 'ignore_secret' (ignore this specific secret)",
    )


async def update_public_incident_status(params: UpdatePublicIncidentStatusParams) -> dict[str, Any]:
    """
    Update the status of a public secret incident detected by GitGuardian Public Monitoring.

    Public incidents are surfaced by GitGuardian Public Monitoring (public GitHub repos/gists,
    Docker Hub, etc.). Public incident IDs are NOT interchangeable with internal incident IDs;
    use this tool — not `manage_private_incident` / `update_incident_status` — when acting on
    results from `list_public_incidents` or `get_public_incident`.

    Supported actions:
    - 'resolve': Mark the public incident as resolved. Requires resolve_reason.
      Valid reasons: revoked, dmca_request, source_deleted.
    - 'ignore': Mark the public incident as ignored. Requires ignore_reason.
      Valid reasons: test_credential, false_positive, low_risk, invalid, ignore_actor,
      ignore_secret.
    - 'reopen': Reopen a previously resolved or ignored public incident.

    Note: To assign a public incident to a member, use `assign_public_incident` instead.

    Args:
        params: UpdatePublicIncidentStatusParams containing:
            - incident_id: ID of the public incident to update
            - action: The action to perform (resolve, ignore, or reopen)
            - resolve_reason: Required when action is 'resolve'
            - ignore_reason: Required when action is 'ignore'

    Returns:
        Dictionary containing the updated public incident data from the API

    Raises:
        ToolError: If the action fails or required parameters are missing
    """
    client = await get_client()
    logger.debug(f"Updating public incident {params.incident_id} status with action: {params.action}")

    try:
        if params.action == "resolve":
            if params.resolve_reason is None:
                raise ToolError(
                    "The 'resolve_reason' parameter is required when resolving a public incident. "
                    "Please ask the user why this incident should be resolved. "
                    "Valid reasons: 'revoked' (secret has been revoked/rotated), "
                    "'dmca_request' (resolved via DMCA takedown), "
                    "'source_deleted' (the public source has been deleted)."
                )
            result = await client.resolve_public_incident(
                incident_id=params.incident_id,
                resolve_reason=params.resolve_reason,
            )

        elif params.action == "ignore":
            if params.ignore_reason is None:
                raise ToolError(
                    "The 'ignore_reason' parameter is required when ignoring a public incident. "
                    "Please ask the user why this incident should be ignored. "
                    "Valid reasons: 'test_credential' (secret is for testing), "
                    "'false_positive' (not a real secret), 'low_risk' (secret poses minimal risk), "
                    "'invalid' (secret is invalid/inactive), 'ignore_actor' (ignore based on "
                    "leaking actor), 'ignore_secret' (ignore this specific secret)."
                )
            result = await client.ignore_public_incident(
                incident_id=params.incident_id,
                ignore_reason=params.ignore_reason,
            )

        elif params.action == "reopen":
            result = await client.reopen_public_incident(incident_id=params.incident_id)

        else:
            raise ToolError(f"Unknown action: {params.action}")

        logger.debug(f"Successfully updated public incident {params.incident_id} status with action: {params.action}")
        return result
    except ToolError:
        raise
    except Exception as e:
        logger.exception(f"Error updating public incident status: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
