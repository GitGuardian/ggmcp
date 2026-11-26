"""Revoke the external sharing link of a Public Monitoring incident."""

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import uncertain_write_error
from gg_api_core.utils import get_client


class RevokePublicIncidentShareLinkParams(BaseModel):
    """The incident whose share link is revoked."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident to stop sharing")


class RevokePublicIncidentShareLinkResult(BaseModel):
    """Whether a link was revoked."""

    incident_id: int = Field(description="ID of the Public Monitoring incident")
    changed: bool = Field(description="False when the incident had no active share link, so nothing changed")


async def revoke_public_incident_share_link(
    params: RevokePublicIncidentShareLinkParams,
) -> RevokePublicIncidentShareLinkResult:
    """Revoke the link granting external access to a public secret incident."""
    client = await get_client()
    try:
        await client.revoke_public_incident_share_link(params.incident_id)
    except Exception as e:
        # The API answers 409 only when the incident has no active link.
        if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 409:
            return RevokePublicIncidentShareLinkResult(incident_id=params.incident_id, changed=False)
        raise uncertain_write_error(
            e, "Check the incident's sharing settings in the GitGuardian dashboard"
        ) or ToolError(str(e))
    return RevokePublicIncidentShareLinkResult(incident_id=params.incident_id, changed=True)
