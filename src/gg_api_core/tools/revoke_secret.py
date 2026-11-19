"""Tool that asks a secret's provider to revoke it."""

import logging

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import uncertain_write_error
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# What to do after a revocation request whose outcome is unknown.
_REVOKE_CHECK = (
    "GitGuardian refuses a second request for the same secret within an hour, and checks the secret's validity "
    "again after a revocation: read the incident's validity later to check"
)


class RevokeSecretParams(BaseModel):
    """Parameters for revoking a secret."""

    secret_id: NumericId = Field(description="ID of the secret: an incident's secret_id, not its incident ID")


class RevokeSecretResult(BaseModel):
    """What the provider did with the revocation request."""

    secret_id: int = Field(description="ID of the secret")
    success: bool = Field(description="Whether the revocation request was made to the provider")
    reason: str | None = Field(
        default=None,
        description="Why the request was not made, when success is false: no revoker for this detector, "
        "GitGuardian does not hold the value, a request was already made in the last hour, or the provider refused",
    )
    is_async: bool | None = Field(
        default=None, description="When success is true, whether the provider is still processing the revocation"
    )


async def revoke_secret(params: RevokeSecretParams) -> RevokeSecretResult:
    """Ask a secret's provider to revoke it, so that it can no longer be used."""
    client = await get_client()
    try:
        response = await client.revoke_secret(params.secret_id)
    except Exception as e:
        raise uncertain_write_error(e, _REVOKE_CHECK) or ToolError(str(e))
    return RevokeSecretResult(
        secret_id=params.secret_id,
        success=bool(response.get("success")),
        reason=response.get("reason"),
        is_async=response.get("is_async"),
    )
