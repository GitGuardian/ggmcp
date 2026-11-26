"""Create an external sharing link for a Public Monitoring incident."""

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import uncertain_write_error
from gg_api_core.utils import get_client


class CreatePublicIncidentShareLinkParams(BaseModel):
    """The incident and the permissions granted to anyone holding the link."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident to share")
    feedback_collection: bool = Field(
        default=False, description="Allow anyone holding the link to submit feedback on the incident"
    )
    auto_healing: bool = Field(
        default=False, description="Allow anyone holding the link to resolve or ignore the incident"
    )
    lifespan: int = Field(
        default=0,
        ge=0,
        description="Link lifespan in hours. Zero uses the workspace's default sharing duration.",
    )
    privacy_mode: bool = Field(
        default=False,
        description=(
            "Send the request in privacy mode. The link is returned either way. When false, the server never "
            "logs the response and follows no redirect; when true, the response can appear in its debug log."
        ),
    )


class CreatePublicIncidentShareLinkResult(BaseModel):
    """The link, its expiration and the permissions granted to its holders."""

    incident_id: int = Field(description="ID of the shared Public Monitoring incident")
    share_url: str = Field(description="Shareable URL. Anyone holding this link can access the shared incident.")
    expire_at: str | None = Field(
        default=None, description="Link expiration time in ISO-8601 format, or null when absent"
    )
    feedback_collection: bool = Field(description="Whether link holders can submit feedback")
    auto_healing: bool = Field(description="Whether link holders can resolve or ignore the incident")


async def create_public_incident_share_link(
    params: CreatePublicIncidentShareLinkParams,
) -> CreatePublicIncidentShareLinkResult:
    """Create a link granting external access to a public secret incident."""
    client = await get_client()
    try:
        response = await client.create_public_incident_share_link(
            params.incident_id,
            feedback_collection=params.feedback_collection,
            auto_healing=params.auto_healing,
            lifespan=params.lifespan,
            privacy_mode=params.privacy_mode,
        )
    except Exception as e:
        raise uncertain_write_error(
            e, "Check the incident's sharing settings in the GitGuardian dashboard"
        ) or ToolError(str(e))
    # The URL already contains the access token; return only the fields clients need.
    return CreatePublicIncidentShareLinkResult.model_validate(response)
