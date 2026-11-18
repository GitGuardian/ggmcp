"""Open a GitGuardian incident from a pasted link or a bare incident ID."""

import asyncio
import re
from typing import Any, Literal
from urllib.parse import SplitResult, urlsplit

import httpx
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_server
from pydantic import BaseModel, Field, model_validator
from pydantic_core import PydanticCustomError

from gg_api_core.client import DownstreamUnauthorizedError, GitGuardianClient
from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.settings import get_settings
from gg_api_core.urls import derive_public_api_url
from gg_api_core.utils import get_client

ResourceType = Literal["internal_incident", "public_incident"]

# ASCII digits only: Python's int() also accepts other scripts' digits, which no ID uses.
_INCIDENT_ID = r"[0-9]{1,20}"

# Dashboard pages that list or search instead of showing one incident, and where to go instead.
_LIST_PAGE_GUIDANCE = {
    "incidents": (
        "This GitGuardian link is the internal incidents list, not one incident. Use list_internal_incidents or "
        "count_internal_incidents with filters, or pass the link of a single incident."
    ),
    "public-incidents": (
        "This GitGuardian link is the public incidents list, not one incident. Use list_public_incidents "
        "with filters, or pass the link of a single public incident."
    ),
    "honeytokens": (
        "This GitGuardian link is a honeytoken page. This server cannot read honeytokens; it can create "
        "one with generate_honeytoken. Open existing honeytokens in the dashboard."
    ),
}


class GetGitGuardianResourceParams(BaseModel):
    """Parameters for opening an incident from a link or a bare ID."""

    url: str | None = Field(
        default=None,
        min_length=1,
        max_length=8192,
        description="GitGuardian dashboard incident link (internal or public) or public API incident URL "
        "for this server's instance.",
    )
    incident_id: int | None = Field(
        default=None,
        ge=1,
        description="An incident ID given without saying whether it is internal or public. Both kinds are "
        "looked up, and the result says which one matched.",
    )
    with_occurrences: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Number of occurrences to include for internal incidents (0-100). Unused for public incidents.",
    )

    @model_validator(mode="after")
    def _one_input(self) -> "GetGitGuardianResourceParams":
        if (self.url is None) == (self.incident_id is None):
            # A custom error, so the message reaches the agent without pydantic's "Value error, " prefix.
            raise PydanticCustomError("one_input", "Provide exactly one of url or incident_id.")
        return self


class GetGitGuardianResourceResult(BaseModel):
    """The incident, which kind it is, and the identifiers it was found by."""

    resource_type: ResourceType
    incident_id: int
    workspace_id: int | None = Field(description="Workspace ID from a dashboard link; null for API URLs and bare IDs.")
    url: str | None = Field(
        description="The link without its query string and fragment, or, for a bare ID, the incident's "
        "dashboard link when the API returns one."
    )
    incident: dict[str, Any]


def _origin(url: SplitResult) -> tuple[str, str | None, int | None]:
    """Compare origins with explicit and implicit default ports treated equally."""
    port = url.port if url.port is not None else {"https": 443, "http": 80}.get(url.scheme)
    return url.scheme, url.hostname, port


def _parse_resource_url(url: str) -> tuple[ResourceType, int, int | None, str]:
    """Accept only detail paths on the configured dashboard and API origins."""
    settings = get_settings()
    dashboard = urlsplit(settings.gitguardian_url)
    api = urlsplit(derive_public_api_url(settings.gitguardian_url))
    value = url
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(character.isspace() or ord(character) < 32 for character in value)
            or "\\" in value
        ):
            raise ValueError
        origin = _origin(parsed)
    except ValueError:
        raise ToolError("Provide a valid absolute GitGuardian HTTP(S) URL without credentials.") from None

    if origin not in {_origin(dashboard), _origin(api)}:
        raise ToolError(
            "This URL belongs to a different instance. Use the MCP server configured for that GitGuardian instance."
        )

    match = None
    if origin == _origin(dashboard):
        dashboard_prefix = re.escape(dashboard.path.rstrip("/"))
        match = re.fullmatch(
            dashboard_prefix
            + rf"/workspace/(?P<workspace_id>{_INCIDENT_ID})/(?P<kind>incidents|public-incidents)/(?P<incident_id>{_INCIDENT_ID})/?",
            parsed.path,
        )
        if match is None:
            page = re.fullmatch(
                dashboard_prefix
                + rf"/workspace/{_INCIDENT_ID}/(?:(?P<list>incidents|public-incidents)|(?P<honeytokens>honeytokens)(?:/[^/]+)?)/?",
                parsed.path,
            )
            if page is not None:
                raise ToolError(_LIST_PAGE_GUIDANCE[page["list"] or page["honeytokens"]])
    if match is None and origin == _origin(api):
        match = re.fullmatch(
            re.escape(api.path.rstrip("/"))
            + rf"/(?P<kind>incidents|public-incidents)/secrets/(?P<incident_id>{_INCIDENT_ID})/?",
            parsed.path,
        )
    if match is None:
        raise ToolError(
            "Unsupported GitGuardian URL. Provide /workspace/{workspace_id}/incidents/{incident_id}, "
            "/workspace/{workspace_id}/public-incidents/{incident_id}, or a public API incident detail URL. "
            "Share links contain a token; use the authenticated dashboard incident URL."
        )

    resource_type: ResourceType = "public_incident" if match["kind"] == "public-incidents" else "internal_incident"
    workspace = match.groupdict().get("workspace_id")
    return (
        resource_type,
        int(match["incident_id"]),
        int(workspace) if workspace is not None else None,
        parsed._replace(query="", fragment="").geturl(),
    )


async def _token_workspace_id(client: GitGuardianClient) -> int | None:
    """The caller's workspace, from the token info the server caches for its scope checks.

    The scope check has already looked the token up for this call, so reading
    the server's cache adds no API request. Outside a running server, the
    client fetches the token info itself.
    """
    try:
        server = get_server()
    except RuntimeError:
        server = None
    if isinstance(server, AbstractGitGuardianFastMCP):
        token_info = await server.get_token_info()
    else:
        token_info = await client.get_current_token_info()
    workspace_id = (token_info or {}).get("workspace_id")
    return int(workspace_id) if workspace_id is not None else None


def _status(outcome: object) -> int | None:
    return outcome.response.status_code if isinstance(outcome, httpx.HTTPStatusError) else None


async def _resolve_bare_id(
    client: GitGuardianClient, incident_id: int, with_occurrences: int
) -> tuple[ResourceType, dict[str, Any]]:
    """Look an ID up as an internal and as a public incident, which are separate number spaces."""
    internal, public = await asyncio.gather(
        client.get_incident(incident_id=incident_id, with_occurrences=with_occurrences),
        client.get_public_incident(incident_id=incident_id),
        return_exceptions=True,
    )
    for outcome in (internal, public):
        if isinstance(outcome, DownstreamUnauthorizedError):
            # Keeps the 401 as the cause, so the client is asked to sign in again.
            raise ToolError(str(outcome)) from outcome

    # A side counts as absent only on a clean "not there": a 404, or for public incidents
    # a 403, which means the workspace has no Public Monitoring. A match on one side is
    # returned only when the other side is absent, so a failed lookup never hides a second match.
    internal_absent = _status(internal) == 404
    public_absent = _status(public) in (403, 404)
    if isinstance(internal, dict) and isinstance(public, dict):
        raise ToolError(
            f"Incident ID {incident_id} exists both as an internal incident and as a public incident, and they "
            "are different incidents. Ask the user which one they mean, then call get_internal_incident or "
            "get_public_incident, or pass the incident's dashboard link."
        )
    if isinstance(internal, dict) and public_absent:
        return "internal_incident", internal
    if isinstance(public, dict) and internal_absent:
        return "public_incident", public
    if internal_absent and public_absent:
        public_note = (
            "nor a public incident with that ID."
            if _status(public) == 404
            else "and public incidents could not be checked: Public Monitoring is likely not enabled for this workspace."
        )
        raise ToolError(
            f"No incident {incident_id} is visible to this token: there is no internal incident with that ID that "
            f"this token can see (it may not exist, or sit outside your teams), {public_note} Retrying will not help."
        )
    # A lookup failed for another reason, such as a 5xx after retries: report that failure.
    failure = internal if isinstance(internal, BaseException) and not internal_absent else public
    if isinstance(failure, BaseException):
        raise ToolError(str(failure)) from failure
    raise ToolError(f"Incident {incident_id} could not be looked up.")


def _dashboard_link(incident: dict[str, Any]) -> str | None:
    link = incident.get("gitguardian_url")
    return link if isinstance(link, str) else None


async def get_gitguardian_resource(params: GetGitGuardianResourceParams) -> GetGitGuardianResourceResult:
    """Open an incident from a link or a bare ID, working out whether it is internal or public.

    Args:
        params: A link or an incident ID, and the internal incident occurrence limit.
    """
    incident_id = params.incident_id
    url = params.url
    # A bare ID pasted where a link was expected.
    if url is not None and re.fullmatch(_INCIDENT_ID, url.strip()):
        incident_id, url = int(url.strip()), None

    client = await get_client()
    if url is None and incident_id is not None:
        resource_type, incident = await _resolve_bare_id(client, incident_id, params.with_occurrences)
        return GetGitGuardianResourceResult(
            resource_type=resource_type,
            incident_id=incident_id,
            workspace_id=None,
            url=_dashboard_link(incident),
            incident=incident,
        )
    if url is None:
        raise ToolError("Provide exactly one of url or incident_id.")

    resource_type, incident_id, workspace_id, url = _parse_resource_url(url)
    if workspace_id is not None:
        token_workspace_id = await _token_workspace_id(client)
        # Incident IDs are unique across workspaces, so without a workspace on the token
        # the API itself refuses an incident from another workspace.
        if token_workspace_id is not None and token_workspace_id != workspace_id:
            raise ToolError(
                f"This link is for workspace {workspace_id}, but this token belongs to workspace "
                f"{token_workspace_id}. Authenticate with a token for workspace {workspace_id}."
            )
    try:
        if resource_type == "public_incident":
            incident = await client.get_public_incident(incident_id=incident_id)
        else:
            incident = await client.get_incident(incident_id=incident_id, with_occurrences=params.with_occurrences)
    except Exception as exc:
        raise ToolError(str(exc)) from exc

    return GetGitGuardianResourceResult(
        resource_type=resource_type,
        incident_id=incident_id,
        workspace_id=workspace_id,
        url=url,
        incident=incident,
    )
