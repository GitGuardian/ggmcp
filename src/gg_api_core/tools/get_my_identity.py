"""Tool describing the caller: the member the token belongs to, and the token itself."""

import logging
from typing import Any

import httpx
from fastmcp.server.dependencies import get_server
from pydantic import BaseModel, Field

from gg_api_core.client import GitGuardianClient
from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

_TOKEN_FIELDS = ("name", "type", "status", "scopes", "created_at", "expire_at")
_MEMBER_FIELDS = ("id", "name", "email", "access_level", "active")


class GetMyIdentityResult(BaseModel):
    """Who the token belongs to, and what the token is."""

    workspace_id: int | None = Field(default=None, description="ID of the workspace the token belongs to")
    token: dict[str, Any] = Field(
        description="The token: name, type, status, scopes, created_at, and expire_at (null when it never expires)"
    )
    member: dict[str, Any] | None = Field(
        default=None,
        description="The workspace member the token belongs to: id, name, email, access_level (their role), and "
        "active. Null when it could not be read; member_unavailable_reason says why.",
    )
    member_unavailable_reason: str | None = Field(
        default=None, description="Why the member could not be read, when member is null"
    )


async def _token_info(client: GitGuardianClient) -> dict[str, Any]:
    """The token info the server caches for its scope checks, or a fresh lookup outside a server."""
    try:
        server = get_server()
    except RuntimeError:
        server = None
    if isinstance(server, AbstractGitGuardianFastMCP):
        return await server.get_token_info()
    return await client.get_current_token_info()


async def get_my_identity() -> GetMyIdentityResult:
    """Describe the caller: the workspace member the token belongs to, and the token's scopes and expiry."""
    client = await get_client()
    token_info = await _token_info(client)

    token = {field: token_info.get(field) for field in _TOKEN_FIELDS}
    workspace_id = token_info.get("workspace_id")
    result = GetMyIdentityResult(workspace_id=int(workspace_id) if workspace_id is not None else None, token=token)

    member_id = token_info.get("member_id")
    if member_id is None:
        result.member_unavailable_reason = (
            "This token is not tied to a workspace member, for example a service account."
        )
        return result

    try:
        member = await client.get_member(member_id)
    except httpx.HTTPStatusError as e:
        reason = f"The member could not be read: {e}"
        if e.response.status_code == 403:
            reason += " Reading it needs the members:read scope."
        result.member_unavailable_reason = reason
        return result

    result.member = {field: member.get(field) for field in _MEMBER_FIELDS}
    return result
