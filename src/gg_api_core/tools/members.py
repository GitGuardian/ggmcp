"""Tools that read the workspace's members, and who can see an internal incident."""

import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PageOfResults,
    page_fields,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

AccessLevel = Literal["owner", "manager", "member", "restricted"]


class ListMembersParams(BaseModel):
    """Parameters for listing the workspace's members."""

    search: str | None = Field(default=None, description="Only the members whose name or email contains this text")
    access_level: AccessLevel | None = Field(default=None, description="Only the members with this role")
    active: bool | None = Field(default=None, description="True for active members only, False for inactive ones")
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListMembersResult(PageOfResults):
    """Workspace members."""

    members: list[dict[str, Any]] = Field(description="Members, each with its id, name, email, access_level and active")


async def list_members(params: ListMembersParams = ListMembersParams()) -> ListMembersResult:
    """List the workspace's members."""
    client = await get_client()
    try:
        response = await client.list_members(
            search=params.search,
            access_level=params.access_level,
            active=params.active,
            per_page=params.page_size,
            cursor=params.cursor,
            get_all=params.get_all,
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListMembersResult(members=response["data"], **page_fields(params, response))


class GetMemberParams(BaseModel):
    """Parameters for reading one member."""

    member_id: NumericId = Field(description="ID of the member, such as an incident's assignee_id")


class GetMemberResult(BaseModel):
    """One workspace member."""

    member: dict[str, Any] = Field(description="The member: id, name, email, access_level and active")


async def get_member(params: GetMemberParams) -> GetMemberResult:
    """Read one workspace member."""
    client = await get_client()
    try:
        member = await client.get_member(params.member_id)
    except Exception as e:
        raise ToolError(str(e))
    return GetMemberResult(member=member)


class ListInternalIncidentMembersParams(BaseModel):
    """Parameters for listing who can see an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    search: str | None = Field(default=None, description="Only the members whose name or email contains this text")
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListInternalIncidentMembersResult(PageOfResults):
    """The members who can see an internal incident."""

    members: list[dict[str, Any]] = Field(description="Members, each with its permission on the incident")


async def list_internal_incident_members(
    params: ListInternalIncidentMembersParams,
) -> ListInternalIncidentMembersResult:
    """List the members who can see an internal incident, with their permission on it."""
    client = await get_client()
    try:
        response = await client.list_incident_members(
            params.incident_id,
            search=params.search,
            per_page=params.page_size,
            cursor=params.cursor,
            get_all=params.get_all,
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListInternalIncidentMembersResult(members=response["data"], **page_fields(params, response))


class ListInternalIncidentTeamsParams(BaseModel):
    """Parameters for listing the teams that can see an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListInternalIncidentTeamsResult(PageOfResults):
    """The teams that can see an internal incident."""

    teams: list[dict[str, Any]] = Field(description="Teams, each with its permission on the incident")


async def list_internal_incident_teams(params: ListInternalIncidentTeamsParams) -> ListInternalIncidentTeamsResult:
    """List the teams that can see an internal incident, with their permission on it."""
    client = await get_client()
    try:
        response = await client.list_incident_teams(
            params.incident_id, per_page=params.page_size, cursor=params.cursor, get_all=params.get_all
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListInternalIncidentTeamsResult(teams=response["data"], **page_fields(params, response))
