"""Tools that assign or unassign a secret incident, one tool per change and per kind."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import GitGuardianClient
from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import CHANGED_DESCRIPTION, IncidentKind, apply_or_confirm, incident_reader
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

ONE_ASSIGNEE = "Give exactly one of assignee_member_id, assignee_email or mine."


def _check_exactly_one_assignee(params: Any) -> None:
    given = sum([params.assignee_member_id is not None, params.assignee_email is not None, params.mine])
    if given != 1:
        raise ValueError("give exactly one of assignee_member_id, assignee_email or mine")


class AssignInternalIncidentParams(BaseModel):
    """Parameters for assigning an internal incident to one member."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    assignee_member_id: NumericId | None = Field(default=None, description=f"ID of the member. {ONE_ASSIGNEE}")
    assignee_email: str | None = Field(default=None, description=f"Email address of the member. {ONE_ASSIGNEE}")
    mine: bool = Field(default=False, description=f"Assign the incident to the current user. {ONE_ASSIGNEE}")

    @model_validator(mode="after")
    def check_exactly_one_assignee(self):
        """Require exactly one way of naming the assignee."""
        _check_exactly_one_assignee(self)
        return self


class AssignPublicIncidentParams(BaseModel):
    """Parameters for assigning a Public Monitoring incident to one member."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    assignee_member_id: NumericId | None = Field(default=None, description=f"ID of the member. {ONE_ASSIGNEE}")
    assignee_email: str | None = Field(default=None, description=f"Email address of the member. {ONE_ASSIGNEE}")
    mine: bool = Field(default=False, description=f"Assign the incident to the current user. {ONE_ASSIGNEE}")

    @model_validator(mode="after")
    def check_exactly_one_assignee(self):
        """Require exactly one way of naming the assignee."""
        _check_exactly_one_assignee(self)
        return self


class UnassignInternalIncidentParams(BaseModel):
    """Parameters for unassigning an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")


class UnassignPublicIncidentParams(BaseModel):
    """Parameters for unassigning a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")


class AssignmentResult(BaseModel):
    """The incident after its assignee changed."""

    incident_kind: IncidentKind = Field(description="Kind of the incident that changed: internal or public")
    incident_id: int = Field(description="ID of the incident that changed")
    action: Literal["assign", "unassign"] = Field(description="The change that was asked for")
    changed: bool = Field(description=CHANGED_DESCRIPTION)
    assignee_id: int | None = Field(description="ID of the member assigned now, or null when unassigned")
    incident: dict[str, Any] = Field(description="The incident as it is now")


def _result(
    kind: IncidentKind,
    incident_id: int,
    action: Literal["assign", "unassign"],
    incident_and_changed: tuple[dict[str, Any], bool],
) -> AssignmentResult:
    incident, changed = incident_and_changed
    return AssignmentResult(
        incident_kind=kind,
        incident_id=incident_id,
        action=action,
        changed=changed,
        assignee_id=incident.get("assignee_id"),
        incident=incident,
    )


async def _member_id_of_caller(client: GitGuardianClient) -> int:
    """The member ID the caller's token belongs to."""
    try:
        token_info = await client.get_current_token_info()
    except Exception as e:
        raise ToolError(str(e))
    member_id = (token_info or {}).get("member_id")
    if member_id is None:
        raise ToolError("This token is not tied to a workspace member, so 'mine' cannot assign the incident.")
    return int(member_id)


async def _assign(
    client: GitGuardianClient,
    kind: IncidentKind,
    assign: Callable[..., Awaitable[dict[str, Any]]],
    params: AssignInternalIncidentParams | AssignPublicIncidentParams,
) -> tuple[dict[str, Any], bool]:
    """Assign the incident to a member ID, an email or the caller, and say whether that changed it."""
    incident_id = str(params.incident_id)
    if params.assignee_email is not None:
        email = params.assignee_email.lower()
        call = _assign_by_email(assign, incident_id, params.assignee_email)

        def is_assigned(current: dict[str, Any]) -> bool:
            return (current.get("assignee_email") or "").lower() == email
    else:
        member_id = params.assignee_member_id or await _member_id_of_caller(client)
        call = assign(incident_id, assignee_id=str(member_id))

        def is_assigned(current: dict[str, Any]) -> bool:
            return current.get("assignee_id") == member_id

    return await apply_or_confirm(call, incident_reader(client, kind, params.incident_id), is_assigned)


async def _assign_by_email(
    assign: Callable[..., Awaitable[dict[str, Any]]], incident_id: str, email: str
) -> dict[str, Any]:
    """Assign by email, explaining the API's bare refusal of an address no member has."""
    try:
        return await assign(incident_id, email=email)
    except httpx.HTTPStatusError as e:
        # The API answers an email no member has with a bare "Invalid payload." The address is
        # not repeated here, so the failure log does not record it.
        if e.response.status_code == 400:
            raise ToolError(
                f"{e} This usually means no member of this workspace has that email address. Check it, or "
                "assign the incident by member ID; retrying with the same email will not help."
            ) from e
        raise


def _is_unassigned(current: dict[str, Any]) -> bool:
    return current.get("assignee_id") is None


async def assign_internal_incident(params: AssignInternalIncidentParams) -> AssignmentResult:
    """Assign an internal secret incident to one member."""
    client = await get_client()
    outcome = await _assign(client, "internal", client.assign_incident, params)
    return _result("internal", params.incident_id, "assign", outcome)


async def unassign_internal_incident(params: UnassignInternalIncidentParams) -> AssignmentResult:
    """Remove the assignee of an internal secret incident."""
    client = await get_client()
    outcome = await apply_or_confirm(
        client.unassign_incident(str(params.incident_id)),
        incident_reader(client, "internal", params.incident_id),
        _is_unassigned,
    )
    return _result("internal", params.incident_id, "unassign", outcome)


async def assign_public_incident(params: AssignPublicIncidentParams) -> AssignmentResult:
    """Assign a Public Monitoring incident to one member."""
    client = await get_client()
    outcome = await _assign(client, "public", client.assign_public_incident, params)
    return _result("public", params.incident_id, "assign", outcome)


async def unassign_public_incident(params: UnassignPublicIncidentParams) -> AssignmentResult:
    """Remove the assignee of a Public Monitoring incident."""
    client = await get_client()
    outcome = await apply_or_confirm(
        client.unassign_public_incident(str(params.incident_id)),
        incident_reader(client, "public", params.incident_id),
        _is_unassigned,
    )
    return _result("public", params.incident_id, "unassign", outcome)
