"""Tools that resolve, ignore or reopen a secret incident, one tool per change and per kind."""

import logging
from collections.abc import Awaitable
from typing import Any, Literal

from pydantic import BaseModel, Field

from gg_api_core.client import GitGuardianClient
from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import (
    CHANGED_DESCRIPTION,
    IncidentKind,
    apply_or_confirm,
    check_advice,
    incident_reader,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

StatusChange = Literal["resolve", "ignore", "reopen"]
# What the incident's status is once each change is made.
_STATUSES_AFTER = {"resolve": {"RESOLVED"}, "ignore": {"IGNORED"}, "reopen": {"TRIGGERED", "ASSIGNED"}}


class ResolveInternalIncidentParams(BaseModel):
    """Parameters for resolving an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    secret_revoked: bool = Field(
        description="Whether the secret was revoked or rotated. Must come from the user: ask, do not assume."
    )


class IgnoreInternalIncidentParams(BaseModel):
    """Parameters for ignoring an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    ignore_reason: Literal["test_credential", "false_positive", "low_risk", "invalid"] = Field(
        description="Why the incident is ignored. Must come from the user: ask, do not choose. 'test_credential' "
        "(a secret used for testing), 'false_positive' (not a real secret), 'low_risk' (the secret poses little "
        "risk), 'invalid' (the secret is invalid or inactive)"
    )


class ReopenInternalIncidentParams(BaseModel):
    """Parameters for reopening an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")


class ResolvePublicIncidentParams(BaseModel):
    """Parameters for resolving a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    resolve_reason: Literal["revoked", "dmca_request", "source_deleted"] = Field(
        description="Why the incident is resolved. Must come from the user: ask, do not choose. 'revoked' (the "
        "secret was revoked or rotated), 'dmca_request' (taken down through a DMCA request), 'source_deleted' (the "
        "public source holding the secret was deleted)"
    )


class IgnorePublicIncidentParams(BaseModel):
    """Parameters for ignoring a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    ignore_reason: Literal[
        "test_credential", "false_positive", "low_risk", "invalid", "ignore_actor", "ignore_secret"
    ] = Field(
        description="Why the incident is ignored. Must come from the user: ask, do not choose. 'test_credential', "
        "'false_positive', 'low_risk', 'invalid', 'ignore_actor' (ignore the account that leaked it), "
        "'ignore_secret' (ignore this secret)"
    )


class ReopenPublicIncidentParams(BaseModel):
    """Parameters for reopening a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")


class IncidentStatusResult(BaseModel):
    """The incident after its status changed."""

    incident_kind: IncidentKind = Field(description="Kind of the incident that changed: internal or public")
    incident_id: int = Field(description="ID of the incident that changed")
    action: StatusChange = Field(description="The change that was asked for")
    changed: bool = Field(description=CHANGED_DESCRIPTION)
    status: str | None = Field(description="The incident's status now, such as RESOLVED or IGNORED")
    incident: dict[str, Any] = Field(description="The incident as it is now")


async def _apply(
    client: GitGuardianClient,
    kind: IncidentKind,
    incident_id: int,
    action: StatusChange,
    call: Awaitable[dict[str, Any]],
) -> IncidentStatusResult:
    """Make the change, and describe the incident it leaves."""
    incident, changed = await apply_or_confirm(
        call,
        incident_reader(client, kind, incident_id),
        lambda current: current.get("status") in _STATUSES_AFTER[action],
        check_advice(kind),
    )
    return IncidentStatusResult(
        incident_kind=kind,
        incident_id=incident_id,
        action=action,
        changed=changed,
        status=incident.get("status"),
        incident=incident,
    )


async def resolve_internal_incident(params: ResolveInternalIncidentParams) -> IncidentStatusResult:
    """Resolve an internal secret incident."""
    client = await get_client()
    call = client.resolve_incident(str(params.incident_id), secret_revoked=params.secret_revoked)
    return await _apply(client, "internal", params.incident_id, "resolve", call)


async def ignore_internal_incident(params: IgnoreInternalIncidentParams) -> IncidentStatusResult:
    """Ignore an internal secret incident."""
    client = await get_client()
    call = client.ignore_incident(str(params.incident_id), ignore_reason=params.ignore_reason)
    return await _apply(client, "internal", params.incident_id, "ignore", call)


async def reopen_internal_incident(params: ReopenInternalIncidentParams) -> IncidentStatusResult:
    """Reopen a resolved or ignored internal secret incident."""
    client = await get_client()
    return await _apply(
        client, "internal", params.incident_id, "reopen", client.reopen_incident(str(params.incident_id))
    )


async def resolve_public_incident(params: ResolvePublicIncidentParams) -> IncidentStatusResult:
    """Resolve a Public Monitoring incident."""
    client = await get_client()
    call = client.resolve_public_incident(str(params.incident_id), resolve_reason=params.resolve_reason)
    return await _apply(client, "public", params.incident_id, "resolve", call)


async def ignore_public_incident(params: IgnorePublicIncidentParams) -> IncidentStatusResult:
    """Ignore a Public Monitoring incident."""
    client = await get_client()
    call = client.ignore_public_incident(str(params.incident_id), ignore_reason=params.ignore_reason)
    return await _apply(client, "public", params.incident_id, "ignore", call)


async def reopen_public_incident(params: ReopenPublicIncidentParams) -> IncidentStatusResult:
    """Reopen a resolved or ignored Public Monitoring incident."""
    client = await get_client()
    call = client.reopen_public_incident(str(params.incident_id))
    return await _apply(client, "public", params.incident_id, "reopen", call)
