"""Tools that set a secret incident's severity, one per kind."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import IncidentKind, check_advice, incident_reader, uncertain_write_error
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

SEVERITY_DESCRIPTION = "The severity to set. Must come from the user: ask, do not choose."


class SetInternalIncidentSeverityParams(BaseModel):
    """Parameters for setting an internal incident's severity."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = Field(description=SEVERITY_DESCRIPTION)


class SetPublicIncidentSeverityParams(BaseModel):
    """Parameters for setting a Public Monitoring incident's severity."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description=SEVERITY_DESCRIPTION)


class IncidentSeverityResult(BaseModel):
    """The incident after its severity was set."""

    incident_kind: IncidentKind = Field(description="Kind of the incident: internal or public")
    incident_id: int = Field(description="ID of the incident")
    action: Literal["set_severity"] = Field(description="The change that was asked for")
    changed: bool = Field(description="False when the incident already had this severity, so nothing was written")
    severity: str | None = Field(description="The incident's severity now")
    incident: dict[str, Any] = Field(description="The incident as it is now")


async def _set_severity(
    kind: IncidentKind,
    incident_id: int,
    severity: str,
    read: Callable[[], Awaitable[dict[str, Any]]],
    write: Callable[[], Awaitable[dict[str, Any]]],
) -> IncidentSeverityResult:
    """Read the incident, and set its severity when it differs."""
    try:
        incident = await read()
    except Exception as e:
        raise ToolError(str(e))
    changed = incident.get("severity") != severity
    if changed:
        try:
            incident = await write()
        except Exception as e:
            raise uncertain_write_error(e, check_advice(kind)) or ToolError(str(e))
    return IncidentSeverityResult(
        incident_kind=kind,
        incident_id=incident_id,
        action="set_severity",
        changed=changed,
        severity=incident.get("severity"),
        incident=incident,
    )


async def set_internal_incident_severity(params: SetInternalIncidentSeverityParams) -> IncidentSeverityResult:
    """Set an internal secret incident's severity."""
    client = await get_client()
    return await _set_severity(
        "internal",
        params.incident_id,
        params.severity,
        incident_reader(client, "internal", params.incident_id),
        lambda: client.set_incident_severity(params.incident_id, params.severity),
    )


async def set_public_incident_severity(params: SetPublicIncidentSeverityParams) -> IncidentSeverityResult:
    """Set a Public Monitoring incident's severity."""
    client = await get_client()
    return await _set_severity(
        "public",
        params.incident_id,
        params.severity,
        incident_reader(client, "public", params.incident_id),
        lambda: client.set_public_incident_severity(params.incident_id, params.severity),
    )
