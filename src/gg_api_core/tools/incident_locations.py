"""Tools for the files that still hold an internal incident's secret, and for fixing them."""

import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import IncidentKind, uncertain_write_error
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PageOfResults,
    PerPage,
    page_fields,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# What to read after a code fix request whose outcome is unknown.
_CODE_FIX_CHECK = (
    "Requesting it again may open a second pull request: list_internal_incident_locations shows each location's "
    "remediation_prs, so check there"
)


class ListInternalIncidentLocationsParams(BaseModel):
    """Parameters for listing where an internal incident's secret still is."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    source_id: NumericId | None = Field(default=None, description="Only the locations in this source")
    active: bool | None = Field(
        default=None, description="True for the locations that still hold the secret, False for the fixed ones"
    )
    search: str | None = Field(default=None, description="Only the locations whose file path contains this text")
    per_page: PerPage = 20
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListInternalIncidentLocationsResult(PageOfResults):
    """Where an internal incident's secret is, file by file."""

    locations: list[dict[str, Any]] = Field(
        description="Locations: one file of one source on its default branch, with its id, the lines of each "
        "match, and the pull requests already opened to fix it (remediation_prs)"
    )


async def list_internal_incident_locations(
    params: ListInternalIncidentLocationsParams,
) -> ListInternalIncidentLocationsResult:
    """List the files on each source's default branch that hold an internal incident's secret."""
    client = await get_client()
    try:
        response = await client.list_incident_locations(
            params.incident_id,
            source_id=params.source_id,
            active=params.active,
            search=params.search,
            per_page=params.per_page,
            cursor=params.cursor,
            get_all=params.get_all,
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListInternalIncidentLocationsResult(locations=response["data"], **page_fields(params, response))


class CreateInternalIncidentCodeFixRequestParams(BaseModel):
    """Parameters for asking GitGuardian to open pull requests that remove an incident's secret."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    location_ids: list[NumericId] = Field(
        min_length=1,
        description="IDs of the locations to fix, from list_internal_incident_locations. GitGuardian opens one pull "
        "request per source.",
    )


class CodeFixRequestResult(BaseModel):
    """The code fix request GitGuardian accepted."""

    incident_kind: IncidentKind = Field(description="Kind of the incident: always internal")
    incident_id: int = Field(description="ID of the incident")
    location_ids: list[int] = Field(description="IDs of the locations the request covers")
    response: dict[str, Any] = Field(description="The API's answer")


async def create_internal_incident_code_fix_request(
    params: CreateInternalIncidentCodeFixRequestParams,
) -> CodeFixRequestResult:
    """Ask GitGuardian to open pull requests that remove an internal incident's secret from these locations."""
    client = await get_client()
    try:
        response = await client.create_code_fix_request(params.incident_id, list(params.location_ids))
    except Exception as e:
        raise uncertain_write_error(e, _CODE_FIX_CHECK) or ToolError(str(e))
    return CodeFixRequestResult(
        incident_kind="internal",
        incident_id=params.incident_id,
        location_ids=list(params.location_ids),
        response=response if isinstance(response, dict) else {"result": response},
    )
