"""Tools that read the endpoint inventory: the machines that report to GitGuardian."""

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

MACHINE_DESCRIPTION = (
    "its id, name (hostname), machine_id (the identifier its operating system gives), last_seen_at, and its "
    "partitions: one per user of the machine plus the machine-wide system context, each with its username, "
    "display_name, home_path, is_privileged_account, last_seen_at and registered_at"
)


class ListMachinesParams(BaseModel):
    """Parameters for listing machines."""

    search: str | None = Field(
        default=None,
        description="Only the machines whose name or machine_id, or one of whose usernames, contains this text",
    )
    usernames: list[str] | None = Field(
        default=None,
        description="Only the machines with a partition of one of these usernames. Each machine still comes with "
        "all its partitions",
    )
    ordering: Literal["id", "-id"] = Field(default="id", description="Sort order: id, prefixed with '-' for descending")
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListMachinesResult(PageOfResults):
    """Machines of the workspace."""

    machines: list[dict[str, Any]] = Field(description=f"Machines, each with {MACHINE_DESCRIPTION}")


class GetMachineParams(BaseModel):
    """Parameters for reading one machine."""

    machine_id: NumericId = Field(
        description="ID of the machine: the id of a machine from list_machines, not its machine_id text"
    )


class GetMachineResult(BaseModel):
    """One machine of the workspace."""

    machine: dict[str, Any] = Field(description=f"The machine: {MACHINE_DESCRIPTION}")


async def list_machines(params: ListMachinesParams = ListMachinesParams()) -> ListMachinesResult:
    """List the machines that ggshield or the endpoint scanner report, with their users."""
    client = await get_client()
    try:
        response = await client.list_machines(
            search=params.search,
            usernames=params.usernames,
            ordering=params.ordering,
            per_page=params.page_size,
            cursor=params.cursor,
            get_all=params.get_all,
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListMachinesResult(machines=response["data"], **page_fields(params, response))


async def get_machine(params: GetMachineParams) -> GetMachineResult:
    """Read one machine, with its users."""
    client = await get_client()
    try:
        machine = await client.get_machine(params.machine_id)
    except Exception as e:
        raise ToolError(str(e))
    return GetMachineResult(machine=machine)
