"""Tools that list the workspace's honeytokens and GitGuardian's secret detectors."""

import json
import logging
import re
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PAGE_SIZE_DESCRIPTION,
    PageOfResults,
    StopReason,
    next_arguments_for,
    page_fields,
    stop_reason_of,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


HoneytokenOrdering = Literal[
    "created_at", "-created_at", "triggered_at", "-triggered_at", "revoked_at", "-revoked_at", "name", "-name"
]
DEFAULT_HONEYTOKEN_ORDERING: HoneytokenOrdering = "-created_at"


class ListHoneytokensParams(BaseModel):
    """Parameters for listing honeytokens."""

    status: Literal["active", "triggered", "revoked"] | None = Field(
        default=None, description="Only the honeytokens in this state; triggered means someone used one"
    )
    search: str | None = Field(default=None, description="Only the honeytokens whose name contains this text")
    mine: bool = Field(default=False, description="Only the honeytokens the current user created")
    ordering: HoneytokenOrdering = Field(
        default=DEFAULT_HONEYTOKEN_ORDERING, description="Sort order: a field, prefixed with '-' for descending"
    )
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListHoneytokensResult(PageOfResults):
    """Honeytokens, without their credentials."""

    honeytokens: list[dict[str, Any]] = Field(
        description="Honeytokens with their name, status, dates and creator. Their credentials are not included."
    )


async def list_honeytokens(params: ListHoneytokensParams = ListHoneytokensParams()) -> ListHoneytokensResult:
    """List the workspace's honeytokens, without their credentials."""
    client = await get_client()
    try:
        creator_id = None
        if params.mine:
            token_info = await client.get_current_token_info()
            creator_id = (token_info or {}).get("member_id")
            if creator_id is None:
                raise ToolError("This token is not tied to a workspace member, so 'mine' cannot filter honeytokens.")
        offset = _read_offset(params.cursor)
        response = await client.list_honeytokens(
            status=params.status,
            search=params.search,
            ordering=params.ordering,
            show_token=False,
            creator_id=None if creator_id is None else str(creator_id),
            per_page=params.page_size,
            cursor=None if offset is not None else params.cursor,
            get_all=params.get_all and offset is None,
        )
    except ToolError:
        raise
    except Exception as e:
        raise ToolError(str(e))
    if response.get("has_more"):
        return ListHoneytokensResult(honeytokens=response["data"], **page_fields(params, response))
    return _page_locally(params, response["data"], offset or 0)


# /honeytokens ignores per_page and answers every honeytoken at once, so the tool pages
# through that answer itself, with a cursor that holds the offset of the next one.
_OFFSET_CURSOR = re.compile(r"offset:(\d+)")


def _read_offset(cursor: str | None) -> int | None:
    match = _OFFSET_CURSOR.fullmatch(cursor or "")
    return int(match[1]) if match else None


def _page_locally(
    params: ListHoneytokensParams, honeytokens: list[dict[str, Any]], offset: int
) -> ListHoneytokensResult:
    """One page of a list the API answered whole, or as much as the size budget holds with get_all."""
    page: list[dict[str, Any]] = []
    stopped_by: StopReason | None = None
    size = 0
    for honeytoken in honeytokens[offset:]:
        if not params.get_all and len(page) == params.page_size:
            break
        item_size = len(json.dumps(honeytoken))
        if params.get_all and page and size + item_size > DEFAULT_PAGINATION_MAX_BYTES:
            stopped_by = "size_budget"
            break
        page.append(honeytoken)
        size += item_size
    next_offset = offset + len(page)
    has_more = next_offset < len(honeytokens)
    return ListHoneytokensResult(
        honeytokens=page,
        page_size=params.page_size,
        has_more=has_more,
        stop_reason=stop_reason_of(has_more, params.get_all, stopped_by),
        next_arguments=next_arguments_for(params, f"offset:{next_offset}" if has_more else None, params.page_size),
    )


class ListDetectorsParams(BaseModel):
    """Parameters for listing GitGuardian's secret detectors."""

    search: str | None = Field(default=None, description="Only the detectors whose name contains this text")
    active: bool | None = Field(
        default=None, description="True for the detectors enabled in the workspace, False for the disabled ones"
    )
    page_size: int = Field(default=20, ge=1, le=100, description=PAGE_SIZE_DESCRIPTION)
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListDetectorsResult(PageOfResults):
    """Secret detectors."""

    detectors: list[dict[str, Any]] = Field(
        description="Detectors with their name, display name, category and whether they are enabled"
    )


async def list_detectors(params: ListDetectorsParams = ListDetectorsParams()) -> ListDetectorsResult:
    """List GitGuardian's secret detectors."""
    client = await get_client()
    try:
        response = await client.list_secret_detectors(
            search=params.search,
            active=params.active,
            per_page=params.page_size,
            cursor=params.cursor,
            get_all=params.get_all,
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListDetectorsResult(detectors=response["data"], **page_fields(params, response))
