"""The pagination contract every list tool follows.

Each list tool takes page_size, cursor and get_all, and its result carries page_size,
has_more, stop_reason and next_arguments. next_arguments repeats the caller's own
arguments with the cursor that resumes after the results returned, so the next call
keeps the same filters and neither skips nor repeats a result.
"""

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, MAX_PAGINATION_PAGES, PAGINATE_ALL_PER_PAGE

StopReason = Literal["end", "page", "size_budget", "page_limit"]

PAGE_SIZE_DESCRIPTION = "Number of results per page, 1 to 100"
CURSOR_DESCRIPTION = (
    "Where to resume, from next_arguments of a previous result. Leave it unset for the first page; do not build one"
)
GET_ALL_DESCRIPTION = (
    f"If True, fetch page after page until the last one, about {DEFAULT_PAGINATION_MAX_BYTES // 1000} KB of "
    f"results, or {MAX_PAGINATION_PAGES} pages, whichever comes first; stop_reason says which. If False, return one "
    "page"
)


class PageOfResults(BaseModel):
    """Fields every list tool's result carries, after its own list of results."""

    page_size: int = Field(description="Number of results per page this call used")
    has_more: bool = Field(description="True when more results match than this result holds")
    stop_reason: StopReason = Field(
        description="Why the results stop here: 'end' (no more results), 'page' (one page was asked for), "
        "'size_budget' (get_all reached its size budget), 'page_limit' (get_all reached its page limit)"
    )
    next_arguments: dict[str, Any] | None = Field(
        description="The arguments for the next call: the same filters, with the cursor that resumes after these "
        "results. Pass them as given. Null when has_more is false."
    )


def stop_reason_of(has_more: bool, get_all: bool, stopped_by: StopReason | None = None) -> StopReason:
    """The stop reason for a result: what get_all stopped on, else the end or one page."""
    if not has_more:
        return "end"
    if get_all:
        return stopped_by or "size_budget"
    return "page"


def next_arguments_for(params: BaseModel, cursor: str | None, page_size: int) -> dict[str, Any] | None:
    """The caller's arguments, with the cursor and page size that resume after this result."""
    if cursor is None:
        return None
    arguments = params.model_dump(mode="json", exclude_unset=True)
    arguments["cursor"] = cursor
    arguments["page_size"] = page_size
    return arguments


def page_fields(params: Any, response: Mapping[str, Any]) -> dict[str, Any]:
    """The pagination fields of a result built from one cursor-paginated API answer.

    params is the tool's parameters, with page_size, cursor and get_all; response is
    the client's ListResponse or PaginatedResult. get_all asks the API for at most
    PAGINATE_ALL_PER_PAGE items per page, so that is the page size it reports.
    """
    page_size = min(params.page_size, PAGINATE_ALL_PER_PAGE) if params.get_all else params.page_size
    has_more = bool(response.get("has_more"))
    cursor = response.get("cursor") if has_more else None
    return {
        "page_size": page_size,
        "has_more": has_more,
        "stop_reason": stop_reason_of(has_more, params.get_all, response.get("stopped_by")),
        "next_arguments": next_arguments_for(params, cursor, page_size),
    }
