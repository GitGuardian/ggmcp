import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListDetectorsParams(BaseModel):
    """Parameters for listing secret detectors."""

    search: str | None = Field(
        default=None,
        description="Search string to filter detectors by name",
    )
    type: str | None = Field(
        default=None,
        description="Filter by detector type: 'specific', 'generic', or 'custom'",
    )
    per_page: int = Field(
        default=20,
        description="Number of results per page (default: 20, min: 1, max: 100)",
    )
    cursor: str | None = Field(default=None, description="Pagination cursor from a previous response")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListDetectorsResult(BaseModel):
    """Result from listing secret detectors."""

    detectors: list[dict[str, Any]] = Field(description="List of detector objects")
    next_cursor: str | None = Field(
        default=None,
        description="Cursor for fetching the next page (null if no more results)",
    )
    has_more: bool = Field(
        default=False,
        description="True if more results exist (use next_cursor to fetch)",
    )


async def list_detectors(params: ListDetectorsParams) -> ListDetectorsResult:
    """
    List secret detectors from the GitGuardian detection engine.

    Returns information about the detectors available in GitGuardian for
    identifying secrets in source code and other content.

    Args:
        params: ListDetectorsParams model containing all filtering options

    Returns:
        ListDetectorsResult: Pydantic model containing:
            - detectors: List of detector objects with name, display_name, family, category, etc.
            - next_cursor: Cursor for pagination
            - has_more: Whether more results exist

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug("Listing secret detectors")

    try:
        response = await client.list_detectors(
            search=params.search,
            type=params.type,
            per_page=params.per_page,
            cursor=params.cursor,
            get_all=params.get_all,
        )

        detectors_data = response["data"]
        next_cursor = response["cursor"]

        logger.debug(f"Found {len(detectors_data)} detectors")
        return ListDetectorsResult(
            detectors=detectors_data,
            next_cursor=next_cursor,
            has_more=response.get("has_more", False),
        )
    except Exception as e:
        logger.exception(f"Error listing detectors: {str(e)}")
        raise ToolError(str(e))
