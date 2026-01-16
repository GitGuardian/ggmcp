import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListHoneytokensParams(BaseModel):
    """Parameters for listing honeytokens."""

    mine: bool = Field(
        default=False,
        description="If True, fetch honeytokens created by the current user. Set to False to get all honeytokens in the workspace.",
    )
    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)")
    search: str | None = Field(default=None, description="Search string to filter results by name or description")
    ordering: str | None = Field(
        default=None, description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')"
    )
    show_token: bool = Field(default=False, description="Whether to include token details in the response")
    creator_id: str | int | None = Field(default=None, description="Filter by creator ID")
    creator_api_token_id: str | int | None = Field(default=None, description="Filter by creator API token ID")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    cursor: str | None = Field(default=None, description="Pagination cursor from a previous response")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListHoneytokensResult(BaseModel):
    """Result from listing honeytokens."""

    honeytokens: list[dict[str, Any]] = Field(description="List of honeytoken objects")
    next_cursor: str | None = Field(
        default=None, description="Cursor for fetching the next page (null if no more results)"
    )
    has_more: bool = Field(default=False, description="True if more results exist (use next_cursor to fetch)")


async def list_honeytokens(params: ListHoneytokensParams) -> ListHoneytokensResult:
    """
    List honeytokens from the GitGuardian dashboard with filtering options.

    IMPORTANT: When the user asks for "my honeytokens", "my tokens", "honeytokens I created",
    "honeytokens created by me", or similar possessive/personal references, you MUST set mine=True
    to filter to only the current user's honeytokens.

    Args:
        params: ListHoneytokensParams model containing all filtering options

    Returns:
        ListHoneytokensResult: Pydantic model containing:
            - honeytokens: List of honeytoken objects matching the specified criteria

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug("Listing honeytokens with filters")

    # Handle mine parameter separately - if mine=True, we'll need to get
    # the current user's info first and set creator_id accordingly
    creator_id = params.creator_id
    if params.mine:
        # Get current token info to identify the user
        token_info = await client.get_current_token_info()
        logger.debug(f"Token info: {token_info}")
        if token_info and "member_id" in token_info:
            # If we have member_id, use it as creator_id
            creator_id = token_info["member_id"]
            logger.debug(f"Setting creator_id to current user: {creator_id}")
        else:
            logger.warning("Could not determine current user ID for 'mine' filter")

    try:
        response = await client.list_honeytokens(
            status=params.status,
            search=params.search,
            ordering=params.ordering,
            show_token=params.show_token,
            creator_id=str(creator_id) if creator_id is not None else None,
            creator_api_token_id=str(params.creator_api_token_id) if params.creator_api_token_id is not None else None,
            per_page=params.per_page,
            cursor=params.cursor,
            get_all=params.get_all,
        )

        honeytokens_data = response["data"]
        next_cursor = response["cursor"]

        logger.debug(f"Found {len(honeytokens_data)} honeytokens")
        return ListHoneytokensResult(
            honeytokens=honeytokens_data,
            next_cursor=next_cursor,
            has_more=response.get("has_more", False),
        )
    except Exception as e:
        logger.exception(f"Error listing honeytokens: {str(e)}")
        raise ToolError(str(e))
