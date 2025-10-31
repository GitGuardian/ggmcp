import json
import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListHoneytokensParams(BaseModel):
    """Parameters for listing honeytokens."""

    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)")
    search: str | None = Field(default=None, description="Search string to filter results by name or description")
    ordering: str | None = Field(
        default=None, description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')"
    )
    show_token: bool = Field(default=False, description="Whether to include token details in the response")
    creator_id: str | int | None = Field(default=None, description="Filter by creator ID")
    creator_api_token_id: str | int | None = Field(default=None, description="Filter by creator API token ID")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")
    mine: bool = Field(default=False, description="If True, fetch honeytokens created by the current user")


class ListHoneytokensResult(BaseModel):
    """Result from listing honeytokens."""

    honeytokens: list[dict[str, Any]] = Field(description="List of honeytoken objects")


async def list_honeytokens(params: ListHoneytokensParams) -> ListHoneytokensResult:
    """
    List honeytokens from the GitGuardian dashboard with filtering options.

    If mine=True, filters honeytokens to show only those created by the current user.

    Args:
        params: ListHoneytokensParams model containing all filtering options

    Returns:
        ListHoneytokensResult: Pydantic model containing:
            - honeytokens: List of honeytoken objects matching the specified criteria

    Raises:
        ToolError: If the listing operation fails
    """
    client = get_client()
    logger.debug("Listing honeytokens with filters")

    # Handle mine parameter separately - if mine=True, we'll need to get
    # the current user's info first and set creator_id accordingly
    creator_id = params.creator_id
    if params.mine:
        try:
            # Get current token info to identify the user
            token_info = await client.get_current_token_info()
            if token_info and "user_id" in token_info:
                # If we have user_id, use it as creator_id
                creator_id = token_info["user_id"]
                logger.debug(f"Setting creator_id to current user: {creator_id}")
            else:
                logger.warning("Could not determine current user ID for 'mine' filter")
        except Exception as e:
            logger.warning(f"Failed to get current user info for 'mine' filter: {str(e)}")

    # Build filters dictionary with parameters supported by the client API
    filters = {
        "status": params.status,
        "search": params.search,
        "ordering": params.ordering,
        "show_token": params.show_token,
        "creator_id": creator_id,
        "creator_api_token_id": params.creator_api_token_id,
        "per_page": params.per_page,
        "get_all": params.get_all,
    }

    logger.debug(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

    try:
        result = await client.list_honeytokens(**filters)

        # Handle both response formats: either a dict with 'honeytokens' key or a list directly
        if isinstance(result, dict):
            honeytokens = result.get("honeytokens", [])
        else:
            # If the result is already a list, use it directly
            honeytokens = result

        logger.debug(f"Found {len(honeytokens)} honeytokens")
        return ListHoneytokensResult(honeytokens=honeytokens)
    except Exception as e:
        logger.error(f"Error listing honeytokens: {str(e)}")
        raise ToolError(str(e))
