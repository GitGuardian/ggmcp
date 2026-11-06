import logging
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class GetMemberParams(BaseModel):
    """Parameters for retrieving a specific member."""

    member_id: int = Field(description="The ID of the member to retrieve")


class GetMemberResult(BaseModel):
    """Result from retrieving a specific member."""

    member: dict[str, Any] = Field(description="Member information")


async def get_member(params: GetMemberParams) -> GetMemberResult:
    """
    Retrieve a specific member by their ID.

    Returns information about the member including:
    - id: Member's unique identifier
    - name: Member's display name
    - email: Member's email address
    - role: Member's role (e.g., owner, manager, member)
    - access_level: Member's access level
    - active: Whether the member is active
    - created_at: When the member was created
    - last_login: When the member last logged in

    Args:
        params: GetMemberParams model containing:
            - member_id: The ID of the member to retrieve

    Returns:
        GetMemberResult: Pydantic model containing:
            - member: Member information dictionary

    Raises:
        ToolError: If the retrieval operation fails
    """
    client = await get_client()
    logger.debug(f"Retrieving member {params.member_id}")

    try:
        response = await client.get_member(member_id=params.member_id)

        logger.debug(f"Retrieved member {params.member_id}")
        return GetMemberResult(member=response)
    except Exception as e:
        logger.exception(f"Error retrieving member {params.member_id}: {str(e)}")
        raise ToolError(str(e))
