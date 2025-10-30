from typing import Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client
import logging

logger = logging.getLogger(__name__)


class ReadCustomTagsParams(BaseModel):
    """Parameters for reading custom tags."""
    action: Literal["list_tags", "get_tag"] = Field(description="Action to perform related to reading custom tags")
    tag_id: str | int | None = Field(
        default=None, description="ID of the custom tag to retrieve (used with 'get_tag' action)"
    )


async def read_custom_tags(params: ReadCustomTagsParams):
    """
    Read custom tags from the GitGuardian dashboard.

    Args:
        params: ReadCustomTagsParams model containing custom tags query configuration

    Returns:
        Custom tag data based on the action performed
    """
    try:
        client = get_client()

        if params.action == "list_tags":
            logger.debug("Listing all custom tags")
            return await client.custom_tags_list()
        elif params.action == "get_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'get_tag'")
            logger.debug(f"Getting custom tag with ID: {params.tag_id}")
            return await client.custom_tags_get(params.tag_id)
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['list_tags', 'get_tag']")
    except Exception as e:
        logger.error(f"Error reading custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
