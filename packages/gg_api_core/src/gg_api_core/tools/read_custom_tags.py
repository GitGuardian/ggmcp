import logging
from typing import Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ReadCustomTagsParams(BaseModel):
    """Parameters for reading custom tags."""

    action: Literal["list_tags", "get_tag"] = Field(
        description="Choose 'list_tags' to retrieve all custom tags, or 'get_tag' to retrieve a specific tag by ID. Required."
    )
    tag_id: str | int = Field(description="The ID of the custom tag to retrieve. Required when action is 'get_tag'.")


async def read_custom_tags(params: ReadCustomTagsParams):
    """
    Read custom tags from the GitGuardian dashboard.

    Use action='list_tags' to list all custom tags.
    Use action='get_tag' with a tag_id to retrieve a specific tag.

    Args:
        params: ReadCustomTagsParams model containing custom tags query configuration
            action: The action to perform ('list_tags' or 'get_tag'). Defaults to 'list_tags'
            tag_id: The ID of a specific tag to retrieve (required when action='get_tag')

    Returns:
        Custom tag data based on the action performed
    """
    try:
        client = await get_client()

        if params.action == "list_tags":
            logger.debug("Listing all custom tags")
            return await client.list_custom_tags()
        elif params.action == "get_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'get_tag'")
            logger.debug(f"Getting custom tag with ID: {params.tag_id}")
            return await client.get_custom_tag(str(params.tag_id))
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['list_tags', 'get_tag']")
    except Exception as e:
        logger.exception(f"Error reading custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
