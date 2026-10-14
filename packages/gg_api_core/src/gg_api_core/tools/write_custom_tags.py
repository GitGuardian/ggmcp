import logging
from typing import Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.custom_tags import parse_tag
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class WriteCustomTagsParams(BaseModel):
    """Parameters for writing custom tags."""

    action: Literal["create_tag", "delete_tag"] = Field(
        description="Choose 'create_tag' to create a new custom tag, or 'delete_tag' to delete an existing tag by ID. For delete_tag, you must first call read_custom_tags to get the tag ID. Required."
    )
    tag: str | None = Field(
        default=None,
        description='Tag to create in "key" or "key:value" format. Required when action is "create_tag".',
    )
    tag_id: str | int | None = Field(
        default=None,
        description="The ID of the custom tag to delete. Required when action is 'delete_tag'. Use read_custom_tags to list available tags and get their IDs.",
    )


async def write_custom_tags(params: WriteCustomTagsParams):
    """
    Create or delete custom tags in the GitGuardian dashboard.

    For creating tags, use the "key" or "key:value" format:
    - "env" creates a label without a value
    - "env:prod" creates a label with key="env" and value="prod"

    For deleting tags:
    1. First call read_custom_tags to list all available tags and get their IDs
    2. Then call this function with action="delete_tag" and the specific tag_id

    Args:
        params: WriteCustomTagsParams model containing custom tags write configuration
            action: The action to perform ('create_tag' or 'delete_tag'). Required.
            tag: Tag to create in "key" or "key:value" format (required for create_tag)
            tag_id: ID of the tag to delete (required for delete_tag, obtain from read_custom_tags)

    Returns:
        Result based on the action performed
    """
    try:
        client = await get_client()

        if params.action == "create_tag":
            if not params.tag:
                raise ValueError("tag is required when action is 'create_tag'")

            key, value = parse_tag(params.tag)
            logger.debug(f"Creating custom tag with key: {key}, value: {value or 'None (label only)'}")
            return await client.create_custom_tag(key, value)

        elif params.action == "delete_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'delete_tag'")

            logger.debug(f"Deleting custom tag with ID: {params.tag_id}")
            return await client.delete_custom_tag(str(params.tag_id))
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['create_tag', 'delete_tag']")
    except Exception as e:
        logger.exception(f"Error writing custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
