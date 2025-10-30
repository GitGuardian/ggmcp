from typing import Literal, Any

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.utils import get_client
import logging

logger = logging.getLogger(__name__)


class WriteCustomTagsParams(BaseModel):
    """Parameters for writing custom tags."""
    action: Literal["create_tag", "delete_tag"] = Field(description="Action to perform related to writing custom tags")
    key: str | None = Field(default=None, description="Key for the new tag (used with 'create_tag' action)")
    value: str | None = Field(default=None, description="Value for the new tag (used with 'create_tag' action)")
    tag_id: str | int | None = Field(
        default=None, description="ID of the custom tag to delete (used with 'delete_tag' action)"
    )


async def write_custom_tags(params: WriteCustomTagsParams):
    """
    Create or delete custom tags in the GitGuardian dashboard.

    Args:
        params: WriteCustomTagsParams model containing custom tags write configuration

    Returns:
        Result based on the action performed
    """
    try:
        client = get_client()

        if params.action == "create_tag":
            if not params.key:
                raise ValueError("key is required when action is 'create_tag'")

            # Value is optional for label-only tags
            logger.debug(f"Creating custom tag with key: {params.key}, value: {params.value or 'None (label only)'}")
            return await client.custom_tags_create(params.key, params.value)

        elif params.action == "delete_tag":
            if not params.tag_id:
                raise ValueError("tag_id is required when action is 'delete_tag'")

            logger.debug(f"Deleting custom tag with ID: {params.tag_id}")
            return await client.custom_tags_delete(params.tag_id)
        else:
            raise ValueError(f"Invalid action: {params.action}. Must be one of ['create_tag', 'delete_tag']")
    except Exception as e:
        logger.error(f"Error writing custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


class UpdateOrCreateIncidentCustomTagsParams(BaseModel):
    """Parameters for updating or creating incident custom tags."""
    incident_id: str | int = Field(description="ID of the secret incident")
    custom_tags: list[str | dict[str, str]] = Field(description="List of custom tags to apply to the incident")


async def update_or_create_incident_custom_tags(params: UpdateOrCreateIncidentCustomTagsParams) -> dict[str, Any]:
    """
    Update a secret incident with status and/or custom tags.
    If a custom tag is a String, a label is created. For example "MCP": None will create a label "MCP" without a value.

    Args:
        params: UpdateOrCreateIncidentCustomTagsParams model containing custom tags configuration

    Returns:
        Updated incident data
    """
    client = get_client()
    logger.debug(f"Updating custom tags for incident {params.incident_id}")

    try:
        # Make the API call
        result = await client.update_or_create_incident_custom_tags(
            incident_id=params.incident_id,
            custom_tags=params.custom_tags,
        )

        logger.debug(f"Updated custom tags for incident {params.incident_id}")
        return result
    except Exception as e:
        logger.error(f"Error updating custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
