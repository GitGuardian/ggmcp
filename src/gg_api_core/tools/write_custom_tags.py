import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

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

            # Parse the tag format "key" or "key:value"
            if ":" in params.tag:
                key, value = params.tag.split(":", 1)
            else:
                key = params.tag
                value = None

            # Value is optional for label-only tags
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


class UpdateOrCreateIncidentCustomTagsParams(BaseModel):
    """Parameters for updating or creating incident custom tags."""

    incident_id: str | int = Field(description="ID of the secret incident")
    custom_tags: list[str] = Field(
        description='List of custom tags to apply to the incident. Format: "key" or "key:value"'
    )


async def update_or_create_incident_custom_tags(params: UpdateOrCreateIncidentCustomTagsParams) -> dict[str, Any]:
    """
    Update a secret incident with custom tags, creating tags if they don't exist.

    Custom tags can be in two formats:
    - "key" (creates a label without a value)
    - "key:value" (creates a label with a value)

    Args:
        params: UpdateOrCreateIncidentCustomTagsParams model containing custom tags configuration

    Returns:
        Updated incident data
    """
    client = await get_client()
    logger.debug(f"Updating custom tags for incident {params.incident_id}")

    try:
        # Parse custom tags and ensure they exist
        parsed_tags = []
        for tag in params.custom_tags:
            if ":" in tag:
                # Split by first occurrence of ":"
                key, value = tag.split(":", 1)
            else:
                # Tag is just a key with no value
                key = tag
                value = None

            # Create the tag if it doesn't exist
            try:
                await client.create_custom_tag(key, value)
                logger.debug(f"Created custom tag: {key}={value}")
            except Exception as e:
                # Tag might already exist, which is fine
                logger.debug(f"Tag {key}={value} may already exist: {str(e)}")

            # Add to parsed tags list in the format expected by update_incident
            parsed_tags.append({"key": key, "value": value})

        # Update the incident with the custom tags
        result = await client.update_incident(
            incident_id=str(params.incident_id),
            custom_tags=parsed_tags,
        )

        logger.debug(f"Updated custom tags for incident {params.incident_id}")
        return result
    except Exception as e:
        logger.exception(f"Error updating custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
