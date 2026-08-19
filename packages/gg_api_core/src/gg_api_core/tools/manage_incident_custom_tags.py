import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, field_validator

from gg_api_core.custom_tags import parse_tag
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class IncidentCustomTagsParams(BaseModel):
    """Parameters for managing custom tags on an incident."""

    incident_id: int = Field(description="ID of the secret incident")
    action: Literal["add", "remove", "set"] = Field(
        default="add",
        description='Operation to perform: "add" merges into existing tags, "remove" unlinks the listed '
        'tags, "set" replaces the whole set with the given tags.',
    )
    custom_tags: list[str] = Field(
        description='Custom tags in "key" or "key:value" format',
    )

    @field_validator("custom_tags")
    @classmethod
    def _validate_tag_format(cls, tags: list[str]) -> list[str]:
        """Reject any tag with an empty key at the model boundary."""
        for tag in tags:
            parse_tag(tag)  # raises ValueError on an empty key
        return tags


def _resolve_tags(
    action: Literal["add", "remove", "set"],
    current: list[tuple[str, str | None]],
    requested: list[tuple[str, str | None]],
) -> list[tuple[str, str | None]]:
    """Fold requested tags into the current incident set according to the action.

    add     -> the union of current and requested, order-preserving, deduplicated
    remove  -> current minus requested
    set     -> just requested, deduplicated
    """
    if action == "add":
        return list(dict.fromkeys([*current, *requested]))
    if action == "remove":
        return [tag for tag in current if tag not in requested]
    return list(dict.fromkeys(requested))  # "set"


async def manage_incident_custom_tags(params: IncidentCustomTagsParams) -> dict[str, Any]:
    """
    Manage custom tags on a secret incident, creating tag definitions if needed.

    The PATCH endpoint applies set semantics (it replaces the incident's full tag
    set), so the current tags are read first and folded into the final set
    according to the action:
    - "add": existing tags preserved, requested tags merged in (union)
    - "remove": requested tags unlinked, the rest kept
    - "set": the whole set replaced by the requested tags

    The read-then-write is not atomic: no atomic per-tag endpoint exists, so a
    concurrent change between the read and the PATCH can be lost for any action.

    Custom tags can be in two formats:
    - "key" (creates a label without a value)
    - "key:value" (creates a label with a value)

    Args:
        params: IncidentCustomTagsParams model containing the operation and tags

    Returns:
        Updated incident data
    """
    client = await get_client()
    logger.debug(f"Managing custom tags for incident {params.incident_id}: {params.action}")

    try:
        requested = [parse_tag(tag) for tag in params.custom_tags]

        incident = await client.get_incident(params.incident_id, with_occurrences=0)
        current = [(tag["key"], tag["value"]) for tag in incident.get("custom_tags") or []]

        final = _resolve_tags(params.action, current, requested)

        # update_incident drops an empty custom_tags payload, so an empty final set
        # cannot be represented as an explicit "clear all". Surface that clearly
        # instead of inheriting a misleading "severity or custom_tags" error.
        if not final:
            raise ToolError(
                "The requested operation would leave the incident with no custom tags, "
                "which the PATCH endpoint cannot express (it drops an empty tag set). "
                "Provide at least one tag in custom_tags."
            )

        result = await client.update_incident(
            incident_id=str(params.incident_id),
            custom_tags=[{"key": key, "value": value} for key, value in final],
        )

        logger.debug(f"Managed custom tags for incident {params.incident_id}")
        return result
    except ToolError:
        raise
    except Exception as e:
        logger.exception(f"Error managing custom tags: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
