"""Tools that add or remove one custom tag on a secret incident, one tool per change and per kind.

The API only replaces an incident's whole tag set. Each tool reads the tags the incident
has, changes the one it was asked to, and writes the set back, so the other tags stay.
Two changes made at the same moment can still overwrite each other: the API offers no
way to change one tag alone.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, StringConstraints

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import IncidentKind, check_advice, incident_reader, uncertain_write_error
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PageOfResults,
    PerPage,
    page_fields,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

TagText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
TagAction = Literal["add", "remove"]

KEY_DESCRIPTION = "The tag's key, such as env"


class CustomTag(BaseModel):
    """One custom tag: a key, and a value or none."""

    key: str = Field(description="The tag's key")
    value: str | None = Field(default=None, description="The tag's value, or null for a tag that is only a key")


class AddInternalIncidentCustomTagParams(BaseModel):
    """Parameters for adding a custom tag to an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    key: TagText = Field(description=KEY_DESCRIPTION)
    value: TagText | None = Field(default=None, description="The tag's value, such as prod. Omit for a key-only tag.")


class RemoveInternalIncidentCustomTagParams(BaseModel):
    """Parameters for removing a custom tag from an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    key: TagText = Field(description=KEY_DESCRIPTION)
    value: TagText | None = Field(
        default=None, description="The value of the tag to remove. Omit to remove every tag with this key."
    )


class AddPublicIncidentCustomTagParams(BaseModel):
    """Parameters for adding a custom tag to a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    key: TagText = Field(description=KEY_DESCRIPTION)
    value: TagText = Field(description="The tag's value, such as prod. Public incident tags always have one.")


class RemovePublicIncidentCustomTagParams(BaseModel):
    """Parameters for removing a custom tag from a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    key: TagText = Field(description=KEY_DESCRIPTION)
    value: TagText | None = Field(
        default=None, description="The value of the tag to remove. Omit to remove every tag with this key."
    )


class IncidentCustomTagsResult(BaseModel):
    """The incident's custom tags after the change."""

    incident_kind: IncidentKind = Field(description="Kind of the incident: internal or public")
    incident_id: int = Field(description="ID of the incident")
    action: TagAction = Field(description="The change that was asked for")
    changed: bool = Field(
        description="False when the incident already had the tag, or did not have the tag to remove, so nothing "
        "was written"
    )
    custom_tags: list[CustomTag] = Field(description="The incident's custom tags now")


def _tags_of(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """The incident's custom tags as the key and value pairs the API takes back."""
    return [
        {"key": tag.get("key"), "value": tag.get("value")}
        for tag in incident.get("custom_tags") or []
        if isinstance(tag, dict) and tag.get("key")
    ]


def _matches(tag: dict[str, Any], key: str, value: str | None) -> bool:
    return tag["key"] == key and (value is None or tag["value"] == value)


async def _change_tags(
    kind: IncidentKind,
    incident_id: int,
    action: TagAction,
    read: Callable[[], Awaitable[dict[str, Any]]],
    write: Callable[[list[dict[str, Any]]], Awaitable[dict[str, Any]]],
    key: str,
    value: str | None,
) -> IncidentCustomTagsResult:
    """Read the incident's tags, add or remove one, and write the set back when it changed."""
    try:
        current = _tags_of(await read())
    except Exception as e:
        raise ToolError(str(e))

    if action == "add":
        wanted = (
            current
            if any(tag["key"] == key and tag["value"] == value for tag in current)
            else [
                *current,
                {"key": key, "value": value},
            ]
        )
    else:
        wanted = [tag for tag in current if not _matches(tag, key, value)]

    if wanted == current:
        return IncidentCustomTagsResult(
            incident_kind=kind, incident_id=incident_id, action=action, changed=False, custom_tags=current
        )
    try:
        incident = await write(wanted)
    except Exception as e:
        raise uncertain_write_error(e, check_advice(kind)) or ToolError(str(e))
    tags = _tags_of(incident) if "custom_tags" in incident else wanted
    return IncidentCustomTagsResult(
        incident_kind=kind, incident_id=incident_id, action=action, changed=True, custom_tags=tags
    )


async def add_internal_incident_custom_tag(params: AddInternalIncidentCustomTagParams) -> IncidentCustomTagsResult:
    """Add one custom tag to an internal secret incident, keeping its other tags."""
    client = await get_client()
    return await _change_tags(
        "internal",
        params.incident_id,
        "add",
        incident_reader(client, "internal", params.incident_id),
        lambda tags: client.set_incident_custom_tags(params.incident_id, tags),
        params.key,
        params.value,
    )


async def remove_internal_incident_custom_tag(
    params: RemoveInternalIncidentCustomTagParams,
) -> IncidentCustomTagsResult:
    """Remove one custom tag, or every tag with a key, from an internal secret incident."""
    client = await get_client()
    return await _change_tags(
        "internal",
        params.incident_id,
        "remove",
        incident_reader(client, "internal", params.incident_id),
        lambda tags: client.set_incident_custom_tags(params.incident_id, tags),
        params.key,
        params.value,
    )


async def add_public_incident_custom_tag(params: AddPublicIncidentCustomTagParams) -> IncidentCustomTagsResult:
    """Add one custom tag to a Public Monitoring incident, keeping its other tags."""
    client = await get_client()
    return await _change_tags(
        "public",
        params.incident_id,
        "add",
        incident_reader(client, "public", params.incident_id),
        lambda tags: client.set_public_incident_custom_tags(params.incident_id, tags),
        params.key,
        params.value,
    )


async def remove_public_incident_custom_tag(params: RemovePublicIncidentCustomTagParams) -> IncidentCustomTagsResult:
    """Remove one custom tag, or every tag with a key, from a Public Monitoring incident."""
    client = await get_client()
    return await _change_tags(
        "public",
        params.incident_id,
        "remove",
        incident_reader(client, "public", params.incident_id),
        lambda tags: client.set_public_incident_custom_tags(params.incident_id, tags),
        params.key,
        params.value,
    )


class ListCustomTagsParams(BaseModel):
    """Parameters for listing the workspace's custom tags."""

    key: str | None = Field(default=None, description="Only the tags with this key")
    per_page: PerPage = 20
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListCustomTagsResult(PageOfResults):
    """The workspace's custom tags."""

    custom_tags: list[dict[str, Any]] = Field(description="Custom tags, each with its id, key and value")


async def list_custom_tags(params: ListCustomTagsParams = ListCustomTagsParams()) -> ListCustomTagsResult:
    """List the custom tags defined in the workspace."""
    client = await get_client()
    try:
        response = await client.list_custom_tags(
            key=params.key, per_page=params.per_page, cursor=params.cursor, get_all=params.get_all
        )
    except Exception as e:
        raise ToolError(str(e))
    return ListCustomTagsResult(custom_tags=response["data"], **page_fields(params, response))
