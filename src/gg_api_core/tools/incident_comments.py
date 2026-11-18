"""Tools that add or edit a comment on a secret incident, one tool per change and per kind.

Comments are the API's incident notes: free-form text members or API tokens leave on an
incident, carried in the note's ``comment`` field. Internal and public incidents keep
their notes apart, so a note ID belongs to one incident of one kind.
"""

import logging
from collections.abc import Awaitable
from typing import Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, StringConstraints

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.incident_writes import IncidentKind, uncertain_write_error
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

# How to see whether a comment write whose outcome is unknown went through. No tool reads
# a public incident's comments, and adding one again may post it twice.
_COMMENT_CHECK = {
    "internal": {
        "add": "Adding it again may post it twice: read the incident's history with get_internal_incident and "
        "with_history to check",
        "edit": "Read the incident's history with get_internal_incident and with_history to check",
    },
    "public": {
        "add": "Adding it again may post it twice: check the incident in the GitGuardian dashboard",
        "edit": "Check the incident in the GitGuardian dashboard",
    },
}

# The public API limits a comment body to 1-10000 characters (whitespace stripped).
CommentStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10_000)]

COMMENT_DESCRIPTION = "Body of the comment, 1 to 10000 characters"
NEW_COMMENT_DESCRIPTION = "New body of the comment, 1 to 10000 characters. It replaces the old body."
COMMENT_ID_DESCRIPTION = "ID of the comment to replace: the comment_id that adding the comment returned"


class AddInternalIncidentCommentParams(BaseModel):
    """Parameters for adding a comment to an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    comment: CommentStr = Field(description=COMMENT_DESCRIPTION)


class EditInternalIncidentCommentParams(BaseModel):
    """Parameters for replacing the body of a comment on an internal incident."""

    incident_id: NumericId = Field(description="ID of the internal secret incident")
    comment_id: NumericId = Field(description=COMMENT_ID_DESCRIPTION)
    comment: CommentStr = Field(description=NEW_COMMENT_DESCRIPTION)


class AddPublicIncidentCommentParams(BaseModel):
    """Parameters for adding a comment to a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    comment: CommentStr = Field(description=COMMENT_DESCRIPTION)


class EditPublicIncidentCommentParams(BaseModel):
    """Parameters for replacing the body of a comment on a Public Monitoring incident."""

    incident_id: NumericId = Field(description="ID of the Public Monitoring incident")
    comment_id: NumericId = Field(description=COMMENT_ID_DESCRIPTION)
    comment: CommentStr = Field(description=NEW_COMMENT_DESCRIPTION)


class IncidentCommentResult(BaseModel):
    """The comment after it was added or edited."""

    incident_kind: IncidentKind = Field(description="Kind of the incident the comment is on: internal or public")
    incident_id: int = Field(description="ID of the incident the comment is on")
    action: Literal["add", "edit"] = Field(description="The change that was applied")
    comment_id: int | None = Field(description="ID of the comment; pass it as comment_id to edit the comment")
    comment: dict[str, Any] = Field(description="The comment as the API returned it")


async def _apply(
    kind: IncidentKind, incident_id: int, action: Literal["add", "edit"], call: Awaitable[dict[str, Any]]
) -> IncidentCommentResult:
    """Await the API call and describe the comment it added or changed."""
    try:
        note = await call
    except Exception as e:
        raise uncertain_write_error(e, _COMMENT_CHECK[kind][action]) or ToolError(str(e))
    return IncidentCommentResult(
        incident_kind=kind, incident_id=incident_id, action=action, comment_id=note.get("id"), comment=note
    )


async def add_internal_incident_comment(params: AddInternalIncidentCommentParams) -> IncidentCommentResult:
    """Add a comment to an internal secret incident."""
    client = await get_client()
    call = client.create_incident_note(incident_id=params.incident_id, comment=params.comment)
    return await _apply("internal", params.incident_id, "add", call)


async def edit_internal_incident_comment(params: EditInternalIncidentCommentParams) -> IncidentCommentResult:
    """Replace the body of a comment on an internal secret incident."""
    client = await get_client()
    call = client.update_incident_note(
        incident_id=params.incident_id, note_id=params.comment_id, comment=params.comment
    )
    return await _apply("internal", params.incident_id, "edit", call)


async def add_public_incident_comment(params: AddPublicIncidentCommentParams) -> IncidentCommentResult:
    """Add a comment to a Public Monitoring incident."""
    client = await get_client()
    call = client.create_public_incident_note(str(params.incident_id), comment=params.comment)
    return await _apply("public", params.incident_id, "add", call)


async def edit_public_incident_comment(params: EditPublicIncidentCommentParams) -> IncidentCommentResult:
    """Replace the body of a comment on a Public Monitoring incident."""
    client = await get_client()
    call = client.update_public_incident_note(
        str(params.incident_id), note_id=str(params.comment_id), comment=params.comment
    )
    return await _apply("public", params.incident_id, "edit", call)
