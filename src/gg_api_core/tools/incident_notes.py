"""Tool for adding or editing notes (comments) on internal secret incidents.

Notes are free-form comments members or API tokens leave on an incident. The
public API exposes them under ``.../notes`` and the comment body is carried in
the ``comment`` field.
"""

import logging
from typing import Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, StringConstraints, model_validator

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


# The public API limits a comment body to 1-10000 characters (whitespace stripped).
CommentStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10_000)]


class ManageIncidentCommentParams(BaseModel):
    """Parameters for adding or editing a comment on a secret incident."""

    incident_id: int = Field(description="ID of the secret incident to comment on")
    action: Literal["add", "edit"] = Field(
        description="Action to perform: 'add' creates a new comment, 'edit' replaces the body of an existing comment "
        "(requires comment_id)"
    )
    comment: CommentStr = Field(
        description="Body of the comment (1-10000 characters). For 'add' this is the new comment; for 'edit' this "
        "is the replacement text."
    )
    comment_id: int | None = Field(
        default=None,
        description="ID of the comment to edit. Required when action is 'edit'. Use the listing tool to find it.",
    )

    @model_validator(mode="after")
    def validate_comment_id_for_edit(self):
        """Require comment_id for edits and reject it for new comments."""
        if self.action == "edit" and self.comment_id is None:
            raise ValueError("comment_id is required when action is 'edit'")
        if self.action == "add" and self.comment_id is not None:
            raise ValueError("comment_id must not be provided when action is 'add'")
        return self


async def manage_incident_comment(params: ManageIncidentCommentParams) -> dict[str, Any]:
    """
    Add a new comment to an internal secret incident, or edit an existing one.

    - action='add': create a new comment on the incident.
    - action='edit': replace the body of the comment identified by `comment_id`
      (the `id` returned when that comment was added).

    Public Monitoring incident ids are not supported; incident and note ids are
    not interchangeable between the two perimeters.

    Args:
        params: ManageIncidentCommentParams with the incident ID, action, comment
            body, and comment_id (for edits)

    Returns:
        Dictionary containing the created or updated comment data from the API

    Raises:
        ToolError: If the operation fails
    """
    client = await get_client()
    logger.debug(f"Managing comment on incident {params.incident_id} with action: {params.action}")

    try:
        if params.action == "add":
            return await client.create_incident_note(incident_id=params.incident_id, comment=params.comment)

        # action == "edit" (comment_id presence enforced by the validator)
        assert params.comment_id is not None
        return await client.update_incident_note(
            incident_id=params.incident_id,
            note_id=params.comment_id,
            comment=params.comment,
        )
    except Exception as e:
        logger.exception(f"Error managing comment on incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
