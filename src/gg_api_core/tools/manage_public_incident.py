"""Tool for commenting on a Public Monitoring incident."""

import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.tools.ids import PathId
from gg_api_core.tools.incident_notes import CommentStr
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ManagePublicIncidentParams(BaseModel):
    """Parameters for acting on a Public Monitoring incident."""

    incident_id: PathId = Field(description="ID of the Public Monitoring incident")
    action: Literal["add_comment", "edit_comment"] = Field(
        description="'add_comment' (needs comment), 'edit_comment' (needs comment and comment_id)"
    )
    comment: CommentStr | None = Field(
        default=None, description="For 'add_comment' and 'edit_comment': the comment body (1-10000 characters)"
    )
    comment_id: PathId | None = Field(
        default=None, description="For 'edit_comment': ID of the comment to edit, the id 'add_comment' returned"
    )

    @model_validator(mode="after")
    def check_the_arguments_of_the_action(self):
        """Require what the action needs, and refuse a comment_id when adding a comment."""
        if self.comment is None:
            raise ValueError(f"comment is required when action is '{self.action}'")
        if self.action == "edit_comment" and self.comment_id is None:
            raise ValueError("comment_id is required when action is 'edit_comment'")
        if self.action == "add_comment" and self.comment_id is not None:
            raise ValueError("comment_id must not be provided when action is 'add_comment'")
        return self


async def manage_public_incident(params: ManagePublicIncidentParams) -> dict[str, Any]:
    """Comment on a Public Monitoring incident.

    Args:
        params: ManagePublicIncidentParams with the incident ID, the action, and what the action needs
    """
    client = await get_client()
    incident_id = str(params.incident_id)

    try:
        assert params.comment is not None
        if params.action == "add_comment":
            return await client.create_public_incident_note(incident_id, comment=params.comment)
        return await client.update_public_incident_note(
            incident_id, note_id=str(params.comment_id), comment=params.comment
        )
    except Exception as e:
        raise ToolError(str(e))
