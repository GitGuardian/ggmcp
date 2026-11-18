"""Tool for acting on a Public Monitoring incident: assignment and comments."""

import logging
from typing import Any, Literal

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import GitGuardianClient
from gg_api_core.tools.ids import PathId
from gg_api_core.tools.incident_notes import CommentStr
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ManagePublicIncidentParams(BaseModel):
    """Parameters for acting on a Public Monitoring incident."""

    incident_id: PathId = Field(description="ID of the Public Monitoring incident")
    action: Literal["assign", "add_comment", "edit_comment"] = Field(
        description="'assign' (needs one of assignee_member_id, assignee_email or mine), 'add_comment' "
        "(needs comment), 'edit_comment' (needs comment and comment_id)"
    )
    assignee_member_id: int | None = Field(default=None, description="For 'assign': ID of the member to assign")
    assignee_email: str | None = Field(default=None, description="For 'assign': email of the member to assign")
    mine: bool = Field(default=False, description="For 'assign': assign the incident to the current user")
    comment: CommentStr | None = Field(
        default=None, description="For 'add_comment' and 'edit_comment': the comment body (1-10000 characters)"
    )
    comment_id: PathId | None = Field(
        default=None, description="For 'edit_comment': ID of the comment to edit, the id 'add_comment' returned"
    )

    @model_validator(mode="after")
    def check_the_arguments_of_the_action(self):
        """Require what the action needs, and refuse a comment_id when adding a comment."""
        if self.action == "assign":
            chosen = sum([self.assignee_member_id is not None, self.assignee_email is not None, self.mine])
            if chosen != 1:
                raise ValueError("'assign' needs exactly one of assignee_member_id, assignee_email or mine")
        if self.action in ("add_comment", "edit_comment") and self.comment is None:
            raise ValueError(f"comment is required when action is '{self.action}'")
        if self.action == "edit_comment" and self.comment_id is None:
            raise ValueError("comment_id is required when action is 'edit_comment'")
        if self.action == "add_comment" and self.comment_id is not None:
            raise ValueError("comment_id must not be provided when action is 'add_comment'")
        return self


async def manage_public_incident(params: ManagePublicIncidentParams) -> dict[str, Any]:
    """Assign, or comment on, a Public Monitoring incident.

    Args:
        params: ManagePublicIncidentParams with the incident ID, the action, and what the action needs
    """
    client = await get_client()
    incident_id = str(params.incident_id)

    try:
        if params.action == "assign":
            return await _assign(client, incident_id, params)
        assert params.comment is not None
        if params.action == "add_comment":
            return await client.create_public_incident_note(incident_id, comment=params.comment)
        return await client.update_public_incident_note(
            incident_id, note_id=str(params.comment_id), comment=params.comment
        )
    except ToolError:
        raise
    except Exception as e:
        raise ToolError(str(e))


async def _assign(client: GitGuardianClient, incident_id: str, params: ManagePublicIncidentParams) -> dict[str, Any]:
    """Assign the incident to a member ID, an email, or the current user."""
    if params.mine:
        token_info = await client.get_current_token_info()
        member_id = (token_info or {}).get("member_id")
        if member_id is None:
            raise ToolError("This token is not tied to a workspace member, so 'mine' cannot assign the incident.")
        return await client.assign_public_incident(incident_id, assignee_id=str(member_id))
    if params.assignee_member_id is not None:
        return await client.assign_public_incident(incident_id, assignee_id=str(params.assignee_member_id))
    try:
        return await client.assign_public_incident(incident_id, email=params.assignee_email)
    except httpx.HTTPStatusError as e:
        # The API answers an email no member has with a bare "Invalid payload." The address is
        # not repeated here, so the failure log does not record it.
        if e.response.status_code == 400:
            raise ToolError(
                f"{e} This usually means no member of this workspace has that email address. Check it, or "
                "assign the incident by member ID; retrying with the same email will not help."
            ) from e
        raise
