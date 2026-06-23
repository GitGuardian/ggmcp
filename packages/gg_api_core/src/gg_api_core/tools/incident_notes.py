"""Tools for managing notes (comments) on secret incidents.

Notes are free-form comments members or API tokens leave on an incident. The
public API exposes them under ``.../notes`` and the comment body is carried in
the ``comment`` field. Internal incidents and Public Monitoring incidents have
separate, non-interchangeable note collections, so each perimeter gets its own
dedicated tools — mirroring the split used elsewhere (e.g. ``assign_incident``
vs ``assign_public_incident``).
"""

import logging
from typing import Annotated, Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field, StringConstraints, model_validator

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, ListResponse
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


# The public API limits a comment body to 1-10000 characters (whitespace stripped).
CommentStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10_000)]


class ListIncidentCommentsParams(BaseModel):
    """Parameters for listing comments on a secret incident."""

    incident_id: int = Field(description="ID of the secret incident whose comments to list")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching the next page of results")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListCommentsResult(BaseModel):
    """Result from listing comments on a secret incident."""

    comments: list[dict[str, Any]] = Field(description="List of comment objects attached to the incident")
    total_count: int = Field(description="Total number of comments returned")
    next_cursor: str | None = Field(default=None, description="Pagination cursor for next page (if applicable)")
    has_more: bool = Field(default=False, description="True if more results exist (use next_cursor to fetch)")


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


def _build_list_result(result: ListResponse) -> ListCommentsResult:
    """Adapt a client ListResponse into a ListCommentsResult."""
    return ListCommentsResult(
        comments=result["data"],
        total_count=len(result["data"]),
        next_cursor=result["cursor"],
        has_more=result["has_more"],
    )


async def list_incident_comments(params: ListIncidentCommentsParams) -> ListCommentsResult:
    """
    List the comments (notes) left on an internal secret incident.

    Use this to read the discussion on an internal incident, and to find the
    `comment_id` of a comment you want to edit with `manage_incident_comment`.
    For Public Monitoring incidents use `list_public_incident_comments` instead.

    Args:
        params: ListIncidentCommentsParams with the incident ID and pagination options

    Returns:
        ListCommentsResult with the comments, total_count, next_cursor, and has_more

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug(f"Listing comments for incident {params.incident_id}")

    query_params: dict[str, Any] = {"per_page": params.per_page}
    if params.cursor:
        query_params["cursor"] = params.cursor

    try:
        result = await client.list_incident_notes(
            incident_id=params.incident_id,
            params=query_params,
            get_all=params.get_all,
        )
        return _build_list_result(result)
    except Exception as e:
        logger.exception(f"Error listing comments for incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


async def manage_incident_comment(params: ManageIncidentCommentParams) -> dict[str, Any]:
    """
    Add a new comment to an internal secret incident, or edit an existing one.

    - action='add': create a new comment on the incident.
    - action='edit': replace the body of the comment identified by `comment_id`
      (find it with `list_incident_comments`).

    For Public Monitoring incidents use `manage_public_incident_comment` instead;
    note ids are not interchangeable between the two perimeters.

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


async def list_public_incident_comments(params: ListIncidentCommentsParams) -> ListCommentsResult:
    """
    List the comments (notes) left on a public secret incident.

    Public incidents are surfaced by GitGuardian Public Monitoring (public GitHub
    repos/gists, Docker Hub, etc.). Use this to read the discussion on a public
    incident and to find the `comment_id` to edit with
    `manage_public_incident_comment`. For internal incidents use
    `list_incident_comments` instead.

    Args:
        params: ListIncidentCommentsParams with the public incident ID and pagination options

    Returns:
        ListCommentsResult with the comments, total_count, next_cursor, and has_more

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug(f"Listing comments for public incident {params.incident_id}")

    query_params: dict[str, Any] = {"per_page": params.per_page}
    if params.cursor:
        query_params["cursor"] = params.cursor

    try:
        result = await client.list_public_incident_notes(
            incident_id=params.incident_id,
            params=query_params,
            get_all=params.get_all,
        )
        return _build_list_result(result)
    except Exception as e:
        logger.exception(f"Error listing comments for public incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")


async def manage_public_incident_comment(params: ManageIncidentCommentParams) -> dict[str, Any]:
    """
    Add a new comment to a public secret incident, or edit an existing one.

    Public incidents are surfaced by GitGuardian Public Monitoring. Public
    incident IDs are NOT interchangeable with internal incident IDs.

    - action='add': create a new comment on the public incident.
    - action='edit': replace the body of the comment identified by `comment_id`
      (find it with `list_public_incident_comments`).

    For internal incidents use `manage_incident_comment` instead.

    Args:
        params: ManageIncidentCommentParams with the public incident ID, action,
            comment body, and comment_id (for edits)

    Returns:
        Dictionary containing the created or updated comment data from the API

    Raises:
        ToolError: If the operation fails
    """
    client = await get_client()
    logger.debug(f"Managing comment on public incident {params.incident_id} with action: {params.action}")

    try:
        if params.action == "add":
            return await client.create_public_incident_note(incident_id=params.incident_id, comment=params.comment)

        # action == "edit" (comment_id presence enforced by the validator)
        assert params.comment_id is not None
        return await client.update_public_incident_note(
            incident_id=params.incident_id,
            note_id=params.comment_id,
            comment=params.comment,
        )
    except Exception as e:
        logger.exception(f"Error managing comment on public incident {params.incident_id}: {str(e)}")
        raise ToolError(f"Error: {str(e)}")
