"""
Tests for the incident comment (note) tools.
"""

from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from gg_api_core.tools.incident_notes import (
    ManageIncidentCommentParams,
    manage_incident_comment,
)


def _note_payload(note_id: int = 42, incident_id: int = 123, comment: str = "Looks like a test credential") -> dict:
    """Realistic note payload as returned by the notes endpoints."""
    return {
        "id": note_id,
        "incident_id": incident_id,
        "member_id": 480870,
        "api_token_id": "11111111-2222-3333-4444-555555555555",
        "created_at": "2026-06-23T10:00:00Z",
        "updated_at": None,
        "comment": comment,
    }


class TestManageIncidentCommentParams:
    """Tests for ManageIncidentCommentParams validation."""

    def test_add_action_is_valid(self):
        """
        GIVEN action='add' with a comment and no comment_id
        WHEN creating the params
        THEN the params are valid
        """
        params = ManageIncidentCommentParams(incident_id=123, action="add", comment="A new comment")
        assert params.action == "add"
        assert params.comment_id is None

    def test_edit_action_with_comment_id_is_valid(self):
        """
        GIVEN action='edit' with a comment_id
        WHEN creating the params
        THEN the params are valid
        """
        params = ManageIncidentCommentParams(incident_id=123, action="edit", comment="Edited", comment_id=42)
        assert params.action == "edit"
        assert params.comment_id == 42

    def test_edit_without_comment_id_raises_error(self):
        """
        GIVEN action='edit' without a comment_id
        WHEN creating the params
        THEN a validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            ManageIncidentCommentParams(incident_id=123, action="edit", comment="Edited")

        assert "comment_id is required when action is 'edit'" in str(exc_info.value)

    def test_add_with_comment_id_raises_error(self):
        """
        GIVEN action='add' with a comment_id
        WHEN creating the params
        THEN a validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            ManageIncidentCommentParams(incident_id=123, action="add", comment="New", comment_id=42)

        assert "comment_id must not be provided when action is 'add'" in str(exc_info.value)

    def test_empty_comment_raises_error(self):
        """
        GIVEN a blank comment
        WHEN creating the params
        THEN a validation error is raised (min length 1 after stripping)
        """
        with pytest.raises(ValidationError):
            ManageIncidentCommentParams(incident_id=123, action="add", comment="   ")

    def test_comment_too_long_raises_error(self):
        """
        GIVEN a comment longer than 10000 characters
        WHEN creating the params
        THEN a validation error is raised
        """
        with pytest.raises(ValidationError):
            ManageIncidentCommentParams(incident_id=123, action="add", comment="x" * 10_001)

    def test_comment_is_stripped(self):
        """
        GIVEN a comment with surrounding whitespace
        WHEN creating the params
        THEN the comment is stripped
        """
        params = ManageIncidentCommentParams(incident_id=123, action="add", comment="  hello  ")
        assert params.comment == "hello"


class TestManageIncidentComment:
    """Tests for the manage_incident_comment function (internal incidents)."""

    @pytest.mark.asyncio
    async def test_add_calls_create(self, mock_gitguardian_client):
        """
        GIVEN action='add'
        WHEN managing the comment
        THEN create_incident_note is called and the created note is returned
        """
        mock_gitguardian_client.create_incident_note = AsyncMock(return_value=_note_payload())

        result = await manage_incident_comment(
            ManageIncidentCommentParams(incident_id=123, action="add", comment="Looks like a test credential")
        )

        mock_gitguardian_client.create_incident_note.assert_called_once_with(
            incident_id=123, comment="Looks like a test credential"
        )
        assert result["id"] == 42
        assert result["comment"] == "Looks like a test credential"

    @pytest.mark.asyncio
    async def test_edit_calls_update(self, mock_gitguardian_client):
        """
        GIVEN action='edit' with a comment_id
        WHEN managing the comment
        THEN update_incident_note is called with the note id
        """
        mock_gitguardian_client.update_incident_note = AsyncMock(return_value=_note_payload(comment="Updated comment"))

        result = await manage_incident_comment(
            ManageIncidentCommentParams(incident_id=123, action="edit", comment="Updated comment", comment_id=42)
        )

        mock_gitguardian_client.update_incident_note.assert_called_once_with(
            incident_id=123, note_id=42, comment="Updated comment"
        )
        assert result["comment"] == "Updated comment"

    @pytest.mark.asyncio
    async def test_api_error_is_wrapped(self, mock_gitguardian_client):
        """
        GIVEN the API raises an exception
        WHEN managing the comment
        THEN a ToolError is raised with the underlying message
        """
        mock_gitguardian_client.create_incident_note = AsyncMock(side_effect=Exception("API error: forbidden"))

        with pytest.raises(ToolError) as exc_info:
            await manage_incident_comment(ManageIncidentCommentParams(incident_id=123, action="add", comment="hi"))

        assert "API error: forbidden" in str(exc_info.value)
