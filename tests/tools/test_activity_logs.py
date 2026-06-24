"""
Tests for the incident activity-log tools.
"""

from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.activity_logs import (
    ListActivityLogsParams,
    ListActivityLogsResult,
    list_incident_activity_logs,
    list_public_incident_activity_logs,
)


def _note_entry(entry_id: int = 9001, incident_id: int = 21460, comment: str = "A note") -> dict:
    """Realistic note activity-log entry as returned by the activity-logs endpoints."""
    return {
        "id": entry_id,
        "incident_id": incident_id,
        "member": {"id": 480870, "name": "Jane Doe", "email": "jane.doe@example.com", "access_level": "owner"},
        "api_token_id": None,
        "created_at": "2026-06-23T10:00:00Z",
        "updated_at": None,
        "content": {"type": "note", "comment": comment},
    }


def _action_entry(entry_id: int = 9002, incident_id: int = 21460, content_key: str = "RESOLVE") -> dict:
    """Realistic system-action activity-log entry."""
    return {
        "id": entry_id,
        "incident_id": incident_id,
        "member": None,
        "api_token_id": None,
        "created_at": "2026-06-23T10:05:00Z",
        "updated_at": None,
        "content": {"type": "action", "content_key": content_key, "data": None},
    }


class TestListIncidentActivityLogs:
    """Tests for the internal incident activity-log tool."""

    @pytest.mark.asyncio
    async def test_list_returns_notes_and_actions(self, mock_gitguardian_client):
        """
        GIVEN an incident with both notes and system actions
        WHEN listing its activity log
        THEN list_incident_activity_logs is called and a ListActivityLogsResult is returned
        """
        mock_gitguardian_client.list_incident_activity_logs = AsyncMock(
            return_value={"data": [_note_entry(), _action_entry()], "cursor": None, "has_more": False}
        )

        result = await list_incident_activity_logs(ListActivityLogsParams(incident_id=21460))

        mock_gitguardian_client.list_incident_activity_logs.assert_called_once_with(
            incident_id=21460, params={"per_page": 20}, get_all=False
        )
        assert isinstance(result, ListActivityLogsResult)
        assert result.total_count == 2
        assert result.has_more is False
        assert {e["content"]["type"] for e in result.activity_logs} == {"note", "action"}

    @pytest.mark.asyncio
    async def test_filters_are_forwarded(self, mock_gitguardian_client):
        """
        GIVEN content_key, member_id, cursor and per_page filters
        WHEN listing the activity log
        THEN every filter is forwarded as a query parameter and pagination metadata is surfaced
        """
        mock_gitguardian_client.list_incident_activity_logs = AsyncMock(
            return_value={"data": [_action_entry()], "cursor": "next-cursor", "has_more": True}
        )

        result = await list_incident_activity_logs(
            ListActivityLogsParams(
                incident_id=21460, content_key="RESOLVE", member_id=480870, cursor="abc", per_page=50
            )
        )

        mock_gitguardian_client.list_incident_activity_logs.assert_called_once_with(
            incident_id=21460,
            params={"per_page": 50, "cursor": "abc", "content_key": "RESOLVE", "member_id": 480870},
            get_all=False,
        )
        assert result.next_cursor == "next-cursor"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_error_is_wrapped(self, mock_gitguardian_client):
        """
        GIVEN the API raises an exception
        WHEN listing the activity log
        THEN a ToolError is raised with the underlying message
        """
        mock_gitguardian_client.list_incident_activity_logs = AsyncMock(side_effect=Exception("boom"))

        with pytest.raises(ToolError) as exc_info:
            await list_incident_activity_logs(ListActivityLogsParams(incident_id=21460))

        assert "boom" in str(exc_info.value)


class TestListPublicIncidentActivityLogs:
    """Tests for the public incident activity-log tool."""

    @pytest.mark.asyncio
    async def test_list_calls_public_method(self, mock_gitguardian_client):
        """
        GIVEN a public incident with activity-log entries
        WHEN listing its activity log
        THEN list_public_incident_activity_logs is called and the entries are returned
        """
        mock_gitguardian_client.list_public_incident_activity_logs = AsyncMock(
            return_value={
                "data": [_note_entry(entry_id=7101, incident_id=3759), _action_entry(entry_id=7102, incident_id=3759)],
                "cursor": None,
                "has_more": False,
            }
        )

        result = await list_public_incident_activity_logs(ListActivityLogsParams(incident_id=3759))

        mock_gitguardian_client.list_public_incident_activity_logs.assert_called_once_with(
            incident_id=3759, params={"per_page": 20}, get_all=False
        )
        assert result.total_count == 2
        assert all(e["incident_id"] == 3759 for e in result.activity_logs)
