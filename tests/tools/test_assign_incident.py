"""
Tests for the assign_incident tool.
"""

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from gg_api_core.tools.assign_incident import (
    AssignIncidentParams,
    AssignIncidentResult,
    assign_incident,
)


class TestAssignIncidentParams:
    """Tests for AssignIncidentParams validation."""

    def test_no_assignee_option_raises_error(self):
        """
        GIVEN: No assignee option is provided
        WHEN: Creating the params
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            AssignIncidentParams(incident_id=123)

        assert "One of assignee_member_id, email, or mine must be provided" in str(exc_info.value)

    def test_multiple_options_raises_error(self):
        """
        GIVEN: Multiple assignee options are provided
        WHEN: Creating the params
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            AssignIncidentParams(incident_id=123, assignee_member_id=456, email="user@example.com")

        assert "Only one of assignee_member_id, email, or mine should be provided" in str(exc_info.value)


class TestAssignIncident:
    """Tests for the assign_incident function."""

    @pytest.mark.asyncio
    async def test_assign_incident_by_member_id(self, mock_gitguardian_client):
        """
        GIVEN: An incident ID and assignee member ID
        WHEN: Assigning the incident
        THEN: The API is called with the member ID directly
        """
        mock_gitguardian_client.assign_incident = AsyncMock(
            return_value={"id": 123, "assignee_id": 456, "status": "ASSIGNED"}
        )

        result = await assign_incident(AssignIncidentParams(incident_id=123, assignee_member_id=456))

        # Verify the client was called with the correct parameters
        mock_gitguardian_client.assign_incident.assert_called_once_with(
            incident_id="123",
            assignee_id="456",
            email=None,
        )

        # Verify result
        assert isinstance(result, AssignIncidentResult)
        assert result.incident_id == 123
        assert result.assignee_id == 456
        assert result.success is True

    @pytest.mark.asyncio
    async def test_assign_incident_by_email_no_member_lookup(self, mock_gitguardian_client):
        """
        GIVEN: An incident ID and assignee email
        WHEN: Assigning the incident
        THEN: The API is called with the email directly (no /members lookup)

        This test verifies that we don't make an extra API call to /members
        when assigning by email - the email is passed directly to the assign API.
        """
        mock_gitguardian_client.assign_incident = AsyncMock(
            return_value={"id": 123, "assignee_id": 789, "status": "ASSIGNED"}
        )

        result = await assign_incident(AssignIncidentParams(incident_id=123, email="user@example.com"))

        # Verify the client was called with email parameter directly
        mock_gitguardian_client.assign_incident.assert_called_once_with(
            incident_id="123",
            assignee_id=None,
            email="user@example.com",
        )

        # Verify that _request_list (used for /members lookup) was NOT called
        # This ensures we're not making an extra API call
        assert not mock_gitguardian_client._request_list.called

        # Verify result - assignee_id comes from API response
        assert isinstance(result, AssignIncidentResult)
        assert result.incident_id == 123
        assert result.assignee_id == 789
        assert result.success is True

    @pytest.mark.asyncio
    async def test_assign_incident_api_error(self, mock_gitguardian_client):
        """
        GIVEN: An incident assignment that fails
        WHEN: Assigning the incident
        THEN: A ToolError is raised with the error message
        """
        from fastmcp.exceptions import ToolError

        mock_gitguardian_client.assign_incident = AsyncMock(side_effect=Exception("API error: Incident not found"))

        with pytest.raises(ToolError) as exc_info:
            await assign_incident(AssignIncidentParams(incident_id=999, assignee_member_id=456))

        assert "API error: Incident not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_assign_incident_mine_no_member_id_in_token(self, mock_gitguardian_client):
        """
        GIVEN: mine=True but token info doesn't contain member_id
        WHEN: Assigning the incident
        THEN: A ToolError is raised
        """
        from fastmcp.exceptions import ToolError

        # Override the mock to return token info without member_id
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"scopes": ["incidents:read"], "id": "token-id"}
        )

        with pytest.raises(ToolError) as exc_info:
            await assign_incident(AssignIncidentParams(incident_id=123, mine=True))

        assert "Could not determine current user ID from token info" in str(exc_info.value)
