"""
Tests for the assign_incident tool.
"""

from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.assign_incident import (
    AssignIncidentParams,
    AssignIncidentResult,
    assign_incident,
)
from pydantic import ValidationError


class TestAssignIncidentParams:
    """Tests for AssignIncidentParams validation."""

    def test_assignee_member_id_alone_is_valid(self):
        """
        GIVEN: Only assignee_member_id is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignIncidentParams(incident_id=123, assignee_member_id=456)
        assert params.assignee_member_id == 456
        assert params.email is None
        assert params.mine is False

    def test_email_alone_is_valid(self):
        """
        GIVEN: Only email is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignIncidentParams(incident_id=123, email="user@example.com")
        assert params.email == "user@example.com"
        assert params.assignee_member_id is None
        assert params.mine is False

    def test_mine_alone_is_valid(self):
        """
        GIVEN: Only mine=True is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignIncidentParams(incident_id=123, mine=True)
        assert params.mine is True
        assert params.assignee_member_id is None
        assert params.email is None

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

    def test_mine_and_member_id_raises_error(self):
        """
        GIVEN: Both mine and assignee_member_id are provided
        WHEN: Creating the params
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            AssignIncidentParams(incident_id=123, assignee_member_id=456, mine=True)

        assert "Only one of assignee_member_id, email, or mine should be provided" in str(exc_info.value)

    def test_model_validator_returns_valid_instance(self):
        """
        GIVEN: Valid parameters
        WHEN: Creating the params (which triggers model_validator)
        THEN: The model instance is not None and is properly constructed
        """
        params = AssignIncidentParams(incident_id=123, email="test@example.com")
        assert params is not None
        assert isinstance(params, AssignIncidentParams)


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
    async def test_assign_incident_mine_uses_token_info(self, mock_gitguardian_client):
        """
        GIVEN: mine=True
        WHEN: Assigning the incident
        THEN: The current user's member ID is fetched from token info (not /members)

        This test verifies that we use get_current_token_info() instead of
        get_current_member() to avoid requiring members:read scope.
        """
        mock_gitguardian_client.assign_incident = AsyncMock(
            return_value={"id": 123, "assignee_id": 480870, "status": "ASSIGNED"}
        )

        result = await assign_incident(AssignIncidentParams(incident_id=123, mine=True))

        # Verify get_current_token_info was called (not get_current_member)
        mock_gitguardian_client.get_current_token_info.assert_called_once()

        # Verify the client was called with the member ID from token info
        mock_gitguardian_client.assign_incident.assert_called_once_with(
            incident_id="123",
            assignee_id="480870",  # From conftest mock: member_id=480870
            email=None,
        )

        # Verify result
        assert isinstance(result, AssignIncidentResult)
        assert result.incident_id == 123
        assert result.assignee_id == 480870
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
