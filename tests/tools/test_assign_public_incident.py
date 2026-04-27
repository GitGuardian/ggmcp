"""
Tests for the assign_public_incident tool.
"""

from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.assign_public_incident import (
    AssignPublicIncidentParams,
    AssignPublicIncidentResult,
    assign_public_incident,
)
from pydantic import ValidationError


def _full_public_incident_payload(incident_id: int = 3759, assignee_id: int = 309) -> dict:
    """Realistic public incident payload as returned by POST .../assign."""
    return {
        "id": incident_id,
        "detector": {
            "name": "slack_bot_token",
            "display_name": "Slack Bot Token",
            "nature": "specific",
            "family": "token",
            "category": "messaging_system",
            "detector_group_name": "slackbot_token",
            "detector_group_display_name": "Slack Bot Token",
        },
        "date": "2019-08-22T14:15:22Z",
        "occurrences_count": 4,
        "status": "ASSIGNED",
        "validity": "valid",
        "severity": "high",
        "assignee_id": assignee_id,
        "assignee_email": "eric@gitguardian.com",
        "tags": ["FROM_HISTORICAL_SCAN"],
        "risk_score": 80,
    }


class TestAssignPublicIncidentParams:
    """Tests for AssignPublicIncidentParams validation."""

    def test_assignee_member_id_alone_is_valid(self):
        """
        GIVEN: Only assignee_member_id is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignPublicIncidentParams(incident_id=123, assignee_member_id=456)
        assert params.assignee_member_id == 456
        assert params.email is None
        assert params.mine is False

    def test_email_alone_is_valid(self):
        """
        GIVEN: Only email is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignPublicIncidentParams(incident_id=123, email="user@example.com")
        assert params.email == "user@example.com"
        assert params.assignee_member_id is None
        assert params.mine is False

    def test_mine_alone_is_valid(self):
        """
        GIVEN: Only mine=True is provided
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = AssignPublicIncidentParams(incident_id=123, mine=True)
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
            AssignPublicIncidentParams(incident_id=123)

        assert "One of assignee_member_id, email, or mine must be provided" in str(exc_info.value)

    def test_multiple_options_raises_error(self):
        """
        GIVEN: Multiple assignee options are provided
        WHEN: Creating the params
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            AssignPublicIncidentParams(incident_id=123, assignee_member_id=456, email="user@example.com")

        assert "Only one of assignee_member_id, email, or mine should be provided" in str(exc_info.value)

    def test_mine_and_member_id_raises_error(self):
        """
        GIVEN: Both mine and assignee_member_id are provided
        WHEN: Creating the params
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            AssignPublicIncidentParams(incident_id=123, assignee_member_id=456, mine=True)

        assert "Only one of assignee_member_id, email, or mine should be provided" in str(exc_info.value)

    def test_send_email_can_be_disabled(self):
        """
        GIVEN: send_email=False is provided alongside a valid assignee option
        WHEN: Creating the params
        THEN: send_email is preserved on the model
        """
        params = AssignPublicIncidentParams(incident_id=123, mine=True, send_email=False)
        assert params.send_email is False


class TestAssignPublicIncident:
    """Tests for the assign_public_incident function."""

    @pytest.mark.asyncio
    async def test_assign_public_incident_by_member_id(self, mock_gitguardian_client):
        """
        GIVEN: A public incident ID and assignee member ID
        WHEN: Assigning the public incident
        THEN: The client is called with member_id and the assignee comes from the API response
        """
        mock_gitguardian_client.assign_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=3759, assignee_id=456)
        )

        result = await assign_public_incident(AssignPublicIncidentParams(incident_id=3759, assignee_member_id=456))

        mock_gitguardian_client.assign_public_incident.assert_called_once_with(
            incident_id=3759,
            assignee_id=456,
            email=None,
            send_email=None,
        )

        assert isinstance(result, AssignPublicIncidentResult)
        assert result.incident_id == 3759
        assert result.assignee_id == 456
        assert result.success is True
        assert result.incident is not None
        assert result.incident["status"] == "ASSIGNED"

    @pytest.mark.asyncio
    async def test_assign_public_incident_by_email_no_member_lookup(self, mock_gitguardian_client):
        """
        GIVEN: A public incident ID and assignee email
        WHEN: Assigning the public incident
        THEN: The API is called with email directly (no /members lookup) and assignee_id
              is recovered from the response
        """
        mock_gitguardian_client.assign_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=3759, assignee_id=789)
        )

        result = await assign_public_incident(AssignPublicIncidentParams(incident_id=3759, email="user@example.com"))

        mock_gitguardian_client.assign_public_incident.assert_called_once_with(
            incident_id=3759,
            assignee_id=None,
            email="user@example.com",
            send_email=None,
        )

        assert not mock_gitguardian_client._request_list.called

        assert result.incident_id == 3759
        assert result.assignee_id == 789
        assert result.success is True

    @pytest.mark.asyncio
    async def test_assign_public_incident_mine_uses_token_info(self, mock_gitguardian_client):
        """
        GIVEN: mine=True
        WHEN: Assigning the public incident
        THEN: The current user's member ID is fetched from token info (not /members)
              and forwarded as member_id
        """
        mock_gitguardian_client.assign_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=3759, assignee_id=480870)
        )

        result = await assign_public_incident(AssignPublicIncidentParams(incident_id=3759, mine=True))

        mock_gitguardian_client.get_current_token_info.assert_called_once()
        mock_gitguardian_client.assign_public_incident.assert_called_once_with(
            incident_id=3759,
            assignee_id=480870,
            email=None,
            send_email=None,
        )

        assert result.incident_id == 3759
        assert result.assignee_id == 480870
        assert result.success is True

    @pytest.mark.asyncio
    async def test_assign_public_incident_forwards_send_email(self, mock_gitguardian_client):
        """
        GIVEN: send_email=False is provided
        WHEN: Assigning the public incident
        THEN: send_email is forwarded to the client method
        """
        mock_gitguardian_client.assign_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=42, assignee_id=480870)
        )

        await assign_public_incident(AssignPublicIncidentParams(incident_id=42, mine=True, send_email=False))

        mock_gitguardian_client.assign_public_incident.assert_called_once_with(
            incident_id=42,
            assignee_id=480870,
            email=None,
            send_email=False,
        )

    @pytest.mark.asyncio
    async def test_assign_public_incident_api_error(self, mock_gitguardian_client):
        """
        GIVEN: A public incident assignment that fails
        WHEN: Assigning the public incident
        THEN: A ToolError is raised with the underlying error message
        """
        from fastmcp.exceptions import ToolError

        mock_gitguardian_client.assign_public_incident = AsyncMock(
            side_effect=Exception("API error: Public incident not found")
        )

        with pytest.raises(ToolError) as exc_info:
            await assign_public_incident(AssignPublicIncidentParams(incident_id=999, assignee_member_id=456))

        assert "API error: Public incident not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_assign_public_incident_mine_no_member_id_in_token(self, mock_gitguardian_client):
        """
        GIVEN: mine=True but the token info does not contain member_id
        WHEN: Assigning the public incident
        THEN: A ToolError is raised
        """
        from fastmcp.exceptions import ToolError

        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"scopes": ["incidents:read"], "id": "token-id"}
        )

        with pytest.raises(ToolError) as exc_info:
            await assign_public_incident(AssignPublicIncidentParams(incident_id=123, mine=True))

        assert "Could not determine current user ID from token info" in str(exc_info.value)
