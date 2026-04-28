"""
Tests for the update_public_incident_status tool.
"""

from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.update_public_incident_status import (
    UpdatePublicIncidentStatusParams,
    update_public_incident_status,
)


def _full_public_incident_payload(incident_id: int = 3759, status: str = "RESOLVED") -> dict:
    """Realistic public incident payload as returned by status-update endpoints."""
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
        "status": status,
        "validity": "valid",
        "severity": "high",
        "tags": ["FROM_HISTORICAL_SCAN"],
        "risk_score": 80,
    }


class TestUpdatePublicIncidentStatusParams:
    """Tests for UpdatePublicIncidentStatusParams validation."""

    def test_resolve_action_with_resolve_reason(self):
        """
        GIVEN: A resolve action with a valid resolve_reason
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = UpdatePublicIncidentStatusParams(incident_id=123, action="resolve", resolve_reason="revoked")
        assert params.action == "resolve"
        assert params.resolve_reason == "revoked"

    def test_resolve_action_without_resolve_reason(self):
        """
        GIVEN: A resolve action without a resolve_reason
        WHEN: Creating the params
        THEN: The params are valid (runtime validation will reject the call)
        """
        params = UpdatePublicIncidentStatusParams(incident_id=123, action="resolve")
        assert params.action == "resolve"
        assert params.resolve_reason is None

    def test_ignore_action_with_ignore_reason(self):
        """
        GIVEN: An ignore action with a valid ignore_reason
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = UpdatePublicIncidentStatusParams(incident_id=123, action="ignore", ignore_reason="test_credential")
        assert params.action == "ignore"
        assert params.ignore_reason == "test_credential"

    def test_ignore_action_without_ignore_reason(self):
        """
        GIVEN: An ignore action without an ignore_reason
        WHEN: Creating the params
        THEN: The params are valid (runtime validation will reject the call)
        """
        params = UpdatePublicIncidentStatusParams(incident_id=123, action="ignore")
        assert params.action == "ignore"
        assert params.ignore_reason is None

    def test_reopen_action(self):
        """
        GIVEN: A reopen action
        WHEN: Creating the params
        THEN: The params are valid without additional fields
        """
        params = UpdatePublicIncidentStatusParams(incident_id=123, action="reopen")
        assert params.action == "reopen"


class TestUpdatePublicIncidentStatusResolve:
    """Tests for the resolve action."""

    @pytest.mark.asyncio
    async def test_resolve_without_resolve_reason_raises_error(self, mock_gitguardian_client):
        """
        GIVEN: A resolve action without resolve_reason
        WHEN: Calling update_public_incident_status
        THEN: A ToolError is raised asking for the reason
        """
        with pytest.raises(ToolError) as exc_info:
            await update_public_incident_status(UpdatePublicIncidentStatusParams(incident_id=123, action="resolve"))

        error_message = str(exc_info.value)
        assert "resolve_reason" in error_message
        assert "required" in error_message.lower()
        assert "ask the user" in error_message.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("reason", ["revoked", "dmca_request", "source_deleted"])
    async def test_resolve_with_each_valid_reason(self, mock_gitguardian_client, reason):
        """
        GIVEN: A resolve action with each valid resolve_reason
        WHEN: Calling update_public_incident_status
        THEN: The client is called with the correct reason
        """
        mock_gitguardian_client.resolve_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=123, status="RESOLVED")
        )

        result = await update_public_incident_status(
            UpdatePublicIncidentStatusParams(incident_id=123, action="resolve", resolve_reason=reason)
        )

        mock_gitguardian_client.resolve_public_incident.assert_called_once_with(
            incident_id=123,
            resolve_reason=reason,
        )
        assert result["status"] == "RESOLVED"


class TestUpdatePublicIncidentStatusIgnore:
    """Tests for the ignore action."""

    @pytest.mark.asyncio
    async def test_ignore_without_ignore_reason_raises_error(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action without ignore_reason
        WHEN: Calling update_public_incident_status
        THEN: A ToolError is raised asking for the reason
        """
        with pytest.raises(ToolError) as exc_info:
            await update_public_incident_status(UpdatePublicIncidentStatusParams(incident_id=123, action="ignore"))

        error_message = str(exc_info.value)
        assert "ignore_reason" in error_message
        assert "required" in error_message.lower()
        assert "ask the user" in error_message.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "reason",
        [
            "test_credential",
            "false_positive",
            "low_risk",
            "invalid",
            "ignore_actor",
            "ignore_secret",
        ],
    )
    async def test_ignore_with_each_valid_reason(self, mock_gitguardian_client, reason):
        """
        GIVEN: An ignore action with each valid ignore_reason
        WHEN: Calling update_public_incident_status
        THEN: The client is called with the correct reason
        """
        mock_gitguardian_client.ignore_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=123, status="IGNORED")
        )

        result = await update_public_incident_status(
            UpdatePublicIncidentStatusParams(incident_id=123, action="ignore", ignore_reason=reason)
        )

        mock_gitguardian_client.ignore_public_incident.assert_called_once_with(
            incident_id=123,
            ignore_reason=reason,
        )
        assert result["status"] == "IGNORED"


class TestUpdatePublicIncidentStatusReopen:
    """Tests for the reopen action."""

    @pytest.mark.asyncio
    async def test_reopen_action(self, mock_gitguardian_client):
        """
        GIVEN: A reopen action
        WHEN: Calling update_public_incident_status
        THEN: The reopen client method is called without additional params
        """
        mock_gitguardian_client.reopen_public_incident = AsyncMock(
            return_value=_full_public_incident_payload(incident_id=123, status="TRIGGERED")
        )

        result = await update_public_incident_status(UpdatePublicIncidentStatusParams(incident_id=123, action="reopen"))

        mock_gitguardian_client.reopen_public_incident.assert_called_once_with(incident_id=123)
        assert result["status"] == "TRIGGERED"


class TestUpdatePublicIncidentStatusErrors:
    """Tests for error handling in update_public_incident_status."""

    @pytest.mark.asyncio
    async def test_resolve_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: A resolve API call that raises an exception
        WHEN: Calling update_public_incident_status with valid parameters
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.resolve_public_incident = AsyncMock(
            side_effect=Exception("API error: Public incident not found")
        )

        with pytest.raises(ToolError) as exc_info:
            await update_public_incident_status(
                UpdatePublicIncidentStatusParams(incident_id=999, action="resolve", resolve_reason="revoked")
            )

        assert "API error: Public incident not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_ignore_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: An ignore API call that raises an exception
        WHEN: Calling update_public_incident_status with valid parameters
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.ignore_public_incident = AsyncMock(
            side_effect=Exception("API error: Cannot ignore public incident in current state")
        )

        with pytest.raises(ToolError) as exc_info:
            await update_public_incident_status(
                UpdatePublicIncidentStatusParams(incident_id=123, action="ignore", ignore_reason="low_risk")
            )

        assert "Cannot ignore public incident in current state" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_reopen_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: A reopen API call that raises an exception
        WHEN: Calling update_public_incident_status
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.reopen_public_incident = AsyncMock(
            side_effect=Exception("API error: Public incident not found")
        )

        with pytest.raises(ToolError) as exc_info:
            await update_public_incident_status(UpdatePublicIncidentStatusParams(incident_id=999, action="reopen"))

        assert "API error: Public incident not found" in str(exc_info.value)
