"""
Tests for the manage_private_incident tool.
"""

from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.manage_incident import (
    ManageIncidentParams,
    manage_private_incident,
)


class TestManageIncidentParams:
    """Tests for ManageIncidentParams validation."""

    def test_resolve_action_without_secret_revoked(self):
        """
        GIVEN: A resolve action without secret_revoked
        WHEN: Creating the params
        THEN: The params are valid (validation happens at runtime)
        """
        params = ManageIncidentParams(incident_id=123, action="resolve")
        assert params.action == "resolve"
        assert params.secret_revoked is None

    def test_resolve_action_with_secret_revoked_true(self):
        """
        GIVEN: A resolve action with secret_revoked=True
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = ManageIncidentParams(incident_id=123, action="resolve", secret_revoked=True)
        assert params.action == "resolve"
        assert params.secret_revoked is True

    def test_resolve_action_with_secret_revoked_false(self):
        """
        GIVEN: A resolve action with secret_revoked=False
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = ManageIncidentParams(incident_id=123, action="resolve", secret_revoked=False)
        assert params.action == "resolve"
        assert params.secret_revoked is False

    def test_ignore_action_without_ignore_reason(self):
        """
        GIVEN: An ignore action without ignore_reason
        WHEN: Creating the params
        THEN: The params are valid (validation happens at runtime)
        """
        params = ManageIncidentParams(incident_id=123, action="ignore")
        assert params.action == "ignore"
        assert params.ignore_reason is None

    def test_ignore_action_with_ignore_reason(self):
        """
        GIVEN: An ignore action with a valid ignore_reason
        WHEN: Creating the params
        THEN: The params are valid
        """
        params = ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="test_credential")
        assert params.action == "ignore"
        assert params.ignore_reason == "test_credential"

    def test_unassign_action(self):
        """
        GIVEN: An unassign action
        WHEN: Creating the params
        THEN: The params are valid without additional fields
        """
        params = ManageIncidentParams(incident_id=123, action="unassign")
        assert params.action == "unassign"

    def test_reopen_action(self):
        """
        GIVEN: A reopen action
        WHEN: Creating the params
        THEN: The params are valid without additional fields
        """
        params = ManageIncidentParams(incident_id=123, action="reopen")
        assert params.action == "reopen"


class TestManagePrivateIncidentResolve:
    """Tests for the manage_private_incident function - resolve action."""

    @pytest.mark.asyncio
    async def test_resolve_without_secret_revoked_raises_error(self, mock_gitguardian_client):
        """
        GIVEN: A resolve action without secret_revoked parameter
        WHEN: Calling manage_private_incident
        THEN: A ToolError is raised asking to get the information from the user
        """
        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(ManageIncidentParams(incident_id=123, action="resolve"))

        error_message = str(exc_info.value)
        assert "secret_revoked" in error_message
        assert "required" in error_message.lower()
        assert "ask the user" in error_message.lower()

    @pytest.mark.asyncio
    async def test_resolve_with_secret_revoked_true(self, mock_gitguardian_client):
        """
        GIVEN: A resolve action with secret_revoked=True
        WHEN: Calling manage_private_incident
        THEN: The API is called with secret_revoked=True
        """
        mock_gitguardian_client.resolve_incident = AsyncMock(return_value={"id": 123, "status": "RESOLVED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="resolve", secret_revoked=True)
        )

        mock_gitguardian_client.resolve_incident.assert_called_once_with(
            incident_id="123",
            secret_revoked=True,
        )
        assert result["status"] == "RESOLVED"

    @pytest.mark.asyncio
    async def test_resolve_with_secret_revoked_false(self, mock_gitguardian_client):
        """
        GIVEN: A resolve action with secret_revoked=False
        WHEN: Calling manage_private_incident
        THEN: The API is called with secret_revoked=False
        """
        mock_gitguardian_client.resolve_incident = AsyncMock(return_value={"id": 123, "status": "RESOLVED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="resolve", secret_revoked=False)
        )

        mock_gitguardian_client.resolve_incident.assert_called_once_with(
            incident_id="123",
            secret_revoked=False,
        )
        assert result["status"] == "RESOLVED"


class TestManagePrivateIncidentIgnore:
    """Tests for the manage_private_incident function - ignore action."""

    @pytest.mark.asyncio
    async def test_ignore_without_ignore_reason_raises_error(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action without ignore_reason parameter
        WHEN: Calling manage_private_incident
        THEN: A ToolError is raised asking to get the information from the user
        """
        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(ManageIncidentParams(incident_id=123, action="ignore"))

        error_message = str(exc_info.value)
        assert "ignore_reason" in error_message
        assert "required" in error_message.lower()
        assert "ask the user" in error_message.lower()

    @pytest.mark.asyncio
    async def test_ignore_with_test_credential_reason(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action with ignore_reason='test_credential'
        WHEN: Calling manage_private_incident
        THEN: The API is called with the correct ignore_reason
        """
        mock_gitguardian_client.ignore_incident = AsyncMock(return_value={"id": 123, "status": "IGNORED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="test_credential")
        )

        mock_gitguardian_client.ignore_incident.assert_called_once_with(
            incident_id="123",
            ignore_reason="test_credential",
        )
        assert result["status"] == "IGNORED"

    @pytest.mark.asyncio
    async def test_ignore_with_false_positive_reason(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action with ignore_reason='false_positive'
        WHEN: Calling manage_private_incident
        THEN: The API is called with the correct ignore_reason
        """
        mock_gitguardian_client.ignore_incident = AsyncMock(return_value={"id": 123, "status": "IGNORED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="false_positive")
        )

        mock_gitguardian_client.ignore_incident.assert_called_once_with(
            incident_id="123",
            ignore_reason="false_positive",
        )
        assert result["status"] == "IGNORED"

    @pytest.mark.asyncio
    async def test_ignore_with_low_risk_reason(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action with ignore_reason='low_risk'
        WHEN: Calling manage_private_incident
        THEN: The API is called with the correct ignore_reason
        """
        mock_gitguardian_client.ignore_incident = AsyncMock(return_value={"id": 123, "status": "IGNORED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="low_risk")
        )

        mock_gitguardian_client.ignore_incident.assert_called_once_with(
            incident_id="123",
            ignore_reason="low_risk",
        )
        assert result["status"] == "IGNORED"

    @pytest.mark.asyncio
    async def test_ignore_with_invalid_reason(self, mock_gitguardian_client):
        """
        GIVEN: An ignore action with ignore_reason='invalid'
        WHEN: Calling manage_private_incident
        THEN: The API is called with the correct ignore_reason
        """
        mock_gitguardian_client.ignore_incident = AsyncMock(return_value={"id": 123, "status": "IGNORED"})

        result = await manage_private_incident(
            ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="invalid")
        )

        mock_gitguardian_client.ignore_incident.assert_called_once_with(
            incident_id="123",
            ignore_reason="invalid",
        )
        assert result["status"] == "IGNORED"


class TestManagePrivateIncidentOtherActions:
    """Tests for the manage_private_incident function - other actions."""

    @pytest.mark.asyncio
    async def test_unassign_action(self, mock_gitguardian_client):
        """
        GIVEN: An unassign action
        WHEN: Calling manage_private_incident
        THEN: The API is called without requiring additional parameters
        """
        mock_gitguardian_client.unassign_incident = AsyncMock(
            return_value={"id": 123, "status": "TRIGGERED", "assignee_id": None}
        )

        result = await manage_private_incident(ManageIncidentParams(incident_id=123, action="unassign"))

        mock_gitguardian_client.unassign_incident.assert_called_once_with(incident_id="123")
        assert result["assignee_id"] is None

    @pytest.mark.asyncio
    async def test_reopen_action(self, mock_gitguardian_client):
        """
        GIVEN: A reopen action
        WHEN: Calling manage_private_incident
        THEN: The API is called without requiring additional parameters
        """
        mock_gitguardian_client.reopen_incident = AsyncMock(return_value={"id": 123, "status": "TRIGGERED"})

        result = await manage_private_incident(ManageIncidentParams(incident_id=123, action="reopen"))

        mock_gitguardian_client.reopen_incident.assert_called_once_with(incident_id="123")
        assert result["status"] == "TRIGGERED"


class TestManagePrivateIncidentErrors:
    """Tests for error handling in manage_private_incident."""

    @pytest.mark.asyncio
    async def test_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: An API call that raises an exception
        WHEN: Calling manage_private_incident
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.reopen_incident = AsyncMock(side_effect=Exception("API error: Incident not found"))

        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(ManageIncidentParams(incident_id=999, action="reopen"))

        assert "API error: Incident not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resolve_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: A resolve API call that raises an exception
        WHEN: Calling manage_private_incident with valid parameters
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.resolve_incident = AsyncMock(
            side_effect=Exception("API error: Cannot resolve incident in current state")
        )

        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(ManageIncidentParams(incident_id=123, action="resolve", secret_revoked=True))

        assert "Cannot resolve incident in current state" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_ignore_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: An ignore API call that raises an exception
        WHEN: Calling manage_private_incident with valid parameters
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.ignore_incident = AsyncMock(
            side_effect=Exception("API error: Cannot ignore incident in current state")
        )

        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(
                ManageIncidentParams(incident_id=123, action="ignore", ignore_reason="low_risk")
            )

        assert "Cannot ignore incident in current state" in str(exc_info.value)
