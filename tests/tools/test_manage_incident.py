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


class TestManagePrivateIncidentIgnore:
    """Tests for the manage_private_incident function - ignore action."""

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
