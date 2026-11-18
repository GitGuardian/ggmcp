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


class TestManagePrivateIncidentErrors:
    """Tests for error handling in manage_private_incident."""

    @pytest.mark.asyncio
    async def test_api_error_is_wrapped_in_tool_error(self, mock_gitguardian_client):
        """
        GIVEN: An API call that raises an exception
        WHEN: Calling manage_private_incident
        THEN: The exception is wrapped in a ToolError
        """
        mock_gitguardian_client.unassign_incident = AsyncMock(side_effect=Exception("API error: Incident not found"))

        with pytest.raises(ToolError) as exc_info:
            await manage_private_incident(ManageIncidentParams(incident_id=999, action="unassign"))

        assert "API error: Incident not found" in str(exc_info.value)
