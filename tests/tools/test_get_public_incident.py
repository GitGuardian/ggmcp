from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError

from gg_api_core.tools.get_public_incident import GetPublicIncidentParams, get_public_incident


class TestGetPublicIncident:
    """Tests for the get_public_incident tool."""

    @pytest.mark.asyncio
    async def test_get_public_incident_success(self, mock_gitguardian_client):
        """
        GIVEN: A public incident exists in GitGuardian
        WHEN: Retrieving the public incident by id
        THEN: The API is called with the id and the incident payload is returned
        """
        mock_response = {
            "id": 3759,
            "date": "2019-08-22T14:15:22Z",
            "detector": {
                "name": "slack_bot_token",
                "display_name": "Slack Bot Token",
                "nature": "specific",
                "family": "token",
                "category": "messaging_system",
                "detector_group_name": "slackbot_token",
                "detector_group_display_name": "Slack Bot Token",
            },
            "status": "IGNORED",
            "severity": "high",
            "validity": "valid",
            "occurrences_count": 4,
            "risk_score": 80,
            "assignee_id": 309,
            "assignee_email": "eric@gitguardian.com",
            "tags": ["FROM_HISTORICAL_SCAN", "INTERNALLY_LEAKED"],
            "share_url": "https://dashboard.gitguardian.com/share/public-incidents/xxx",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/public-incidents/3759",
        }
        mock_gitguardian_client.get_public_incident = AsyncMock(return_value=mock_response)

        result = await get_public_incident(GetPublicIncidentParams(incident_id=3759))

        mock_gitguardian_client.get_public_incident.assert_called_once_with(incident_id=3759)
        assert result.incident["id"] == 3759
        assert result.incident["status"] == "IGNORED"
        assert result.incident["severity"] == "high"
        assert result.incident["risk_score"] == 80
        assert "FROM_HISTORICAL_SCAN" in result.incident["tags"]

    @pytest.mark.asyncio
    async def test_get_public_incident_not_found(self, mock_gitguardian_client):
        """
        GIVEN: A public incident does not exist
        WHEN: Retrieving it by id
        THEN: A ToolError is raised carrying the underlying error message
        """
        mock_gitguardian_client.get_public_incident = AsyncMock(side_effect=Exception("Public incident not found"))

        with pytest.raises(ToolError) as excinfo:
            await get_public_incident(GetPublicIncidentParams(incident_id=99999))

        assert "Public incident not found" in str(excinfo.value)
