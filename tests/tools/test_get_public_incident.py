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
    async def test_get_public_incident_full_response(self, mock_gitguardian_client):
        """
        GIVEN: A public incident with every documented field populated
        WHEN: Retrieving it
        THEN: Every field is passed through unchanged on the returned model
        """
        mock_response = {
            "id": 3759,
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
            "secret_id": 1,
            "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
            "hmsl_hash": "05975add34ddc9a38a0fb57c7d3e676ffed57080516fc16bf8d8f14308fedb86",
            "occurrences_count": 4,
            "status": "IGNORED",
            "triggered_at": "2019-05-12T09:37:49Z",
            "ignored_at": "2019-08-24T14:15:22Z",
            "ignore_reason": "test_credential,ignore_actor",
            "ignorer_id": 309,
            "ignorer_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
            "resolved_at": None,
            "resolver_id": 395,
            "resolver_api_token_id": "fdf075f9-1662-4cf1-9171-af50568158a8",
            "secret_revoked": False,
            "validity": "valid",
            "severity": "high",
            "assignee_id": 309,
            "assignee_email": "eric@gitguardian.com",
            "share_url": "https://dashboard.gitguardian.com/share/public-incidents/uuid",
            "feedback_list": [],
            "declarative_secret_status": "revoked",
            "resolve_reason": "revoked",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/public-incidents/3759",
            "tags": ["FROM_HISTORICAL_SCAN", "INTERNALLY_LEAKED"],
            "custom_tags": [{"id": "d45a123f", "key": "env", "value": "prod"}],
            "risk_score": 80,
            "severity_rule_id": 42,
            "incident_name": "Slack Bot Token",
            "is_vaulted": False,
        }
        mock_gitguardian_client.get_public_incident = AsyncMock(return_value=mock_response)

        result = await get_public_incident(GetPublicIncidentParams(incident_id=3759))

        assert result.incident == mock_response

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

    @pytest.mark.asyncio
    async def test_get_public_incident_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The HTTP client raises
        WHEN: Retrieving a public incident
        THEN: A ToolError is raised
        """
        mock_gitguardian_client.get_public_incident = AsyncMock(side_effect=Exception("API connection failed"))

        with pytest.raises(ToolError) as excinfo:
            await get_public_incident(GetPublicIncidentParams(incident_id=1234))

        assert "API connection failed" in str(excinfo.value)

    def test_get_public_incident_params_requires_incident_id(self):
        """
        GIVEN: No incident_id provided
        WHEN: Creating GetPublicIncidentParams
        THEN: A validation error is raised
        """
        with pytest.raises(ValueError):
            GetPublicIncidentParams()  # type: ignore[call-arg]
