from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.get_incident import GetIncidentParams, get_incident


class TestGetIncident:
    """Tests for the get_incident tool."""

    @pytest.mark.asyncio
    async def test_get_incident_success(self, mock_gitguardian_client):
        """
        GIVEN: An incident exists in GitGuardian
        WHEN: Retrieving the incident by ID
        THEN: The API returns the incident details
        """
        mock_response = {
            "id": 3759,
            "date": "2019-08-22T14:15:22Z",
            "detector": {
                "name": "slack_bot_token",
                "display_name": "Slack Bot Token",
                "nature": "specific",
                "family": "apikey",
            },
            "status": "IGNORED",
            "severity": "high",
            "validity": "valid",
            "occurrences_count": 4,
            "occurrences": [
                {
                    "id": 4421,
                    "incident_id": 3759,
                    "kind": "realtime",
                }
            ],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=mock_response)

        result = await get_incident(GetIncidentParams(incident_id=3759))

        mock_gitguardian_client.get_incident.assert_called_once_with(
            incident_id=3759,
            with_occurrences=20,
        )
        assert result.incident is not None
        assert result.incident["id"] == 3759
        assert result.incident["status"] == "IGNORED"
        assert result.incident["severity"] == "high"
        assert len(result.incident["occurrences"]) == 1

    @pytest.mark.asyncio
    async def test_get_incident_with_occurrences(self, mock_gitguardian_client):
        """
        GIVEN: An incident exists with many occurrences
        WHEN: Retrieving the incident with a custom with_occurrences value
        THEN: The API is called with the correct with_occurrences parameter
        """
        mock_response = {
            "id": 1234,
            "status": "TRIGGERED",
            "occurrences": [],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=mock_response)

        await get_incident(GetIncidentParams(incident_id=1234, with_occurrences=50))

        call_kwargs = mock_gitguardian_client.get_incident.call_args.kwargs
        assert call_kwargs["incident_id"] == 1234
        assert call_kwargs["with_occurrences"] == 50

    @pytest.mark.asyncio
    async def test_get_incident_with_zero_occurrences(self, mock_gitguardian_client):
        """
        GIVEN: A user wants incident metadata only
        WHEN: Retrieving the incident with with_occurrences=0
        THEN: The API is called with with_occurrences=0
        """
        mock_response = {
            "id": 5678,
            "status": "RESOLVED",
            "occurrences": [],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=mock_response)

        await get_incident(GetIncidentParams(incident_id=5678, with_occurrences=0))

        call_kwargs = mock_gitguardian_client.get_incident.call_args.kwargs
        assert call_kwargs["with_occurrences"] == 0

    @pytest.mark.asyncio
    async def test_get_incident_with_max_occurrences(self, mock_gitguardian_client):
        """
        GIVEN: A user wants all occurrences
        WHEN: Retrieving the incident with with_occurrences=100
        THEN: The API is called with with_occurrences=100
        """
        mock_response = {
            "id": 9999,
            "status": "ASSIGNED",
            "occurrences": [{"id": i} for i in range(100)],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=mock_response)

        result = await get_incident(GetIncidentParams(incident_id=9999, with_occurrences=100))

        call_kwargs = mock_gitguardian_client.get_incident.call_args.kwargs
        assert call_kwargs["with_occurrences"] == 100
        assert len(result.incident["occurrences"]) == 100

    @pytest.mark.asyncio
    async def test_get_incident_full_response(self, mock_gitguardian_client):
        """
        GIVEN: An incident with all fields populated
        WHEN: Retrieving the incident
        THEN: All fields are returned correctly
        """
        mock_response = {
            "id": 3759,
            "date": "2019-08-22T14:15:22Z",
            "detector": {
                "name": "slack_bot_token",
                "display_name": "Slack Bot Token",
                "nature": "specific",
                "family": "apikey",
                "detector_group_name": "slackbot_token",
                "detector_group_display_name": "Slack Bot Token",
            },
            "secret_hash": "Ri9FjVgdOlPnBmujoxP4XPJcbe82BhJXB/SAngijw/juCISuOMgPzYhV28m6OG24",
            "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/3899",
            "regression": False,
            "status": "IGNORED",
            "assignee_id": 309,
            "assignee_email": "eric@gitguardian.com",
            "occurrences_count": 4,
            "secret_presence": {
                "files_requiring_code_fix": 1,
                "files_pending_merge": 1,
                "files_fixed": 1,
                "outside_vcs": 1,
            },
            "ignore_reason": "test_credential",
            "triggered_at": "2019-05-12T09:37:49Z",
            "ignored_at": "2019-08-24T14:15:22Z",
            "severity": "high",
            "validity": "valid",
            "tags": ["FROM_HISTORICAL_SCAN", "SENSITIVE_FILE"],
            "custom_tags": [{"id": "d45a123f", "key": "env", "value": "prod"}],
            "occurrences": [
                {
                    "id": 4421,
                    "incident_id": 3759,
                    "kind": "realtime",
                    "source": {
                        "id": 6531,
                        "type": "github",
                        "full_name": "gitguardian/gg-shield",
                    },
                }
            ],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=mock_response)

        result = await get_incident(GetIncidentParams(incident_id=3759))

        assert result.incident["id"] == 3759
        assert result.incident["detector"]["name"] == "slack_bot_token"
        assert result.incident["assignee_email"] == "eric@gitguardian.com"
        assert result.incident["ignore_reason"] == "test_credential"
        assert "FROM_HISTORICAL_SCAN" in result.incident["tags"]
        assert result.incident["custom_tags"][0]["key"] == "env"
        assert result.incident["occurrences"][0]["source"]["type"] == "github"

    @pytest.mark.asyncio
    async def test_get_incident_not_found(self, mock_gitguardian_client):
        """
        GIVEN: An incident does not exist
        WHEN: Retrieving the incident by ID
        THEN: A ToolError is raised
        """
        error_message = "Incident not found"
        mock_gitguardian_client.get_incident = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await get_incident(GetIncidentParams(incident_id=99999))

        assert error_message in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_get_incident_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Retrieving an incident
        THEN: A ToolError is raised
        """
        error_message = "API connection failed"
        mock_gitguardian_client.get_incident = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await get_incident(GetIncidentParams(incident_id=1234))

        assert error_message in str(excinfo.value)

    def test_get_incident_params_validation(self):
        """
        GIVEN: Invalid parameter values
        WHEN: Creating GetIncidentParams
        THEN: Validation errors are raised
        """
        # with_occurrences below minimum
        with pytest.raises(ValueError):
            GetIncidentParams(incident_id=1, with_occurrences=-1)

        # with_occurrences above maximum
        with pytest.raises(ValueError):
            GetIncidentParams(incident_id=1, with_occurrences=101)

    def test_get_incident_params_defaults(self):
        """
        GIVEN: Only required parameters
        WHEN: Creating GetIncidentParams
        THEN: Default values are applied
        """
        params = GetIncidentParams(incident_id=123)
        assert params.incident_id == 123
        assert params.with_occurrences == 20
