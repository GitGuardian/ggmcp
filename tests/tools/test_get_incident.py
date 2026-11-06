from unittest.mock import AsyncMock

import pytest

from gg_api_core.tools.get_incident import GetIncidentParams, get_incident


class TestGetIncident:
    """Tests for the get_incident tool."""

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
