"""
VCR tests for get_incident tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.get_incident import (
    GetIncidentParams,
    GetIncidentResult,
    get_incident,
)


class TestGetIncidentVCR:
    """VCR tests for the get_incident tool."""

    # Note: This incident ID should be replaced with a real one when recording cassettes
    # You can find an incident ID by running: list_incidents with per_page=1
    TEST_INCIDENT_ID = 21460

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incident_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling get_incident with an incident ID
        THEN: Returns the incident details
        """
        with use_cassette("test_get_incident_basic"):
            with patch(
                "gg_api_core.tools.get_incident.get_client",
                return_value=real_client,
            ):
                params = GetIncidentParams(
                    incident_id=self.TEST_INCIDENT_ID,
                )

                result = await get_incident(params)

                assert result is not None
                assert isinstance(result, GetIncidentResult)
                assert result.incident is not None
                assert isinstance(result.incident, dict)
                # Verify basic incident structure
                assert "id" in result.incident
                assert "status" in result.incident
                assert "severity" in result.incident

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incident_with_occurrences(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling get_incident with with_occurrences=5
        THEN: Returns the incident with up to 5 occurrences
        """
        with use_cassette("test_get_incident_with_occurrences"):
            with patch(
                "gg_api_core.tools.get_incident.get_client",
                return_value=real_client,
            ):
                params = GetIncidentParams(
                    incident_id=self.TEST_INCIDENT_ID,
                    with_occurrences=5,
                )

                result = await get_incident(params)

                assert result is not None
                assert isinstance(result, GetIncidentResult)
                assert result.incident is not None
                # Check that occurrences field exists
                assert "occurrences" in result.incident or "occurrences_count" in result.incident

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incident_no_occurrences(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling get_incident with with_occurrences=0
        THEN: Returns the incident without occurrences
        """
        with use_cassette("test_get_incident_no_occurrences"):
            with patch(
                "gg_api_core.tools.get_incident.get_client",
                return_value=real_client,
            ):
                params = GetIncidentParams(
                    incident_id=self.TEST_INCIDENT_ID,
                    with_occurrences=0,
                )

                result = await get_incident(params)

                assert result is not None
                assert isinstance(result, GetIncidentResult)
                assert result.incident is not None
                # With 0 occurrences requested, the occurrences list should be empty
                occurrences = result.incident.get("occurrences", [])
                assert len(occurrences) == 0

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incident_has_detector_info(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling get_incident
        THEN: Returns the incident with detector information
        """
        with use_cassette("test_get_incident_has_detector_info"):
            with patch(
                "gg_api_core.tools.get_incident.get_client",
                return_value=real_client,
            ):
                params = GetIncidentParams(
                    incident_id=self.TEST_INCIDENT_ID,
                )

                result = await get_incident(params)

                assert result is not None
                assert result.incident is not None
                # Verify detector information is present
                assert "detector" in result.incident
                detector = result.incident["detector"]
                assert "name" in detector
                assert "display_name" in detector
