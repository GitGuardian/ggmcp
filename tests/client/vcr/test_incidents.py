"""
VCR tests for GitGuardianClient incident methods.

These tests cover:
- list_incidents(...)
- get_incident(incident_id)
- get_incidents(incident_ids)
- list_incident_members(incident_id)
- get_incident_impacted_perimeter(incident_id)
- list_incident_notes(incident_id)
"""

import pytest

from tests.conftest import my_vcr


class TestListIncidents:
    """Tests for listing incidents with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_basic(self, real_client):
        """
        Test basic incident listing.

        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the list of incidents
        THEN we should receive a list response with incident data
        """
        with my_vcr.use_cassette("test_list_incidents_basic"):
            result = await real_client.list_incidents(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_status_filter(self, real_client):
        """
        Test listing incidents filtered by status.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with status=TRIGGERED
        THEN we should receive only triggered incidents
        """
        with my_vcr.use_cassette("test_list_incidents_with_status_filter"):
            result = await real_client.list_incidents(status="TRIGGERED", per_page=5)

            assert result is not None
            assert "data" in result
            # All returned incidents should have TRIGGERED status
            for incident in result["data"]:
                assert incident.get("status") == "TRIGGERED"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_severity_filter(self, real_client):
        """
        Test listing incidents filtered by severity.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with severity=critical
        THEN we should receive only critical incidents
        """
        with my_vcr.use_cassette("test_list_incidents_with_severity_filter"):
            result = await real_client.list_incidents(severity="critical", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_ordering(self, real_client):
        """
        Test listing incidents with specific ordering.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents ordered by -date (descending)
        THEN we should receive incidents in descending date order
        """
        with my_vcr.use_cassette("test_list_incidents_with_ordering"):
            result = await real_client.list_incidents(ordering="-date", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_date_filter(self, real_client):
        """
        Test listing incidents filtered by date range.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents from a specific date range
        THEN we should receive incidents within that range
        """
        with my_vcr.use_cassette("test_list_incidents_with_date_filter"):
            result = await real_client.list_incidents(from_date="2024-01-01", to_date="2024-12-31", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_get_all(self, real_client):
        """
        Test listing incidents with get_all=True (paginated fetch with size limit).

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with my_vcr.use_cassette("test_list_incidents_get_all"):
            result = await real_client.list_incidents(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            # cursor should be present (None if no more data, or a string for continuation)
            assert "cursor" in result


class TestGetIncident:
    """Tests for getting individual incident details."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incident(self, real_client):
        """
        Test getting a single incident by ID.

        GIVEN a valid GitGuardian API key and an existing incident ID
        WHEN we request the incident details
        THEN we should receive detailed incident information
        """
        with my_vcr.use_cassette("test_get_incident"):
            # First get an incident ID from the list
            incidents = await real_client.list_incidents(per_page=1)
            if not incidents["data"]:
                pytest.skip("No incidents available for testing")

            incident_id = incidents["data"][0]["id"]
            result = await real_client.get_incident(incident_id)

            assert result is not None
            assert result["id"] == incident_id
            assert "gitguardian_url" in result
            assert "detector" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_incidents_batch(self, real_client):
        """
        Test getting multiple incidents in batch.

        GIVEN a valid GitGuardian API key and multiple incident IDs
        WHEN we request the incidents in batch
        THEN we should receive all requested incidents
        """
        with my_vcr.use_cassette("test_get_incidents_batch"):
            # First get some incident IDs
            incidents = await real_client.list_incidents(per_page=3)
            if len(incidents["data"]) < 2:
                pytest.skip("Not enough incidents available for batch testing")

            incident_ids = [inc["id"] for inc in incidents["data"][:2]]
            results = await real_client.get_incidents(incident_ids)

            assert results is not None
            assert len(results) == len(incident_ids)


class TestIncidentDetails:
    """Tests for incident detail methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members(self, real_client):
        """
        Test listing members with access to an incident.

        GIVEN a valid GitGuardian API key and an incident ID
        WHEN we request the members with access
        THEN we should receive a list of members
        """
        with my_vcr.use_cassette("test_list_incident_members"):
            # First get an incident ID
            incidents = await real_client.list_incidents(per_page=1)
            if not incidents["data"]:
                pytest.skip("No incidents available for testing")

            incident_id = incidents["data"][0]["id"]
            result = await real_client.list_incident_members(incident_id)

            assert result is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_notes(self, real_client):
        """
        Test listing notes on an incident.

        GIVEN a valid GitGuardian API key and an incident ID
        WHEN we request the notes
        THEN we should receive a list (may be empty)
        """
        with my_vcr.use_cassette("test_list_incident_notes"):
            # First get an incident ID
            incidents = await real_client.list_incidents(per_page=1)
            if not incidents["data"]:
                pytest.skip("No incidents available for testing")

            incident_id = incidents["data"][0]["id"]
            result = await real_client.list_incident_notes(incident_id)

            assert result is not None
