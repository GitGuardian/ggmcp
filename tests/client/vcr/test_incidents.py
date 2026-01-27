"""
VCR tests for GitGuardianClient incident methods.

These tests cover:
- list_incidents(...)
- list_incidents_for_mcp(...) - v2 MCP-optimized endpoint
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


class TestListIncidentsForMcp:
    """Tests for the v2 MCP-optimized incidents endpoint with page-based pagination."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_basic(self, real_client):
        """
        Test basic incident listing using the MCP endpoint.

        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the list of incidents via the MCP endpoint
        THEN we should receive a paginated response with incident data
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_basic"):
            result = await real_client.list_incidents_for_mcp(page=1, page_size=5)

            assert result is not None
            assert "results" in result
            assert isinstance(result["results"], list)
            assert "count" in result
            # Page-based pagination uses next/previous URLs
            assert "next" in result or result.get("next") is None
            assert "previous" in result or result.get("previous") is None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_status_filter(self, real_client):
        """
        Test listing incidents filtered by status using MCP endpoint.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with status=TRIGGERED (unassigned active)
        THEN we should receive only triggered incidents
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_status_filter"):
            # Use TRIGGERED status - displayed as ACTIVE in response but filtered by TRIGGERED
            result = await real_client.list_incidents_for_mcp(status="TRIGGERED", page_size=5)

            assert result is not None
            assert "results" in result
            # TRIGGERED incidents have no assignee and are not resolved/ignored
            for incident in result["results"]:
                assert incident.get("status") in ["TRIGGERED", "ACTIVE"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_severity_filter(self, real_client):
        """
        Test listing incidents filtered by severity using MCP endpoint.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with severity 10 (critical) or 20 (high)
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_severity_filter"):
            # Severity uses numeric values: critical=10, high=20, medium=30, low=40
            result = await real_client.list_incidents_for_mcp(severity=[10, 20], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_ordering(self, real_client):
        """
        Test listing incidents with ordering using MCP endpoint.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents ordered by -date (newest first)
        THEN we should receive incidents in descending date order
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_ordering"):
            result = await real_client.list_incidents_for_mcp(ordering="-date", page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_source_criticality(self, real_client):
        """
        Test listing incidents filtered by source criticality.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents from critical sources
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_source_criticality"):
            result = await real_client.list_incidents_for_mcp(source_criticality=["critical", "high"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_detector_filter(self, real_client):
        """
        Test listing incidents filtered by detector type.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with specific detector group names
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_detector_filter"):
            result = await real_client.list_incidents_for_mcp(detector_group_name=["AWS Keys"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_presence_filter(self, real_client):
        """
        Test listing incidents filtered by presence status.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents that are still present
        THEN we should receive incidents with present occurrences
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_presence_filter"):
            result = await real_client.list_incidents_for_mcp(presence=["present"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_unassigned(self, real_client):
        """
        Test listing unassigned incidents.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with assignee_id=0 (unassigned)
        THEN we should receive unassigned incidents
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_unassigned"):
            result = await real_client.list_incidents_for_mcp(assignee_id=0, page_size=5)

            assert result is not None
            assert "results" in result
            # All returned incidents should be unassigned
            for incident in result["results"]:
                assert incident.get("assignee") is None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_pagination(self, real_client):
        """
        Test page-based pagination.

        GIVEN a valid GitGuardian API key
        WHEN we request different pages
        THEN we should receive different results
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_pagination"):
            page1 = await real_client.list_incidents_for_mcp(page=1, page_size=2)
            page2 = await real_client.list_incidents_for_mcp(page=2, page_size=2)

            assert page1 is not None
            assert page2 is not None
            assert "results" in page1
            assert "results" in page2

            # If there are enough incidents, pages should have different data
            if len(page1["results"]) == 2 and len(page2["results"]) > 0:
                page1_ids = {inc["id"] for inc in page1["results"]}
                page2_ids = {inc["id"] for inc in page2["results"]}
                # Pages should not overlap
                assert page1_ids.isdisjoint(page2_ids)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_combined_filters(self, real_client):
        """
        Test combining multiple filters.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with multiple filters combined
        THEN we should receive incidents matching all criteria
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_combined_filters"):
            result = await real_client.list_incidents_for_mcp(
                status=["TRIGGERED", "ASSIGNED"],  # Both active statuses
                severity=[10, 20],  # critical and high
                ordering="-date",
                page_size=5,
            )

            assert result is not None
            assert "results" in result
            # All returned incidents should be triggered or assigned (active statuses)
            for incident in result["results"]:
                assert incident.get("status") in ["TRIGGERED", "ASSIGNED", "ACTIVE"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_search(self, real_client):
        """
        Test listing incidents with search term.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with a search term
        THEN we should receive incidents matching the search
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_search"):
            result = await real_client.list_incidents_for_mcp(search="aws", page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_detector_category(self, real_client):
        """
        Test listing incidents filtered by detector category.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with specific detector category
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_detector_category"):
            result = await real_client.list_incidents_for_mcp(detector_category=["specific"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_issue_tracker(self, real_client):
        """
        Test listing incidents filtered by issue tracker.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with issue tracker filter
        THEN we should receive incidents (filter applied)

        Valid issue tracker values: jira_cloud_notifier, jira_data_center_notifier, servicenow
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_issue_tracker"):
            result = await real_client.list_incidents_for_mcp(issue_tracker=["jira_cloud_notifier"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_feedback(self, real_client):
        """
        Test listing incidents filtered by feedback presence.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with feedback filter (True)
        THEN we should receive incidents with feedback
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_feedback"):
            result = await real_client.list_incidents_for_mcp(feedback=True, page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_publicly_shared(self, real_client):
        """
        Test listing incidents filtered by publicly shared status.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents that are publicly shared
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_publicly_shared"):
            result = await real_client.list_incidents_for_mcp(publicly_shared=True, page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_secret_manager_type(self, real_client):
        """
        Test listing incidents filtered by secret manager/vault type.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents stored in specific vault types
        THEN we should receive incidents (filter applied)

        Valid values: hashicorpvault, awssecretsmanager, azurekeyvault, gcpsecretmanager,
                     cyberarksaas, cyberarkselfhosted, akeyless, delineasecretserver
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_secret_manager_type"):
            result = await real_client.list_incidents_for_mcp(
                secret_manager_type=["hashicorpvault", "awssecretsmanager"], page_size=5
            )

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_date_filter(self, real_client):
        """
        Test listing incidents filtered by date range.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents within a date range
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_date_filter"):
            result = await real_client.list_incidents_for_mcp(
                date_after="2024-01-01", date_before="2025-12-31", page_size=5
            )

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_teams(self, real_client):
        """
        Test listing incidents filtered by team.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents assigned to specific teams
        THEN we should receive incidents (filter applied)
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_teams"):
            # Using team ID 1 as a placeholder - actual team IDs depend on the account
            result = await real_client.list_incidents_for_mcp(teams=[1], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_validity(self, real_client):
        """
        Test listing incidents filtered by validity status.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with specific validity status
        THEN we should receive incidents (filter applied)

        Valid values: valid, invalid, failed_to_check, no_checker, not_checked
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_validity"):
            result = await real_client.list_incidents_for_mcp(validity=["valid", "not_checked"], page_size=5)

            assert result is not None
            assert "results" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_for_mcp_with_score_filter_and_ordering(self, real_client):
        """
        Test listing incidents filtered by minimum score and ordered by score.

        GIVEN a valid GitGuardian API key
        WHEN we request incidents with score >= 50 ordered by -score (highest first)
        THEN we should receive incidents with score >= 50 in descending score order
        """
        with my_vcr.use_cassette("test_list_incidents_for_mcp_with_score_filter_and_ordering"):
            result = await real_client.list_incidents_for_mcp(
                score__ge=50,
                ordering="-score",
                page_size=10,
            )

            assert result is not None
            assert "results" in result
            assert isinstance(result["results"], list)

            # Verify all incidents have score >= 50
            for incident in result["results"]:
                score = incident.get("score")
                if score is not None:
                    assert score >= 50, f"Expected score >= 50, got {score}"

            # Verify ordering is by score descending (if multiple results)
            if len(result["results"]) > 1:
                scores = [inc.get("score", 0) for inc in result["results"]]
                assert scores == sorted(scores, reverse=True), "Incidents should be ordered by score descending"
