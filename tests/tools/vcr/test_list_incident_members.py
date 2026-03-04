"""
VCR tests for list_incident_members tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_incident_members import (
    ListIncidentMembersParams,
    ListIncidentMembersResult,
    list_incident_members,
)


class TestListIncidentMembersVCR:
    """VCR tests for the list_incident_members tool.

    These tests cover various parameter combinations for the list_incident_members tool.
    The tool uses the /incidents/secrets/{incident_id}/members endpoint to retrieve
    members with access to a secret incident.
    """

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_members with minimal parameters
        THEN returns a list of members with access to the incident

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_members_basic"):
            with patch(
                "gg_api_core.tools.list_incident_members.get_client",
                return_value=real_client,
            ):
                params = ListIncidentMembersParams(
                    incident_id=21460,
                    per_page=5,
                )

                result = await list_incident_members(params)

                assert result is not None
                assert isinstance(result, ListIncidentMembersResult)
                assert result.members is not None
                assert isinstance(result.members, list)
                assert result.total_count >= 0
                # Verify member structure
                if result.members:
                    member = result.members[0]
                    assert "id" in member
                    assert "email" in member
                    assert "incident_id" in member
                    assert "incident_permission" in member

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members_with_search(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_members with a search filter
        THEN returns members matching the search term

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_members_with_search"):
            with patch(
                "gg_api_core.tools.list_incident_members.get_client",
                return_value=real_client,
            ):
                params = ListIncidentMembersParams(
                    incident_id=21460,
                    search="gitguardian",
                    per_page=10,
                )

                result = await list_incident_members(params)

                assert result is not None
                assert isinstance(result, ListIncidentMembersResult)
                assert result.members is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members_with_access_level(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_members filtered by access_level
        THEN returns only members with that access level

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_members_with_access_level"):
            with patch(
                "gg_api_core.tools.list_incident_members.get_client",
                return_value=real_client,
            ):
                params = ListIncidentMembersParams(
                    incident_id=21460,
                    access_level="owner",
                    per_page=10,
                )

                result = await list_incident_members(params)

                assert result is not None
                assert isinstance(result, ListIncidentMembersResult)
                assert result.members is not None
                # Verify all returned members have incident permission info
                for member in result.members:
                    assert "incident_permission" in member

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members_with_ordering(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_members with ordering by created_at descending
        THEN returns members sorted by creation date (newest first)

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_members_with_ordering"):
            with patch(
                "gg_api_core.tools.list_incident_members.get_client",
                return_value=real_client,
            ):
                params = ListIncidentMembersParams(
                    incident_id=21460,
                    ordering="-created_at",
                    per_page=10,
                )

                result = await list_incident_members(params)

                assert result is not None
                assert isinstance(result, ListIncidentMembersResult)
                assert result.members is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_members_with_direct_access(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_members filtered by direct access
        THEN returns only members with direct access to the incident

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_members_with_direct_access"):
            with patch(
                "gg_api_core.tools.list_incident_members.get_client",
                return_value=real_client,
            ):
                params = ListIncidentMembersParams(
                    incident_id=21460,
                    direct_access=True,
                    per_page=10,
                )

                result = await list_incident_members(params)

                assert result is not None
                assert isinstance(result, ListIncidentMembersResult)
                assert result.members is not None
