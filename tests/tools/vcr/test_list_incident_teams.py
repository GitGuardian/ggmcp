"""
VCR tests for list_incident_teams tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_incident_teams import (
    ListIncidentTeamsParams,
    ListIncidentTeamsResult,
    list_incident_teams,
)


class TestListIncidentTeamsVCR:
    """VCR tests for the list_incident_teams tool.

    These tests cover various parameter combinations for the list_incident_teams tool.
    The tool uses the /incidents/secrets/{incident_id}/teams endpoint to retrieve
    teams with access to a secret incident.
    """

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_teams_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_teams with minimal parameters
        THEN returns a list of teams with access to the incident

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_teams_basic"):
            with patch(
                "gg_api_core.tools.list_incident_teams.get_client",
                return_value=real_client,
            ):
                params = ListIncidentTeamsParams(
                    incident_id=21460,
                    per_page=5,
                )

                result = await list_incident_teams(params)

                assert result is not None
                assert isinstance(result, ListIncidentTeamsResult)
                assert result.teams is not None
                assert isinstance(result.teams, list)
                assert result.total_count >= 0
                # Verify team structure
                if result.teams:
                    team = result.teams[0]
                    assert "team_id" in team
                    assert "incident_id" in team
                    assert "incident_permission" in team

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_teams_with_search(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_teams with a search filter
        THEN returns teams matching the search term

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_teams_with_search"):
            with patch(
                "gg_api_core.tools.list_incident_teams.get_client",
                return_value=real_client,
            ):
                params = ListIncidentTeamsParams(
                    incident_id=21460,
                    search="feature",
                    per_page=10,
                )

                result = await list_incident_teams(params)

                assert result is not None
                assert isinstance(result, ListIncidentTeamsResult)
                assert result.teams is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_teams_with_direct_access(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling list_incident_teams filtered by direct access
        THEN returns only teams with direct access to the incident

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_incident_teams_with_direct_access"):
            with patch(
                "gg_api_core.tools.list_incident_teams.get_client",
                return_value=real_client,
            ):
                params = ListIncidentTeamsParams(
                    incident_id=21460,
                    direct_access=True,
                    per_page=10,
                )

                result = await list_incident_teams(params)

                assert result is not None
                assert isinstance(result, ListIncidentTeamsResult)
                assert result.teams is not None
