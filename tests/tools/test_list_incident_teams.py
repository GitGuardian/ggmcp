"""
Tests for list_incident_teams tool.
"""

from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.list_incident_teams import (
    ListIncidentTeamsParams,
    ListIncidentTeamsResult,
    list_incident_teams,
)


class TestListIncidentTeams:
    """Tests for the list_incident_teams tool."""

    @pytest.mark.asyncio
    async def test_list_incident_teams_basic(self):
        """
        GIVEN a valid incident ID
        WHEN calling list_incident_teams with minimal parameters
        THEN returns a list of teams with access to the incident
        """
        mock_client = AsyncMock()
        mock_client.list_incident_teams.return_value = {
            "data": [
                {
                    "team_id": 304856,
                    "incident_id": 42,
                    "incident_permission": "full_access",
                }
            ],
            "cursor": None,
            "has_more": False,
        }

        with patch(
            "gg_api_core.tools.list_incident_teams.get_client",
            return_value=mock_client,
        ):
            params = ListIncidentTeamsParams(incident_id=42)
            result = await list_incident_teams(params)

            assert isinstance(result, ListIncidentTeamsResult)
            assert result.total_count == 1
            assert result.teams[0]["team_id"] == 304856
            assert result.has_more is False
            assert result.next_cursor is None

            mock_client.list_incident_teams.assert_called_once_with(
                incident_id=42,
                params={"per_page": 20},
                get_all=False,
            )

    @pytest.mark.asyncio
    async def test_list_incident_teams_with_filters(self):
        """
        GIVEN a valid incident ID and filter parameters
        WHEN calling list_incident_teams with search and direct_access filters
        THEN passes the correct query parameters to the client
        """
        mock_client = AsyncMock()
        mock_client.list_incident_teams.return_value = {
            "data": [],
            "cursor": None,
            "has_more": False,
        }

        with patch(
            "gg_api_core.tools.list_incident_teams.get_client",
            return_value=mock_client,
        ):
            params = ListIncidentTeamsParams(
                incident_id=42,
                search="feature",
                direct_access=True,
                per_page=50,
            )
            result = await list_incident_teams(params)

            assert isinstance(result, ListIncidentTeamsResult)
            assert result.total_count == 0

            mock_client.list_incident_teams.assert_called_once_with(
                incident_id=42,
                params={
                    "per_page": 50,
                    "search": "feature",
                    "direct_access": "true",
                },
                get_all=False,
            )

    @pytest.mark.asyncio
    async def test_list_incident_teams_with_pagination(self):
        """
        GIVEN a valid incident ID and pagination cursor
        WHEN calling list_incident_teams with a cursor
        THEN returns results with pagination info
        """
        mock_client = AsyncMock()
        mock_client.list_incident_teams.return_value = {
            "data": [{"id": 1, "name": "Team 1"}],
            "cursor": "next_page_cursor",
            "has_more": True,
        }

        with patch(
            "gg_api_core.tools.list_incident_teams.get_client",
            return_value=mock_client,
        ):
            params = ListIncidentTeamsParams(
                incident_id=42,
                cursor="some_cursor",
            )
            result = await list_incident_teams(params)

            assert result.has_more is True
            assert result.next_cursor == "next_page_cursor"

    @pytest.mark.asyncio
    async def test_list_incident_teams_get_all(self):
        """
        GIVEN a valid incident ID with get_all=True
        WHEN calling list_incident_teams
        THEN passes get_all=True to the client
        """
        mock_client = AsyncMock()
        mock_client.list_incident_teams.return_value = {
            "data": [{"id": 1}, {"id": 2}],
            "cursor": None,
            "has_more": False,
        }

        with patch(
            "gg_api_core.tools.list_incident_teams.get_client",
            return_value=mock_client,
        ):
            params = ListIncidentTeamsParams(incident_id=42, get_all=True)
            result = await list_incident_teams(params)

            assert result.total_count == 2
            mock_client.list_incident_teams.assert_called_once_with(
                incident_id=42,
                params={"per_page": 20},
                get_all=True,
            )

    @pytest.mark.asyncio
    async def test_list_incident_teams_direct_access_false(self):
        """
        GIVEN a valid incident ID with direct_access=False
        WHEN calling list_incident_teams
        THEN passes direct_access=false as string to the client
        """
        mock_client = AsyncMock()
        mock_client.list_incident_teams.return_value = {
            "data": [],
            "cursor": None,
            "has_more": False,
        }

        with patch(
            "gg_api_core.tools.list_incident_teams.get_client",
            return_value=mock_client,
        ):
            params = ListIncidentTeamsParams(incident_id=42, direct_access=False)
            result = await list_incident_teams(params)

            assert isinstance(result, ListIncidentTeamsResult)
            mock_client.list_incident_teams.assert_called_once_with(
                incident_id=42,
                params={"per_page": 20, "direct_access": "false"},
                get_all=False,
            )
