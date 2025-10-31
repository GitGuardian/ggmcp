from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.list_repo_incidents import ListRepoIncidentsParams, list_repo_incidents


class TestListRepoIncidents:
    """Tests for the list_repo_incidents tool."""

    @pytest.mark.asyncio
    async def test_list_repo_incidents_with_repository_name(self, mock_gitguardian_client):
        """
        GIVEN: A repository name
        WHEN: Listing incidents for the repository
        THEN: The API returns the incidents for that repository
        """
        # Mock the client response
        mock_response = {
            "incidents": [
                {
                    "id": "incident_1",
                    "detector": {"name": "AWS Access Key"},
                    "date": "2023-01-01T00:00:00Z",
                    "assignee_id": "user1",
                }
            ],
            "total_count": 1,
        }
        mock_gitguardian_client.list_repo_incidents_directly = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name="GitGuardian/test-repo",
                source_id=None,
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=True,
            )
        )

        # Verify client was called
        mock_gitguardian_client.list_repo_incidents_directly.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_repo_incidents_directly.call_args.kwargs
        assert call_kwargs["repository_name"] == "GitGuardian/test-repo"
        assert call_kwargs["mine"] is True

        # Verify response
        assert result.total_count == mock_response["total_count"]
        assert len(result.incidents) == len(mock_response["incidents"])

    @pytest.mark.asyncio
    async def test_list_repo_incidents_with_source_id(self, mock_gitguardian_client):
        """
        GIVEN: A GitGuardian source ID
        WHEN: Listing incidents for the source
        THEN: The API returns incidents for that source
        """
        # Mock the client response
        mock_response = {
            "data": [
                {
                    "id": "incident_1",
                    "detector": {"name": "Generic API Key"},
                }
            ],
            "total_count": 1,
        }
        mock_gitguardian_client.list_source_incidents = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name=None,
                source_id="source_123",
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=True,
            )
        )

        # Verify client was called with correct parameters including with_sources=false
        mock_gitguardian_client.list_source_incidents.assert_called_once()
        call_args = mock_gitguardian_client.list_source_incidents.call_args
        # Check positional arg (source_id)
        assert call_args[0][0] == "source_123"
        # Check keyword args include with_sources
        assert "with_sources" in call_args[1]
        assert call_args[1]["with_sources"] == "false"

        # Verify response
        assert hasattr(result, "source_id")
        assert result.source_id == "source_123"
        assert len(result.incidents) == 1

    @pytest.mark.asyncio
    async def test_list_repo_incidents_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple filter parameters
        WHEN: Listing incidents with filters
        THEN: The API is called with correct filter parameters
        """
        # Mock the client response
        mock_response = {
            "data": [],
            "total_count": 0,
        }
        mock_gitguardian_client.list_repo_incidents_directly = AsyncMock(return_value=mock_response)

        # Call the function with filters
        await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name="GitGuardian/test-repo",
                source_id=None,
                from_date="2023-01-01",
                to_date="2023-12-31",
                presence="present",
                tags=["tag1", "tag2"],
                ordering="-date",
                per_page=50,
                cursor=None,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with correct parameters
        mock_gitguardian_client.list_repo_incidents_directly.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_repo_incidents_directly.call_args.kwargs
        assert call_kwargs["repository_name"] == "GitGuardian/test-repo"
        assert call_kwargs["from_date"] == "2023-01-01"
        assert call_kwargs["to_date"] == "2023-12-31"
        assert call_kwargs["presence"] == "present"
        assert call_kwargs["tags"] == ["tag1", "tag2"]
        assert call_kwargs["per_page"] == 50
        assert call_kwargs["ordering"] == "-date"
        assert call_kwargs["mine"] is False

    @pytest.mark.asyncio
    async def test_list_repo_incidents_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all flag is True
        WHEN: Listing incidents with pagination
        THEN: All incidents are fetched using paginate_all
        """
        # Mock the paginate_all response
        mock_response = [
            {"id": "incident_1"},
            {"id": "incident_2"},
            {"id": "incident_3"},
        ]
        mock_gitguardian_client.paginate_all = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                source_id="source_123",
                get_all=True,
            )
        )

        # Verify paginate_all was called
        mock_gitguardian_client.paginate_all.assert_called_once()

        # Verify response
        assert result.total_count == 3
        assert len(result.incidents) == 3

    @pytest.mark.asyncio
    async def test_list_repo_incidents_no_repository_or_source(self, mock_gitguardian_client):
        """
        GIVEN: Neither repository_name nor source_id provided
        WHEN: Attempting to list incidents
        THEN: An error is returned
        """
        # Call the function without repository_name or source_id
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name=None,
                source_id=None,
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=True,
            )
        )

        # Verify error response
        assert hasattr(result, "error")
        assert "Either repository_name or source_id must be provided" in result.error

    @pytest.mark.asyncio
    async def test_list_repo_incidents_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Attempting to list incidents
        THEN: An error response is returned
        """
        # Mock the client to raise an exception
        error_message = "API connection failed"
        mock_gitguardian_client.list_repo_incidents_directly = AsyncMock(side_effect=Exception(error_message))

        # Call the function
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name="GitGuardian/test-repo",
                source_id=None,
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=True,
            )
        )

        # Verify error response
        assert hasattr(result, "error")
        assert "Failed to list repository incidents" in result.error

    @pytest.mark.asyncio
    async def test_list_repo_incidents_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor
        WHEN: Listing incidents with the cursor
        THEN: The API is called with the cursor parameter
        """
        # Mock the client response with cursor
        mock_response = {
            "data": [{"id": "incident_1"}],
            "total_count": 1,
            "next_cursor": "cursor_abc",
        }
        mock_gitguardian_client.list_repo_incidents_directly = AsyncMock(return_value=mock_response)

        # Call the function with cursor
        await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name="GitGuardian/test-repo",
                source_id=None,
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor="cursor_abc",
                get_all=False,
                mine=True,
            )
        )

        # Verify client was called with cursor
        mock_gitguardian_client.list_repo_incidents_directly.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_repo_incidents_directly.call_args.kwargs
        assert call_kwargs["cursor"] == "cursor_abc"
        assert call_kwargs["repository_name"] == "GitGuardian/test-repo"

    @pytest.mark.asyncio
    async def test_list_repo_incidents_source_id_list_response(self, mock_gitguardian_client):
        """
        GIVEN: The API returns a list directly
        WHEN: Listing incidents by source_id
        THEN: The response is properly formatted
        """
        # Mock the client to return a list directly
        mock_response = [{"id": "incident_1"}, {"id": "incident_2"}]
        mock_gitguardian_client.list_source_incidents = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_incidents(
            ListRepoIncidentsParams(
                repository_name=None,
                source_id="source_123",
                from_date=None,
                to_date=None,
                presence=None,
                tags=None,
                ordering=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=True,
            )
        )

        # Verify response format
        assert result.source_id == "source_123"
        assert result.total_count == 2
        assert len(result.incidents) == 2

    @pytest.mark.asyncio
    async def test_list_repo_incidents_get_all_dict_response(self, mock_gitguardian_client):
        """
        GIVEN: paginate_all returns a dict response
        WHEN: Listing all incidents with get_all=True
        THEN: The response is properly formatted
        """
        # Mock paginate_all to return a dict
        mock_response = {
            "data": [{"id": "incident_1"}, {"id": "incident_2"}],
            "total_count": 2,
        }
        mock_gitguardian_client.paginate_all = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_repo_incidents(ListRepoIncidentsParams(source_id="source_123", get_all=True))

        # Verify response
        assert result.source_id == "source_123"
        assert result.total_count == 2
        assert len(result.incidents) == 2
