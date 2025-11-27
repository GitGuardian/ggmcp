from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.list_incidents import ListIncidentsParams, list_incidents


class TestListIncidents:
    """Tests for the list_incidents tool."""

    @pytest.mark.asyncio
    async def test_list_incidents_with_repository_name(self, mock_gitguardian_client):
        """
        GIVEN: A repository name
        WHEN: Listing incidents for the repository
        THEN: The API returns the incidents for that repository
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "incident_1",
                    "detector": {"name": "AWS Access Key"},
                    "date": "2023-01-01T00:00:00Z",
                    "assignee_id": "user1",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_incidents(
            ListIncidentsParams(
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
        mock_gitguardian_client.list_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_incidents.call_args.kwargs
        assert call_kwargs["source_id"] == "source_123"
        assert call_kwargs["assignee_email"] == "test@example.com"

        # Verify response
        assert result.total_count == len(mock_response["data"])
        assert len(result.incidents) == len(mock_response["data"])

    @pytest.mark.asyncio
    async def test_list_incidents_with_source_id(self, mock_gitguardian_client):
        """
        GIVEN: A GitGuardian source ID
        WHEN: Listing incidents for the source
        THEN: The API returns incidents for that source
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "incident_1",
                    "detector": {"name": "Generic API Key"},
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_incidents(
            ListIncidentsParams(
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

        # Verify client was called with correct parameters
        mock_gitguardian_client.list_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_incidents.call_args.kwargs
        # Check source_id and assignee_email
        assert call_kwargs["source_id"] == "source_123"
        assert call_kwargs["assignee_email"] == "test@example.com"

        # Verify response
        assert result.source_id == "source_123"
        assert result.total_count == 1
        assert len(result.incidents) == 1

    @pytest.mark.asyncio
    async def test_list_incidents_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple filter parameters
        WHEN: Listing incidents with filters
        THEN: The API is called with correct filter parameters
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function with filters
        await list_incidents(
            ListIncidentsParams(
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
        mock_gitguardian_client.list_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_incidents.call_args.kwargs
        assert call_kwargs["source_id"] == "source_123"
        assert call_kwargs["date_after"] == "2023-01-01"
        assert call_kwargs["date_before"] == "2023-12-31"
        assert call_kwargs["presence"] == "present"
        assert call_kwargs["tags"] == "tag1,tag2"
        assert call_kwargs["per_page"] == 50
        assert call_kwargs["ordering"] == "-date"
        # mine=False means assignee_email should not be in the call
        assert "assignee_email" not in call_kwargs

    @pytest.mark.asyncio
    async def test_list_incidents_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all flag is True
        WHEN: Listing incidents with get_all
        THEN: All incidents are fetched and returned with cursor=None
        """
        # Mock list_incidents to return ListResponse format (get_all returns cursor=None)
        mock_response = {
            "data": [
                {"id": "incident_1"},
                {"id": "incident_2"},
                {"id": "incident_3"},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_incidents(
            ListIncidentsParams(
                source_id="source_123",
                get_all=True,
            )
        )

        # Verify list_incidents was called with get_all=True
        mock_gitguardian_client.list_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_incidents.call_args.kwargs
        assert call_kwargs["get_all"] is True

        # Verify response
        assert result.total_count == 3
        assert len(result.incidents) == 3

    @pytest.mark.asyncio
    async def test_list_incidents_no_repository_or_source(self, mock_gitguardian_client):
        """
        GIVEN: Neither repository_name nor source_id provided
        WHEN: Attempting to list incidents
        THEN: An error is returned
        """
        # Mock the client to raise an error when source_id is missing
        mock_gitguardian_client.list_incidents = AsyncMock(side_effect=TypeError("source_id is required"))

        # Call the function without repository_name or source_id
        result = await list_incidents(
            ListIncidentsParams(
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
        assert "Failed to list repository incidents" in result.error

    @pytest.mark.asyncio
    async def test_list_incidents_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Attempting to list incidents
        THEN: An error response is returned
        """
        # Mock the client to raise an exception
        error_message = "API connection failed"
        mock_gitguardian_client.list_incidents = AsyncMock(side_effect=Exception(error_message))

        # Call the function
        result = await list_incidents(
            ListIncidentsParams(
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
    async def test_list_incidents_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor
        WHEN: Listing incidents with the cursor
        THEN: The API is called with the cursor parameter
        """
        # Mock the client response with ListResponse format including cursor
        mock_response = {
            "data": [{"id": "incident_1"}],
            "cursor": "cursor_abc",
            "has_more": True,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function with cursor
        await list_incidents(
            ListIncidentsParams(
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
        mock_gitguardian_client.list_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_incidents.call_args.kwargs
        assert call_kwargs["cursor"] == "cursor_abc"
        assert call_kwargs["source_id"] == "source_123"

    @pytest.mark.asyncio
    async def test_list_incidents_source_id_list_response(self, mock_gitguardian_client):
        """
        GIVEN: The API returns ListResponse format
        WHEN: Listing incidents by source_id
        THEN: The response is properly formatted
        """
        # Mock the client to return ListResponse format
        mock_response = {
            "data": [{"id": "incident_1"}, {"id": "incident_2"}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_incidents(
            ListIncidentsParams(
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
        assert not hasattr(result, "error")
        assert result.source_id == "source_123"
        assert result.total_count == 2
        assert len(result.incidents) == 2
        assert result.next_cursor is None

    @pytest.mark.asyncio
    async def test_list_incidents_get_all_dict_response(self, mock_gitguardian_client):
        """
        GIVEN: list_incidents with get_all=True
        WHEN: Listing all incidents with get_all=True
        THEN: The response is properly formatted with all data
        """
        # Mock list_incidents to return ListResponse format (get_all returns cursor=None)
        mock_response = {
            "data": [{"id": "incident_1"}, {"id": "incident_2"}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_incidents = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_incidents(ListIncidentsParams(source_id="source_123", get_all=True))

        # Verify response
        assert result.source_id == "source_123"
        assert result.total_count == 2
        assert len(result.incidents) == 2
        assert result.next_cursor is None  # get_all should have no cursor
