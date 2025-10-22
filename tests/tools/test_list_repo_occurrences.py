from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams


class TestListRepoOccurrences:
    """Tests for the list_repo_occurrences tool."""

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_repository_name(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: A repository name
        WHEN: Listing occurrences for the repository
        THEN: The API returns occurrences with exact match locations and with_sources=False
        """
        # Mock the client response
        mock_response = {
            "occurrences": [
                {
                    "id": "occ_1",
                    "matches": [
                        {
                            "type": "apikey",
                            "match": {
                                "filename": "config.py",
                                "line_start": 10,
                                "line_end": 10,
                                "index_start": 15,
                                "index_end": 35,
                            },
                        }
                    ],
                    "incident": {"id": "incident_1", "detector": {"name": "AWS Key"}},
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
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
            )
        )

        # Verify client was called with with_sources=False
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["source_name"] == "GitGuardian/test-repo"
        assert call_kwargs["source_type"] == "github"
        assert call_kwargs["with_sources"] is False

        # Verify response
        assert result["repository"] == "GitGuardian/test-repo"
        assert result["occurrences_count"] == 1
        assert len(result["occurrences"]) == 1

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_source_id(self, mock_gitguardian_client):
        """
        GIVEN: A GitGuardian source ID
        WHEN: Listing occurrences for the source
        THEN: The API returns occurrences for that source with with_sources=False
        """
        # Mock the client response
        mock_response = {
            "occurrences": [
                {
                    "id": "occ_1",
                    "matches": [],
                    "incident": {"id": "incident_1"},
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(source_id="source_123")
        )

        # Verify client was called with source_id and with_sources=False
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["source_id"] == "source_123"
        assert call_kwargs["with_sources"] is False

        # Verify response
        assert result["occurrences_count"] == 1

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple filter parameters
        WHEN: Listing occurrences with filters
        THEN: The API is called with correct filter parameters
        """
        # Mock the client response
        mock_response = {
            "occurrences": [],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with filters
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
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
            )
        )

        # Verify client was called with correct parameters
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["source_name"] == "GitGuardian/test-repo"
        assert call_kwargs["from_date"] == "2023-01-01"
        assert call_kwargs["to_date"] == "2023-12-31"
        assert call_kwargs["presence"] == "present"
        assert call_kwargs["tags"] == ["tag1", "tag2"]
        assert call_kwargs["per_page"] == 50
        assert call_kwargs["ordering"] == "-date"

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all flag is True
        WHEN: Listing occurrences with pagination
        THEN: All occurrences are fetched and returned as a list
        """
        # Mock the client to return a list directly when get_all=True
        mock_response = [
            {"id": "occ_1", "matches": [], "incident": {"id": "incident_1"}},
            {"id": "occ_2", "matches": [], "incident": {"id": "incident_2"}},
        ]
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                repository_name="GitGuardian/test-repo",
                get_all=True,
            )
        )

        # Verify response
        assert result["occurrences_count"] == 2
        assert len(result["occurrences"]) == 2

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_no_repository_or_source(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: Neither repository_name nor source_id provided
        WHEN: Attempting to list occurrences
        THEN: An error is returned
        """
        # Call the function without repository_name or source_id
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
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
            )
        )

        # Verify error response
        assert "error" in result
        assert "Either repository_name or source_id must be provided" in result["error"]

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Attempting to list occurrences
        THEN: An error response is returned
        """
        # Mock the client to raise an exception
        error_message = "API connection failed"
        mock_gitguardian_client.list_occurrences = AsyncMock(
            side_effect=Exception(error_message)
        )

        # Call the function
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo")
        )

        # Verify error response
        assert "error" in result
        assert "Failed to list repository occurrences" in result["error"]

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor
        WHEN: Listing occurrences with the cursor
        THEN: The API is called with the cursor parameter
        """
        # Mock the client response with cursor
        mock_response = {
            "occurrences": [{"id": "occ_1"}],
            "cursor": "next_cursor_123",
            "has_more": True,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with cursor
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
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
            )
        )

        # Verify client was called with cursor
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["cursor"] == "cursor_abc"
        assert call_kwargs["source_name"] == "GitGuardian/test-repo"

        # Verify response includes cursor
        assert result["cursor"] == "next_cursor_123"
        assert result["has_more"] is True

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_empty_response(self, mock_gitguardian_client):
        """
        GIVEN: No occurrences exist
        WHEN: Listing occurrences
        THEN: An empty list is returned
        """
        # Mock the client response with no occurrences
        mock_response = {
            "occurrences": [],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo")
        )

        # Verify response
        assert result["occurrences_count"] == 0
        assert len(result["occurrences"]) == 0

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_unexpected_response_type(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: The API returns an unexpected response type
        WHEN: Processing the response
        THEN: Default empty values are returned
        """
        # Mock the client to return unexpected type
        mock_response = "unexpected_string"
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo")
        )

        # Verify response defaults to empty
        assert result["occurrences_count"] == 0
        assert result["occurrences"] == []
