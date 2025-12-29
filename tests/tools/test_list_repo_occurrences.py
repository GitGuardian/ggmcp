from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesFilters,
    ListRepoOccurrencesParams,
    list_repo_occurrences,
)
from pydantic import ValidationError


class TestListRepoOccurrences:
    """Tests for the list_repo_occurrences tool."""

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_repository_name(self, mock_gitguardian_client):
        """
        GIVEN: A repository name
        WHEN: Listing occurrences for the repository
        THEN: The API returns occurrences with exact match locations and with_sources=False
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
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
        assert result.repository == "GitGuardian/test-repo"
        assert result.occurrences_count == 1
        assert len(result.occurrences) == 1
        assert result.applied_filters is not None
        assert result.suggestion is not None

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_source_id(self, mock_gitguardian_client):
        """
        GIVEN: A GitGuardian source ID
        WHEN: Listing occurrences for the source
        THEN: The API returns occurrences for that source with with_sources=False
        """
        # Mock the client response
        mock_response = {
            "data": [
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
        result = await list_repo_occurrences(ListRepoOccurrencesParams(source_id="source_123"))

        # Verify client was called with source_id and with_sources=False
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["source_id"] == "source_123"
        assert call_kwargs["with_sources"] is False

        # Verify response
        assert result.occurrences_count == 1
        assert result.applied_filters is not None
        assert result.suggestion is not None

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple filter parameters
        WHEN: Listing occurrences with filters
        THEN: The API is called with correct filter parameters
        """
        # Mock the client response
        mock_response = {
            "data": [],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with filters
        await list_repo_occurrences(
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
        # Mock the client to return proper dict structure when get_all=True
        mock_response = {
            "data": [
                {"id": "occ_1", "matches": [], "incident": {"id": "incident_1"}},
                {"id": "occ_2", "matches": [], "incident": {"id": "incident_2"}},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                repository_name="GitGuardian/test-repo",
                get_all=True,
            )
        )

        # Verify response
        assert result.occurrences_count == 2
        assert len(result.occurrences) == 2
        assert result.applied_filters is not None
        assert result.suggestion is not None

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_no_repository_or_source(self, mock_gitguardian_client):
        """
        GIVEN: Neither repository_name nor source_id provided
        WHEN: Listing occurrences
        THEN: All occurrences across all repositories are returned
        """
        mock_response = {
            "data": [{"id": "occ_1", "matches": [], "incident": {"id": "incident_1"}}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                repository_name=None,
                source_id=None,
            )
        )

        # Verify client was called without source filters
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["source_name"] is None

        # Verify response
        assert result.occurrences_count == 1

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Attempting to list occurrences
        THEN: An error response is returned
        """
        # Mock the client to raise an exception
        error_message = "API connection failed"
        mock_gitguardian_client.list_occurrences = AsyncMock(side_effect=Exception(error_message))

        # Call the function
        result = await list_repo_occurrences(ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo"))

        # Verify error response
        assert hasattr(result, "error")
        assert "Failed to list repository occurrences" in result.error

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor
        WHEN: Listing occurrences with the cursor
        THEN: The API is called with the cursor parameter
        """
        # Mock the client response with cursor
        mock_response = {
            "data": [{"id": "occ_1"}],
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
        assert result.cursor == "next_cursor_123"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_empty_response(self, mock_gitguardian_client):
        """
        GIVEN: No occurrences exist
        WHEN: Listing occurrences
        THEN: An empty list is returned
        """
        # Mock the client response with no occurrences
        mock_response = {
            "data": [],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_repo_occurrences(ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo"))

        # Verify response
        assert result.occurrences_count == 0
        assert len(result.occurrences) == 0
        assert result.applied_filters is not None
        assert result.suggestion is not None

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_unexpected_response_type(self, mock_gitguardian_client):
        """
        GIVEN: The API returns an unexpected response type
        WHEN: Processing the response
        THEN: An error is returned
        """
        # Mock the client to raise an exception for unexpected response
        mock_gitguardian_client.list_occurrences = AsyncMock(side_effect=Exception("Unexpected response format"))

        # Call the function
        result = await list_repo_occurrences(ListRepoOccurrencesParams(repository_name="GitGuardian/test-repo"))

        # Verify error response is returned
        assert hasattr(result, "error")
        assert "Failed to list repository occurrences" in result.error

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_member_assignee_id(self, mock_gitguardian_client):
        """
        GIVEN: A member_assignee_id filter
        WHEN: Listing occurrences
        THEN: The API is called with the member_assignee_id parameter
        """
        mock_response = {
            "data": [{"id": "occ_1", "matches": [], "incident": {"id": "incident_1"}}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)

        # Call the function with member_assignee_id
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                repository_name="GitGuardian/test-repo",
                member_assignee_id=12345,
            )
        )

        # Verify client was called with member_assignee_id
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["member_assignee_id"] == 12345

        # Verify filter is reported in response
        assert result.applied_filters is not None
        assert result.applied_filters.get("member_assignee_id") == 12345

    @pytest.mark.asyncio
    async def test_list_repo_occurrences_with_mine_filter(self, mock_gitguardian_client):
        """
        GIVEN: The mine filter is True
        WHEN: Listing occurrences
        THEN: The current member ID is fetched and used as member_assignee_id
        """
        mock_response = {
            "data": [{"id": "occ_1", "matches": [], "incident": {"id": "incident_1"}}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_occurrences = AsyncMock(return_value=mock_response)
        mock_gitguardian_client.get_current_member = AsyncMock(
            return_value={"id": 67890, "email": "test@example.com", "name": "Test User"}
        )

        # Call the function with mine=True
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                repository_name="GitGuardian/test-repo",
                mine=True,
            )
        )

        # Verify get_current_member was called
        mock_gitguardian_client.get_current_member.assert_called_once()

        # Verify list_occurrences was called with the member ID
        mock_gitguardian_client.list_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_occurrences.call_args.kwargs
        assert call_kwargs["member_assignee_id"] == 67890

        # Verify filter is reported in response
        assert result.applied_filters is not None
        assert result.applied_filters.get("mine") is True


class TestListRepoOccurrencesFilters:
    """Tests for ListRepoOccurrencesFilters validation."""

    def test_mine_and_member_assignee_id_mutually_exclusive(self):
        """
        GIVEN: Both mine and member_assignee_id are provided
        WHEN: Creating the filters
        THEN: A validation error is raised
        """
        with pytest.raises(ValidationError) as exc_info:
            ListRepoOccurrencesFilters(mine=True, member_assignee_id=12345)

        assert "Only one of assignee_member_id, or mine should be provided" in str(exc_info.value)

    def test_mine_alone_is_valid(self):
        """
        GIVEN: Only mine filter is provided
        WHEN: Creating the filters
        THEN: The filters are valid
        """
        filters = ListRepoOccurrencesFilters(mine=True)
        assert filters.mine is True
        assert filters.member_assignee_id is None

    def test_member_assignee_id_alone_is_valid(self):
        """
        GIVEN: Only member_assignee_id is provided
        WHEN: Creating the filters
        THEN: The filters are valid
        """
        filters = ListRepoOccurrencesFilters(member_assignee_id=12345)
        assert filters.member_assignee_id == 12345
        assert filters.mine is False
