from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesFilters,
    ListRepoOccurrencesParams,
    list_repo_occurrences,
)


class TestListRepoOccurrences:
    """Tests for the list_repo_occurrences tool."""

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
                source_id="source_123",
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
        # Use get_current_token_info instead of get_current_member to avoid
        # requiring members:read scope (fixes 403 error for restricted users)
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"member_id": 67890, "scopes": ["incidents:read"]}
        )

        # Call the function with mine=True
        result = await list_repo_occurrences(
            ListRepoOccurrencesParams(
                source_id="source_123",
                mine=True,
            )
        )

        # Verify get_current_token_info was called (not get_current_member)
        mock_gitguardian_client.get_current_token_info.assert_called_once()

        # Verify list_occurrences was called with the member ID from token info
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
