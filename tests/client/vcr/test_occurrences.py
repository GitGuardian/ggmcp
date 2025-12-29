"""
VCR tests for GitGuardianClient occurrence methods.

These tests cover:
- list_occurrences(...)
- list_secret_occurrences(incident_id)
"""

import pytest

from tests.conftest import my_vcr


class TestListOccurrences:
    """Tests for listing occurrences with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_basic(self, real_client):
        """
        Test basic occurrence listing.

        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the list of occurrences
        THEN we should receive a list response with occurrence data
        """
        with my_vcr.use_cassette("test_list_occurrences_basic"):
            result = await real_client.list_occurrences(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_with_date_filter(self, real_client):
        """
        Test listing occurrences filtered by date range.

        GIVEN a valid GitGuardian API key
        WHEN we request occurrences from a specific date range
        THEN we should receive occurrences within that range
        """
        with my_vcr.use_cassette("test_list_occurrences_with_date_filter"):
            result = await real_client.list_occurrences(from_date="2024-01-01", to_date="2024-12-31", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_with_presence_filter(self, real_client):
        """
        Test listing occurrences filtered by presence status.

        GIVEN a valid GitGuardian API key
        WHEN we request occurrences with specific presence
        THEN we should receive filtered results
        """
        with my_vcr.use_cassette("test_list_occurrences_with_presence_filter"):
            result = await real_client.list_occurrences(presence="present", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_with_sources(self, real_client):
        """
        Test listing occurrences with source details included.

        GIVEN a valid GitGuardian API key
        WHEN we request occurrences with with_sources=True
        THEN we should receive occurrences with source information
        """
        with my_vcr.use_cassette("test_list_occurrences_with_sources"):
            result = await real_client.list_occurrences(with_sources=True, per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_get_all(self, real_client):
        """
        Test listing occurrences with get_all=True (paginated fetch with size limit).

        GIVEN a valid GitGuardian API key
        WHEN we request occurrences with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with my_vcr.use_cassette("test_list_occurrences_get_all"):
            result = await real_client.list_occurrences(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_occurrences_with_member_assignee_id(self, real_client):
        """
        Test listing occurrences filtered by member assignee ID.

        GIVEN a valid GitGuardian API key
        WHEN we request occurrences assigned to a specific member
        THEN we should receive occurrences filtered by that member's ID
        """
        # First get a valid member ID to filter by
        with my_vcr.use_cassette("test_list_occurrences_with_member_assignee_id"):
            member = await real_client.get_current_member()
            member_id = member["id"]
            result = await real_client.list_occurrences(member_assignee_id=member_id, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result
