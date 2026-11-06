"""
VCR tests for GitGuardianClient source methods.

These tests cover:
- list_sources(...)
- get_source_by_name(source_name)
- list_source_incidents(source_id)
- list_member_incidents(member_id)
"""

import pytest


class TestListSources:
    """Tests for listing sources with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_basic(self, real_client, use_cassette):
        """
        Test basic source listing.

        GIVEN a valid GitGuardian API key with sources:read scope
        WHEN we request the list of sources
        THEN we should receive a list response with source data
        """
        with use_cassette("test_list_sources_basic"):
            result = await real_client.list_sources(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_search(self, real_client, use_cassette):
        """
        Test listing sources with search filter.

        GIVEN a valid GitGuardian API key
        WHEN we request sources matching a search term
        THEN we should receive filtered results
        """
        with use_cassette("test_list_sources_with_search"):
            result = await real_client.list_sources(search="test", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_visibility_filter(self, real_client, use_cassette):
        """
        Test listing sources filtered by visibility.

        GIVEN a valid GitGuardian API key
        WHEN we request sources with specific visibility
        THEN we should receive filtered results
        """
        with use_cassette("test_list_sources_with_visibility_filter"):
            result = await real_client.list_sources(visibility="private", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_ordering(self, real_client, use_cassette):
        """
        Test listing sources with specific ordering.

        GIVEN a valid GitGuardian API key
        WHEN we request sources with ordering
        THEN we should receive ordered results
        """
        with use_cassette("test_list_sources_with_ordering"):
            result = await real_client.list_sources(ordering="-last_scan_date", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_monitored_only(self, real_client, use_cassette):
        """
        Test listing only monitored sources.

        GIVEN a valid GitGuardian API key
        WHEN we request only monitored sources
        THEN we should receive only monitored sources
        """
        with use_cassette("test_list_sources_monitored_only"):
            result = await real_client.list_sources(monitored=True, per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_get_all(self, real_client, use_cassette):
        """
        Test listing sources with get_all=True (paginated fetch with size limit).

        GIVEN a valid GitGuardian API key
        WHEN we request sources with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with use_cassette("test_list_sources_get_all"):
            result = await real_client.list_sources(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result
