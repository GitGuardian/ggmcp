"""
VCR tests for list_sources tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_sources import (
    ListSourcesParams,
    ListSourcesResult,
    list_sources,
)


class TestListSourcesVCR:
    """VCR tests for the list_sources tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with minimal parameters
        THEN: Returns a list of sources
        """
        with use_cassette("test_list_sources_basic"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    per_page=5,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                assert isinstance(result.sources, list)
                assert len(result.sources) > 0
                # Verify source structure
                first_source = result.sources[0]
                assert "id" in first_source
                assert "type" in first_source

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_search(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a search term
        THEN: Returns sources matching the search criteria
        """
        with use_cassette("test_list_sources_with_search"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    search="test",
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_type_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a type filter
        THEN: Returns only sources of the specified type
        """
        with use_cassette("test_list_sources_with_type_filter"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    type="github",
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                # Verify all returned sources are of type 'github'
                for source in result.sources:
                    assert source.get("type") == "github"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_health_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a health filter
        THEN: Returns only sources with the specified health status
        """
        with use_cassette("test_list_sources_with_health_filter"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    health="safe",
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                # Verify all returned sources have 'safe' health
                for source in result.sources:
                    assert source.get("health") == "safe"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_visibility_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a visibility filter
        THEN: Returns only sources with the specified visibility
        """
        with use_cassette("test_list_sources_with_visibility_filter"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    visibility="private",
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                # Verify all returned sources have 'private' visibility
                for source in result.sources:
                    assert source.get("visibility") == "private"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_source_criticality_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a source_criticality filter
        THEN: Returns only sources with the specified criticality
        """
        with use_cassette("test_list_sources_with_source_criticality_filter"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    source_criticality="unknown",
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                # Verify all returned sources have 'unknown' criticality
                for source in result.sources:
                    assert source.get("source_criticality") == "unknown"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_ordering(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with ordering
        THEN: Returns sources sorted by the specified field
        """
        with use_cassette("test_list_sources_with_ordering"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    ordering="-last_scan_date",
                    per_page=5,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_per_page(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with a specific per_page value
        THEN: Returns at most per_page sources
        """
        with use_cassette("test_list_sources_with_per_page"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    per_page=3,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                assert len(result.sources) <= 3

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_pagination(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources and then fetching the next page with cursor
        THEN: Returns subsequent page of sources
        """
        with use_cassette("test_list_sources_pagination"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                # First request to get a cursor
                params = ListSourcesParams(
                    per_page=3,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                # If there's a next cursor, verify pagination works
                if result.next_cursor:
                    assert result.has_more is True

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_get_all(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with get_all=True
        THEN: Returns all sources (up to the byte limit)
        """
        with use_cassette("test_list_sources_get_all"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    per_page=20,
                    get_all=True,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
                assert isinstance(result.sources, list)
                # Should return multiple sources
                assert len(result.sources) > 0

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_monitored_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with sources:read scope
        WHEN: Calling list_sources with monitored=True
        THEN: Returns only monitored sources
        """
        with use_cassette("test_list_sources_with_monitored_filter"):
            with patch(
                "gg_api_core.tools.list_sources.get_client",
                return_value=real_client,
            ):
                params = ListSourcesParams(
                    monitored=True,
                    per_page=10,
                    get_all=False,
                )

                result = await list_sources(params)

                assert result is not None
                assert isinstance(result, ListSourcesResult)
                assert result.sources is not None
