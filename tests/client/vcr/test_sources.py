"""
VCR tests for GitGuardianClient source methods.

These tests cover:
- list_sources(...)
- get_source_by_name(source_name)
- list_source_incidents(source_id)
- list_member_incidents(member_id)
"""

import pytest

from tests.conftest import my_vcr


class TestListSources:
    """Tests for listing sources with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_basic(self, real_client):
        """
        Test basic source listing.

        GIVEN a valid GitGuardian API key with sources:read scope
        WHEN we request the list of sources
        THEN we should receive a list response with source data
        """
        with my_vcr.use_cassette("test_list_sources_basic"):
            result = await real_client.list_sources(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_search(self, real_client):
        """
        Test listing sources with search filter.

        GIVEN a valid GitGuardian API key
        WHEN we request sources matching a search term
        THEN we should receive filtered results
        """
        with my_vcr.use_cassette("test_list_sources_with_search"):
            result = await real_client.list_sources(search="test", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_visibility_filter(self, real_client):
        """
        Test listing sources filtered by visibility.

        GIVEN a valid GitGuardian API key
        WHEN we request sources with specific visibility
        THEN we should receive filtered results
        """
        with my_vcr.use_cassette("test_list_sources_with_visibility_filter"):
            result = await real_client.list_sources(visibility="private", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_with_ordering(self, real_client):
        """
        Test listing sources with specific ordering.

        GIVEN a valid GitGuardian API key
        WHEN we request sources with ordering
        THEN we should receive ordered results
        """
        with my_vcr.use_cassette("test_list_sources_with_ordering"):
            result = await real_client.list_sources(ordering="-last_scan_date", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_monitored_only(self, real_client):
        """
        Test listing only monitored sources.

        GIVEN a valid GitGuardian API key
        WHEN we request only monitored sources
        THEN we should receive only monitored sources
        """
        with my_vcr.use_cassette("test_list_sources_monitored_only"):
            result = await real_client.list_sources(monitored=True, per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_sources_get_all(self, real_client):
        """
        Test listing sources with get_all=True (paginated fetch with size limit).

        GIVEN a valid GitGuardian API key
        WHEN we request sources with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with my_vcr.use_cassette("test_list_sources_get_all"):
            result = await real_client.list_sources(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result


class TestGetSourceByName:
    """Tests for finding sources by name."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_source_by_name(self, real_client):
        """
        Test getting a source by its name.

        GIVEN a valid GitGuardian API key and an existing source name
        WHEN we search for the source by name
        THEN we should receive the source details
        """
        with my_vcr.use_cassette("test_get_source_by_name"):
            # First get a source name from the list
            sources = await real_client.list_sources(per_page=1)
            if not sources["data"]:
                pytest.skip("No sources available for testing")

            source_name = sources["data"][0].get("name") or sources["data"][0].get("full_name")
            result = await real_client.get_source_by_name(source_name)

            assert result is not None
            # Result should be the matching source
            if isinstance(result, dict):
                assert "id" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_source_by_name_no_match(self, real_client):
        """
        Test searching for a non-existent source.

        GIVEN a valid GitGuardian API key and a non-existent source name
        WHEN we search for the source by name
        THEN we should receive None
        """
        with my_vcr.use_cassette("test_get_source_by_name_no_match"):
            result = await real_client.get_source_by_name("non-existent-repo-name-12345")

            assert result is None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_source_by_name_return_all_on_no_match(self, real_client):
        """
        Test searching for a source with return_all_on_no_match=True.

        GIVEN a valid GitGuardian API key and a partial source name
        WHEN we search with return_all_on_no_match=True
        THEN we should receive all matching candidates
        """
        with my_vcr.use_cassette("test_get_source_by_name_return_all_on_no_match"):
            # Search for a partial name that might match multiple sources
            result = await real_client.get_source_by_name("test", return_all_on_no_match=True)

            # Result should be a list of candidates or None
            assert result is None or isinstance(result, (list, dict))


class TestSourceIncidents:
    """Tests for source-related incident methods."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_source_incidents(self, real_client):
        """
        Test listing incidents for a specific source.

        GIVEN a valid GitGuardian API key and a source ID
        WHEN we request incidents for that source
        THEN we should receive a list of incidents
        """
        with my_vcr.use_cassette("test_list_source_incidents"):
            # First get a source ID
            sources = await real_client.list_sources(per_page=1)
            if not sources["data"]:
                pytest.skip("No sources available for testing")

            source_id = sources["data"][0]["id"]
            result = await real_client.list_source_incidents(source_id)

            assert result is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_member_incidents(self, real_client):
        """
        Test listing incidents a member has access to.

        GIVEN a valid GitGuardian API key and a member ID
        WHEN we request incidents for that member
        THEN we should receive a list of incidents
        """
        with my_vcr.use_cassette("test_list_member_incidents"):
            # First get the current member ID
            current = await real_client.get_current_member()
            member_id = current["id"]

            result = await real_client.list_member_incidents(member_id)

            assert result is not None
