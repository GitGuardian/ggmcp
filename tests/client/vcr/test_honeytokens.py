"""
VCR tests for GitGuardianClient honeytoken methods.

These tests cover:
- list_honeytokens(...)
- get_honeytoken(honeytoken_id)
"""

import pytest

from tests.conftest import my_vcr


class TestListHoneytokens:
    """Tests for listing honeytokens with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_basic(self, real_client):
        """
        Test basic honeytoken listing.

        GIVEN a valid GitGuardian API key with honeytokens:read scope
        WHEN we request the list of honeytokens
        THEN we should receive a list response with honeytoken data
        """
        with my_vcr.use_cassette("test_list_honeytokens_basic"):
            result = await real_client.list_honeytokens(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_search(self, real_client):
        """
        Test listing honeytokens with search filter.

        GIVEN a valid GitGuardian API key
        WHEN we request honeytokens with a search term
        THEN we should receive filtered results
        """
        with my_vcr.use_cassette("test_list_honeytokens_with_search"):
            result = await real_client.list_honeytokens(search="test", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_ordering(self, real_client):
        """
        Test listing honeytokens with specific ordering.

        GIVEN a valid GitGuardian API key
        WHEN we request honeytokens ordered by -created_at
        THEN we should receive honeytokens in descending creation order
        """
        with my_vcr.use_cassette("test_list_honeytokens_with_ordering"):
            result = await real_client.list_honeytokens(ordering="-created_at", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_show_token(self, real_client):
        """
        Test listing honeytokens with token details visible.

        GIVEN a valid GitGuardian API key
        WHEN we request honeytokens with show_token=True
        THEN we should receive honeytokens with token values
        """
        with my_vcr.use_cassette("test_list_honeytokens_show_token"):
            result = await real_client.list_honeytokens(show_token=True, per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_get_all(self, real_client):
        """
        Test listing honeytokens with get_all=True (paginated fetch with size limit).

        GIVEN a valid GitGuardian API key
        WHEN we request honeytokens with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with my_vcr.use_cassette("test_list_honeytokens_get_all"):
            result = await real_client.list_honeytokens(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result


class TestGetHoneytoken:
    """Tests for getting individual honeytoken details."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_honeytoken(self, real_client):
        """
        Test getting a single honeytoken by ID.

        GIVEN a valid GitGuardian API key and an existing honeytoken ID
        WHEN we request the honeytoken details
        THEN we should receive detailed honeytoken information
        """
        with my_vcr.use_cassette("test_get_honeytoken"):
            # First get a honeytoken ID from the list
            honeytokens = await real_client.list_honeytokens(per_page=1)
            if not honeytokens["data"]:
                pytest.skip("No honeytokens available for testing")

            honeytoken_id = honeytokens["data"][0]["id"]
            result = await real_client.get_honeytoken(honeytoken_id, show_token=True)

            assert result is not None
            assert result["id"] == honeytoken_id
            assert "name" in result
            assert "status" in result
            assert "type" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_honeytoken_without_token(self, real_client):
        """
        Test getting a honeytoken without showing the token value.

        GIVEN a valid GitGuardian API key and an existing honeytoken ID
        WHEN we request the honeytoken details with show_token=False
        THEN we should receive details without the actual token value
        """
        with my_vcr.use_cassette("test_get_honeytoken_without_token"):
            # First get a honeytoken ID from the list
            honeytokens = await real_client.list_honeytokens(per_page=1)
            if not honeytokens["data"]:
                pytest.skip("No honeytokens available for testing")

            honeytoken_id = honeytokens["data"][0]["id"]
            result = await real_client.get_honeytoken(honeytoken_id, show_token=False)

            assert result is not None
            assert result["id"] == honeytoken_id
