"""
VCR tests for list_honeytokens tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_honeytokens import (
    ListHoneytokensParams,
    ListHoneytokensResult,
    list_honeytokens,
)


class TestListHoneytokensVCR:
    """VCR tests for the list_honeytokens tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens with minimal parameters
        THEN: Returns a list of honeytokens in the workspace

        Uses cassette: test_list_honeytokens_basic.yaml (existing)
        Cassette params: show_token=false&per_page=5
        """
        with use_cassette("test_list_honeytokens_basic"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    show_token=False,
                    per_page=5,
                    get_all=False,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None
                assert isinstance(result.honeytokens, list)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_status_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens filtered by active status
        THEN: Returns only active honeytokens

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_honeytokens_with_status_filter"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    status="active",
                    per_page=10,
                    get_all=False,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None
                # Verify all returned honeytokens are active
                for honeytoken in result.honeytokens:
                    assert honeytoken.get("status") == "active"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_search(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens with a search term
        THEN: Returns honeytokens matching the search criteria

        Uses cassette: test_list_honeytokens_with_search.yaml (existing)
        Cassette params: search=test&show_token=false&per_page=5
        """
        with use_cassette("test_list_honeytokens_with_search"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    search="test",
                    show_token=False,
                    per_page=5,
                    get_all=False,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_ordering(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens with ordering by created_at descending
        THEN: Returns honeytokens sorted by creation date (newest first)

        Uses cassette: test_list_honeytokens_with_ordering.yaml (existing)
        Cassette params: ordering=-created_at&show_token=false&per_page=5
        """
        with use_cassette("test_list_honeytokens_with_ordering"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    ordering="-created_at",
                    show_token=False,
                    per_page=5,
                    get_all=False,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_with_show_token(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens with show_token=True
        THEN: Returns honeytokens with token details included

        Uses cassette: test_list_honeytokens_show_token.yaml (existing)
        Cassette params: show_token=true&per_page=5
        """
        with use_cassette("test_list_honeytokens_show_token"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    show_token=True,
                    per_page=5,
                    get_all=False,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_honeytokens_get_all(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with honeytokens:read scope
        WHEN: Calling list_honeytokens with get_all=True
        THEN: Returns all honeytokens (up to the byte limit)

        Uses cassette: test_list_honeytokens_get_all.yaml (existing)
        Cassette params: show_token=false&per_page=5
        Note: The cassette was recorded with a single page, so get_all returns
        all results in one request (no pagination needed).
        """
        with use_cassette("test_list_honeytokens_get_all"):
            with patch(
                "gg_api_core.tools.list_honeytokens.get_client",
                return_value=real_client,
            ):
                params = ListHoneytokensParams(
                    show_token=False,
                    get_all=True,
                    per_page=5,
                )

                result = await list_honeytokens(params)

                assert result is not None
                assert isinstance(result, ListHoneytokensResult)
                assert result.honeytokens is not None
                assert isinstance(result.honeytokens, list)
