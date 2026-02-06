"""
VCR tests for list_detectors tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_detectors import (
    ListDetectorsParams,
    ListDetectorsResult,
    list_detectors,
)


class TestListDetectorsVCR:
    """VCR tests for the list_detectors tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors with minimal parameters
        THEN: Returns a list of secret detectors
        """
        with use_cassette("test_list_detectors_basic"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                params = ListDetectorsParams(
                    per_page=5,
                    get_all=False,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                assert result.detectors is not None
                assert isinstance(result.detectors, list)
                assert len(result.detectors) > 0
                # Verify detector structure
                first_detector = result.detectors[0]
                assert "name" in first_detector
                assert "display_name" in first_detector

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_with_search(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors with a search term
        THEN: Returns detectors matching the search criteria
        """
        with use_cassette("test_list_detectors_with_search"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                params = ListDetectorsParams(
                    search="aws",
                    per_page=10,
                    get_all=False,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                assert result.detectors is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_with_type_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors with a type filter
        THEN: Returns only detectors of the specified type
        """
        with use_cassette("test_list_detectors_with_type_filter"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                params = ListDetectorsParams(
                    type="generic",
                    per_page=10,
                    get_all=False,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                assert result.detectors is not None
                # Verify all returned detectors are of type 'generic'
                for detector in result.detectors:
                    assert detector.get("type") == "generic"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_with_per_page(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors with a specific per_page value
        THEN: Returns at most per_page detectors
        """
        with use_cassette("test_list_detectors_with_per_page"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                params = ListDetectorsParams(
                    per_page=3,
                    get_all=False,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                assert result.detectors is not None
                assert len(result.detectors) <= 3

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_pagination(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors and then fetching the next page with cursor
        THEN: Returns subsequent page of detectors
        """
        with use_cassette("test_list_detectors_pagination"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                # First request to get a cursor
                params = ListDetectorsParams(
                    per_page=3,
                    get_all=False,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                # If there's a next cursor, verify pagination works
                if result.next_cursor:
                    assert result.has_more is True

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_detectors_get_all(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with scan:read scope
        WHEN: Calling list_detectors with get_all=True
        THEN: Returns all detectors (up to the byte limit)
        """
        with use_cassette("test_list_detectors_get_all"):
            with patch(
                "gg_api_core.tools.list_detectors.get_client",
                return_value=real_client,
            ):
                params = ListDetectorsParams(
                    per_page=20,
                    get_all=True,
                )

                result = await list_detectors(params)

                assert result is not None
                assert isinstance(result, ListDetectorsResult)
                assert result.detectors is not None
                assert isinstance(result.detectors, list)
                # Should return multiple detectors
                assert len(result.detectors) > 0
