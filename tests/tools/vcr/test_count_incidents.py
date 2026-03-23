"""
VCR tests for count_incidents tool.

These tests verify end-to-end integration with the API.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.count_incidents import (
    CountIncidentsParams,
    CountIncidentsResult,
    count_incidents,
)
from gg_api_core.tools.list_incidents import SeverityValues


class TestCountIncidentsVCR:
    """VCR tests for count_incidents tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling count_incidents with default params
        THEN a CountIncidentsResult is returned with a non-negative count
        """
        with use_cassette("test_count_incidents_basic"):
            with patch(
                "gg_api_core.tools.count_incidents.get_client",
                return_value=real_client,
            ):
                params = CountIncidentsParams()
                result = await count_incidents(params)

                assert result is not None
                assert isinstance(result, CountIncidentsResult)
                assert result.count >= 0

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_with_status_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling count_incidents with status=TRIGGERED
        THEN a CountIncidentsResult is returned with the applied filter reflected
        """
        with use_cassette("test_count_incidents_with_status_filter"):
            with patch(
                "gg_api_core.tools.count_incidents.get_client",
                return_value=real_client,
            ):
                params = CountIncidentsParams(status=["TRIGGERED"])
                result = await count_incidents(params)

                assert result is not None
                assert isinstance(result, CountIncidentsResult)
                assert result.count >= 0
                assert result.applied_filters["status"] == ["TRIGGERED"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_with_severity_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling count_incidents with severity=critical
        THEN a CountIncidentsResult is returned
        """
        with use_cassette("test_count_incidents_with_severity_filter"):
            with patch(
                "gg_api_core.tools.count_incidents.get_client",
                return_value=real_client,
            ):
                params = CountIncidentsParams(severity=[SeverityValues.CRITICAL])
                result = await count_incidents(params)

                assert result is not None
                assert isinstance(result, CountIncidentsResult)
                assert result.count >= 0

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_with_combined_filters(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling count_incidents with multiple filters
        THEN a CountIncidentsResult is returned with all filters reflected
        """
        with use_cassette("test_count_incidents_with_combined_filters"):
            with patch(
                "gg_api_core.tools.count_incidents.get_client",
                return_value=real_client,
            ):
                params = CountIncidentsParams(
                    status=["TRIGGERED", "ASSIGNED"],
                    severity=[SeverityValues.CRITICAL, SeverityValues.HIGH],
                    validity=["valid"],
                    exclude_tags=[],
                )
                result = await count_incidents(params)

                assert result is not None
                assert isinstance(result, CountIncidentsResult)
                assert result.count >= 0
                assert result.applied_filters["status"] == ["TRIGGERED", "ASSIGNED"]
                assert result.applied_filters["validity"] == ["valid"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_coerce_single_values(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN calling count_incidents with single values (not lists) - LLM scenario
        THEN values are coerced to lists and the API call succeeds
        """
        with use_cassette("test_count_incidents_coerce_single_values"):
            with patch(
                "gg_api_core.tools.count_incidents.get_client",
                return_value=real_client,
            ):
                params = CountIncidentsParams(
                    status="TRIGGERED",
                    severity=SeverityValues.CRITICAL,
                    validity="valid",
                )

                # Verify coercion happened
                assert params.status == ["TRIGGERED"]
                assert params.severity == [SeverityValues.CRITICAL]
                assert params.validity == ["valid"]

                result = await count_incidents(params)

                assert result is not None
                assert isinstance(result, CountIncidentsResult)
                assert result.count >= 0
