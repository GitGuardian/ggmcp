"""
VCR tests for list_incidents tool.

These tests verify end-to-end integration with the API when single values
are passed instead of lists (LLM compatibility).

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env

The coercion feature unit tests are in tests/tools/test_list_incidents.py
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_incidents import (
    ListIncidentsParams,
    ListIncidentsResult,
    SeverityValues,
    list_incidents,
)

from tests.conftest import my_vcr


class TestListIncidentsCoercionVCR:
    """VCR tests for list_incidents tool with coercion.

    These tests verify that the coercion works correctly end-to-end,
    from parameter parsing through API call execution.
    """

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_single_status_value(self, real_client):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_incidents with a single status value (not a list)
        THEN: The coercion converts it to a list and the API call succeeds

        This tests that LLMs passing status="TRIGGERED" instead of status=["TRIGGERED"]
        still works correctly.
        """
        with my_vcr.use_cassette("test_list_incidents_coerce_single_status"):
            with patch(
                "gg_api_core.tools.list_incidents.get_client",
                return_value=real_client,
            ):
                # Single string value, not a list - this is how LLMs often call tools
                params = ListIncidentsParams(
                    status="TRIGGERED",  # Single value, not a list
                    page_size=5,
                    get_all=False,
                )

                # Verify coercion happened
                assert params.status == ["TRIGGERED"]

                result = await list_incidents(params)

                assert result is not None
                assert isinstance(result, ListIncidentsResult)
                assert result.incidents is not None
                assert isinstance(result.incidents, list)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_single_severity_value(self, real_client):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_incidents with a single severity value (not a list)
        THEN: The coercion converts it to a list and the API call succeeds

        This tests that LLMs passing severity=10 instead of severity=[10]
        still works correctly.
        """
        with my_vcr.use_cassette("test_list_incidents_coerce_single_severity"):
            with patch(
                "gg_api_core.tools.list_incidents.get_client",
                return_value=real_client,
            ):
                # Single int value for severity
                params = ListIncidentsParams(
                    severity=SeverityValues.CRITICAL,  # Single value: 10
                    page_size=5,
                    get_all=False,
                )

                # Verify coercion happened
                assert params.severity == [SeverityValues.CRITICAL]

                result = await list_incidents(params)

                assert result is not None
                assert isinstance(result, ListIncidentsResult)
                assert result.incidents is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_single_validity_value(self, real_client):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_incidents with a single validity value (not a list)
        THEN: The coercion converts it to a list and the API call succeeds
        """
        with my_vcr.use_cassette("test_list_incidents_coerce_single_validity"):
            with patch(
                "gg_api_core.tools.list_incidents.get_client",
                return_value=real_client,
            ):
                # Single string value for validity - tests coercion AND uses valid API value
                params = ListIncidentsParams(
                    validity="valid",  # Single value, not a list - will be coerced to ["valid"]
                    page_size=5,
                    get_all=False,
                )

                # Verify coercion happened
                assert params.validity == ["valid"]

                result = await list_incidents(params)

                assert result is not None
                assert isinstance(result, ListIncidentsResult)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incidents_with_multiple_single_values(self, real_client):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_incidents with multiple single values (not lists)
        THEN: All values are coerced to lists and the API call succeeds

        This is the most realistic test case - LLMs often pass multiple
        parameters as single values instead of lists.
        """
        with my_vcr.use_cassette("test_list_incidents_coerce_multiple_single_values"):
            with patch(
                "gg_api_core.tools.list_incidents.get_client",
                return_value=real_client,
            ):
                # Multiple single values that would typically be passed by an LLM
                # This also tests that validity coercion works and uses a valid API value
                params = ListIncidentsParams(
                    status="TRIGGERED",  # Single value - will be coerced to ["TRIGGERED"]
                    severity=SeverityValues.CRITICAL,  # Single value - will be coerced to [10]
                    validity="valid",  # Single value - will be coerced to ["valid"]
                    exclude_tags="TEST_FILE",  # Single value - will be coerced to ["TEST_FILE"]
                    page_size=5,
                    get_all=False,
                )

                # Verify all coercions happened
                assert params.status == ["TRIGGERED"]
                assert params.severity == [SeverityValues.CRITICAL]
                assert params.validity == ["valid"]
                assert params.exclude_tags == ["TEST_FILE"]

                result = await list_incidents(params)

                assert result is not None
                assert isinstance(result, ListIncidentsResult)
                assert result.incidents is not None
                assert isinstance(result.incidents, list)
                # Verify applied filters reflect the coerced values
                assert result.applied_filters is not None
