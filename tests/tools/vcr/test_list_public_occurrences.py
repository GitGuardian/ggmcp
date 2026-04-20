"""
VCR tests for the list_public_occurrences tool.

These tests exercise the MCP tool wrapper (not just the low-level client)
and cover every filter parameter exposed by ListPublicOccurrencesParams.
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_public_occurrences import (
    ListPublicOccurrencesParams,
    ListPublicOccurrencesResult,
    list_public_occurrences,
)


class TestListPublicOccurrencesVCR:
    """VCR tests for the list_public_occurrences tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_public_occurrences with only incident_id
        THEN: The tool returns a valid ListPublicOccurrencesResult
        """
        with use_cassette("test_list_public_occurrences_basic"):
            with patch(
                "gg_api_core.tools.list_public_occurrences.get_client",
                return_value=real_client,
            ):
                incidents = await real_client.list_public_incidents(per_page=1)
                if not incidents["data"]:
                    pytest.skip("No public incidents available")
                incident_id = incidents["data"][0]["id"]

                params = ListPublicOccurrencesParams(incident_id=incident_id, per_page=5)
                result = await list_public_occurrences(params)

                assert result is not None
                assert isinstance(result, ListPublicOccurrencesResult)
                assert isinstance(result.occurrences, list)
                assert result.applied_filters["incident_id"] == incident_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_multi_value_filters(self, real_client, use_cassette):
        """
        GIVEN: A real public incident, plus permissive multi-value comma-separated filters
        WHEN: Calling list_public_occurrences
        THEN: The API accepts the filters and occurrences are returned with attributes inside
            the requested sets
        """
        with use_cassette("test_list_public_occurrences_with_multi_value_filters"):
            with patch(
                "gg_api_core.tools.list_public_occurrences.get_client",
                return_value=real_client,
            ):
                incidents = await real_client.list_public_incidents(per_page=1)
                if not incidents["data"]:
                    pytest.skip("No public incidents available")
                incident_id = incidents["data"][0]["id"]

                params = ListPublicOccurrencesParams(
                    incident_id=incident_id,
                    per_page=10,
                    presence="present",
                    severity="critical,high,medium,low,info,unknown",
                    status="TRIGGERED,ASSIGNED,RESOLVED,IGNORED",
                    validity="valid,invalid,failed_to_check,no_checker,unknown",
                    ordering="-date",
                )
                result = await list_public_occurrences(params)

                assert isinstance(result, ListPublicOccurrencesResult)
                assert result.occurrences_count > 0, "expected non-empty result with permissive filters"
                for occ in result.occurrences:
                    assert occ.get("presence") == "present"

                applied = result.applied_filters
                assert applied["incident_id"] == incident_id
                assert applied["presence"] == "present"
                assert applied["severity"] == "critical,high,medium,low,info,unknown"
                assert applied["status"] == "TRIGGERED,ASSIGNED,RESOLVED,IGNORED"
                assert applied["validity"] == "valid,invalid,failed_to_check,no_checker,unknown"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_date_range(self, real_client, use_cassette):
        """
        GIVEN: A real public incident and a broad date window
        WHEN: Calling list_public_occurrences
        THEN: Occurrences are returned and fall inside the window
        """
        with use_cassette("test_list_public_occurrences_with_date_range"):
            with patch(
                "gg_api_core.tools.list_public_occurrences.get_client",
                return_value=real_client,
            ):
                incidents = await real_client.list_public_incidents(per_page=1)
                if not incidents["data"]:
                    pytest.skip("No public incidents available")
                incident_id = incidents["data"][0]["id"]

                params = ListPublicOccurrencesParams(
                    incident_id=incident_id,
                    per_page=10,
                    date_after="2020-01-01T00:00:00Z",
                )
                result = await list_public_occurrences(params)

                assert isinstance(result, ListPublicOccurrencesResult)
                assert result.occurrences_count > 0
                for occ in result.occurrences:
                    assert occ["date"] >= "2020-01-01T00:00:00Z"
