"""
VCR tests for the list_public_incidents tool.

These tests exercise the MCP tool wrapper (not just the low-level client)
and cover every filter parameter exposed by ListPublicIncidentsParams.
"""

from unittest.mock import patch

import pytest
from gg_api_core.client import IncidentSeverity, IncidentStatus, IncidentValidity
from gg_api_core.tools.list_public_incidents import (
    ListPublicIncidentsParams,
    ListPublicIncidentsResult,
    list_public_incidents,
)


class TestListPublicIncidentsVCR:
    """VCR tests for the list_public_incidents tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with incidents:read scope
        WHEN: Calling list_public_incidents with default parameters
        THEN: The tool returns a valid ListPublicIncidentsResult
        """
        with use_cassette("test_list_public_incidents_basic"):
            with patch(
                "gg_api_core.tools.list_public_incidents.get_client",
                return_value=real_client,
            ):
                # The default tool applies status/severity/validity noise-reduction filters;
                # disable them here to match the baseline cassette, which was recorded without
                # any filters.
                params = ListPublicIncidentsParams(
                    per_page=5,
                    status=None,
                    severity=None,
                    validity=None,
                )
                result = await list_public_incidents(params)

                assert result is not None
                assert isinstance(result, ListPublicIncidentsResult)
                assert isinstance(result.incidents, list)
                assert result.applied_filters is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_multi_value_enum_filters(self, real_client, use_cassette):
        """
        GIVEN: Permissive multi-value list filters for status/severity/validity
        WHEN: Calling list_public_incidents
        THEN: The API honors the lists (comma-separated) and the tool returns data
            whose status/severity/validity all fall inside the requested sets
        """
        statuses = [IncidentStatus.TRIGGERED, IncidentStatus.ASSIGNED, IncidentStatus.RESOLVED, IncidentStatus.IGNORED]
        severities = [
            IncidentSeverity.CRITICAL,
            IncidentSeverity.HIGH,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.LOW,
            IncidentSeverity.INFO,
            IncidentSeverity.UNKNOWN,
        ]
        validities = [
            IncidentValidity.VALID,
            IncidentValidity.INVALID,
            IncidentValidity.FAILED_TO_CHECK,
            IncidentValidity.NO_CHECKER,
            IncidentValidity.UNKNOWN,
        ]
        with use_cassette("test_list_public_incidents_with_multi_value_enum_filters"):
            with patch(
                "gg_api_core.tools.list_public_incidents.get_client",
                return_value=real_client,
            ):
                params = ListPublicIncidentsParams(
                    per_page=10,
                    status=statuses,
                    severity=severities,
                    validity=validities,
                )
                result = await list_public_incidents(params)

                assert isinstance(result, ListPublicIncidentsResult)
                assert result.incidents_count > 0, "expected non-empty result with permissive filters"

                allowed_status = {s.value for s in statuses}
                allowed_severity = {s.value for s in severities}
                allowed_validity = {v.value for v in validities}
                for inc in result.incidents:
                    assert inc["status"] in allowed_status
                    assert inc["severity"] in allowed_severity
                    assert inc["validity"] in allowed_validity

                applied = result.applied_filters
                assert applied["status"] == [s.value for s in statuses]
                assert applied["severity"] == [s.value for s in severities]
                assert applied["validity"] == [v.value for v in validities]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_date_and_risk_score_bounds(self, real_client, use_cassette):
        """
        GIVEN: A broad date window, full risk-score range, and ordering=-risk_score
        WHEN: Calling list_public_incidents with defaults disabled
        THEN: Incidents are returned and respect the bounds
        """
        with use_cassette("test_list_public_incidents_with_date_and_risk_score_bounds"):
            with patch(
                "gg_api_core.tools.list_public_incidents.get_client",
                return_value=real_client,
            ):
                params = ListPublicIncidentsParams(
                    per_page=10,
                    status=None,
                    severity=None,
                    validity=None,
                    date_after="2020-01-01T00:00:00Z",
                    risk_score_min=0,
                    risk_score_max=100,
                    ordering="-risk_score",
                )
                result = await list_public_incidents(params)

                assert isinstance(result, ListPublicIncidentsResult)
                assert result.incidents_count > 0
                for inc in result.incidents:
                    assert 0 <= inc["risk_score"] <= 100
                    assert inc["date"] >= "2020-01-01T00:00:00Z"
