"""
VCR tests for GitGuardianClient.count_incidents_for_mcp method.

These tests cover the /incidents-for-mcp/count endpoint with various filters.
"""

import pytest


class TestCountIncidentsForMcp:
    """Tests for the MCP-optimized count endpoint."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the count of incidents via the MCP count endpoint
        THEN we should receive a response with a "count" key
        """
        with use_cassette("test_count_incidents_for_mcp_basic"):
            result = await real_client.count_incidents_for_mcp()

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)
            assert result["count"] >= 0

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_with_status_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request incident count with status=TRIGGERED
        THEN we should receive a count reflecting that filter
        """
        with use_cassette("test_count_incidents_for_mcp_with_status_filter"):
            result = await real_client.count_incidents_for_mcp(status="TRIGGERED")

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_with_severity_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request incident count with severity 10 (critical) and 20 (high)
        THEN we should receive a count reflecting that filter
        """
        with use_cassette("test_count_incidents_for_mcp_with_severity_filter"):
            result = await real_client.count_incidents_for_mcp(severity=[10, 20])

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_with_combined_filters(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request incident count with multiple filters combined
        THEN we should receive a count reflecting all filters
        """
        with use_cassette("test_count_incidents_for_mcp_with_combined_filters"):
            result = await real_client.count_incidents_for_mcp(
                status=["TRIGGERED", "ASSIGNED"],
                severity=[10, 20],
                validity=["valid"],
            )

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_with_date_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request incident count within a date range
        THEN we should receive a count reflecting that filter
        """
        with use_cassette("test_count_incidents_for_mcp_with_date_filter"):
            result = await real_client.count_incidents_for_mcp(
                date_after="2024-01-01",
                date_before="2025-12-31",
            )

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_count_incidents_for_mcp_with_search(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request incident count with a search term
        THEN we should receive a count reflecting the search filter
        """
        with use_cassette("test_count_incidents_for_mcp_with_search"):
            result = await real_client.count_incidents_for_mcp(search="aws")

            assert result is not None
            assert "count" in result
            assert isinstance(result["count"], int)
