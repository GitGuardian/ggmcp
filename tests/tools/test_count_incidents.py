"""
Tests for the count_incidents tool.
"""

from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.count_incidents import (
    CountIncidentsError,
    CountIncidentsParams,
    CountIncidentsResult,
    count_incidents,
)
from gg_api_core.tools.list_incidents import (
    DEFAULT_EXCLUDED_TAGS,
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    SeverityValues,
)


class TestCountIncidentsParamsDefaults:
    """Tests for CountIncidentsParams default filters (same as list_incidents)."""

    def test_default_status_excludes_ignored(self):
        params = CountIncidentsParams()
        assert params.status == DEFAULT_STATUSES
        assert "IGNORED" not in params.status

    def test_default_severity_excludes_low_and_info(self):
        params = CountIncidentsParams()
        assert params.severity == DEFAULT_SEVERITIES
        assert SeverityValues.LOW not in params.severity
        assert SeverityValues.INFO not in params.severity

    def test_default_validity_excludes_invalid(self):
        params = CountIncidentsParams()
        assert params.validity == DEFAULT_VALIDITIES
        assert "invalid" not in params.validity

    def test_default_exclude_tags_filters_noise(self):
        params = CountIncidentsParams()
        assert params.exclude_tags == DEFAULT_EXCLUDED_TAGS

    def test_default_mine_is_false(self):
        params = CountIncidentsParams()
        assert params.mine is False

    def test_no_pagination_fields(self):
        """CountIncidentsParams should not have pagination-related fields."""
        params = CountIncidentsParams()
        assert not hasattr(params, "page")
        assert not hasattr(params, "page_size")
        assert not hasattr(params, "get_all")
        assert not hasattr(params, "ordering")


class TestCountIncidentsParamsCoercion:
    """Tests for CountIncidentsParams coerce_to_list validator."""

    def test_coerce_single_status_to_list(self):
        params = CountIncidentsParams(status="TRIGGERED")
        assert params.status == ["TRIGGERED"]

    def test_coerce_single_severity_to_list(self):
        params = CountIncidentsParams(severity=SeverityValues.CRITICAL)
        assert params.severity == [SeverityValues.CRITICAL]

    def test_coerce_single_validity_to_list(self):
        params = CountIncidentsParams(validity="valid")
        assert params.validity == ["valid"]

    def test_coerce_single_source_ids_to_list(self):
        params = CountIncidentsParams(source_ids=123)
        assert params.source_ids == [123]

    def test_coerce_preserves_list_input(self):
        params = CountIncidentsParams(status=["TRIGGERED", "ASSIGNED"])
        assert params.status == ["TRIGGERED", "ASSIGNED"]

    def test_coerce_preserves_none_input(self):
        params = CountIncidentsParams(detector_group_name=None)
        assert params.detector_group_name is None


class TestCountIncidentsTool:
    """Tests for the count_incidents async tool function."""

    @pytest.mark.asyncio
    async def test_count_returns_result(self):
        mock_client = AsyncMock()
        mock_client.count_incidents_for_mcp.return_value = {"count": 42}

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(CountIncidentsParams())

        assert isinstance(result, CountIncidentsResult)
        assert result.count == 42

    @pytest.mark.asyncio
    async def test_count_zero(self):
        mock_client = AsyncMock()
        mock_client.count_incidents_for_mcp.return_value = {"count": 0}

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(CountIncidentsParams())

        assert isinstance(result, CountIncidentsResult)
        assert result.count == 0

    @pytest.mark.asyncio
    async def test_count_passes_filters(self):
        mock_client = AsyncMock()
        mock_client.count_incidents_for_mcp.return_value = {"count": 5}

        params = CountIncidentsParams(
            status=["TRIGGERED"],
            severity=[SeverityValues.CRITICAL],
            detector_group_name=["AWS Keys"],
        )

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(params)

        assert isinstance(result, CountIncidentsResult)
        assert result.count == 5
        assert result.applied_filters["status"] == ["TRIGGERED"]
        assert result.applied_filters["detector_group_name"] == ["AWS Keys"]

        # Verify the client was called with the right params
        call_kwargs = mock_client.count_incidents_for_mcp.call_args.kwargs
        assert call_kwargs["status"] == ["TRIGGERED"]
        assert call_kwargs["severity"] == [SeverityValues.CRITICAL]
        assert call_kwargs["detector_group_name"] == ["AWS Keys"]

    @pytest.mark.asyncio
    async def test_count_with_mine(self):
        mock_client = AsyncMock()
        mock_client.get_current_member.return_value = {"id": 99}
        mock_client.count_incidents_for_mcp.return_value = {"count": 3}

        params = CountIncidentsParams(mine=True)

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(params)

        assert isinstance(result, CountIncidentsResult)
        assert result.count == 3
        call_kwargs = mock_client.count_incidents_for_mcp.call_args.kwargs
        assert call_kwargs["assignee_id"] == 99

    @pytest.mark.asyncio
    async def test_count_mine_conflict_with_assignee_id(self):
        mock_client = AsyncMock()
        mock_client.get_current_member.return_value = {"id": 99}

        params = CountIncidentsParams(mine=True, assignee_id=50)

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(params)

        assert isinstance(result, CountIncidentsError)
        assert "Conflict" in result.error

    @pytest.mark.asyncio
    async def test_count_returns_error_on_exception(self):
        mock_client = AsyncMock()
        mock_client.count_incidents_for_mcp.side_effect = Exception("API error")

        with patch("gg_api_core.tools.count_incidents.get_client", return_value=mock_client):
            result = await count_incidents(CountIncidentsParams())

        assert isinstance(result, CountIncidentsError)
        assert "API error" in result.error
