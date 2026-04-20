from unittest.mock import AsyncMock

import pytest
from gg_api_core.client import IncidentSeverity, IncidentStatus, IncidentValidity
from gg_api_core.tools.list_public_incidents import (
    ListPublicIncidentsParams,
    list_public_incidents,
)


class TestListPublicIncidents:
    """Tests for the list_public_incidents tool."""

    @pytest.mark.asyncio
    async def test_basic_call_passes_pagination_and_defaults(self, mock_gitguardian_client):
        """
        GIVEN: Default parameters
        WHEN: Listing public incidents
        THEN: The client receives the noise-reducing default filters plus default pagination
        """
        mock_response = {
            "data": [{"id": 3759, "status": "TRIGGERED"}],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_public_incidents = AsyncMock(return_value=mock_response)

        result = await list_public_incidents(ListPublicIncidentsParams())

        mock_gitguardian_client.list_public_incidents.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_public_incidents.call_args.kwargs
        assert call_kwargs["per_page"] == 20
        assert call_kwargs["ordering"] == "-date"
        assert call_kwargs["get_all"] is False
        # Default filters mirror list_incidents: IGNORED / LOW / INFO / INVALID excluded.
        assert call_kwargs["status"] == [IncidentStatus.TRIGGERED, IncidentStatus.ASSIGNED, IncidentStatus.RESOLVED]
        assert call_kwargs["severity"] == [
            IncidentSeverity.CRITICAL,
            IncidentSeverity.HIGH,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.UNKNOWN,
        ]
        assert call_kwargs["validity"] == [
            IncidentValidity.VALID,
            IncidentValidity.FAILED_TO_CHECK,
            IncidentValidity.NO_CHECKER,
            IncidentValidity.UNKNOWN,
        ]

        assert result.incidents_count == 1
        assert result.incidents == mock_response["data"]
        assert result.cursor is None
        assert result.has_more is False

    @pytest.mark.asyncio
    async def test_with_filters_accepts_single_value_and_list(self, mock_gitguardian_client):
        """
        GIVEN: Filters passed as a mix of scalars and lists
        WHEN: Listing public incidents
        THEN: All filters are coerced to lists, forwarded to the client, and reported in applied_filters
        """
        mock_gitguardian_client.list_public_incidents = AsyncMock(
            return_value={"data": [], "cursor": None, "has_more": False}
        )

        params = ListPublicIncidentsParams(
            status=IncidentStatus.TRIGGERED,  # scalar coerced to list
            severity=[IncidentSeverity.HIGH, IncidentSeverity.CRITICAL],
            validity=[IncidentValidity.VALID],
            tags="FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED",
            risk_score_min=70,
            risk_score_max=100,
            assignee_id=42,
            feedback=True,
            declarative_secret_status="active",
            ordering="-risk_score",
            per_page=50,
        )
        result = await list_public_incidents(params)

        call_kwargs = mock_gitguardian_client.list_public_incidents.call_args.kwargs
        assert call_kwargs["status"] == [IncidentStatus.TRIGGERED]
        assert call_kwargs["severity"] == [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
        assert call_kwargs["validity"] == [IncidentValidity.VALID]
        assert call_kwargs["tags"] == "FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED"
        assert call_kwargs["risk_score_min"] == 70
        assert call_kwargs["risk_score_max"] == 100
        assert call_kwargs["assignee_id"] == 42
        assert call_kwargs["feedback"] is True
        assert call_kwargs["declarative_secret_status"] == "active"
        assert call_kwargs["ordering"] == "-risk_score"
        assert call_kwargs["per_page"] == 50

        assert result.applied_filters["status"] == ["TRIGGERED"]
        assert result.applied_filters["severity"] == ["high", "critical"]
        assert result.applied_filters["validity"] == ["valid"]
        assert result.applied_filters["risk_score_min"] == 70
        assert result.applied_filters["assignee_id"] == 42

    @pytest.mark.asyncio
    async def test_defaults_can_be_disabled(self, mock_gitguardian_client):
        """
        GIVEN: Explicit None for status/severity/validity
        WHEN: Listing public incidents
        THEN: No status/severity/validity filter is sent to the client
        """
        mock_gitguardian_client.list_public_incidents = AsyncMock(
            return_value={"data": [], "cursor": None, "has_more": False}
        )

        params = ListPublicIncidentsParams(status=None, severity=None, validity=None)
        await list_public_incidents(params)

        call_kwargs = mock_gitguardian_client.list_public_incidents.call_args.kwargs
        assert call_kwargs["status"] is None
        assert call_kwargs["severity"] is None
        assert call_kwargs["validity"] is None

    @pytest.mark.asyncio
    async def test_with_cursor_returns_pagination_info(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor on the response
        WHEN: Listing public incidents
        THEN: cursor and has_more are surfaced in the result
        """
        mock_gitguardian_client.list_public_incidents = AsyncMock(
            return_value={"data": [{"id": 1}], "cursor": "next_cursor_xyz", "has_more": True}
        )

        result = await list_public_incidents(ListPublicIncidentsParams(cursor="prev_cursor"))

        call_kwargs = mock_gitguardian_client.list_public_incidents.call_args.kwargs
        assert call_kwargs["cursor"] == "prev_cursor"
        assert result.cursor == "next_cursor_xyz"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_get_all_forwarded(self, mock_gitguardian_client):
        """
        GIVEN: get_all=True
        WHEN: Listing public incidents
        THEN: get_all is forwarded to the client method
        """
        mock_gitguardian_client.list_public_incidents = AsyncMock(
            return_value={"data": [{"id": 1}, {"id": 2}], "cursor": None, "has_more": False}
        )

        result = await list_public_incidents(ListPublicIncidentsParams(get_all=True))

        call_kwargs = mock_gitguardian_client.list_public_incidents.call_args.kwargs
        assert call_kwargs["get_all"] is True
        assert result.incidents_count == 2

    @pytest.mark.asyncio
    async def test_client_error_returns_error_result(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Listing public incidents
        THEN: An error result is returned
        """
        mock_gitguardian_client.list_public_incidents = AsyncMock(side_effect=Exception("Boom"))

        result = await list_public_incidents(ListPublicIncidentsParams())

        assert hasattr(result, "error")
        assert "Failed to list public incidents" in result.error
