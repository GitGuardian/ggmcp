from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.list_public_occurrences import (
    ListPublicOccurrencesParams,
    list_public_occurrences,
)


class TestListPublicOccurrences:
    """Tests for the list_public_occurrences tool."""

    @pytest.mark.asyncio
    async def test_basic_call_passes_incident_id(self, mock_gitguardian_client):
        """
        GIVEN: An incident_id
        WHEN: Listing public occurrences
        THEN: The client method is called with that incident_id and default pagination
        """
        mock_gitguardian_client.list_public_occurrences = AsyncMock(
            return_value={"data": [{"id": 12345, "incident_id": 3759}], "cursor": None, "has_more": False}
        )

        result = await list_public_occurrences(ListPublicOccurrencesParams(incident_id=3759))

        mock_gitguardian_client.list_public_occurrences.assert_called_once()
        call_kwargs = mock_gitguardian_client.list_public_occurrences.call_args.kwargs
        assert call_kwargs["incident_id"] == 3759
        assert call_kwargs["per_page"] == 20
        assert call_kwargs["ordering"] == "-date"
        assert call_kwargs["get_all"] is False

        assert result.occurrences_count == 1
        assert result.applied_filters["incident_id"] == 3759

    @pytest.mark.asyncio
    async def test_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple occurrence-level filters
        WHEN: Listing public occurrences
        THEN: Filters are forwarded to the client and reflected in applied_filters
        """
        mock_gitguardian_client.list_public_occurrences = AsyncMock(
            return_value={"data": [], "cursor": None, "has_more": False}
        )

        params = ListPublicOccurrencesParams(
            incident_id=42,
            source_id=6531,
            presence="present",
            sha="fccebf0562",
            filepath="src/config",
            attachment_reason="by_dev_from_perimeter,on_github_org_in_perimeter",
            severity="critical,high",
            status="TRIGGERED,ASSIGNED",
            validity="valid",
            tags="FROM_HISTORICAL_SCAN",
            ordering="-id",
            per_page=100,
        )
        result = await list_public_occurrences(params)

        call_kwargs = mock_gitguardian_client.list_public_occurrences.call_args.kwargs
        assert call_kwargs["incident_id"] == 42
        assert call_kwargs["source_id"] == 6531
        assert call_kwargs["presence"] == "present"
        assert call_kwargs["sha"] == "fccebf0562"
        assert call_kwargs["filepath"] == "src/config"
        assert call_kwargs["attachment_reason"] == "by_dev_from_perimeter,on_github_org_in_perimeter"
        assert call_kwargs["severity"] == "critical,high"
        assert call_kwargs["status"] == "TRIGGERED,ASSIGNED"
        assert call_kwargs["validity"] == "valid"
        assert call_kwargs["tags"] == "FROM_HISTORICAL_SCAN"
        assert call_kwargs["ordering"] == "-id"
        assert call_kwargs["per_page"] == 100

        assert result.applied_filters["source_id"] == 6531
        assert result.applied_filters["presence"] == "present"
        assert result.applied_filters["filepath"] == "src/config"

    @pytest.mark.asyncio
    async def test_with_cursor_returns_pagination_info(self, mock_gitguardian_client):
        """
        GIVEN: A pagination cursor on the response
        WHEN: Listing public occurrences
        THEN: cursor and has_more are surfaced in the result
        """
        mock_gitguardian_client.list_public_occurrences = AsyncMock(
            return_value={"data": [{"id": 1}], "cursor": "next_cursor", "has_more": True}
        )

        result = await list_public_occurrences(ListPublicOccurrencesParams(incident_id=1, cursor="prev_cursor"))

        call_kwargs = mock_gitguardian_client.list_public_occurrences.call_args.kwargs
        assert call_kwargs["cursor"] == "prev_cursor"
        assert result.cursor == "next_cursor"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_get_all_forwarded(self, mock_gitguardian_client):
        """
        GIVEN: get_all=True
        WHEN: Listing public occurrences
        THEN: get_all is forwarded to the client method
        """
        mock_gitguardian_client.list_public_occurrences = AsyncMock(
            return_value={
                "data": [{"id": 1}, {"id": 2}],
                "cursor": None,
                "has_more": False,
            }
        )

        result = await list_public_occurrences(ListPublicOccurrencesParams(incident_id=1, get_all=True))

        call_kwargs = mock_gitguardian_client.list_public_occurrences.call_args.kwargs
        assert call_kwargs["get_all"] is True
        assert result.occurrences_count == 2

    @pytest.mark.asyncio
    async def test_client_error_returns_error_result(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Listing public occurrences
        THEN: An error result is returned
        """
        mock_gitguardian_client.list_public_occurrences = AsyncMock(side_effect=Exception("Boom"))

        result = await list_public_occurrences(ListPublicOccurrencesParams(incident_id=1))

        assert hasattr(result, "error")
        assert "Failed to list public occurrences" in result.error
