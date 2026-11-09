from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError

from gg_api_core.tools.list_sources import ListSourcesParams, list_sources


class TestListSources:
    """Tests for the list_sources tool."""

    @pytest.mark.asyncio
    async def test_list_sources_with_last_scan_status_filter(self, mock_gitguardian_client):
        """
        GIVEN: A last_scan_status filter parameter
        WHEN: Listing sources with last_scan_status filter
        THEN: The API is called with correct last_scan_status parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "last_scan_status": "finished",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(last_scan_status="finished"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["last_scan_status"] == "finished"
        assert len(result.sources) == 1

    @pytest.mark.asyncio
    async def test_list_sources_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Listing sources
        THEN: A ToolError is raised
        """
        error_message = "API connection failed"
        mock_gitguardian_client.list_sources = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await list_sources(ListSourcesParams())

        assert error_message in str(excinfo.value)
