from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.list_sources import ListSourcesParams, list_sources


class TestListSources:
    """Tests for the list_sources tool."""

    @pytest.mark.asyncio
    async def test_list_sources_success(self, mock_gitguardian_client):
        """
        GIVEN: Sources exist in GitGuardian
        WHEN: Listing sources
        THEN: The API returns the list of sources
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "full_name": "org/repo1",
                    "health": "safe",
                    "visibility": "private",
                },
                {
                    "id": 2,
                    "type": "gitlab",
                    "full_name": "org/repo2",
                    "health": "at_risk",
                    "visibility": "public",
                },
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams())

        mock_gitguardian_client.list_sources.assert_called_once()
        assert len(result.sources) == 2
        assert result.sources[0]["type"] == "github"
        assert result.sources[1]["health"] == "at_risk"

    @pytest.mark.asyncio
    async def test_list_sources_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: The API returns results with a next cursor
        WHEN: Listing sources
        THEN: The cursor is properly returned for pagination
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "full_name": "org/repo1",
                }
            ],
            "cursor": "next_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams())

        assert len(result.sources) == 1
        assert result.next_cursor == "next_page_cursor"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_list_sources_with_search_filter(self, mock_gitguardian_client):
        """
        GIVEN: A search filter parameter
        WHEN: Listing sources with search
        THEN: The API is called with correct filter parameters
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "full_name": "myorg/myrepo",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(search="myrepo"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["search"] == "myrepo"
        assert len(result.sources) == 1
        assert result.sources[0]["full_name"] == "myorg/myrepo"

    @pytest.mark.asyncio
    async def test_list_sources_with_type_filter(self, mock_gitguardian_client):
        """
        GIVEN: A type filter parameter
        WHEN: Listing sources with type filter
        THEN: The API is called with correct type parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "gitlab",
                    "full_name": "org/repo",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(type="gitlab"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["type"] == "gitlab"
        assert len(result.sources) == 1
        assert result.sources[0]["type"] == "gitlab"

    @pytest.mark.asyncio
    async def test_list_sources_with_health_filter(self, mock_gitguardian_client):
        """
        GIVEN: A health filter parameter
        WHEN: Listing sources with health filter
        THEN: The API is called with correct health parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "health": "at_risk",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(health="at_risk"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["health"] == "at_risk"
        assert len(result.sources) == 1
        assert result.sources[0]["health"] == "at_risk"

    @pytest.mark.asyncio
    async def test_list_sources_with_visibility_filter(self, mock_gitguardian_client):
        """
        GIVEN: A visibility filter parameter
        WHEN: Listing sources with visibility filter
        THEN: The API is called with correct visibility parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "visibility": "public",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(visibility="public"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["visibility"] == "public"
        assert len(result.sources) == 1
        assert result.sources[0]["visibility"] == "public"

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
    async def test_list_sources_with_source_criticality_filter(self, mock_gitguardian_client):
        """
        GIVEN: A source_criticality filter parameter
        WHEN: Listing sources with source_criticality filter
        THEN: The API is called with correct source_criticality parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "source_criticality": "critical",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(source_criticality="critical"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["source_criticality"] == "critical"
        assert len(result.sources) == 1

    @pytest.mark.asyncio
    async def test_list_sources_with_monitored_filter(self, mock_gitguardian_client):
        """
        GIVEN: A monitored filter parameter
        WHEN: Listing sources with monitored filter
        THEN: The API is called with correct monitored parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "monitored": True,
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(monitored=True))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["monitored"] is True
        assert len(result.sources) == 1

    @pytest.mark.asyncio
    async def test_list_sources_with_ordering(self, mock_gitguardian_client):
        """
        GIVEN: An ordering parameter
        WHEN: Listing sources with ordering
        THEN: The API is called with correct ordering parameter
        """
        mock_response = {
            "data": [
                {"id": 1, "type": "github"},
                {"id": 2, "type": "gitlab"},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        await list_sources(ListSourcesParams(ordering="-last_scan_date"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["ordering"] == "-last_scan_date"

    @pytest.mark.asyncio
    async def test_list_sources_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all=True flag
        WHEN: Listing sources
        THEN: All sources are fetched using pagination
        """
        mock_response = {
            "data": [
                {"id": 1},
                {"id": 2},
                {"id": 3},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(get_all=True))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["get_all"] is True
        assert len(result.sources) == 3

    @pytest.mark.asyncio
    async def test_list_sources_empty_response(self, mock_gitguardian_client):
        """
        GIVEN: No sources match the criteria
        WHEN: Listing sources
        THEN: An empty list is returned
        """
        mock_response = {"data": [], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(search="nonexistent"))

        assert len(result.sources) == 0
        assert result.next_cursor is None
        assert result.has_more is False

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

    @pytest.mark.asyncio
    async def test_list_sources_with_per_page(self, mock_gitguardian_client):
        """
        GIVEN: A per_page parameter
        WHEN: Listing sources
        THEN: The API is called with the correct per_page value
        """
        mock_response = {
            "data": [{"id": 1}],
            "cursor": "next",
            "has_more": True,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        await list_sources(ListSourcesParams(per_page=50))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["per_page"] == 50

    @pytest.mark.asyncio
    async def test_list_sources_cursor_pagination(self, mock_gitguardian_client):
        """
        GIVEN: A cursor from a previous page
        WHEN: Listing sources with that cursor
        THEN: The cursor is passed to the API
        """
        mock_response = {
            "data": [{"id": 2}],
            "cursor": "third_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(cursor="second_page_cursor"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["cursor"] == "second_page_cursor"
        assert result.next_cursor == "third_page_cursor"

    @pytest.mark.asyncio
    async def test_list_sources_with_external_id_filter(self, mock_gitguardian_client):
        """
        GIVEN: An external_id filter parameter
        WHEN: Listing sources with external_id filter
        THEN: The API is called with correct external_id parameter
        """
        mock_response = {
            "data": [
                {
                    "id": 1,
                    "type": "github",
                    "external_id": "12345",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_sources = AsyncMock(return_value=mock_response)

        result = await list_sources(ListSourcesParams(external_id="12345"))

        call_kwargs = mock_gitguardian_client.list_sources.call_args.kwargs
        assert call_kwargs["external_id"] == "12345"
        assert len(result.sources) == 1
