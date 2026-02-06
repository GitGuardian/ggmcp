from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.list_detectors import ListDetectorsParams, list_detectors


class TestListDetectors:
    """Tests for the list_detectors tool."""

    @pytest.mark.asyncio
    async def test_list_detectors_success(self, mock_gitguardian_client):
        """
        GIVEN: Detectors exist in GitGuardian
        WHEN: Listing detectors
        THEN: The API returns the list of detectors
        """
        mock_response = {
            "data": [
                {
                    "name": "aws_iam",
                    "display_name": "AWS IAM Keys",
                    "nature": "specific",
                    "family": "credentials",
                    "detector_group_name": "aws_iam",
                },
                {
                    "name": "generic_high_entropy",
                    "display_name": "Generic High Entropy Secret",
                    "nature": "generic",
                    "family": "credentials",
                    "detector_group_name": "generic_high_entropy",
                },
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams())

        mock_gitguardian_client.list_detectors.assert_called_once()
        assert len(result.detectors) == 2
        assert result.detectors[0]["name"] == "aws_iam"
        assert result.detectors[1]["nature"] == "generic"

    @pytest.mark.asyncio
    async def test_list_detectors_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: The API returns results with a next cursor
        WHEN: Listing detectors
        THEN: The cursor is properly returned for pagination
        """
        mock_response = {
            "data": [
                {
                    "name": "private_key_rsa",
                    "display_name": "RSA Private Key",
                    "nature": "specific",
                    "family": "cryptographic_key",
                }
            ],
            "cursor": "next_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams())

        assert len(result.detectors) == 1
        assert result.next_cursor == "next_page_cursor"
        assert result.has_more is True

    @pytest.mark.asyncio
    async def test_list_detectors_with_search_filter(self, mock_gitguardian_client):
        """
        GIVEN: A search filter parameter
        WHEN: Listing detectors with search
        THEN: The API is called with correct filter parameters
        """
        mock_response = {
            "data": [
                {
                    "name": "github_token",
                    "display_name": "GitHub Token",
                    "nature": "specific",
                    "family": "credentials",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams(search="github"))

        call_kwargs = mock_gitguardian_client.list_detectors.call_args.kwargs
        assert call_kwargs["search"] == "github"
        assert len(result.detectors) == 1
        assert result.detectors[0]["name"] == "github_token"

    @pytest.mark.asyncio
    async def test_list_detectors_with_type_filter(self, mock_gitguardian_client):
        """
        GIVEN: A type filter parameter
        WHEN: Listing detectors with type filter
        THEN: The API is called with correct type parameter
        """
        mock_response = {
            "data": [
                {
                    "name": "generic_high_entropy",
                    "display_name": "Generic High Entropy Secret",
                    "type": "generic",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams(type="generic"))

        call_kwargs = mock_gitguardian_client.list_detectors.call_args.kwargs
        assert call_kwargs["type"] == "generic"
        assert len(result.detectors) == 1
        assert result.detectors[0]["type"] == "generic"

    @pytest.mark.asyncio
    async def test_list_detectors_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all=True flag
        WHEN: Listing detectors
        THEN: All detectors are fetched using pagination
        """
        mock_response = {
            "data": [
                {"name": "detector_1"},
                {"name": "detector_2"},
                {"name": "detector_3"},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams(get_all=True))

        call_kwargs = mock_gitguardian_client.list_detectors.call_args.kwargs
        assert call_kwargs["get_all"] is True
        assert len(result.detectors) == 3

    @pytest.mark.asyncio
    async def test_list_detectors_empty_response(self, mock_gitguardian_client):
        """
        GIVEN: No detectors match the criteria
        WHEN: Listing detectors
        THEN: An empty list is returned
        """
        mock_response = {"data": [], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams(search="nonexistent"))

        assert len(result.detectors) == 0
        assert result.next_cursor is None
        assert result.has_more is False

    @pytest.mark.asyncio
    async def test_list_detectors_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Listing detectors
        THEN: A ToolError is raised
        """
        error_message = "API connection failed"
        mock_gitguardian_client.list_detectors = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await list_detectors(ListDetectorsParams())

        assert error_message in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_list_detectors_with_per_page(self, mock_gitguardian_client):
        """
        GIVEN: A per_page parameter
        WHEN: Listing detectors
        THEN: The API is called with the correct per_page value
        """
        mock_response = {
            "data": [{"name": "detector_1"}],
            "cursor": "next",
            "has_more": True,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        await list_detectors(ListDetectorsParams(per_page=50))

        call_kwargs = mock_gitguardian_client.list_detectors.call_args.kwargs
        assert call_kwargs["per_page"] == 50

    @pytest.mark.asyncio
    async def test_list_detectors_cursor_pagination(self, mock_gitguardian_client):
        """
        GIVEN: A cursor from a previous page
        WHEN: Listing detectors with that cursor
        THEN: The cursor is passed to the API
        """
        mock_response = {
            "data": [{"name": "detector_page2"}],
            "cursor": "third_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_detectors = AsyncMock(return_value=mock_response)

        result = await list_detectors(ListDetectorsParams(cursor="second_page_cursor"))

        call_kwargs = mock_gitguardian_client.list_detectors.call_args.kwargs
        assert call_kwargs["cursor"] == "second_page_cursor"
        assert result.next_cursor == "third_page_cursor"
