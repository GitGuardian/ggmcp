from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.list_honeytokens import ListHoneytokensParams, list_honeytokens


class TestListHoneytokens:
    """Tests for the list_honeytokens tool."""

    @pytest.mark.asyncio
    async def test_list_honeytokens_success(self, mock_gitguardian_client):
        """
        GIVEN: Honeytokens exist in GitGuardian
        WHEN: Listing honeytokens
        THEN: The API returns the list of honeytokens
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "honeytoken_1",
                    "name": "test_token_1",
                    "status": "ACTIVE",
                    "created_at": "2023-01-01T00:00:00Z",
                },
                {
                    "id": "honeytoken_2",
                    "name": "test_token_2",
                    "status": "REVOKED",
                    "created_at": "2023-02-01T00:00:00Z",
                },
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with correct parameters
        mock_gitguardian_client.list_honeytokens.assert_called_once()

        # Verify response
        assert len(result.honeytokens) == 2
        assert result.honeytokens[0]["name"] == "test_token_1"
        assert result.honeytokens[1]["status"] == "REVOKED"

    @pytest.mark.asyncio
    async def test_list_honeytokens_with_cursor(self, mock_gitguardian_client):
        """
        GIVEN: The API returns results with a next cursor
        WHEN: Listing honeytokens
        THEN: The cursor is properly returned for pagination
        """
        # Mock the client response with ListResponse format including cursor
        mock_response = {
            "data": [
                {
                    "id": "honeytoken_1",
                    "name": "test_token_1",
                    "status": "ACTIVE",
                }
            ],
            "cursor": "next_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=False,
            )
        )

        # Verify response includes cursor
        assert len(result.honeytokens) == 1
        assert result.honeytokens[0]["id"] == "honeytoken_1"
        assert result.next_cursor == "next_page_cursor"

    @pytest.mark.asyncio
    async def test_list_honeytokens_with_filters(self, mock_gitguardian_client):
        """
        GIVEN: Multiple filter parameters
        WHEN: Listing honeytokens with filters
        THEN: The API is called with correct filter parameters
        """
        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "honeytoken_1",
                    "name": "filtered_token",
                    "status": "ACTIVE",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with filters
        result = await list_honeytokens(
            ListHoneytokensParams(
                status="ACTIVE",
                search="filtered",
                ordering="-created_at",
                show_token=True,
                creator_id=None,
                creator_api_token_id=None,
                per_page=50,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with correct parameters
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["status"] == "ACTIVE"
        assert call_kwargs["search"] == "filtered"
        assert call_kwargs["ordering"] == "-created_at"
        assert call_kwargs["show_token"] is True
        assert call_kwargs["per_page"] == 50

        # Verify response
        assert len(result.honeytokens) == 1
        assert result.honeytokens[0]["status"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_list_honeytokens_mine_true(self, mock_gitguardian_client):
        """
        GIVEN: mine=True flag to filter by current user
        WHEN: Listing honeytokens
        THEN: Only honeytokens created by current user are returned
        """
        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user_123"})

        # Mock the client response with ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "honeytoken_1",
                    "name": "my_token",
                    "creator_id": "user_123",
                    "status": "ACTIVE",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with mine=True
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                get_all=False,
                mine=True,
            )
        )

        # Verify get_current_token_info was called
        mock_gitguardian_client.get_current_token_info.assert_called_once()

        # Verify list_honeytokens was called with creator_id
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["creator_id"] == "user_123"

        # Verify response
        assert len(result.honeytokens) == 1
        assert result.honeytokens[0]["creator_id"] == "user_123"

    @pytest.mark.asyncio
    async def test_list_honeytokens_mine_true_no_user_id(self, mock_gitguardian_client):
        """
        GIVEN: mine=True but user_id is not available
        WHEN: Listing honeytokens
        THEN: The request proceeds without user filtering
        """
        # Mock get_current_token_info to return None user_id
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"other_field": "value"})

        # Mock the client response with ListResponse format
        mock_response = {"data": [], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with mine=True
        await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                get_all=False,
                mine=True,
            )
        )

        # Verify that creator_id was not set (should be None)
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["creator_id"] is None

    @pytest.mark.asyncio
    async def test_list_honeytokens_get_all(self, mock_gitguardian_client):
        """
        GIVEN: get_all=True flag
        WHEN: Listing honeytokens with pagination
        THEN: All honeytokens are fetched using pagination
        """
        # Mock the client response with ListResponse format (get_all returns all with cursor=None)
        mock_response = {
            "data": [
                {"id": "honeytoken_1"},
                {"id": "honeytoken_2"},
                {"id": "honeytoken_3"},
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with get_all=True
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                get_all=True,
                mine=False,
            )
        )

        # Verify client was called with get_all=True
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["get_all"] is True

        # Verify response
        assert len(result.honeytokens) == 3

    @pytest.mark.asyncio
    async def test_list_honeytokens_empty_response(self, mock_gitguardian_client):
        """
        GIVEN: No honeytokens exist
        WHEN: Listing honeytokens
        THEN: An empty list is returned
        """
        # Mock the client response with empty list in ListResponse format
        mock_response = {"data": [], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=False,
            )
        )

        # Verify response is empty
        assert len(result.honeytokens) == 0

    @pytest.mark.asyncio
    async def test_list_honeytokens_client_error(self, mock_gitguardian_client):
        """Test error handling when client raises an exception."""
        # Mock the client to raise an exception
        error_message = "API connection failed"
        mock_gitguardian_client.list_honeytokens = AsyncMock(side_effect=Exception(error_message))

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await list_honeytokens(
                ListHoneytokensParams(
                    status=None,
                    search=None,
                    ordering=None,
                    show_token=False,
                    creator_id=None,
                    creator_api_token_id=None,
                    per_page=20,
                    get_all=False,
                    mine=False,
                )
            )

        # Verify error message
        assert error_message in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_list_honeytokens_with_creator_id(self, mock_gitguardian_client):
        """
        GIVEN: An explicit creator_id parameter
        WHEN: Listing honeytokens
        THEN: The API is called with the creator_id filter
        """
        # Mock the client response with ListResponse format
        mock_response = {"data": [{"id": "honeytoken_1"}], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with explicit creator_id
        await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id="specific_user_123",
                creator_api_token_id=None,
                per_page=20,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with correct creator_id
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["creator_id"] == "specific_user_123"

    @pytest.mark.asyncio
    async def test_list_honeytokens_with_creator_api_token_id(self, mock_gitguardian_client):
        """
        GIVEN: A creator_api_token_id parameter
        WHEN: Listing honeytokens
        THEN: The API is called with the creator_api_token_id filter
        """
        # Mock the client response with ListResponse format
        mock_response = {"data": [{"id": "honeytoken_1"}], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with creator_api_token_id
        await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id="token_123",
                per_page=20,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with correct creator_api_token_id
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["creator_api_token_id"] == "token_123"

    @pytest.mark.asyncio
    async def test_list_honeytokens_show_token_true(self, mock_gitguardian_client):
        """
        GIVEN: show_token=True flag
        WHEN: Listing honeytokens
        THEN: Honeytoken details including token values are returned
        """
        # Mock the client response with token details and ListResponse format
        mock_response = {
            "data": [
                {
                    "id": "honeytoken_1",
                    "name": "test_token",
                    "token": "secret_value",
                    "status": "ACTIVE",
                }
            ],
            "cursor": None,
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with show_token=True
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=True,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                get_all=False,
                mine=False,
            )
        )

        # Verify client was called with show_token=True
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["show_token"] is True

        # Verify response includes token
        assert result.honeytokens[0]["token"] == "secret_value"

    @pytest.mark.asyncio
    async def test_list_honeytokens_mine_true_token_info_error(self, mock_gitguardian_client):
        """
        GIVEN: get_current_token_info raises an exception
        WHEN: Listing honeytokens with mine=True
        THEN: The exception propagates to the caller
        """
        # Mock get_current_token_info to raise exception
        mock_gitguardian_client.get_current_token_info = AsyncMock(side_effect=Exception("Token info failed"))

        # Mock the client response with ListResponse format
        mock_response = {"data": [], "cursor": None, "has_more": False}
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with mine=True - should raise the exception
        with pytest.raises(Exception, match="Token info failed"):
            await list_honeytokens(
                ListHoneytokensParams(
                    status=None,
                    search=None,
                    ordering=None,
                    show_token=False,
                    creator_id=None,
                    creator_api_token_id=None,
                    per_page=20,
                    get_all=False,
                    mine=True,
                )
            )

    @pytest.mark.asyncio
    async def test_list_honeytokens_cursor_pagination(self, mock_gitguardian_client):
        """
        GIVEN: A cursor from a previous page
        WHEN: Listing honeytokens with that cursor
        THEN: The cursor is passed to the API and next page is returned
        """
        # Mock the client response with next cursor
        mock_response = {
            "data": [
                {"id": "honeytoken_3", "name": "page2_token1"},
                {"id": "honeytoken_4", "name": "page2_token2"},
            ],
            "cursor": "third_page_cursor",
            "has_more": True,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function with a cursor from "previous page"
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                cursor="second_page_cursor",  # Cursor from previous request
                get_all=False,
                mine=False,
            )
        )

        # Verify cursor was passed to the client
        call_kwargs = mock_gitguardian_client.list_honeytokens.call_args.kwargs
        assert call_kwargs["cursor"] == "second_page_cursor"

        # Verify response includes data and next cursor
        assert len(result.honeytokens) == 2
        assert result.next_cursor == "third_page_cursor"

    @pytest.mark.asyncio
    async def test_list_honeytokens_last_page_no_cursor(self, mock_gitguardian_client):
        """
        GIVEN: The last page of results
        WHEN: Listing honeytokens
        THEN: next_cursor should be None indicating no more pages
        """
        # Mock the client response for last page (no cursor)
        mock_response = {
            "data": [
                {"id": "honeytoken_last", "name": "last_token"},
            ],
            "cursor": None,  # No more pages
            "has_more": False,
        }
        mock_gitguardian_client.list_honeytokens = AsyncMock(return_value=mock_response)

        # Call the function
        result = await list_honeytokens(
            ListHoneytokensParams(
                status=None,
                search=None,
                ordering=None,
                show_token=False,
                creator_id=None,
                creator_api_token_id=None,
                per_page=20,
                cursor=None,
                get_all=False,
                mine=False,
            )
        )

        # Verify next_cursor is None (last page)
        assert len(result.honeytokens) == 1
        assert result.next_cursor is None
