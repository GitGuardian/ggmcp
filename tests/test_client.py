import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from gg_api_core.client import GitGuardianClient, IncidentSeverity, IncidentStatus, IncidentValidity


@pytest.fixture
def client():
    """Fixture to create a client instance with OAuth authentication."""
    with patch.dict(os.environ, {"GITGUARDIAN_URL": "https://test.gitguardian.com"}):
        client = GitGuardianClient()
        # Mock the OAuth token to prevent OAuth flow during tests
        client._oauth_token = "test_oauth_token"
        client._token_info = {"user_id": "test_user", "scopes": ["scan"]}
        # Mock the OAuth token ensuring method to prevent OAuth flow
        client._ensure_api_token = AsyncMock()
        return client


@pytest.fixture
def mock_response():
    """Fixture to create a mock response."""
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"data": "test_data"}
    return mock


@pytest.fixture
def mock_httpx_client():
    """Fixture to create a mock httpx client."""
    mock_client = AsyncMock()
    mock_client.request = AsyncMock()
    return mock_client


class TestGitGuardianClient:
    """Tests for the GitGuardian API client."""

    def test_init_with_env_vars(self, client):
        """Test client initialization with environment variables."""
        assert client.public_api_url == "https://test.gitguardian.com/exposed/v1"

    def test_init_with_params(self):
        """Test client initialization with parameters."""
        client = GitGuardianClient(gitguardian_url="https://custom.api.url")
        assert client.public_api_url == "https://custom.api.url/exposed/v1"

    def test_init_oauth_authentication(self):
        """Test client initialization with OAuth authentication."""
        client = GitGuardianClient()
        assert client._oauth_token is None  # Initially no token until OAuth flow

    @pytest.mark.asyncio
    async def test_request_success(self, client, mock_response, mock_httpx_client):
        """Test successful API request."""
        # Use regular MagicMock for raise_for_status since it's not an async method
        mock_response.raise_for_status = MagicMock()

        # Mock the httpx.AsyncClient context manager
        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client
        mock_httpx_client.request = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client._request_get("/test")

            # Assert request was called with correct parameters
            mock_httpx_client.request.assert_called_once()
            args, kwargs = mock_httpx_client.request.call_args
            assert args[0] == "GET"
            assert args[1].endswith("/test")
            assert kwargs["headers"]["Authorization"].startswith("Token ")

            # Assert response was processed correctly
            assert result == {"data": "test_data"}

    @pytest.mark.asyncio
    async def test_request_no_content(self, client, mock_httpx_client):
        """Test API request with no content response."""
        # Create a mock response with 204 status
        mock_response = MagicMock()
        mock_response.status_code = 204
        # Use regular MagicMock for raise_for_status since it's not an async method
        mock_response.raise_for_status = MagicMock()

        # Mock the httpx.AsyncClient context manager
        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client
        mock_httpx_client.request = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client._request_get("/test")

            # Should return empty dict for 204 responses
            assert result == {}

    @pytest.mark.asyncio
    async def test_request_error(self, client, mock_httpx_client):
        """Test API request with error response."""
        # Create a mock response with a working raise_for_status method
        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"

        # Create the HTTPStatusError that will be raised
        error = httpx.HTTPStatusError("Test error", request=mock_request, response=mock_response)

        # Set up the raise_for_status method to raise the error
        # This needs to be a normal method, not an AsyncMock, since raise_for_status is not async
        mock_response.raise_for_status.side_effect = error

        # Mock the httpx.AsyncClient context manager
        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client
        mock_httpx_client.request = AsyncMock(return_value=mock_response)

        # Patch the AsyncClient class to return our mock
        with patch("httpx.AsyncClient", return_value=async_client_instance):
            # The request should raise the HTTPStatusError
            with pytest.raises(httpx.HTTPStatusError):
                await client._request_get("/test")

    @pytest.mark.asyncio
    async def test_create_honeytoken(self, client):
        """Test create_honeytoken method."""
        expected_response = {
            "id": "test_id",
            "name": "Test Token",
            "token": "AKIAXXXXXXXXXXXXXXXX",
            "type": "AWS",
            "status": "ACTIVE",
            "created_at": "2023-01-01T00:00:00Z",
        }

        with patch.object(client, "_request", AsyncMock(return_value=expected_response)) as mock_request:
            result = await client.create_honeytoken(
                name="Test Token", description="Test description", custom_tags=[{"key": "test", "value": "value"}]
            )

            # Assert _request was called with correct parameters
            mock_request.assert_called_once_with(
                "POST",
                "/honeytokens",
                json={
                    "name": "Test Token",
                    "description": "Test description",
                    "type": "AWS",
                    "custom_tags": [{"key": "test", "value": "value"}],
                },
            )

            # Assert response
            assert result == expected_response
            assert result["id"] == "test_id"
            assert result["name"] == "Test Token"
            assert result["token"] == "AKIAXXXXXXXXXXXXXXXX"

    @pytest.mark.asyncio
    async def test_get_honeytoken(self, client):
        """Test get_honeytoken method."""
        expected_response = {
            "id": "test_id",
            "name": "Test Token",
            "token": "AKIAXXXXXXXXXXXXXXXX" if True else None,
            "type": "AWS",
            "status": "ACTIVE",
            "created_at": "2023-01-01T00:00:00Z",
        }

        with patch.object(client, "_request", AsyncMock(return_value=expected_response)) as mock_request:
            result = await client.get_honeytoken("test_id", show_token=True)

            # Assert _request was called with correct parameters
            mock_request.assert_called_once_with("GET", "/honeytokens/test_id?show_token=true")

            # Assert response
            assert result == expected_response
            assert result["id"] == "test_id"
            assert result["token"] == "AKIAXXXXXXXXXXXXXXXX"

    @pytest.mark.asyncio
    async def test_list_incidents(self, client):
        """Test list_incidents method with cursor-based pagination."""
        # Mock response in ListResponse format (cursor-based pagination)
        expected_response = {
            "data": [{"id": "incident_1", "severity": "critical", "status": "TRIGGERED"}],
            "cursor": "next_page_cursor",
            "has_more": True,
        }

        with patch.object(client, "_request_list", AsyncMock(return_value=expected_response)) as mock_request_list:
            result = await client.list_incidents(
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.TRIGGERED,
                from_date="2023-01-01",
                to_date="2023-12-31",
                per_page=20,
            )

            # Assert _request_list was called
            mock_request_list.assert_called_once()

            # Assert response uses cursor-based pagination format
            assert result == expected_response
            assert len(result["data"]) == 1
            assert result["data"][0]["severity"] == "critical"
            assert result["cursor"] == "next_page_cursor"
            assert result["has_more"] is True

    @pytest.mark.asyncio
    async def test_list_incidents_with_validity(self, client):
        """Test list_incidents method with validity filter using cursor-based pagination."""
        # Mock response in ListResponse format (cursor-based pagination)
        expected_response = {
            "data": [{"id": "incident_1", "severity": "critical", "status": "TRIGGERED", "validity": "VALID"}],
            "cursor": None,  # Last page
            "has_more": False,
        }

        with patch.object(client, "_request_list", AsyncMock(return_value=expected_response)) as mock_request_list:
            result = await client.list_incidents(
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.TRIGGERED,
                from_date="2023-01-01",
                to_date="2023-12-31",
                per_page=20,
                validity=IncidentValidity.VALID,
            )

            # Assert _request_list was called
            mock_request_list.assert_called_once()

            # Assert response uses cursor-based pagination format
            assert result == expected_response
            assert len(result["data"]) == 1
            assert result["data"][0]["severity"] == "critical"
            assert result["data"][0]["validity"] == "VALID"
            assert result["cursor"] is None  # Last page
            assert result["has_more"] is False


class TestGitGuardianClientURLs:
    """Tests for GitGuardianClient URL computation."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            (
                "https://api.gitguardian.com/",
                {
                    "dashboard_url": "https://dashboard.gitguardian.com",
                    "public_api_url": "https://api.gitguardian.com/v1",
                    "private_api_url": "https://dashboard.gitguardian.com/api/v1",
                },
            ),
            (
                "https://dashboard.gitguardian.com/",
                {
                    "dashboard_url": "https://dashboard.gitguardian.com",
                    "public_api_url": "https://api.gitguardian.com/v1",
                    "private_api_url": "https://dashboard.gitguardian.com/api/v1",
                },
            ),
            (
                "https://self-hosted.acme.com/",
                {
                    "dashboard_url": "https://self-hosted.acme.com",
                    "public_api_url": "https://self-hosted.acme.com/exposed/v1",
                    "private_api_url": "https://self-hosted.acme.com/api/v1",
                },
            ),
            (
                "https://dashboard.staging.gitguardian.tech/whatever",
                {
                    "dashboard_url": "https://dashboard.staging.gitguardian.tech",
                    "public_api_url": "https://api.staging.gitguardian.tech/v1",
                    "private_api_url": "https://dashboard.staging.gitguardian.tech/api/v1",
                },
            ),
            (
                "https://dashboard.eu1.gitguardian.com/",
                {
                    "dashboard_url": "https://dashboard.eu1.gitguardian.com",
                    "public_api_url": "https://api.eu1.gitguardian.com/v1",
                    "private_api_url": "https://dashboard.eu1.gitguardian.com/api/v1",
                },
            ),
            (
                "https://api.eu1.gitguardian.com/",
                {
                    "dashboard_url": "https://dashboard.eu1.gitguardian.com",
                    "public_api_url": "https://api.eu1.gitguardian.com/v1",
                    "private_api_url": "https://dashboard.eu1.gitguardian.com/api/v1",
                },
            ),
            (
                "https://dashboard.preprod.gitguardian.com/",
                {
                    "dashboard_url": "https://dashboard.preprod.gitguardian.com",
                    "public_api_url": "https://api.preprod.gitguardian.com/v1",
                    "private_api_url": "https://dashboard.preprod.gitguardian.com/api/v1",
                },
            ),
            (
                "http://localhost:3000",
                {
                    "dashboard_url": "http://localhost:3000",
                    "public_api_url": "http://localhost:3000/exposed/v1",
                    "private_api_url": "http://localhost:3000/api/v1",
                },
            ),
            (
                "http://127.0.0.1:3000",
                {
                    "dashboard_url": "http://127.0.0.1:3000",
                    "public_api_url": "http://127.0.0.1:3000/exposed/v1",
                    "private_api_url": "http://127.0.0.1:3000/api/v1",
                },
            ),
        ],
    )
    def test_computed_urls(self, url, expected):
        """Test client initialization with URLs containing paths."""
        with patch.dict(os.environ, {"GITGUARDIAN_URL": url}):
            client = GitGuardianClient()

            assert client.public_api_url == expected["public_api_url"]
            assert client.dashboard_url == expected["dashboard_url"]
            assert client.private_api_url == expected["private_api_url"]


class TestCursorPagination:
    """Tests for cursor pagination functionality."""

    @pytest.mark.asyncio
    async def test_request_list_returns_list_response(self, client):
        """
        GIVEN a list endpoint that returns data with pagination headers
        WHEN _request_list is called
        THEN it should return a ListResponse with data, cursor, and has_more
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": 1}, {"id": 2}]
        mock_response.headers = {"link": '<https://api.gitguardian.com/v1/test?cursor=next_cursor_value>; rel="next"'}
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client._request_list("/test")

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result
            assert isinstance(result["data"], list)
            assert len(result["data"]) == 2
            assert result["cursor"] == "next_cursor_value"
            assert result["has_more"] is True

    @pytest.mark.asyncio
    async def test_request_list_last_page(self, client):
        """
        GIVEN a list endpoint that returns the last page (no Link header)
        WHEN _request_list is called
        THEN cursor should be None and has_more should be False
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": 3}]
        mock_response.headers = {}  # No Link header = last page
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client._request_list("/test")

            assert result["data"] == [{"id": 3}]
            assert result["cursor"] is None
            assert result["has_more"] is False

    @pytest.mark.asyncio
    async def test_request_list_handles_dict_response(self, client):
        """
        GIVEN a list endpoint that returns a dict with "results" or "data" key
        WHEN _request_list is called
        THEN it should extract the list and return proper ListResponse
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": [{"id": 1}, {"id": 2}], "count": 2}
        mock_response.headers = {}
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client._request_list("/test")

            assert result["data"] == [{"id": 1}, {"id": 2}]
            assert result["cursor"] is None
            assert result["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_incidents_returns_list_response(self, client):
        """
        GIVEN the list_incidents method
        WHEN called without get_all
        THEN it should return a ListResponse structure
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": 1, "severity": "high"},
            {"id": 2, "severity": "medium"},
        ]
        mock_response.headers = {"link": '<https://api.gitguardian.com/v1/incidents/secrets?cursor=abc123>; rel="next"'}
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client.list_incidents(get_all=False)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result
            assert len(result["data"]) == 2
            assert result["cursor"] == "abc123"
            assert result["has_more"] is True

    @pytest.mark.asyncio
    async def test_list_incidents_with_get_all(self, client):
        """
        GIVEN the list_incidents method with get_all=True
        WHEN called
        THEN it should return a PaginatedResult with data, cursor, and has_more
        """
        # Mock paginate_all to return PaginatedResult format
        with patch.object(client, "paginate_all", new_callable=AsyncMock) as mock_paginate:
            mock_paginate.return_value = {
                "data": [{"id": 1}, {"id": 2}, {"id": 3}],
                "cursor": None,
                "has_more": False,
            }

            result = await client.list_incidents(get_all=True)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result
            assert len(result["data"]) == 3
            assert result["cursor"] is None
            assert result["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_honeytokens_returns_list_response(self, client):
        """
        GIVEN the list_honeytokens method
        WHEN called without get_all
        THEN it should return a ListResponse structure
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": 1, "name": "token1"},
            {"id": 2, "name": "token2"},
        ]
        mock_response.headers = {"link": '<https://api.gitguardian.com/v1/honeytokens?cursor=xyz789>; rel="next"'}
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client.list_honeytokens(get_all=False)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result
            assert len(result["data"]) == 2
            assert result["cursor"] == "xyz789"

    @pytest.mark.asyncio
    async def test_list_occurrences_returns_list_response(self, client):
        """
        GIVEN the list_occurrences method
        WHEN called
        THEN it should return a ListResponse structure
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": 1, "severity": "high"},
        ]
        mock_response.headers = {}
        mock_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(return_value=mock_response)

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client.list_occurrences(get_all=False)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result
            assert result["cursor"] is None  # No next page

    @pytest.mark.asyncio
    async def test_paginate_all_uses_request_list(self, client):
        """
        GIVEN the paginate_all method
        WHEN it follows pagination cursors
        THEN it should accumulate all items from all pages
        """
        # Mock three pages of results
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = [{"id": 1}, {"id": 2}]
        page1_response.headers = {"link": '<https://api.gitguardian.com/v1/test?cursor=page2>; rel="next"'}
        page1_response.raise_for_status = MagicMock()

        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = [{"id": 3}, {"id": 4}]
        page2_response.headers = {"link": '<https://api.gitguardian.com/v1/test?cursor=page3>; rel="next"'}
        page2_response.raise_for_status = MagicMock()

        page3_response = MagicMock()
        page3_response.status_code = 200
        page3_response.json.return_value = [{"id": 5}]
        page3_response.headers = {}  # Last page
        page3_response.raise_for_status = MagicMock()

        mock_httpx_client = AsyncMock()
        mock_httpx_client.get = AsyncMock(side_effect=[page1_response, page2_response, page3_response])

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        with patch("httpx.AsyncClient", return_value=async_client_instance):
            result = await client.paginate_all("/test")

            # Should have collected all items from all pages
            assert len(result["data"]) == 5
            assert result["data"] == [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}]
            assert result["has_more"] is False

    @pytest.mark.asyncio
    async def test_extract_next_cursor_decodes_url(self, client):
        """
        GIVEN a Link header with URL-encoded cursor
        WHEN _extract_next_cursor is called
        THEN it should return the decoded cursor value
        """
        headers = {"link": '<https://api.gitguardian.com/v1/test?cursor=test%2Bvalue%3D123>; rel="next"'}

        cursor = client._extract_next_cursor(headers)

        assert cursor == "test+value=123"

    @pytest.mark.asyncio
    async def test_extract_next_cursor_no_link_header(self, client):
        """
        GIVEN headers without a Link header
        WHEN _extract_next_cursor is called
        THEN it should return None
        """
        headers = {}

        cursor = client._extract_next_cursor(headers)

        assert cursor is None
