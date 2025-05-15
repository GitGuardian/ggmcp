import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gg_api_mcp_server.client import GitGuardianClient, IncidentSeverity, IncidentStatus, IncidentValidity


@pytest.fixture
def client():
    """Fixture to create a client instance with test API key."""
    with patch.dict(
        os.environ, {"GITGUARDIAN_API_KEY": "test_api_key", "GITGUARDIAN_API_URL": "https://test.gitguardian.com"}
    ):
        return GitGuardianClient()


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
        assert client.api_key == "test_api_key"
        assert client.api_url == "https://test.gitguardian.com"

    def test_init_with_params(self):
        """Test client initialization with parameters."""
        client = GitGuardianClient(api_key="custom_key", api_url="https://custom.api.url")
        assert client.api_key == "custom_key"
        assert client.api_url == "https://custom.api.url"

    def test_init_without_api_key(self):
        """Test client initialization without API key."""
        with patch.dict(os.environ, {"GITGUARDIAN_API_KEY": ""}):
            with pytest.raises(ValueError):
                GitGuardianClient()

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
            result = await client._request("GET", "/test")

            # Assert request was called with correct parameters
            mock_httpx_client.request.assert_called_once()
            args, kwargs = mock_httpx_client.request.call_args
            assert args[0] == "GET"
            assert args[1].endswith("/test")
            assert kwargs["headers"]["Authorization"] == "Token test_api_key"

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
            result = await client._request("GET", "/test")

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
                await client._request("GET", "/test")

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
        """Test list_incidents method."""
        expected_response = {
            "data": [{"id": "incident_1", "severity": "critical", "status": "TRIGGERED"}],
            "pagination": {"total_count": 1, "page": 1, "per_page": 20},
        }

        with patch.object(client, "_request", AsyncMock(return_value=expected_response)) as mock_request:
            result = await client.list_incidents(
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.TRIGGERED,
                from_date="2023-01-01",
                to_date="2023-12-31",
                per_page=20,
                page=1,
            )

            # Assert _request was called with correct parameters
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            assert args[0] == "GET"
            assert "/incidents" in args[1]

            # Assert response
            assert result == expected_response
            assert len(result["data"]) == 1
            assert result["data"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_list_incidents_with_validity(self, client):
        """Test list_incidents method with validity."""
        expected_response = {
            "data": [{"id": "incident_1", "severity": "critical", "status": "TRIGGERED", "validity": "VALID"}],
            "pagination": {"total_count": 1, "page": 1, "per_page": 20},
        }

        with patch.object(client, "_request", AsyncMock(return_value=expected_response)) as mock_request:
            result = await client.list_incidents(
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.TRIGGERED,
                from_date="2023-01-01",
                to_date="2023-12-31",
                per_page=20,
                page=1,
                validity=IncidentValidity.VALID,
            )

            # Assert _request was called with correct parameters
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            assert args[0] == "GET"
            assert "/incidents" in args[1]

            # Assert response
            assert result == expected_response
            assert len(result["data"]) == 1
            assert result["data"][0]["severity"] == "critical"
            assert result["data"][0]["validity"] == "VALID"
