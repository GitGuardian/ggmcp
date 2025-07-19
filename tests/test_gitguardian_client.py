import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gg_api_mcp_server.client import GitGuardianClient


@pytest.fixture
def client():
    """Fixture to create a client instance with OAuth authentication."""
    with patch.dict(
        os.environ, {"GITGUARDIAN_URL": "https://test.gitguardian.com"}
    ):
        return GitGuardianClient()


class TestGitGuardianClient:
    """Tests for the GitGuardian API client."""

    def test_init_with_env_vars(self, client):
        """
        GIVEN a GitGuardianClient without explicit credentials
        WHEN the client is initialized
        THEN it should use environment variables
        """
        assert client.api_key == "test_api_key"
        assert client.api_url == "https://test.gitguardian.com"

    def test_init_with_params(self):
        """
        GIVEN explicit API credentials
        WHEN the GitGuardianClient is initialized with those credentials
        THEN it should use the provided values instead of environment variables
        """
        client = GitGuardianClient(api_key="custom_key", api_url="https://custom.api.url")
        assert client.api_key == "custom_key"
        assert client.api_url == "https://custom.api.url"

    def test_init_oauth_only(self):
        """
        GIVEN OAuth authentication is used
        WHEN the GitGuardianClient is initialized
        THEN it should set OAuth mode and no API key
        """
        client = GitGuardianClient()
        assert client.use_oauth is True
        assert client.api_key is None

    @pytest.mark.asyncio
    async def test_request_success(self, client):
        """Test successful API request."""
        # Create a mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test_data"}
        # Use regular MagicMock for raise_for_status since it's not an async method
        mock_response.raise_for_status = MagicMock()

        # Create a mock AsyncClient and its instance
        mock_httpx_client = AsyncMock()
        mock_httpx_client.request = AsyncMock(return_value=mock_response)

        # Create a mock for the AsyncClient context manager
        async_client_instance = AsyncMock()
        async_client_instance.__aenter__.return_value = mock_httpx_client

        # Patch the AsyncClient class to return our context manager mock
        with patch("httpx.AsyncClient", return_value=async_client_instance):
            # Call the request method
            result = await client._request("GET", "/test")

            # Verify the request was made with correct parameters
            mock_httpx_client.request.assert_called_once()

            # Verify the response was processed correctly
            assert result == {"data": "test_data"}

    @pytest.mark.asyncio
    async def test_create_honeytoken(self, client):
        """
        GIVEN a configured GitGuardianClient
        WHEN creating a honeytoken
        THEN it should send the correct data to the API and return the response
        """
        mock_response = {
            "id": "test_id",
            "name": "Test Token",
            "token": "AKIAXXXXXXXXXXXXXXXX",
        }

        with patch.object(client, "_request", AsyncMock(return_value=mock_response)) as mock_request:
            result = await client.create_honeytoken(
                name="Test Token", description="Test description", custom_tags=["test"]
            )

            mock_request.assert_called_once()
            assert result["id"] == "test_id"
            assert result["name"] == "Test Token"
            assert result["token"] == "AKIAXXXXXXXXXXXXXXXX"
