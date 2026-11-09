from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gg_api_core.mcp_server import get_mcp_server


@pytest.fixture
def mcp_server():
    """Fixture to create a GitGuardianFastMCP instance."""
    server = get_mcp_server("test_server")
    server._fetch_token_scopes_from_api = AsyncMock()
    return server


@pytest.fixture
def mock_client():
    """Fixture to create a mock client."""
    client = MagicMock()
    client.get_current_token_info = AsyncMock(return_value={"scopes": ["scan", "incidents:read"]})
    return client


class TestGitGuardianFastMCP:
    """Tests for the GitGuardianFastMCP class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mcp = get_mcp_server("test_server")
        # Mock the token scopes fetching to avoid actual API calls
        self.mcp._fetch_token_scopes_from_api = AsyncMock()
        # Set token scopes directly for testing
        self.mcp.token_scopes = ["scan", "incidents:read"]

    def teardown_method(self):
        """Tear down test fixtures."""
        pass

    @patch("gg_api_core.mcp_server.get_access_token")
    def test_get_personal_access_token_raises_without_scope_token(self, mock_get_access_token):
        """get_personal_access_token() raises ValidationError when no AccessToken is in the request scope."""
        from fastmcp.exceptions import ValidationError

        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        mock_get_access_token.return_value = None

        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        with pytest.raises(ValidationError, match="No access token available"):
            mcp.get_personal_access_token()
