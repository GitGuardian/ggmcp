from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from gg_api_core.mcp_server import GitGuardianFastMCP


@pytest.fixture
def mcp_server():
    """Fixture to create a GitGuardianFastMCP instance."""
    server = GitGuardianFastMCP("test_server")
    server._fetch_token_scopes = AsyncMock()
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
        self.mcp = GitGuardianFastMCP("test_server")
        # Mock the token scopes fetching to avoid actual API calls
        self.mcp._fetch_token_scopes = AsyncMock()
        # Set token scopes directly for testing
        self.mcp.token_scopes = ["scan", "incidents:read"]

    def teardown_method(self):
        """Tear down test fixtures."""
        pass

    def test_init(self):
        """Test initialization."""
        assert self.mcp.name == "test_server"
        assert self.mcp._tool_scopes == {}

    @pytest.mark.asyncio
    async def test_fetch_token_scopes(self, mock_gitguardian_client):
        """Test fetching token scopes."""
        # Use the conftest fixture's mock client and configure it for this test
        test_scopes = ["scan", "incidents:read", "honeytokens:read", "honeytokens:write"]
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"scopes": test_scopes})

        # Create a test fixture for the GitGuardianFastMCP class
        self.mcp = GitGuardianFastMCP("TestMCP")

        # Call the method
        await self.mcp._fetch_token_scopes()

        # Verify the client method was called
        mock_gitguardian_client.get_current_token_info.assert_called_once()

        # Verify scopes were set correctly - convert to set for comparison
        assert self.mcp._token_scopes == set(test_scopes)

    @pytest.mark.asyncio
    async def test_create_token_scope_lifespan(self):
        """Test creating token scope lifespan."""
        # Create a mock lifespan
        mock_original_lifespan = MagicMock()
        mock_context_manager = MagicMock()
        mock_original_lifespan.return_value = mock_context_manager
        mock_context_manager.__aenter__ = AsyncMock(return_value={})
        mock_context_manager.__aexit__ = AsyncMock(return_value=None)

        # Mock the fetch_token_scopes method
        self.mcp._fetch_token_scopes = AsyncMock()

        # Create the lifespan
        lifespan = self.mcp._create_token_scope_lifespan(mock_original_lifespan)

        # Use the lifespan
        async with lifespan(self.mcp) as context:
            # Verify fetch_token_scopes was called
            self.mcp._fetch_token_scopes.assert_called_once()
            # Verify the original lifespan was used
            mock_original_lifespan.assert_called_once_with(self.mcp)
            # Verify the context is passed through
            assert context == {}

    @pytest.mark.asyncio
    async def test_tool_decorator(self):
        """Test that the tool decorator properly registers tools."""

        # Create a test tool
        @self.mcp.tool()
        async def test_tool():
            """Test tool docstring."""
            return "test_result"

        # Test that the tool is registered
        tools = await self.mcp.list_tools()
        assert "test_tool" in [tool.name for tool in tools]

    @pytest.mark.asyncio
    async def test_list_tools_all_scopes_available(self):
        """Test that list_tools returns all tools when all scopes are available."""
        # Set token scopes to include all required scopes
        self.mcp._token_scopes = {"scan", "incidents:read", "honeytokens:read"}

        # Create test tools
        @self.mcp.tool(required_scopes=["scan"])
        async def tool_with_scan():
            """Tool requiring scan scope."""
            return "scan_result"

        @self.mcp.tool(required_scopes=["incidents:read"])
        async def tool_with_incidents_read():
            """Tool requiring incidents:read scope."""
            return "incidents_read_result"

        # List tools
        tools = await self.mcp.list_tools()
        tool_names = [tool.name for tool in tools]

        # Check that both tools are included
        assert "tool_with_scan" in tool_names
        assert "tool_with_incidents_read" in tool_names

    @pytest.mark.asyncio
    async def test_list_tools_missing_scopes(self):
        """Test that list_tools excludes tools with missing scopes."""
        # Set token scopes to include only some required scopes
        self.mcp._token_scopes = {"scan", "incidents:read"}

        # Create test tools
        @self.mcp.tool(required_scopes=["scan"])
        async def tool_with_scan():
            """Tool requiring scan scope."""
            return "scan_result"

        @self.mcp.tool(required_scopes=["teams:write"])
        async def tool_with_teams_write():
            """Tool requiring teams:write scope."""
            return "teams_write_result"

        # List tools
        tools = await self.mcp.list_tools()

        # Get tool names and check that the scan tool is included
        tool_names = [tool.name for tool in tools]
        assert "tool_with_scan" in tool_names

        # The teams:write tool should be excluded since the required scope is missing
        assert "tool_with_teams_write" not in tool_names

    def test_extract_token_from_header(self):
        """Test extracting tokens from various Authorization header formats."""
        # Test Bearer format
        token = self.mcp._extract_token_from_header("Bearer test-token-123")
        assert token == "test-token-123"

        # Test Token format
        token = self.mcp._extract_token_from_header("Token another-token-456")
        assert token == "another-token-456"

        # Test raw token (no prefix)
        token = self.mcp._extract_token_from_header("raw-token-789")
        assert token == "raw-token-789"

        # Test case insensitivity
        token = self.mcp._extract_token_from_header("bearer lowercase-token")
        assert token == "lowercase-token"

        # Test with extra whitespace
        token = self.mcp._extract_token_from_header("Bearer   token-with-spaces   ")
        assert token == "token-with-spaces"

        # Test empty string
        token = self.mcp._extract_token_from_header("")
        assert token is None

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_with_authorization_header(self, mock_get_client, mock_get_http_headers):
        """Test that get_client uses Authorization header when available."""
        # Mock HTTP headers with Authorization header
        mock_get_http_headers.return_value = {"authorization": "Bearer test-pat-token-123"}

        # Mock the get_client function
        mock_client_instance = MagicMock()
        mock_get_client.return_value = mock_client_instance

        # Call get_client
        client = self.mcp.get_client()

        # Verify get_client was called with the extracted token
        mock_get_client.assert_called_once_with(personal_access_token="test-pat-token-123")
        assert client == mock_client_instance

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_without_authorization_header(self, mock_get_client, mock_get_http_headers):
        """Test that get_client falls back to default when no Authorization header."""
        # Mock HTTP headers without Authorization header
        mock_get_http_headers.return_value = {}

        # Mock the get_client function
        mock_client_instance = MagicMock()
        mock_get_client.return_value = mock_client_instance

        # Call get_client
        client = self.mcp.get_client()

        # Verify get_client was called without token (fallback)
        mock_get_client.assert_called_once_with()
        assert client == mock_client_instance

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_no_http_context(self, mock_get_client, mock_get_http_headers):
        """Test that get_client handles missing HTTP context (stdio transport)."""
        # Mock get_http_headers to raise exception (no HTTP context)
        mock_get_http_headers.side_effect = RuntimeError("No HTTP context")

        # Mock the get_client function
        mock_client_instance = MagicMock()
        mock_get_client.return_value = mock_client_instance

        # Call get_client (should not raise, should fall back)
        client = self.mcp.get_client()

        # Verify get_client was called without token (fallback)
        mock_get_client.assert_called_once_with()
        assert client == mock_client_instance
