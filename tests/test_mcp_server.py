from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gg_api_mcp_server.mcp_server import GitGuardianFastMCP


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
    async def test_fetch_token_scopes(self):
        """Test fetching token scopes."""
        # Create a test fixture for the GitGuardianFastMCP class
        self.mcp = GitGuardianFastMCP("TestMCP")

        # Create mock token info response
        token_info = {"scopes": ["scan", "incidents:read", "honeytokens:read", "honeytokens:write"]}

        # Create a mock client with an async get_current_token_info method
        mock_client = MagicMock()
        mock_client.get_current_token_info = AsyncMock(return_value=token_info)

        # Patch the get_gitguardian_client function to return our mock client
        with patch("gg_api_mcp_server.mcp_server.get_gitguardian_client", return_value=mock_client):
            # Call the method
            await self.mcp._fetch_token_scopes()

            # Verify the client method was called
            mock_client.get_current_token_info.assert_called_once()

            # Verify scopes were set correctly - convert to set for comparison
            assert self.mcp._token_scopes == set(["scan", "incidents:read", "honeytokens:read", "honeytokens:write"])

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
        self.mcp.token_scopes = ["scan", "incidents:read", "honeytokens:read"]

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
        self.mcp.token_scopes = ["scan", "incidents:read"]

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

        # The teams:write tool should still be in the list but with a warning in its description
        teams_write_tool = next((t for t in tools if t.name == "tool_with_teams_write"), None)
        assert teams_write_tool is not None
        assert "⚠️ DO NOT USE THIS TOOL" in teams_write_tool.description
        assert "Missing required scopes: teams:write" in teams_write_tool.description
