from types import SimpleNamespace
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

    def test_init(self):
        """Test initialization."""
        assert self.mcp.name == "test_server"
        assert self.mcp._tool_scopes == {}

    @pytest.mark.asyncio
    async def test_fetch_token_scopes_from_api(self, mock_gitguardian_client):
        """Test fetching token scopes from SaaS instance."""
        import os
        from unittest.mock import patch

        # Use the conftest fixture's mock client and configure it for this test
        test_scopes = ["scan", "incidents:read", "honeytokens:read", "honeytokens:write"]
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"scopes": test_scopes})

        # Use a SaaS URL instead of test/localhost URL
        with patch.dict(
            os.environ, {"ENABLE_LOCAL_OAUTH": "true", "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"}
        ):
            mcp = get_mcp_server("TestMCP")

            # Call the method - it now returns scopes instead of setting them
            returned_scopes = await mcp._fetch_token_scopes_from_api()

            # Verify the client method was called for SaaS
            mock_gitguardian_client.get_current_token_info.assert_called_once()

            # Verify scopes were returned correctly - convert to set for comparison
            assert returned_scopes == set(test_scopes)

    @pytest.mark.asyncio
    async def test_create_token_scope_lifespan(self):
        """Test that cached scopes mode (OAuth/PAT env) has lifespan for fetching scopes."""
        import os
        from unittest.mock import patch

        from gg_api_core.mcp_server import CachedTokenInfoMixin, GitGuardianLocalOAuthMCP

        # Create OAuth MCP instance
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            mcp = GitGuardianLocalOAuthMCP("test_server_lifespan")

            # Verify it has the CachedTokenInfoMixin
            assert isinstance(mcp, CachedTokenInfoMixin)

            # Verify it has the _create_token_scope_lifespan method
            assert hasattr(mcp, "_create_token_scope_lifespan")

            # Mock the fetch method
            mcp._fetch_token_scopes_from_api = AsyncMock(return_value={"scan", "incidents:read"})

            # Create and test the lifespan
            lifespan = mcp._create_token_scope_lifespan()
            async with lifespan(mcp):
                # Verify fetch_token_scopes_from_api was called
                mcp._fetch_token_scopes_from_api.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_token_scope_lifespan_oauth_disabled(self):
        """Test creating token scope lifespan with non-caching mode (HTTP mode)."""
        import os
        from unittest.mock import patch

        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        # Create MCP server using AuthorizationHeader mode (non-caching)
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}):
            mcp = GitGuardianAuthorizationHeaderMCP("test_server")

            # Verify it doesn't have the CachedTokenInfoMixin methods
            assert not hasattr(mcp, "_create_token_scope_lifespan")

            # Verify it's not an instance of CachedTokenInfoMixin
            from gg_api_core.mcp_server import CachedTokenInfoMixin

            assert not isinstance(mcp, CachedTokenInfoMixin)

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
        import os
        from unittest.mock import patch

        # Test in OAuth mode (cached scopes)
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
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
        """Test that list_tools excludes tools with missing scopes in cached mode."""
        import os
        from unittest.mock import patch

        from gg_api_core.mcp_server import GitGuardianLocalOAuthMCP

        # Test in OAuth mode (cached scopes) - create a new instance
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            mcp = GitGuardianLocalOAuthMCP("test_server_scopes")

            # Set token scopes to include only some required scopes
            mcp._token_scopes = {"scan", "incidents:read"}

            # Create test tools
            @mcp.tool(required_scopes=["scan"])
            async def tool_with_scan():
                """Tool requiring scan scope."""
                return "scan_result"

            @mcp.tool(required_scopes=["teams:write"])
            async def tool_with_teams_write():
                """Tool requiring teams:write scope."""
                return "teams_write_result"

            # List tools
            tools = await mcp.list_tools()

            # Get tool names and check that the scan tool is included
            tool_names = [tool.name for tool in tools]
            assert "tool_with_scan" in tool_names

            # The teams:write tool should be excluded since the required scope is missing
            assert "tool_with_teams_write" not in tool_names

    @patch("gg_api_core.mcp_server.get_access_token")
    def test_get_personal_access_token_returns_scope_token(self, mock_get_access_token):
        """get_personal_access_token() returns the bearer token installed in the request scope."""
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        access_token = SimpleNamespace(token="test-pat-token-123")
        mock_get_access_token.return_value = access_token

        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        assert mcp.get_personal_access_token() == "test-pat-token-123"

    @patch("gg_api_core.mcp_server.get_access_token")
    def test_get_personal_access_token_raises_without_scope_token(self, mock_get_access_token):
        """get_personal_access_token() raises ValidationError when no AccessToken is in the request scope."""
        from fastmcp.exceptions import ValidationError
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        mock_get_access_token.return_value = None

        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        with pytest.raises(ValidationError, match="No access token available"):
            mcp.get_personal_access_token()
