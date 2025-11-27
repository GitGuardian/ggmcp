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

    def test_extract_token_from_header(self):
        """Test extracting tokens from various Authorization header formats."""
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        # Test Bearer format
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("Bearer test-token-123")
        assert token == "test-token-123"

        # Test Token format
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("Token another-token-456")
        assert token == "another-token-456"

        # Test raw token (no prefix)
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("raw-token-789")
        assert token == "raw-token-789"

        # Test case insensitivity
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("bearer lowercase-token")
        assert token == "lowercase-token"

        # Test with extra whitespace
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("Bearer   token-with-spaces   ")
        assert token == "token-with-spaces"

        # Test empty string
        token = GitGuardianAuthorizationHeaderMCP._default_extract_token("")
        assert token is None

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_with_authorization_header(self, mock_get_client, mock_get_http_headers):
        """Test that get_personal_access_token extracts token from Authorization header."""
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        # Mock HTTP headers with Authorization header
        mock_get_http_headers.return_value = {"authorization": "Bearer test-pat-token-123"}

        # Create MCP with Authorization header mode
        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        # Call get_personal_access_token
        token = mcp.get_personal_access_token()

        # Verify token was extracted correctly
        assert token == "test-pat-token-123"

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_without_authorization_header(self, mock_get_client, mock_get_http_headers):
        """Test that get_personal_access_token raises ValidationError when no Authorization header."""
        from fastmcp.exceptions import ValidationError
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        # Mock HTTP headers without Authorization header
        mock_get_http_headers.return_value = {}

        # Create MCP with Authorization header mode
        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        # Call get_personal_access_token - should raise ValidationError
        with pytest.raises(ValidationError, match="Authorization header required"):
            mcp.get_personal_access_token()

    @patch("gg_api_core.mcp_server.get_http_headers")
    @patch("gg_api_core.mcp_server.get_client")
    def test_get_client_no_http_context(self, mock_get_client, mock_get_http_headers):
        """Test that get_personal_access_token propagates RuntimeError when no HTTP context."""
        from gg_api_core.mcp_server import GitGuardianAuthorizationHeaderMCP

        # Mock get_http_headers to raise exception (no HTTP context)
        mock_get_http_headers.side_effect = RuntimeError("No HTTP context")

        # Create MCP with Authorization header mode
        mcp = GitGuardianAuthorizationHeaderMCP("test_server")

        # Call get_personal_access_token - should raise RuntimeError
        with pytest.raises(RuntimeError, match="No HTTP context"):
            mcp.get_personal_access_token()
