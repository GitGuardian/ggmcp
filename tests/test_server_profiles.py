"""Test that server modules can be imported and initialized for both profiles.

This test ensures that both developer and secops server modules can be
successfully imported and that their tool registration doesn't have syntax errors
(like using mcp.add_tool instead of mcp.tool).
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_env_no_http():
    """Mock environment variables to prevent HTTP server from starting.

    Sets ENABLE_LOCAL_OAUTH=true to use cached scope mode (stdio mode).
    """
    with patch.dict("os.environ", {"MCP_PORT": "", "ENABLE_LOCAL_OAUTH": "true"}, clear=False):
        yield


@pytest.fixture
def mock_gitguardian_modules():
    """Mock GitGuardian API modules to avoid actual API calls during import."""
    with (
        patch("gg_api_core.utils.get_client") as mock_get_client,
        patch("gg_api_core.scopes.set_developer_scopes") as mock_set_dev_scopes,
        patch("gg_api_core.scopes.set_secops_scopes") as mock_set_secops_scopes,
    ):
        # Mock client
        mock_client = MagicMock()
        mock_client.get_current_token_info = AsyncMock(return_value={"scopes": ["scan"]})
        mock_get_client.return_value = mock_client

        yield {
            "get_client": mock_get_client,
            "set_dev_scopes": mock_set_dev_scopes,
            "set_secops_scopes": mock_set_secops_scopes,
        }


def clean_module_imports(module_name: str):
    """Remove a module and its submodules from sys.modules."""
    modules_to_remove = [key for key in sys.modules if key.startswith(module_name)]
    for module in modules_to_remove:
        del sys.modules[module]


class TestServerProfiles:
    """Test that both server profiles can be initialized successfully."""

    def test_developer_server_imports_successfully(self, mock_gitguardian_modules, mock_env_no_http):
        """Test that the developer server module can be imported without errors.

        This test would catch issues like:
        - Using mcp.add_tool instead of mcp.tool
        - Syntax errors in tool registration
        - Missing imports
        """
        # Clean any previous imports
        clean_module_imports("developer_mcp_server")

        try:
            # Import the developer server module
            import developer_mcp_server.server as dev_server

            # Verify the server was created
            assert hasattr(dev_server, "mcp")
            assert dev_server.mcp is not None

            # Verify it's a GitGuardian MCP server (uses the abstract base class)
            from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

            assert isinstance(dev_server.mcp, AbstractGitGuardianFastMCP)

            # Verify the server has the expected name
            assert dev_server.mcp.name == "GitGuardian Developer"

        except AttributeError as e:
            if "add_tool" in str(e):
                pytest.fail(f"Developer server is using mcp.add_tool instead of mcp.tool: {e}")
            raise
        except Exception as e:
            pytest.fail(f"Failed to import developer server: {e}")

    def test_secops_server_imports_successfully(self, mock_gitguardian_modules, mock_env_no_http):
        """Test that the secops server module can be imported without errors.

        This test would catch issues like:
        - Using mcp.add_tool instead of mcp.tool
        - Syntax errors in tool registration
        - Missing imports
        """
        # Clean any previous imports
        clean_module_imports("secops_mcp_server")

        try:
            # Import the secops server module
            import secops_mcp_server.server as secops_server

            # Verify the server was created
            assert hasattr(secops_server, "mcp")
            assert secops_server.mcp is not None

            # Verify it's a GitGuardian MCP server (uses the abstract base class)
            from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

            assert isinstance(secops_server.mcp, AbstractGitGuardianFastMCP)

            # Verify the server has the expected name
            assert secops_server.mcp.name == "GitGuardian SecOps"

        except AttributeError as e:
            if "add_tool" in str(e):
                pytest.fail(f"SecOps server is using mcp.add_tool instead of mcp.tool: {e}")
            raise
        except Exception as e:
            pytest.fail(f"Failed to import secops server: {e}")

    @pytest.mark.asyncio
    async def test_developer_server_tools_registered(self, mock_gitguardian_modules, mock_env_no_http):
        """Test that developer server has tools registered properly."""
        # Clean any previous imports
        clean_module_imports("developer_mcp_server")

        import developer_mcp_server.server as dev_server

        # Mock the _fetch_token_scopes_from_api to avoid actual API calls
        dev_server.mcp._fetch_token_scopes_from_api = AsyncMock()
        dev_server.mcp._token_scopes = {"scan", "incidents:read"}

        # List tools - this would fail if any tool was registered incorrectly
        tools = await dev_server.mcp.list_tools()

        # Verify we have some tools registered
        assert len(tools) > 0, "Developer server should have tools registered"

    @pytest.mark.asyncio
    async def test_secops_server_tools_registered(self, mock_gitguardian_modules, mock_env_no_http):
        """Test that secops server has tools registered properly."""
        # Clean any previous imports
        clean_module_imports("secops_mcp_server")

        import secops_mcp_server.server as secops_server

        # Mock the _fetch_token_scopes_from_api to avoid actual API calls
        secops_server.mcp._fetch_token_scopes_from_api = AsyncMock()
        secops_server.mcp._token_scopes = {"scan", "incidents:read", "incidents:write"}

        # List tools - this would fail if any tool was registered incorrectly
        tools = await secops_server.mcp.list_tools()

        # Verify we have some tools registered
        assert len(tools) > 0, "SecOps server should have tools registered"

        # Verify some expected secops-specific tools are present
        tool_names = [tool.name for tool in tools]
        # Check for a secops-specific tool that should be registered
        assert "assign_incident" in tool_names, "SecOps server should have assign_incident tool"
        assert "create_code_fix_request" in tool_names, "SecOps server should have create_code_fix_request tool"

    def test_both_servers_can_coexist(self, mock_gitguardian_modules, mock_env_no_http):
        """Test that both server modules can be imported in the same test session.

        This ensures there are no naming conflicts or import issues.
        """
        # Clean any previous imports
        clean_module_imports("developer_mcp_server")
        clean_module_imports("secops_mcp_server")

        try:
            import developer_mcp_server.server as dev_server
            import secops_mcp_server.server as secops_server

            # Both servers should be distinct instances
            assert dev_server.mcp is not secops_server.mcp
            assert dev_server.mcp.name != secops_server.mcp.name

        except Exception as e:
            pytest.fail(f"Failed to import both servers: {e}")
