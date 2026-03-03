"""Test scope-based tool filtering in GitGuardianFastMCP."""

import os
from unittest.mock import patch

import pytest
from gg_api_core.mcp_server import get_mcp_server


@pytest.mark.asyncio
async def test_tools_filtered_by_scopes():
    """Test that tools are filtered based on user's available scopes."""

    # Test in OAuth mode (uses cached scopes)
    with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
        # Create MCP instance
        mcp = get_mcp_server("Test Server")

        # Set token scopes directly for testing (simulating what would be fetched on startup)
        mcp._token_scopes = {"scan", "incidents:read"}

        # Register tools with different scope requirements
        @mcp.tool(name="tool_no_scopes", description="Tool with no scope requirements")
        async def tool_no_scopes():
            return "no scopes"

        @mcp.tool(name="tool_with_scan", description="Tool requiring scan scope", required_scopes=["scan"])
        async def tool_with_scan():
            return "scan"

        @mcp.tool(
            name="tool_with_write",
            description="Tool requiring incidents:write scope",
            required_scopes=["incidents:write"],
        )
        async def tool_with_write():
            return "write"

        @mcp.tool(
            name="tool_with_multiple",
            description="Tool requiring multiple scopes",
            required_scopes=["scan", "incidents:read"],
        )
        async def tool_with_multiple():
            return "multiple"

        @mcp.tool(
            name="tool_with_unavailable",
            description="Tool requiring unavailable scopes",
            required_scopes=["honeytokens:write"],
        )
        async def tool_with_unavailable():
            return "unavailable"

        # Get list of tools
        tools = await mcp.list_tools()
        tool_names = [tool.name for tool in tools]

        # Verify that only tools with satisfied scope requirements are included
        assert "tool_no_scopes" in tool_names, "Tool with no requirements should be included"
        assert "tool_with_scan" in tool_names, "Tool with satisfied scope should be included"
        assert "tool_with_multiple" in tool_names, "Tool with multiple satisfied scopes should be included"

        # Verify that tools with unsatisfied scope requirements are excluded
        assert "tool_with_write" not in tool_names, "Tool with unsatisfied scope should be hidden"
        assert "tool_with_unavailable" not in tool_names, "Tool with unavailable scope should be hidden"


@pytest.mark.asyncio
async def test_direct_call_tools_filtered_by_scopes():
    """Test that tools registered via direct call (mcp.tool(fn, ...)) are filtered by scopes."""

    with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
        mcp = get_mcp_server("Test Direct Call")
        mcp._token_scopes = {"scan"}

        async def allowed_fn():
            return "allowed"

        async def denied_fn():
            return "denied"

        async def no_scope_fn():
            return "no scope"

        # Register tools via direct call (the pattern used in secops_mcp_server)
        mcp.tool(allowed_fn, description="Allowed tool", required_scopes=["scan"])
        mcp.tool(denied_fn, description="Denied tool", required_scopes=["incidents:write"])
        mcp.tool(no_scope_fn, description="No scope tool")

        tools = await mcp.list_tools()
        tool_names = [tool.name for tool in tools]

        assert "allowed_fn" in tool_names, "Direct-call tool with satisfied scope should be included"
        assert "denied_fn" not in tool_names, "Direct-call tool with missing scope should be hidden"
        assert "no_scope_fn" in tool_names, "Direct-call tool without scope requirement should be included"


@pytest.mark.asyncio
async def test_direct_call_tools_with_custom_name_filtered_by_scopes():
    """Test that direct-call tools with explicit name= are filtered correctly."""

    with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
        mcp = get_mcp_server("Test Custom Name")
        mcp._token_scopes = {"incidents:read"}

        async def my_func():
            return "result"

        async def my_other_func():
            return "other"

        mcp.tool(my_func, name="custom_allowed", description="Allowed", required_scopes=["incidents:read"])
        mcp.tool(my_other_func, name="custom_denied", description="Denied", required_scopes=["honeytokens:write"])

        tools = await mcp.list_tools()
        tool_names = [tool.name for tool in tools]

        assert "custom_allowed" in tool_names, "Custom-named tool with satisfied scope should be included"
        assert "custom_denied" not in tool_names, "Custom-named tool with missing scope should be hidden"


@pytest.mark.asyncio
async def test_scope_filtering_with_partially_satisfied_multiple_scopes():
    """Test that a tool requiring multiple scopes is hidden when only some are available."""

    with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
        mcp = get_mcp_server("Test Partial Scopes")
        mcp._token_scopes = {"incidents:read"}

        @mcp.tool(
            name="needs_both",
            description="Needs read and write",
            required_scopes=["incidents:read", "incidents:write"],
        )
        async def needs_both():
            return "both"

        tools = await mcp.list_tools()
        tool_names = [tool.name for tool in tools]

        assert "needs_both" not in tool_names, (
            "Tool should be hidden when only a subset of required scopes is available"
        )
