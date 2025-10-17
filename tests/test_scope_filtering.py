"""Test scope-based tool filtering in GitGuardianFastMCP."""

import pytest
from gg_api_core.mcp_server import GitGuardianFastMCP


@pytest.mark.asyncio
async def test_tools_filtered_by_scopes():
    """Test that tools are filtered based on user's available scopes."""

    # Create MCP instance with known scopes
    mcp = GitGuardianFastMCP("Test Server", default_scopes=["scan", "incidents:read"])

    # Register tools with different scope requirements
    @mcp.tool(name="tool_no_scopes", description="Tool with no scope requirements")
    async def tool_no_scopes():
        return "no scopes"

    @mcp.tool(name="tool_with_scan", description="Tool requiring scan scope", required_scopes=["scan"])
    async def tool_with_scan():
        return "scan"

    @mcp.tool(
        name="tool_with_write", description="Tool requiring incidents:write scope", required_scopes=["incidents:write"]
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
