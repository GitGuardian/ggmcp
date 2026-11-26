"""Header attribution through the production HTTP app."""

from gg_api_core.request_headers import DEFAULT_USER_AGENT
from tests.e2e.harness import call_tool, list_tool_names, mcp_headers, tool_output


async def test_http_user_agent_fallback_and_tool_attribution(mcp_client, gg_api, mock_token_scopes):
    scopes = mock_token_scopes()
    incident = gg_api.get("/incidents/secrets/77").respond(200, json={"id": 77})
    headers = {**mcp_headers(), "User-Agent": "http-client/2"}

    await list_tool_names(mcp_client, headers=headers)
    assert "X-GG-MCP-Tool" not in scopes.calls.last.request.headers
    result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77}, headers=headers)

    assert tool_output(result) == {"incident": {"id": 77}}
    outgoing = incident.calls.last.request.headers
    assert outgoing["User-Agent"] == f"{DEFAULT_USER_AGENT} (transport=http; client=http-client/2)"
    assert outgoing["X-GG-MCP-Tool"] == "get_internal_incident"
