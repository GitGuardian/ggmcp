"""Pure helpers for the remote MCP e2e suite (fixtures live in conftest.py).

Helpers assert on the two boundaries of the server: JSON-RPC requests and
responses on the MCP side, HTTP requests captured by respx on the
GitGuardian API side.
"""

import json
from typing import Any

import httpx
import respx

# The hosted server's own public URL (used for OAuth metadata) and the
# GitGuardian SaaS API it talks to.
MCP_BASE_URL = "https://mcp.gitguardian.com"
GG_API_URL = "https://api.gitguardian.com/v1"

# Bearer token the simulated MCP client sends. The server must forward it
# verbatim to the GitGuardian API as ``Authorization: Token <PAT>``.
TEST_PAT = "e2e-test-pat"

TEST_MEMBER_ID = 4242

# Keep this test oracle independent from ``gg_api_core.scopes.ALL_SCOPES``:
# an accidental production-scope removal must fail the remote contract tests.
EXPECTED_SCOPES = [
    "scan",
    "incidents:read",
    "sources:read",
    "honeytokens:read",
    "honeytokens:write",
    "incidents:write",
    "incidents:share",
    "audit_logs:read",
    "api_tokens:write",
    "api_tokens:read",
    "ip_allowlist:read",
    "ip_allowlist:write",
    "sources:write",
    "custom_tags:read",
    "custom_tags:write",
    "members:read",
    "secrets:write",
    "secrets:read",
]


def mcp_headers(token: str = TEST_PAT) -> dict[str, str]:
    """Headers sent by an MCP client authenticated with ``token``."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }


MCP_HEADERS = mcp_headers()


def token_info(scopes: list[str] | None = None, member_id: int | None = TEST_MEMBER_ID) -> dict[str, Any]:
    """Payload of GET /v1/api_tokens/self for a token with the given scopes."""
    return {
        "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
        "name": "e2e token",
        "workspace_id": 1,
        "type": "personal_access_token",
        "status": "active",
        "member_id": member_id,
        "scopes": scopes if scopes is not None else list(EXPECTED_SCOPES),
    }


async def rpc(
    client: httpx.AsyncClient,
    method: str,
    params: dict[str, Any] | None = None,
    request_id: int | str = 1,
    **kwargs,
) -> httpx.Response:
    """POST a raw JSON-RPC 2.0 request to the /mcp endpoint."""
    headers = kwargs.pop("headers", MCP_HEADERS)
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return await client.post("/mcp", json=payload, headers=headers, **kwargs)


def rpc_result(response: httpx.Response, expected_id: int | str = 1) -> dict[str, Any]:
    """Assert a successful JSON-RPC response and return its ``result``."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert body.get("jsonrpc") == "2.0"
    assert body.get("id") == expected_id
    assert "error" not in body, body
    return body["result"]


async def call_tool(
    client: httpx.AsyncClient,
    name: str,
    arguments: dict[str, Any] | None = None,
    **kwargs,
) -> dict[str, Any]:
    """Call an MCP tool and return the JSON-RPC ``result`` (CallToolResult)."""
    request_id = kwargs.pop("request_id", 1)
    response = await rpc(
        client,
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        request_id=request_id,
        **kwargs,
    )
    return rpc_result(response, expected_id=request_id)


def tool_output(result: dict[str, Any]) -> Any:
    """Extract a successful tool call's output from a CallToolResult, verbatim.

    Use for tools whose output shape is asserted exactly; use
    :func:`unwrap_result` for union-typed tools whose output FastMCP wraps
    in a ``result`` envelope.
    """
    assert result.get("isError") is not True, result
    content = result.get("content")
    assert isinstance(content, list) and content, result
    assert content[0].get("type") == "text", result
    text_content = json.loads(content[0]["text"])

    if "structuredContent" in result:
        structured_content = result["structuredContent"]
        if result.get("_meta", {}).get("fastmcp", {}).get("wrap_result") is True:
            assert structured_content == {"result": text_content}
        else:
            assert structured_content == text_content
        return structured_content
    return text_content


def unwrap_result(result: dict[str, Any]) -> Any:
    """Tool output minus the ``result`` envelope FastMCP adds for union-typed tools.

    Asserts the envelope is present so a change in FastMCP's wire shape for
    union-typed tools fails loudly instead of being silently absorbed.
    """
    output = tool_output(result)
    assert isinstance(output, dict) and set(output) == {"result"}, output
    return output["result"]


def tool_error_text(result: dict[str, Any]) -> str:
    """Extract the error message from a failed CallToolResult."""
    assert result.get("isError") is True, result
    return result["content"][0]["text"]


def sent_body(route: respx.Route) -> Any:
    """JSON body of the last request the GitGuardian API received on a route."""
    content = route.calls.last.request.read()
    return json.loads(content) if content else None


def sent_params(route: respx.Route) -> dict[str, str]:
    """Query params of the last request the GitGuardian API received on a route."""
    return dict(route.calls.last.request.url.params)


def assert_authenticated_request(route: respx.Route, token: str = TEST_PAT) -> None:
    """Assert that a captured GitGuardian API request carries its tenant token."""
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"Token {token}"
    assert request.headers["X-Privacy-Mode"] == "true"


async def list_tool_names(client: httpx.AsyncClient, **kwargs) -> set[str]:
    """Call tools/list and return the visible tool names."""
    request_id = kwargs.pop("request_id", 1)
    result = rpc_result(
        await rpc(client, "tools/list", request_id=request_id, **kwargs),
        expected_id=request_id,
    )
    return {tool["name"] for tool in result["tools"]}
