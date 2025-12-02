"""ASGI application for MCP server over HTTP/SSE.

Note: This SSE transport requires sticky sessions for horizontal scaling since
session state is maintained in-memory per worker. For stateless operation,
use http_app.py instead which uses StreamableHTTP with JSON responses.
"""

from fastmcp.server.http import create_sse_app

from developer_mcp_server.server import mcp

sse_app = create_sse_app(
    server=mcp,
    message_path="/messages/",
    sse_path="/sse",
)
