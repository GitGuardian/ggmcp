"""ASGI application for MCP server over StreamableHTTP.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its StreamableHTTP application.
"""

from fastmcp.server.http import create_streamable_http_app

from developer_mcp_server.server import mcp

# Note: We use StreamableHTTP with json_response=True and stateless_http=True to enable
# fully stateless operation. This allows horizontal scaling without sticky sessions
# since no session state is maintained between requests.
http_app = create_streamable_http_app(
    server=mcp,
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
)
