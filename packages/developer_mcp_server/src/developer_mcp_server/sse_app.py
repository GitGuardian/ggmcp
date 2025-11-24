from fastmcp.server.http import create_sse_app

from developer_mcp_server.server import mcp

sse_app = create_sse_app(
    server=mcp,
    message_path="/messages/",
    sse_path="/sse",
)
