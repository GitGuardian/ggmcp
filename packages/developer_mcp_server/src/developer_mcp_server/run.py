"""Runtime entry points for the Developer MCP server.

This module provides different ways to run the MCP server:
- stdio: Standard input/output transport (default for CLI tools)
- http: StreamableHTTP transport using uvicorn (for local development)
"""

import logging
import os

from gg_api_core.sentry_integration import init_sentry

from developer_mcp_server.server import mcp

logger = logging.getLogger(__name__)


def run_stdio():
    """Run the MCP server over stdio transport.

    This is the default mode for MCP servers, used when the server
    is invoked as a subprocess by MCP clients like Claude Desktop.
    """
    init_sentry()
    logger.info("Developer MCP server running on stdio")
    mcp.run(show_banner=False)


def run_http_with_uvicorn():
    """Run the MCP server over HTTP using uvicorn ASGI server.

    This is meant for local development. For production ready setup,
    better use gunicorn with uvicorn ASGI workers via developer_mcp_server.http_app:http_app
    """
    init_sentry()

    # Get host and port from environment variables
    mcp_port = int(os.environ.get("MCP_PORT", "8000"))
    mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")

    # Use StreamableHTTP transport with stateless JSON mode for scalability
    import uvicorn

    logger.info(f"Starting Developer MCP server on {mcp_host}:{mcp_port}")
    uvicorn.run(
        mcp.http_app(path="/mcp", json_response=True, stateless_http=True),
        host=mcp_host,
        port=mcp_port,
    )


def run_mcp_server():
    """Run the MCP server with transport auto-detection.

    If MCP_PORT is set, uses StreamableHTTP transport.
    Otherwise, uses stdio transport (default).
    """
    mcp_port = os.environ.get("MCP_PORT")

    if mcp_port:
        run_http_with_uvicorn()
    else:
        run_stdio()


if __name__ == "__main__":
    run_mcp_server()
