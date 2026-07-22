"""Runtime entry points for the GitGuardian MCP server.

This module provides different ways to run the MCP server:
- stdio: Standard input/output transport (default for CLI tools)
- http: StreamableHTTP transport using uvicorn (for local development)
"""

import logging

from gg_api_core.sentry_integration import init_sentry
from gg_api_core.settings import get_settings

from gg_mcp_server.server import mcp

logger = logging.getLogger(__name__)


def run_stdio():
    """Run the MCP server over stdio transport.

    This is the default mode for MCP servers, used when the server
    is invoked as a subprocess by MCP clients like Claude Desktop.
    """
    init_sentry()
    logger.info("GitGuardian MCP server running on stdio")
    mcp.run(show_banner=False)


def run_http_with_uvicorn():
    """Run the MCP server over HTTP using uvicorn ASGI server.

    This is meant for local development. For production setups, use gunicorn
    with uvicorn ASGI workers via ``gg_mcp_server.http_app:http_app``.
    """
    init_sentry()

    settings = get_settings()
    mcp_port = int(settings.mcp_port or "8000")
    mcp_host = settings.mcp_host

    import uvicorn

    logger.info(f"Starting GitGuardian MCP server on {mcp_host}:{mcp_port}")
    uvicorn.run(
        mcp.http_app(path="/mcp", json_response=True, stateless_http=True),
        host=mcp_host,
        port=mcp_port,
        log_config=None,
    )


def run_mcp_server():
    """Run the MCP server with transport auto-detection.

    If MCP_PORT is set, uses StreamableHTTP transport.
    Otherwise, uses stdio transport (default).
    """
    if get_settings().mcp_port:
        run_http_with_uvicorn()
    else:
        run_stdio()


if __name__ == "__main__":
    run_mcp_server()
