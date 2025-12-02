"""ASGI application for MCP server over StreamableHTTP.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its StreamableHTTP application.

This module is specifically for production deployment with gunicorn.
For local development, use the run_http_with_uvicorn() function instead.


"""

import logging

from fastmcp.server.http import create_streamable_http_app
from gg_api_core.sentry_integration import init_sentry

from secops_mcp_server.server import mcp

logger = logging.getLogger(__name__)

# Initialize Sentry for production deployment
init_sentry()

# Note: We use StreamableHTTP with json_response=True and stateless_http=True to enable
# fully stateless operation. This allows horizontal scaling without sticky sessions
# since no session state is maintained between requests.
app = create_streamable_http_app(
    server=mcp,
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
)

logger.info("MCP application initialized for StreamableHTTP transport (stateless JSON mode)")
