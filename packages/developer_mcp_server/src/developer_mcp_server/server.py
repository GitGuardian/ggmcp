"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os

from developer_mcp_server.register_tools import register_developer_tools, DEVELOPER_INSTRUCTIONS
from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_developer_scopes, validate_scopes, set_developer_scopes
from gg_api_core.host import is_self_hosted_instance

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions=DEVELOPER_INSTRUCTIONS,
)
logger.info("Created Developer GitGuardianFastMCP instance")

register_developer_tools(mcp)

set_developer_scopes()


def run_mcp_server():
    logger.info("Starting Developer MCP server...")

    # Check if HTTP/SSE transport is requested via environment variables
    mcp_port = os.environ.get("MCP_PORT")
    mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")

    if mcp_port:
        # Use HTTP/SSE transport
        import uvicorn

        logger.info(f"Starting MCP server with HTTP/SSE transport on {mcp_host}:{mcp_port}")
        uvicorn.run(mcp.sse_app(), host=mcp_host, port=int(mcp_port))
    else:
        # Use default stdio transport
        logger.info("Starting MCP server with stdio transport (default)")
        mcp.run()


if __name__ == "__main__":
    run_mcp_server()
