"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os

from developer_mcp_server.register_tools import register_developer_tools, DEVELOPER_INSTRUCTIONS
from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_developer_scopes, validate_scopes
from gg_api_core.host import is_self_hosted_instance

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables
gitguardian_url = os.environ.get("GITGUARDIAN_URL")

logger.info("Starting Developer MCP Server")
logger.debug(f"GitGuardian URL: {gitguardian_url or 'Using default'}")

# Set specific environment variable for this server to request only developer-specific scopes
# Use dynamic scope detection based on instance type (self-hosted vs SaaS)
# But respect user-specified scopes if they exist
is_self_hosted = is_self_hosted_instance(gitguardian_url)

# Only override scopes if user hasn't specified them
if not os.environ.get("GITGUARDIAN_SCOPES"):
    developer_scopes = get_developer_scopes(gitguardian_url)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(developer_scopes)
    logger.debug(f"Auto-detected scopes for instance type: {'Self-hosted' if is_self_hosted else 'SaaS'}")
    if is_self_hosted:
        logger.info("Self-hosted instance detected - honeytokens:write scope omitted to avoid permission issues")
else:
    # Validate user-specified scopes
    try:
        user_scopes_str = os.environ.get("GITGUARDIAN_SCOPES")
        validated_scopes = validate_scopes(user_scopes_str)
        os.environ["GITGUARDIAN_SCOPES"] = ",".join(validated_scopes)
        logger.info(f"Using validated user-specified scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")
    except ValueError as e:
        logger.error(f"Invalid scopes configuration: {e}")
        logger.error("Please check your GITGUARDIAN_SCOPES environment variable")
        raise

logger.debug(f"Final scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions=DEVELOPER_INSTRUCTIONS,
)
logger.info("Created Developer GitGuardianFastMCP instance")

register_developer_tools(mcp)

def run_mcp_server():
    logger.info("Starting Developer MCP server...")

    # Check if HTTP/SSE transport is requested via environment variables
    mcp_port = os.environ.get("MCP_PORT")
    mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")

    if mcp_port:
        # Use HTTP/SSE transport
        import uvicorn
        logger.info(f"Starting MCP server with HTTP/SSE transport on {mcp_host}:{mcp_port}")
        # Get the SSE ASGI app from FastMCP
        uvicorn.run(mcp.sse_app(), host=mcp_host, port=int(mcp_port))
    else:
        # Use default stdio transport
        logger.info("Starting MCP server with stdio transport (default)")
        mcp.run()


if __name__ == "__main__":
    run_mcp_server()
