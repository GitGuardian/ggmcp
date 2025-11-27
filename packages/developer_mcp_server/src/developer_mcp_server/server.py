"""GitGuardian MCP server for developers with remediation tools."""

import logging

from gg_api_core.mcp_server import get_mcp_server
from gg_api_core.scopes import set_developer_scopes

from developer_mcp_server.add_health_check import add_health_check
from developer_mcp_server.register_tools import DEVELOPER_INSTRUCTIONS, register_developer_tools

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Use our custom GitGuardianFastMCP from the core package
mcp = get_mcp_server(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions=DEVELOPER_INSTRUCTIONS,
)

register_developer_tools(mcp)
add_health_check(mcp)

set_developer_scopes()

logger.info("Developer MCP server instance created and configured")
