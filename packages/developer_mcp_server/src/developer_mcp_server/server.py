"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os

# Declare this process's profile before anything in gg_api_core reads Settings.
# Used by ``Settings.effective_scopes`` to cap the OAuth scope set.
os.environ.setdefault("SERVER_PROFILE", "developer")

from gg_api_core.mcp_server import get_mcp_server  # noqa: E402

from developer_mcp_server.add_health_check import add_health_check  # noqa: E402
from developer_mcp_server.register_tools import DEVELOPER_INSTRUCTIONS, register_developer_tools  # noqa: E402

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Use our custom GitGuardianFastMCP from the core package
mcp = get_mcp_server(
    "GitGuardian Developer",
    instructions=DEVELOPER_INSTRUCTIONS,
)

register_developer_tools(mcp)
add_health_check(mcp)

logger.info("Developer MCP server instance created and configured")
