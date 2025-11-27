"""Core functionality for GitGuardian MCP servers."""

import logging
import sys

__version__ = "0.1.0"


def configure_mcp_logging(level: int = logging.INFO) -> None:
    """Configure logging to use stderr (stdout is reserved for MCP JSON-RPC protocol)."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
        force=True,
    )
    # Reduce noise from library loggers
    for name in ("mcp", "fastmcp", "rich"):
        logging.getLogger(name).setLevel(logging.WARNING)
