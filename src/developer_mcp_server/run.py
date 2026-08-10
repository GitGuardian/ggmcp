"""Deprecated compatibility shim — use ``gg-mcp-server`` instead."""

import warnings

from gg_mcp_server.run import (
    run_http_with_uvicorn,
    run_stdio,
)
from gg_mcp_server.run import (
    run_mcp_server as _run_mcp_server,
)

__all__ = ["run_http_with_uvicorn", "run_mcp_server", "run_stdio"]


def run_mcp_server():
    warnings.warn(
        "developer-mcp-server is deprecated; use gg-mcp-server instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    _run_mcp_server()


if __name__ == "__main__":
    run_mcp_server()
