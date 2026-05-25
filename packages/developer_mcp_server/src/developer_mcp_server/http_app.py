"""Deprecated compatibility shim — use ``gg_mcp_server.http_app`` instead."""

import warnings

from gg_mcp_server.http_app import http_app

warnings.warn(
    "developer_mcp_server.http_app is deprecated; use gg_mcp_server.http_app instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["http_app"]
