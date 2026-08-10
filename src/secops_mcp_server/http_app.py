"""Deprecated compatibility shim — use ``gg_mcp_server.http_app`` instead."""

import warnings

from gg_mcp_server.http_app import app, http_app

warnings.warn(
    "secops_mcp_server.http_app is deprecated; use gg_mcp_server.http_app instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["app", "http_app"]
