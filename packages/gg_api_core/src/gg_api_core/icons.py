"""Branding icons exposed by GitGuardian MCP servers."""

import base64
from functools import lru_cache
from importlib.resources import files

from mcp.types import Icon


@lru_cache(maxsize=1)
def get_gitguardian_icons() -> list[Icon]:
    """Return the GitGuardian icon list to advertise in the MCP server metadata."""
    logo_bytes = (files("gg_api_core") / "assets" / "gitguardian-icon-256x256.png").read_bytes()
    encoded = base64.b64encode(logo_bytes).decode("ascii")
    return [
        Icon(
            src=f"data:image/png;base64,{encoded}",
            mimeType="image/png",
            sizes=["256x256"],
        )
    ]
