"""Shared helpers for GitHub tools."""

from __future__ import annotations

from typing import Any

import httpx

from gg_api_core.settings import get_settings

GITHUB_API = "https://api.github.com"
GITHUB_TIMEOUT = 10.0
USER_AGENT = "GitGuardian-MCP/HIL-tools"


def github_token() -> str | None:
    """Return the configured GitHub token (via ``GITHUB_TOKEN`` env), else None."""
    return get_settings().github_token or None


def build_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers


def rate_limit_info(headers: Any) -> dict[str, str]:
    """Pull ``x-ratelimit-*`` headers from a response for surfacing to the caller."""
    out: dict[str, str] = {}
    for key in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-resource"):
        if key in headers:
            out[key.replace("x-ratelimit-", "")] = str(headers[key])
    return out


async def github_get(path: str, params: dict[str, Any] | None = None) -> tuple[Any, dict[str, str], int]:
    """GET ``api.github.com/{path}`` and return ``(json, rate_limit, status)``.

    Raises ``httpx.HTTPError`` on transport errors. The caller decides what
    to do with non-2xx status codes (most tools surface them via ``error``).
    """
    url = f"{GITHUB_API}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=GITHUB_TIMEOUT, follow_redirects=True) as client:
        response = await client.get(url, headers=build_headers(), params=params)
    try:
        body = response.json()
    except ValueError:
        body = None
    return body, rate_limit_info(response.headers), response.status_code
