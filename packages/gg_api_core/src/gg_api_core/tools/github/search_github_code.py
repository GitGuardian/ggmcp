"""Search GitHub code, optionally scoped to a repo. Requires ``GITHUB_TOKEN``."""

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from ._common import github_get, github_token

logger = logging.getLogger(__name__)


class SearchGithubCodeParams(BaseModel):
    """Parameters for ``search_github_code``."""

    query: str = Field(description="Free-text query (passed as the GitHub search ``q``).")
    repo: str | None = Field(default=None, description="Optional ``owner/name`` scope.")
    limit: int = Field(default=20, ge=1, le=100, description="Max results (1-100).")


class GithubCodeHit(BaseModel):
    path: str
    repo: str
    html_url: str
    text_matches: list[str] = Field(default_factory=list)


class SearchGithubCodeResult(BaseModel):
    matches: list[GithubCodeHit] = Field(default_factory=list)
    total_count: int = 0
    rate_limit: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


def _extract_text_matches(item: dict[str, Any]) -> list[str]:
    matches = item.get("text_matches") or []
    out: list[str] = []
    for m in matches:
        if isinstance(m, dict):
            frag = m.get("fragment")
            if isinstance(frag, str):
                out.append(frag)
    return out


async def search_github_code(params: SearchGithubCodeParams) -> SearchGithubCodeResult:
    """Search GitHub code (optionally scoped to a repo).

    Use to find additional occurrences of a leaked value, or files such as
    ``README.md`` / ``CODEOWNERS`` / ``package.json`` that tie a repo to a
    company. Requires ``GITHUB_TOKEN`` to be set — GitHub gates code search
    behind authentication.

    Args:
        params: ``SearchGithubCodeParams``.

    Returns:
        ``SearchGithubCodeResult`` with matches and rate-limit info. If no
        token is set, ``error`` is ``no_github_token`` and no request is made.
    """
    if not github_token():
        return SearchGithubCodeResult(
            error="no_github_token: set GITHUB_TOKEN to use search_github_code",
        )

    q = params.query
    if params.repo:
        q = f"{q} repo:{params.repo}"

    logger.debug(f"search_github_code q='{q}' limit={params.limit}")

    try:
        body, rate, status = await github_get(
            "search/code",
            params={"q": q, "per_page": params.limit},
        )
    except httpx.HTTPError as exc:
        return SearchGithubCodeResult(error=f"http_error:{exc.__class__.__name__}")

    if status >= 400:
        message = body.get("message") if isinstance(body, dict) else None
        return SearchGithubCodeResult(
            error=f"http_{status}:{message}" if message else f"http_{status}",
            rate_limit=rate,
        )

    items = body.get("items", []) if isinstance(body, dict) else []
    matches: list[GithubCodeHit] = []
    for item in items[: params.limit]:
        if not isinstance(item, dict):
            continue
        repo = (item.get("repository") or {}).get("full_name", "")
        matches.append(
            GithubCodeHit(
                path=str(item.get("path", "")),
                repo=str(repo),
                html_url=str(item.get("html_url", "")),
                text_matches=_extract_text_matches(item),
            )
        )

    return SearchGithubCodeResult(
        matches=matches,
        total_count=int(body.get("total_count", len(matches))) if isinstance(body, dict) else len(matches),
        rate_limit=rate,
    )
