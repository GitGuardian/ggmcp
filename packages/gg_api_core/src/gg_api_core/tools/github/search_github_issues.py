"""Search GitHub issues, optionally scoped to a repo."""

import logging
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from ._common import github_get

logger = logging.getLogger(__name__)


class SearchGithubIssuesParams(BaseModel):
    """Parameters for ``search_github_issues``."""

    query: str = Field(description="Free-text query (passed as the GitHub search ``q``).")
    repo: str | None = Field(
        default=None,
        description="Optional ``owner/name`` scope. When set, ``repo:<repo>`` is appended to the query.",
    )
    state: Literal["open", "closed", "all"] = Field(default="all", description="Filter by issue state.")
    limit: int = Field(default=20, ge=1, le=100, description="Max issues to return (1-100).")


class GithubIssueHit(BaseModel):
    number: int
    title: str
    body_excerpt: str
    state: str
    html_url: str
    created_at: str
    author: str


class SearchGithubIssuesResult(BaseModel):
    issues: list[GithubIssueHit] = Field(default_factory=list)
    total_count: int = 0
    rate_limit: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


def _excerpt(body: Any, limit: int = 200) -> str:
    if not isinstance(body, str):
        return ""
    return body[:limit].rstrip() + ("…" if len(body) > limit else "")


async def search_github_issues(params: SearchGithubIssuesParams) -> SearchGithubIssuesResult:
    """Search GitHub issues (optionally scoped to a repo).

    Useful to check whether a leaked secret was already reported, or to find
    context tying a repo to a company (e.g., issues mentioning company
    employees by name or email).

    Args:
        params: ``SearchGithubIssuesParams``.

    Returns:
        ``SearchGithubIssuesResult`` with hits, total, and GitHub rate-limit
        info (so the caller can decide whether to back off).
    """
    q = params.query
    if params.repo:
        q = f"{q} repo:{params.repo}"
    if params.state != "all":
        q = f"{q} state:{params.state}"
    # Limit to issues (exclude PRs) by default to keep results focused.
    q = f"{q} is:issue"

    logger.debug(f"search_github_issues q='{q}' limit={params.limit}")

    try:
        body, rate, status = await github_get(
            "search/issues",
            params={"q": q, "per_page": params.limit},
        )
    except httpx.HTTPError as exc:
        return SearchGithubIssuesResult(error=f"http_error:{exc.__class__.__name__}")

    if status >= 400:
        message = body.get("message") if isinstance(body, dict) else None
        return SearchGithubIssuesResult(
            error=f"http_{status}:{message}" if message else f"http_{status}", rate_limit=rate
        )

    items = body.get("items", []) if isinstance(body, dict) else []
    issues: list[GithubIssueHit] = []
    for item in items[: params.limit]:
        if not isinstance(item, dict):
            continue
        issues.append(
            GithubIssueHit(
                number=int(item.get("number", 0)),
                title=str(item.get("title", "")),
                body_excerpt=_excerpt(item.get("body")),
                state=str(item.get("state", "")),
                html_url=str(item.get("html_url", "")),
                created_at=str(item.get("created_at", "")),
                author=str((item.get("user") or {}).get("login", "")),
            )
        )

    return SearchGithubIssuesResult(
        issues=issues,
        total_count=int(body.get("total_count", len(issues))) if isinstance(body, dict) else len(issues),
        rate_limit=rate,
    )
