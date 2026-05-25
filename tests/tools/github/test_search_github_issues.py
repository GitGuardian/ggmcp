"""Tests for ``search_github_issues``. GitHub API mocked via ``respx``."""

import httpx
import pytest
import respx
from gg_api_core.tools.github.search_github_issues import (
    SearchGithubIssuesParams,
    search_github_issues,
)

_SAMPLE_ISSUES = {
    "total_count": 2,
    "items": [
        {
            "number": 42,
            "title": "Investigate leaked AWS key in commit abc123",
            "body": "We noticed an AWS key was committed last week...",
            "state": "open",
            "html_url": "https://github.com/acme/repo/issues/42",
            "created_at": "2024-08-01T12:00:00Z",
            "user": {"login": "alice"},
        },
        {
            "number": 41,
            "title": "Old issue",
            "body": None,
            "state": "closed",
            "html_url": "https://github.com/acme/repo/issues/41",
            "created_at": "2023-01-01T00:00:00Z",
            "user": {"login": "bob"},
        },
    ],
}


@pytest.mark.asyncio
async def test_search_github_issues_happy_path():
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/search/issues").mock(return_value=httpx.Response(200, json=_SAMPLE_ISSUES))
        result = await search_github_issues(SearchGithubIssuesParams(query="aws key", repo="acme/repo"))

    assert result.error is None
    assert result.total_count == 2
    assert len(result.issues) == 2
    assert result.issues[0].number == 42
    assert result.issues[0].author == "alice"
    assert "AWS key was committed" in result.issues[0].body_excerpt


@pytest.mark.asyncio
async def test_search_github_issues_rate_limited():
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/search/issues").mock(
            return_value=httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
                headers={"x-ratelimit-remaining": "0"},
            )
        )
        result = await search_github_issues(SearchGithubIssuesParams(query="anything"))

    assert result.error is not None
    assert "403" in result.error
    assert result.rate_limit.get("remaining") == "0"
