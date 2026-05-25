"""Tests for ``list_github_repo_contributors``."""

import httpx
import pytest
import respx
from gg_api_core.tools.github.list_github_repo_contributors import (
    ListGithubRepoContributorsParams,
    list_github_repo_contributors,
)


@pytest.mark.asyncio
async def test_list_contributors_with_enrichment():
    contributors = [
        {"login": "alice", "contributions": 200},
        {"login": "bob", "contributions": 50},
    ]
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/acme/repo/contributors").mock(return_value=httpx.Response(200, json=contributors))
        router.get("/users/alice").mock(
            return_value=httpx.Response(
                200,
                json={"company": "Acme Corp", "email": "alice@acme.com", "name": "Alice"},
            )
        )
        router.get("/users/bob").mock(
            return_value=httpx.Response(
                200,
                json={"company": None, "email": None, "name": "Bob"},
            )
        )
        result = await list_github_repo_contributors(ListGithubRepoContributorsParams(repo="acme/repo", limit=2))

    assert result.error is None
    assert len(result.contributors) == 2
    alice = next(c for c in result.contributors if c.login == "alice")
    assert alice.company == "Acme Corp"
    assert alice.email == "alice@acme.com"


@pytest.mark.asyncio
async def test_list_contributors_no_enrichment_when_limit_zero():
    contributors = [{"login": "alice", "contributions": 200}]
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/acme/repo/contributors").mock(return_value=httpx.Response(200, json=contributors))
        # If /users/alice is hit, this will fail because no route is set.
        result = await list_github_repo_contributors(ListGithubRepoContributorsParams(repo="acme/repo", limit=0))

    assert result.error is None
    assert len(result.contributors) == 1
    assert result.contributors[0].company is None


@pytest.mark.asyncio
async def test_list_contributors_repo_not_found():
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/acme/missing/contributors").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        result = await list_github_repo_contributors(ListGithubRepoContributorsParams(repo="acme/missing", limit=5))

    assert result.error is not None
    assert "404" in result.error
