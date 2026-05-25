"""Tests for ``get_github_repo_metadata``."""

import httpx
import pytest
import respx
from gg_api_core.tools.github.get_github_repo_metadata import (
    GetGithubRepoMetadataParams,
    get_github_repo_metadata,
)

_REPO_RESPONSE = {
    "description": "Acme's open-source CLI",
    "homepage": "https://acme.com",
    "owner": {"login": "acme", "type": "Organization"},
    "stargazers_count": 1234,
    "fork": False,
    "archived": False,
    "topics": ["security", "cli"],
    "default_branch": "main",
    "license": {"spdx_id": "MIT"},
    "created_at": "2020-01-01T00:00:00Z",
    "pushed_at": "2024-08-01T00:00:00Z",
}

_ORG_RESPONSE = {"company": "Acme Corp"}


@pytest.mark.asyncio
async def test_get_github_repo_metadata_happy_path():
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/acme/repo").mock(return_value=httpx.Response(200, json=_REPO_RESPONSE))
        router.get("/orgs/acme").mock(return_value=httpx.Response(200, json=_ORG_RESPONSE))
        result = await get_github_repo_metadata(GetGithubRepoMetadataParams(repo="acme/repo"))

    assert result.error is None
    assert result.description == "Acme's open-source CLI"
    assert result.owner_type == "Organization"
    assert result.owner_company == "Acme Corp"
    assert result.stars == 1234
    assert result.license == "MIT"
    assert "security" in result.topics


@pytest.mark.asyncio
async def test_get_github_repo_metadata_not_found():
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/acme/missing").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
        result = await get_github_repo_metadata(GetGithubRepoMetadataParams(repo="acme/missing"))

    assert result.error is not None
    assert "404" in result.error
