"""Tests for ``search_github_code``."""

import httpx
import pytest
import respx
from gg_api_core.tools.github.search_github_code import (
    SearchGithubCodeParams,
    search_github_code,
)


@pytest.mark.asyncio
async def test_search_github_code_no_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = await search_github_code(SearchGithubCodeParams(query="foo"))
    assert result.error is not None
    assert "no_github_token" in result.error
    assert result.matches == []


@pytest.mark.asyncio
async def test_search_github_code_happy_path(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    sample = {
        "total_count": 1,
        "items": [
            {
                "path": "README.md",
                "repository": {"full_name": "acme/repo"},
                "html_url": "https://github.com/acme/repo/blob/main/README.md",
                "text_matches": [{"fragment": "Acme Corp internal tooling"}],
            }
        ],
    }
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/search/code").mock(return_value=httpx.Response(200, json=sample))
        result = await search_github_code(SearchGithubCodeParams(query="Acme", repo="acme/repo"))

    assert result.error is None
    assert len(result.matches) == 1
    assert result.matches[0].path == "README.md"
    assert result.matches[0].text_matches == ["Acme Corp internal tooling"]
