from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.find_current_source_id import (
    FindCurrentSourceIdError,
    FindCurrentSourceIdSuggestion,
    find_current_source_id,
)


class TestFindCurrentSourceId:
    """Tests for the find_current_source_id tool.

    The tool is transport-agnostic: it resolves the repository name solely from
    ``remote_url`` and never shells out to git, so the same code path serves both
    the local (stdio) and remote (HTTP) servers.
    """

    @pytest.mark.asyncio
    async def test_find_current_source_id_exact_match(self, mock_gitguardian_client):
        """
        GIVEN a git remote URL and an exact match in GitGuardian
        WHEN finding the source_id with the remote_url
        THEN the source_id and full source information are returned
        """
        mock_response = {
            "id": "source_123",
            "full_name": "GitGuardian/ggmcp",
            "url": "https://github.com/GitGuardian/ggmcp",
            "monitored": True,
        }
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

        result = await find_current_source_id(remote_url="https://github.com/GitGuardian/ggmcp.git")

        # Client is called with the parsed bare repository name.
        mock_gitguardian_client.get_source_by_name.assert_called_once_with("ggmcp", return_all_on_no_match=True)
        assert result.repository_name == "ggmcp"
        assert result.source_id == "source_123"
        assert hasattr(result, "message")

    @pytest.mark.asyncio
    async def test_find_current_source_id_multiple_candidates(self, mock_gitguardian_client):
        """
        GIVEN a git remote URL that matches multiple sources
        WHEN finding the source_id
        THEN all candidate sources are returned for user selection
        """
        mock_response = [
            {
                "id": "source_1",
                "full_name": "GitGuardian/test-repo",
                "url": "https://github.com/GitGuardian/test-repo",
                "monitored": True,
            },
            {
                "id": "source_2",
                "full_name": "GitGuardian/test-repo-fork",
                "url": "https://github.com/GitGuardian/test-repo-fork",
                "monitored": False,
            },
        ]
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

        result = await find_current_source_id(remote_url="https://github.com/GitGuardian/test-repo.git")

        assert result.repository_name == "test-repo"
        assert hasattr(result, "candidates")
        assert len(result.candidates) == 2
        assert hasattr(result, "message")
        assert hasattr(result, "suggestion")

    @pytest.mark.asyncio
    async def test_find_current_source_id_direct_match(self, mock_gitguardian_client):
        """
        GIVEN a repository URL that gets parsed to just the repo name
        WHEN finding the source_id with a direct match
        THEN the source_id is returned
        """
        mock_response = {
            "id": "source_123",
            "name": "repo-name",
            "url": "https://github.com/OrgName/repo-name",
        }
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

        result = await find_current_source_id(remote_url="https://github.com/OrgName/repo-name.git")

        assert result.repository_name == "repo-name"
        assert result.source_id == "source_123"

    @pytest.mark.asyncio
    async def test_find_current_source_id_no_match_at_all(self, mock_gitguardian_client):
        """
        GIVEN no sources match the repository in GitGuardian
        WHEN finding the source_id
        THEN an error is returned indicating repository not found
        """
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=[])

        result = await find_current_source_id(remote_url="https://github.com/Unknown/repo.git")

        assert result.repository_name == "repo"
        assert hasattr(result, "error")
        assert "not found in GitGuardian" in result.error

    @pytest.mark.asyncio
    async def test_find_current_source_id_invalid_url(self, mock_gitguardian_client):
        """
        GIVEN a git URL that cannot be parsed
        WHEN attempting to find the source_id
        THEN an error is returned
        """
        result = await find_current_source_id(remote_url="invalid-url-format")

        # The unparsable URL passes through as the repository name, so the search
        # simply finds nothing and reports the repository as missing.
        assert isinstance(result, FindCurrentSourceIdError)
        assert "not found in GitGuardian" in result.error

    @pytest.mark.asyncio
    async def test_find_current_source_id_gitlab_url(self, mock_gitguardian_client):
        """
        GIVEN a GitLab repository URL
        WHEN finding the source_id
        THEN the URL is correctly parsed and source_id is returned
        """
        mock_response = {
            "id": "source_gitlab",
            "full_name": "company/project",
            "url": "https://gitlab.com/company/project",
        }
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

        result = await find_current_source_id(remote_url="https://gitlab.com/company/project.git")

        assert result.repository_name == "project"
        assert result.source_id == "source_gitlab"

    @pytest.mark.asyncio
    async def test_find_current_source_id_ssh_url(self, mock_gitguardian_client):
        """
        GIVEN a git SSH URL
        WHEN finding the source_id
        THEN the SSH URL is correctly parsed and source_id is returned
        """
        mock_response = {
            "id": "source_ssh",
            "full_name": "GitGuardian/ggmcp",
        }
        mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

        result = await find_current_source_id(remote_url="git@github.com:GitGuardian/ggmcp.git")

        assert result.repository_name == "ggmcp"
        assert result.source_id == "source_ssh"

    @pytest.mark.asyncio
    async def test_find_current_source_id_client_error(self, mock_gitguardian_client):
        """
        GIVEN the GitGuardian client raises an exception
        WHEN attempting to find the source_id
        THEN an error is returned
        """
        mock_gitguardian_client.get_source_by_name = AsyncMock(side_effect=Exception("API error"))

        result = await find_current_source_id(remote_url="https://github.com/GitGuardian/test.git")

        assert hasattr(result, "error")
        assert "Failed to find source_id" in result.error

    @pytest.mark.asyncio
    async def test_find_current_source_id_without_remote_url_returns_suggestion(self, mock_gitguardian_client):
        """
        GIVEN no remote_url is provided
        WHEN finding the source_id
        THEN a suggestion asking the agent to run git locally is returned and the
             API is never queried
        """
        result = await find_current_source_id()

        assert isinstance(result, FindCurrentSourceIdSuggestion)
        assert "git config --get remote.origin.url" in result.suggestion
        assert "remote_url" in result.suggestion
        mock_gitguardian_client.get_source_by_name.assert_not_called()

    @pytest.mark.asyncio
    async def test_find_current_source_id_with_empty_remote_url(self, mock_gitguardian_client):
        """
        GIVEN an empty remote_url that cannot be parsed into a repository name
        WHEN finding the source_id
        THEN an error explaining the bad remote_url is returned
        """
        result = await find_current_source_id(remote_url="")

        assert isinstance(result, FindCurrentSourceIdError)
        assert "could not be parsed" in result.message
