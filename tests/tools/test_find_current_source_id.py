from unittest.mock import AsyncMock, patch, MagicMock
import subprocess

import pytest
from gg_api_core.tools.find_current_source_id import find_current_source_id


class TestFindCurrentSourceId:
    """Tests for the find_current_source_id tool."""

    @pytest.mark.asyncio
    async def test_find_current_source_id_exact_match(self, mock_gitguardian_client):
        """
        GIVEN: A git repository with a remote URL
        WHEN: Finding the source_id with an exact match in GitGuardian
        THEN: The source_id and full source information are returned
        """
        # Mock git command to return a remote URL
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/GitGuardian/gg-mcp.git\n",
                returncode=0,
            )

            # Mock the client response with exact match
            mock_response = {
                "id": "source_123",
                "full_name": "GitGuardian/gg-mcp",
                "url": "https://github.com/GitGuardian/gg-mcp",
                "monitored": True,
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(
                return_value=mock_response
            )

            # Call the function
            result = await find_current_source_id()

            # Verify git command was called
            mock_run.assert_called_once_with(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            # Verify client was called with parsed repository name
            mock_gitguardian_client.get_source_by_name.assert_called_once_with(
                "GitGuardian/gg-mcp", return_all_on_no_match=True
            )

            # Verify response
            assert result["repository_name"] == "GitGuardian/gg-mcp"
            assert result["source_id"] == "source_123"
            assert "message" in result

    @pytest.mark.asyncio
    async def test_find_current_source_id_multiple_candidates(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: A git repository URL that matches multiple sources
        WHEN: Finding the source_id
        THEN: All candidate sources are returned for user selection
        """
        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/GitGuardian/test-repo.git\n",
                returncode=0,
            )

            # Mock the client response with multiple candidates
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
            mock_gitguardian_client.get_source_by_name = AsyncMock(
                return_value=mock_response
            )

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result["repository_name"] == "GitGuardian/test-repo"
            assert "candidates" in result
            assert len(result["candidates"]) == 2
            assert "message" in result
            assert "suggestion" in result

    @pytest.mark.asyncio
    async def test_find_current_source_id_no_match_with_fallback(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: No match for full repository name but repo name alone matches
        WHEN: Finding the source_id with fallback search
        THEN: The source_id from fallback search is returned
        """
        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/OrgName/repo-name.git\n",
                returncode=0,
            )

            # Mock the client to return None first, then a match on fallback
            call_count = 0

            async def mock_get_source(name, return_all_on_no_match=False):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return []  # No match for full name
                else:
                    return {
                        "id": "source_fallback",
                        "name": "repo-name",
                        "url": "https://github.com/OrgName/repo-name",
                    }  # Match on repo name only

            mock_gitguardian_client.get_source_by_name = mock_get_source

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result["repository_name"] == "OrgName/repo-name"
            assert result["source_id"] == "source_fallback"

    @pytest.mark.asyncio
    async def test_find_current_source_id_no_match_at_all(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: No sources match the repository in GitGuardian
        WHEN: Finding the source_id
        THEN: An error is returned indicating repository not found
        """
        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/Unknown/repo.git\n",
                returncode=0,
            )

            # Mock the client to return empty results
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=[])

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result["repository_name"] == "Unknown/repo"
            assert "error" in result
            assert "not found in GitGuardian" in result["error"]

    @pytest.mark.asyncio
    async def test_find_current_source_id_not_a_git_repo(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: The current directory is not a git repository
        WHEN: Attempting to find the source_id
        THEN: An error is returned
        """
        # Mock git command to raise an error
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                128, "git", stderr="not a git repository"
            )

            # Call the function
            result = await find_current_source_id()

            # Verify error response
            assert "error" in result
            assert "Not a git repository" in result["error"]

    @pytest.mark.asyncio
    async def test_find_current_source_id_git_timeout(self, mock_gitguardian_client):
        """
        GIVEN: The git command times out
        WHEN: Attempting to find the source_id
        THEN: An error is returned
        """
        # Mock git command to timeout
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("git", 5)

            # Call the function
            result = await find_current_source_id()

            # Verify error response
            assert "error" in result
            assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_find_current_source_id_invalid_url(self, mock_gitguardian_client):
        """
        GIVEN: A git URL that cannot be parsed
        WHEN: Attempting to find the source_id
        THEN: An error is returned
        """
        # Mock git command to return invalid URL
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="invalid-url-format\n",
                returncode=0,
            )

            # Call the function
            result = await find_current_source_id()

            # Verify error response
            assert "error" in result
            assert "Could not parse repository URL" in result["error"]

    @pytest.mark.asyncio
    async def test_find_current_source_id_gitlab_url(self, mock_gitguardian_client):
        """
        GIVEN: A GitLab repository URL
        WHEN: Finding the source_id
        THEN: The URL is correctly parsed and source_id is returned
        """
        # Mock git command with GitLab URL
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://gitlab.com/company/project.git\n",
                returncode=0,
            )

            # Mock the client response
            mock_response = {
                "id": "source_gitlab",
                "full_name": "company/project",
                "url": "https://gitlab.com/company/project",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(
                return_value=mock_response
            )

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result["repository_name"] == "company/project"
            assert result["source_id"] == "source_gitlab"

    @pytest.mark.asyncio
    async def test_find_current_source_id_ssh_url(self, mock_gitguardian_client):
        """
        GIVEN: A git SSH URL
        WHEN: Finding the source_id
        THEN: The SSH URL is correctly parsed and source_id is returned
        """
        # Mock git command with SSH URL
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@github.com:GitGuardian/gg-mcp.git\n",
                returncode=0,
            )

            # Mock the client response
            mock_response = {
                "id": "source_ssh",
                "full_name": "GitGuardian/gg-mcp",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(
                return_value=mock_response
            )

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result["repository_name"] == "GitGuardian/gg-mcp"
            assert result["source_id"] == "source_ssh"

    @pytest.mark.asyncio
    async def test_find_current_source_id_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The GitGuardian client raises an exception
        WHEN: Attempting to find the source_id
        THEN: An error is returned
        """
        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/GitGuardian/test.git\n",
                returncode=0,
            )

            # Mock the client to raise an exception
            mock_gitguardian_client.get_source_by_name = AsyncMock(
                side_effect=Exception("API error")
            )

            # Call the function
            result = await find_current_source_id()

            # Verify error response
            assert "error" in result
            assert "Failed to find source_id" in result["error"]
