import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

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
                stdout="https://github.com/GitGuardian/ggmcp.git\n",
                returncode=0,
            )

            # Mock the client response with exact match
            mock_response = {
                "id": "source_123",
                "full_name": "GitGuardian/ggmcp",
                "url": "https://github.com/GitGuardian/ggmcp",
                "monitored": True,
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify git command was called
            mock_run.assert_called_once_with(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
                cwd=".",
            )

            # Verify client was called with parsed repository name (just repo name, not org/repo)
            mock_gitguardian_client.get_source_by_name.assert_called_once_with("ggmcp", return_all_on_no_match=True)

            # Verify response
            assert result.repository_name == "ggmcp"
            assert result.source_id == "source_123"
            assert hasattr(result, "message")

    @pytest.mark.asyncio
    async def test_find_current_source_id_multiple_candidates(self, mock_gitguardian_client):
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
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result.repository_name == "test-repo"
            assert hasattr(result, "candidates")
            assert len(result.candidates) == 2
            assert hasattr(result, "message")
            assert hasattr(result, "suggestion")

    @pytest.mark.asyncio
    async def test_find_current_source_id_direct_match(self, mock_gitguardian_client):
        """
        GIVEN: A repository URL that gets parsed to just the repo name
        WHEN: Finding the source_id with a direct match
        THEN: The source_id is returned
        """
        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/OrgName/repo-name.git\n",
                returncode=0,
            )

            # Mock the client to return a direct match
            mock_response = {
                "id": "source_123",
                "name": "repo-name",
                "url": "https://github.com/OrgName/repo-name",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result.repository_name == "repo-name"
            assert result.source_id == "source_123"

    @pytest.mark.asyncio
    async def test_find_current_source_id_no_match_at_all(self, mock_gitguardian_client):
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
            assert result.repository_name == "repo"
            assert hasattr(result, "error")
            assert "not found in GitGuardian" in result.error

    @pytest.mark.asyncio
    async def test_find_current_source_id_not_a_git_repo_fallback_to_dir_name(self, mock_gitguardian_client):
        """
        GIVEN: The current directory is not a git repository
        WHEN: Attempting to find the source_id
        THEN: The tool falls back to using the directory name and searches GitGuardian
        """
        # Mock git command to raise an error
        with (
            patch("subprocess.run") as mock_run,
            patch("os.path.abspath") as mock_abspath,
            patch("pathlib.Path") as mock_path,
        ):
            mock_run.side_effect = subprocess.CalledProcessError(128, "git", stderr="not a git repository")
            mock_abspath.return_value = "/some/path/my-repo-name"

            # Mock Path to return the directory name
            mock_path_instance = MagicMock()
            mock_path_instance.name = "my-repo-name"
            mock_path.return_value = mock_path_instance

            # Mock GitGuardian client to return a match
            mock_response = {
                "id": "source_fallback",
                "full_name": "org/my-repo-name",
                "url": "https://github.com/org/my-repo-name",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify it used directory name and found a match
            assert result.repository_name == "my-repo-name"
            assert result.source_id == "source_fallback"
            assert "directory name" in result.message

    @pytest.mark.asyncio
    async def test_find_current_source_id_git_timeout_fallback(self, mock_gitguardian_client):
        """
        GIVEN: The git command times out
        WHEN: Attempting to find the source_id
        THEN: The tool falls back to using the directory name
        """
        # Mock git command to timeout
        with (
            patch("subprocess.run") as mock_run,
            patch("os.path.abspath") as mock_abspath,
            patch("pathlib.Path") as mock_path,
        ):
            mock_run.side_effect = subprocess.TimeoutExpired("git", 5)
            mock_abspath.return_value = "/some/path/timeout-repo"

            # Mock Path to return the directory name
            mock_path_instance = MagicMock()
            mock_path_instance.name = "timeout-repo"
            mock_path.return_value = mock_path_instance

            # Mock GitGuardian client to return a match
            mock_response = {
                "id": "source_timeout",
                "full_name": "org/timeout-repo",
                "url": "https://github.com/org/timeout-repo",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify it used directory name fallback
            assert result.repository_name == "timeout-repo"
            assert result.source_id == "source_timeout"
            assert "directory name" in result.message

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

            # Verify error response - invalid URL returns original input, so repo name is "invalid-url-format"
            # and then search fails with "not found" error
            assert hasattr(result, "error")
            assert "not found in GitGuardian" in result.error

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
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result.repository_name == "project"
            assert result.source_id == "source_gitlab"

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
                stdout="git@github.com:GitGuardian/ggmcp.git\n",
                returncode=0,
            )

            # Mock the client response
            mock_response = {
                "id": "source_ssh",
                "full_name": "GitGuardian/ggmcp",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function
            result = await find_current_source_id()

            # Verify response
            assert result.repository_name == "ggmcp"
            assert result.source_id == "source_ssh"

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
            mock_gitguardian_client.get_source_by_name = AsyncMock(side_effect=Exception("API error"))

            # Call the function
            result = await find_current_source_id()

            # Verify error response
            assert hasattr(result, "error")
            assert "Failed to find source_id" in result.error

    @pytest.mark.asyncio
    async def test_find_current_source_id_custom_path(self, mock_gitguardian_client):
        """
        GIVEN: A custom repository path is provided
        WHEN: Finding the source_id
        THEN: The git command runs in the specified directory
        """
        custom_path = "/path/to/custom/repo"

        # Mock git command
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/GitGuardian/custom-repo.git\n",
                returncode=0,
            )

            # Mock the client response
            mock_response = {
                "id": "source_custom",
                "full_name": "GitGuardian/custom-repo",
                "url": "https://github.com/GitGuardian/custom-repo",
            }
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=mock_response)

            # Call the function with custom path
            result = await find_current_source_id(repository_path=custom_path)

            # Verify git command was called with custom path
            mock_run.assert_called_once_with(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
                cwd=custom_path,
            )

            # Verify response
            assert result.repository_name == "custom-repo"
            assert result.source_id == "source_custom"

    @pytest.mark.asyncio
    async def test_find_current_source_id_fallback_no_match(self, mock_gitguardian_client):
        """
        GIVEN: The directory is not a git repo and the directory name doesn't match any source
        WHEN: Attempting to find the source_id
        THEN: An error is returned with helpful information about the fallback
        """
        # Mock git command to raise an error
        with (
            patch("subprocess.run") as mock_run,
            patch("os.path.abspath") as mock_abspath,
            patch("pathlib.Path") as mock_path,
        ):
            mock_run.side_effect = subprocess.CalledProcessError(128, "git", stderr="not a git repository")
            mock_abspath.return_value = "/some/path/unknown-repo"

            # Mock Path to return the directory name
            mock_path_instance = MagicMock()
            mock_path_instance.name = "unknown-repo"
            mock_path.return_value = mock_path_instance

            # Mock GitGuardian client to return no matches
            mock_gitguardian_client.get_source_by_name = AsyncMock(return_value=[])

            # Call the function
            result = await find_current_source_id()

            # Verify error response with fallback info
            assert result.repository_name == "unknown-repo"
            assert hasattr(result, "error")
            assert "not found in GitGuardian" in result.error
            assert "directory name" in result.message
