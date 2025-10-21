"""Tests for parse_repo_url function - Git URL parsing for multiple hosting platforms"""

import pytest

from gg_api_core.utils import parse_repo_url


class TestParseRepoUrl:
    """Test suite for parsing Git remote URLs from various hosting platforms"""

    # GitHub tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/GitGuardian/ggmcp.git", "GitGuardian/ggmcp"),
            ("https://github.com/GitGuardian/ggmcp", "GitGuardian/ggmcp"),
            ("git@github.com:GitGuardian/ggmcp.git", "GitGuardian/ggmcp"),
            ("git@github.com:GitGuardian/ggmcp", "GitGuardian/ggmcp"),
        ],
    )
    def test_github_urls(self, url, expected):
        """Test GitHub URL parsing (HTTPS and SSH)"""
        assert parse_repo_url(url) == expected

    # GitLab Cloud tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://gitlab.com/myorg/myrepo.git", "myorg/myrepo"),
            ("git@gitlab.com:myorg/myrepo.git", "myorg/myrepo"),
        ],
    )
    def test_gitlab_cloud_urls(self, url, expected):
        """Test GitLab Cloud URL parsing"""
        assert parse_repo_url(url) == expected

    # GitLab Self-hosted tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://gitlab.company.com/team/project.git", "team/project"),
            ("git@gitlab.company.com:team/project.git", "team/project"),
        ],
    )
    def test_gitlab_selfhosted_urls(self, url, expected):
        """Test GitLab Self-hosted URL parsing"""
        assert parse_repo_url(url) == expected

    # Bitbucket Cloud tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://bitbucket.org/workspace/repo.git", "workspace/repo"),
            ("git@bitbucket.org:workspace/repo.git", "workspace/repo"),
        ],
    )
    def test_bitbucket_cloud_urls(self, url, expected):
        """Test Bitbucket Cloud URL parsing"""
        assert parse_repo_url(url) == expected

    # Bitbucket Data Center tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            # /scm/ format
            ("https://bitbucket.company.com/scm/proj/repo.git", "proj/repo"),
            ("https://bitbucket.company.com/scm/PROJECT/my-repo", "PROJECT/my-repo"),
            # /projects/ format
            ("https://bitbucket.company.com/projects/PROJ/repos/repo", "PROJ/repo"),
            ("https://bitbucket.company.com/projects/PROJECT/repos/my-repo/browse", "PROJECT/my-repo"),
            # SSH with port
            ("ssh://git@bitbucket.company.com:7999/proj/repo.git", "proj/repo"),
            ("ssh://git@bitbucket.company.com:7999/PROJECT/my-repo", "PROJECT/my-repo"),
            # SSH without port
            ("git@bitbucket.company.com:PROJECT/repo.git", "PROJECT/repo"),
        ],
    )
    def test_bitbucket_datacenter_urls(self, url, expected):
        """Test Bitbucket Data Center URL parsing"""
        assert parse_repo_url(url) == expected

    # Azure DevOps tests
    @pytest.mark.parametrize(
        "url,expected",
        [
            # New format
            ("https://dev.azure.com/myorg/myproject/_git/myrepo", "myorg/myproject/myrepo"),
            ("https://dev.azure.com/myorg/myproject/_git/myrepo.git", "myorg/myproject/myrepo"),
            # Old format
            ("https://myorg.visualstudio.com/myproject/_git/myrepo", "myorg/myproject/myrepo"),
            # SSH
            ("git@ssh.dev.azure.com:v3/myorg/myproject/myrepo", "myorg/myproject/myrepo"),
            ("git@ssh.dev.azure.com:v3/myorg/myproject/myrepo.git", "myorg/myproject/myrepo"),
        ],
    )
    def test_azure_devops_urls(self, url, expected):
        """Test Azure DevOps URL parsing"""
        assert parse_repo_url(url) == expected

    # Edge cases and invalid URLs
    @pytest.mark.parametrize(
        "url",
        [
            "not-a-valid-url",
            "http://",
            "",
        ],
    )
    def test_invalid_urls(self, url):
        """Test that invalid URLs return None"""
        assert parse_repo_url(url) is None

    def test_unusual_protocol_urls(self):
        """Test that URLs with unusual protocols still get parsed (even if not valid Git URLs)"""
        # The parser is permissive and will extract the path part from any ://-style URL
        # This is acceptable since Git config shouldn't contain FTP URLs anyway
        result = parse_repo_url("ftp://invalid.com/repo")
        assert result == "repo"  # Parser extracts the path, even if protocol is unusual

    def test_urls_without_git_suffix(self):
        """Test that URLs work both with and without .git suffix"""
        with_git = parse_repo_url("https://github.com/org/repo.git")
        without_git = parse_repo_url("https://github.com/org/repo")
        assert with_git == without_git == "org/repo"


# For running this test file directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
