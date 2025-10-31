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

    # Edge cases with .git suffix
    @pytest.mark.parametrize(
        "url_with_git,url_without_git,expected",
        [
            ("https://github.com/org/repo.git", "https://github.com/org/repo", "org/repo"),
            ("git@github.com:org/repo.git", "git@github.com:org/repo", "org/repo"),
            ("https://gitlab.com/org/repo.git", "https://gitlab.com/org/repo", "org/repo"),
            ("https://bitbucket.org/org/repo.git", "https://bitbucket.org/org/repo", "org/repo"),
        ],
    )
    def test_urls_with_and_without_git_suffix(self, url_with_git, url_without_git, expected):
        """Test that URLs work both with and without .git suffix"""
        assert parse_repo_url(url_with_git) == expected
        assert parse_repo_url(url_without_git) == expected

    # SSH URLs with port numbers
    @pytest.mark.parametrize(
        "url,expected",
        [
            # Standard SSH with port
            ("git@github.com:22:org/repo.git", "org/repo"),
            ("git@gitlab.com:2222:team/project.git", "team/project"),
            # Bitbucket Data Center SSH with port (already tested above but adding more)
            ("ssh://git@bitbucket.server.com:7999/PROJ/repo.git", "PROJ/repo"),
        ],
    )
    def test_ssh_urls_with_ports(self, url, expected):
        """Test SSH URLs with port numbers"""
        assert parse_repo_url(url) == expected

    # Nested paths (GitLab groups/subgroups)
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://gitlab.com/group/subgroup/repo.git", "group/subgroup/repo"),
            ("git@gitlab.com:org/team/project.git", "org/team/project"),
            ("https://gitlab.self-hosted.com/top/mid/bottom/repo", "top/mid/bottom/repo"),
        ],
    )
    def test_nested_paths(self, url, expected):
        """Test URLs with nested paths (e.g., GitLab groups)"""
        assert parse_repo_url(url) == expected

    # URLs with trailing slashes
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/org/repo/", "org/repo/"),
            ("https://gitlab.com/org/repo.git/", "org/repo/"),
            ("https://bitbucket.company.com/projects/PROJ/repos/repo/", "PROJ/repo"),
        ],
    )
    def test_urls_with_trailing_slashes(self, url, expected):
        """Test URLs with trailing slashes"""
        assert parse_repo_url(url) == expected

    # Unusual protocol URLs
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("ftp://invalid.com/repo", "repo"),
            ("http://custom-git.com/org/repo", "org/repo"),
        ],
    )
    def test_unusual_protocol_urls(self, url, expected):
        """Test that URLs with unusual protocols still get parsed (even if not valid Git URLs)"""
        # The parser is permissive and will extract the path part from any ://-style URL
        assert parse_repo_url(url) == expected

    # Invalid/edge case URLs that return the original input
    @pytest.mark.parametrize(
        "url",
        ["not-a-valid-url", "http://", "", "just-text", "GitGuardian/ggmcp", "gg-code/prm/ward-runs-app"],
    )
    def test_unrecognized_urls_return_original(self, url):
        """Test that unrecognized URLs return the original input"""
        # The function returns the original URL if no pattern matches
        assert parse_repo_url(url) == url


# For running this test file directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
