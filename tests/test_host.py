"""Tests for the host module."""

import os
from unittest.mock import patch

from gg_api_core.host import SAAS_HOSTNAMES, is_self_hosted_instance


class TestIsSelfHostedInstance:
    """Tests for the is_self_hosted_instance function."""

    def test_saas_hostname_returns_false(self):
        """Test that SaaS hostnames return False."""
        for hostname in [
            "https://dashboard.gitguardian.com",
            "https://api.gitguardian.com",
            "https://dashboard.eu1.gitguardian.com",
            "https://api.eu1.gitguardian.com",
        ]:
            assert is_self_hosted_instance(hostname) is False, f"Expected False for {hostname}"

    def test_staging_and_preprod_return_false(self):
        """Test that staging and preprod hostnames return False."""
        assert is_self_hosted_instance("https://dashboard.staging.gitguardian.tech") is False
        assert is_self_hosted_instance("https://dashboard.preprod.gitguardian.com") is False

    def test_localhost_returns_false(self):
        """Test that localhost and 127.0.0.1 return False."""
        assert is_self_hosted_instance("http://localhost") is False
        assert is_self_hosted_instance("http://127.0.0.1") is False
        assert is_self_hosted_instance("http://localhost:3000") is False
        assert is_self_hosted_instance("http://127.0.0.1:3000") is False

    def test_self_hosted_hostname_returns_true(self):
        """Test that self-hosted hostnames return True."""
        self_hosted_urls = [
            "https://gitguardian.mycompany.com",
            "https://gg.internal.corp",
            "https://custom-domain.com",
            "http://192.168.1.100",
            "https://gg-instance.local:8080",
        ]
        for url in self_hosted_urls:
            assert is_self_hosted_instance(url) is True, f"Expected True for {url}"

    def test_case_insensitive_hostname_check(self):
        """Test that hostname checking is case-insensitive."""
        assert is_self_hosted_instance("https://DASHBOARD.GITGUARDIAN.COM") is False
        assert is_self_hosted_instance("https://Dashboard.GitGuardian.Com") is False
        assert is_self_hosted_instance("https://API.GITGUARDIAN.COM") is False

    def test_url_without_scheme(self):
        """Test handling of URLs without a scheme."""
        # Without a scheme, urlparse might not parse the hostname correctly
        # The function should handle this gracefully
        result = is_self_hosted_instance("dashboard.gitguardian.com")
        # urlparse will put the hostname in path if no scheme is present
        # So this should return True (not in SAAS_HOSTNAMES as netloc)
        assert result is True

    def test_url_with_path(self):
        """Test that URLs with paths are handled correctly."""
        assert is_self_hosted_instance("https://dashboard.gitguardian.com/api/v1") is False
        assert is_self_hosted_instance("https://custom.domain.com/api/v1") is True

    def test_url_with_query_parameters(self):
        """Test that URLs with query parameters are handled correctly."""
        assert is_self_hosted_instance("https://dashboard.gitguardian.com?param=value") is False
        assert is_self_hosted_instance("https://custom.domain.com?param=value") is True

    def test_invalid_url_returns_true(self):
        """Test that invalid URLs return True (fail-safe behavior)."""
        # The function should catch exceptions and return True for safety
        # However, urlparse is quite forgiving, so we test with truly malformed input
        assert is_self_hosted_instance("not a url at all") is True
        assert is_self_hosted_instance("://invalid") is True

    def test_none_url_with_env_var(self):
        """Test that function uses GITGUARDIAN_URL env var when url is None."""
        with patch.dict(os.environ, {"GITGUARDIAN_URL": "https://custom.domain.com"}):
            assert is_self_hosted_instance(None) is True

        with patch.dict(os.environ, {"GITGUARDIAN_URL": "https://dashboard.gitguardian.com"}):
            assert is_self_hosted_instance(None) is False

    def test_none_url_without_env_var(self):
        """Test that function uses default SaaS URL when no url or env var provided."""
        with patch.dict(os.environ, {}, clear=True):
            # Should default to https://dashboard.gitguardian.com (SaaS)
            assert is_self_hosted_instance(None) is False

    def test_empty_string_url(self):
        """Test handling of empty string URL."""
        # Empty string should trigger the default behavior
        with patch.dict(os.environ, {}, clear=True):
            assert is_self_hosted_instance("") is False

    def test_url_with_different_ports(self):
        """Test that URLs with different ports are handled correctly."""
        assert is_self_hosted_instance("https://dashboard.gitguardian.com:443") is True  # Port not in SAAS_HOSTNAMES
        assert is_self_hosted_instance("https://custom.domain.com:8443") is True
        assert is_self_hosted_instance("http://localhost:3000") is False  # Explicitly in SAAS_HOSTNAMES
        assert is_self_hosted_instance("http://127.0.0.1:3000") is False  # Explicitly in SAAS_HOSTNAMES

    def test_url_with_basic_auth(self):
        """Test that URLs with basic auth credentials are handled correctly."""
        # Note: urlparse includes credentials in netloc (e.g., "user:pass@hostname")
        # Since "user:pass@dashboard.gitguardian.com" is not in SAAS_HOSTNAMES,
        # the function returns True (treats it as self-hosted)
        # This is an edge case where the current implementation doesn't strip credentials
        assert is_self_hosted_instance("https://user:pass@dashboard.gitguardian.com") is True
        assert is_self_hosted_instance("https://user:pass@custom.domain.com") is True

    def test_all_saas_hostnames_in_list(self):
        """Test that all hostnames in SAAS_HOSTNAMES are correctly identified."""
        for hostname in SAAS_HOSTNAMES:
            # Construct a full URL for each hostname
            url = f"https://{hostname}"
            assert is_self_hosted_instance(url) is False, f"Expected False for {url}"
