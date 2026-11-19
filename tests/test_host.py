"""Tests for the host module."""

import os
from unittest.mock import patch

from gg_api_core.host import SAAS_DOMAIN_SUFFIXES, is_self_hosted_instance
from gg_api_core.urls import derive_public_api_url


class TestIsSelfHostedInstance:
    """Tests for the is_self_hosted_instance function."""

    def test_url_without_scheme(self):
        """Test handling of URLs without a scheme."""
        # Without a scheme, urlparse might not parse the hostname correctly
        # The function should handle this gracefully
        result = is_self_hosted_instance("dashboard.gitguardian.com")
        # urlparse will put the hostname in path if no scheme is present
        # An empty netloc is classified as self-hosted.
        assert result is True

    def test_none_url_without_env_var(self):
        """Test that function uses default SaaS URL when no url or env var provided."""
        with patch.dict(os.environ, {}, clear=True):
            # Should default to https://dashboard.gitguardian.com (SaaS)
            assert is_self_hosted_instance(None) is False

    def test_url_with_different_ports(self):
        """Test that URLs with different ports are handled correctly."""
        # SaaS matching uses the full netloc, including the port.
        assert is_self_hosted_instance("https://dashboard.gitguardian.com:443") is True
        assert is_self_hosted_instance("https://custom.domain.com:8443") is True
        # Local hostname detection handles ports separately.
        assert is_self_hosted_instance("http://localhost:3000") is False
        assert is_self_hosted_instance("http://127.0.0.1:3000") is False

    def test_url_with_basic_auth(self):
        """Test that URLs with basic auth credentials are handled correctly."""
        # urlparse includes credentials in netloc (e.g., "user:pass@hostname")
        # The suffix-based matching still recognizes the SaaS domain
        assert is_self_hosted_instance("https://user:pass@dashboard.gitguardian.com") is False
        assert is_self_hosted_instance("https://user:pass@custom.domain.com") is True

    def test_public_saas_hosts_return_false(self):
        """Test that suffix matching recognizes the public dashboard and API endpoints."""
        hosts = [
            "dashboard.gitguardian.com",
            "api.gitguardian.com",
            "dashboard.eu1.gitguardian.com",
            "api.eu1.gitguardian.com",
        ]
        for host in hosts:
            assert is_self_hosted_instance(f"https://{host}") is False

    def test_configured_suffixes_recognize_subdomains(self):
        """Test that each configured SaaS suffix recognizes additional subdomains."""
        for suffix in SAAS_DOMAIN_SUFFIXES:
            assert is_self_hosted_instance(f"https://dashboard.example{suffix}") is False

    def test_dynamic_subdomains_return_false(self):
        """Test that dynamic subdomains of a configured SaaS suffix are recognized."""
        urls = [
            "https://dashboard-alpha.preview.example.test",
            "https://api-alpha.preview.example.test",
            "https://dashboard-beta.preview.example.test",
        ]
        with patch("gg_api_core.host.SAAS_DOMAIN_SUFFIXES", [".example.test"]):
            for url in urls:
                assert is_self_hosted_instance(url) is False, f"Expected False for {url}"


class TestOnPremOverride:
    """Tests for the IS_ON_PREM environment variable override."""

    def test_on_prem_true_derives_exposed_api_url(self):
        """
        GIVEN IS_ON_PREM=true and a self-hosted instance under a SaaS-like domain
        WHEN the public API URL is derived from the base URL
        THEN the /exposed/v1 prefix is appended
        """
        url = "https://self-hosted.example.test"
        with patch("gg_api_core.host.SAAS_DOMAIN_SUFFIXES", [".example.test"]):
            with patch.dict(os.environ, {"IS_ON_PREM": "false"}):
                assert is_self_hosted_instance(url) is False
            with patch.dict(os.environ, {"IS_ON_PREM": "true"}):
                assert is_self_hosted_instance(url) is True
                assert derive_public_api_url(url) == f"{url}/exposed/v1"
