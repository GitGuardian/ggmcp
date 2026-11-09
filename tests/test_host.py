"""Tests for the host module."""

import os
from unittest.mock import patch

from gg_api_core.host import is_self_hosted_instance
from gg_api_core.urls import derive_public_api_url


class TestIsSelfHostedInstance:
    """Tests for the is_self_hosted_instance function."""

    def test_url_without_scheme(self):
        """Test handling of URLs without a scheme."""
        # Without a scheme, urlparse might not parse the hostname correctly
        # The function should handle this gracefully
        result = is_self_hosted_instance("dashboard.gitguardian.com")
        # urlparse will put the hostname in path if no scheme is present
        # So this should return True (not in SAAS_HOSTNAMES as netloc)
        assert result is True

    def test_none_url_without_env_var(self):
        """Test that function uses default SaaS URL when no url or env var provided."""
        with patch.dict(os.environ, {}, clear=True):
            # Should default to https://dashboard.gitguardian.com (SaaS)
            assert is_self_hosted_instance(None) is False

    def test_url_with_different_ports(self):
        """Test that URLs with different ports are handled correctly."""
        assert is_self_hosted_instance("https://dashboard.gitguardian.com:443") is True  # Port not in SAAS_HOSTNAMES
        assert is_self_hosted_instance("https://custom.domain.com:8443") is True
        assert is_self_hosted_instance("http://localhost:3000") is False  # Explicitly in SAAS_HOSTNAMES
        assert is_self_hosted_instance("http://127.0.0.1:3000") is False  # Explicitly in SAAS_HOSTNAMES

    def test_url_with_basic_auth(self):
        """Test that URLs with basic auth credentials are handled correctly."""
        # urlparse includes credentials in netloc (e.g., "user:pass@hostname")
        # The suffix-based matching still recognizes the SaaS domain
        assert is_self_hosted_instance("https://user:pass@dashboard.gitguardian.com") is False
        assert is_self_hosted_instance("https://user:pass@custom.domain.com") is True

    def test_review_app_returns_false(self):
        """Test that review-app URLs are recognized as SaaS-like (not self-hosted)."""
        review_app_urls = [
            "https://dashboard-23683.review-apps.preprod.gitguardian.tech",
            "https://api-23683.review-apps.preprod.gitguardian.tech",
            "https://dashboard-99999.review-apps.preprod.gitguardian.tech",
        ]
        for url in review_app_urls:
            assert is_self_hosted_instance(url) is False, f"Expected False for {url}"


class TestOnPremOverride:
    """Tests for the IS_ON_PREM environment variable override."""

    def test_on_prem_true_derives_exposed_api_url(self):
        """
        GIVEN IS_ON_PREM=true and a self-hosted instance under a SaaS-like domain
        WHEN the public API URL is derived from the base URL
        THEN the /exposed/v1 prefix is appended
        """
        with patch.dict(os.environ, {"IS_ON_PREM": "true"}):
            assert (
                derive_public_api_url("https://on-prem.preprod.gitguardian.tech")
                == "https://on-prem.preprod.gitguardian.tech/exposed/v1"
            )
