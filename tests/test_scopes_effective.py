"""Test ``Settings.effective_scopes`` — the readout combining
``GITGUARDIAN_SCOPES`` and the self-hosted ``GITGUARDIAN_URL`` cap.

The self-hosted cap intersects against ``SCOPES_SUPPORTED_IN_SELF_HOSTED``
(self-hosted releases lag SaaS, so a scope available in SaaS may not yet be
available in self-hosted). Tests that exercise the cap mechanism patch
``SCOPES_SUPPORTED_IN_SELF_HOSTED`` so they don't depend on the constant's
current value.
"""

import os
from unittest.mock import patch

from gg_api_core import scopes as scopes_module
from gg_api_core.scopes import DEFAULT_SCOPES
from gg_api_core.settings import get_settings


class TestEffectiveScopesSaaS:
    def test_no_env_returns_the_default_scopes(self):
        """
        GIVEN no GITGUARDIAN_SCOPES is set and the URL points at SaaS
        WHEN effective_scopes is read
        THEN DEFAULT_SCOPES, the scopes the tools use, is returned
        """
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "https://dashboard.gitguardian.com"},
            clear=True,
        ):
            assert get_settings().effective_scopes == DEFAULT_SCOPES

    def test_explicit_scopes_returned_as_is(self):
        """
        GIVEN GITGUARDIAN_SCOPES narrows the request
        WHEN effective_scopes is read on SaaS
        THEN exactly the requested scopes are returned
        """
        with patch.dict(
            os.environ,
            {
                "GITGUARDIAN_URL": "https://dashboard.gitguardian.com",
                "GITGUARDIAN_SCOPES": "scan,incidents:read",
            },
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == ["incidents:read", "scan"]

    def test_no_url_no_scopes_returns_the_default_scopes(self):
        """
        GIVEN no env vars at all
        WHEN effective_scopes is read
        THEN the default URL (SaaS) yields DEFAULT_SCOPES
        """
        with patch.dict(os.environ, {}, clear=True):
            assert get_settings().effective_scopes == DEFAULT_SCOPES


class TestEffectiveScopesSelfHostedCap:
    def test_non_local_self_hosted_caps_to_supported_set_when_no_user_scopes(self, monkeypatch):
        """
        GIVEN SCOPES_SUPPORTED_IN_SELF_HOSTED is a subset of DEFAULT_SCOPES
        AND GITGUARDIAN_URL is a non-local self-hosted instance
        AND GITGUARDIAN_SCOPES is unset
        WHEN effective_scopes is read
        THEN the default scopes are capped to SCOPES_SUPPORTED_IN_SELF_HOSTED
        """
        narrowed = ["scan", "incidents:read", "sources:read"]
        monkeypatch.setattr(scopes_module, "SCOPES_SUPPORTED_IN_SELF_HOSTED", narrowed)
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "https://gitguardian.mycompany.com"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted(narrowed)

    def test_non_local_self_hosted_intersects_with_user_scopes(self, monkeypatch):
        """
        GIVEN SCOPES_SUPPORTED_IN_SELF_HOSTED excludes some SaaS-only scopes
        AND GITGUARDIAN_SCOPES asks for a mix of supported and unsupported scopes
        WHEN effective_scopes is read on a non-local self-hosted instance
        THEN only the supported subset is returned
        """
        monkeypatch.setattr(
            scopes_module,
            "SCOPES_SUPPORTED_IN_SELF_HOSTED",
            ["scan", "incidents:read"],
        )
        with patch.dict(
            os.environ,
            {
                "GITGUARDIAN_URL": "https://gitguardian.mycompany.com",
                "GITGUARDIAN_SCOPES": "scan,incidents:read,incidents:write,honeytokens:write",
            },
            clear=True,
        ):
            effective = set(get_settings().effective_scopes)
            assert effective == {"scan", "incidents:read"}

    def test_local_instance_is_not_treated_as_self_hosted(self):
        """
        GIVEN GITGUARDIAN_URL points at localhost
        WHEN effective_scopes is read
        THEN DEFAULT_SCOPES is returned uncapped (local dev runs treated as SaaS-like)
        """
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "http://localhost:3000"},
            clear=True,
        ):
            assert get_settings().effective_scopes == DEFAULT_SCOPES
