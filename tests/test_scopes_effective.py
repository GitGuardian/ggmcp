"""Test ``Settings.effective_scopes`` — the readout combining
``GITGUARDIAN_SCOPES`` and the self-hosted ``GITGUARDIAN_URL`` cap.

The old per-server-profile cap was removed: runtime tool visibility is now
driven by the access token's actual scopes via ``ScopeFilteringMiddleware``.
"""

import os
from unittest.mock import patch

from gg_api_core.scopes import ALL_SCOPES, MINIMAL_SCOPES
from gg_api_core.settings import get_settings


class TestEffectiveScopesSaaS:
    def test_no_env_returns_all_scopes(self):
        """
        GIVEN no GITGUARDIAN_SCOPES is set and the URL points at SaaS
        WHEN effective_scopes is read
        THEN the full ALL_SCOPES set is returned (the dashboard's consent UI narrows it)
        """
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "https://dashboard.gitguardian.com"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted(ALL_SCOPES)

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

    def test_no_url_no_scopes_returns_all_scopes(self):
        """
        GIVEN no env vars at all
        WHEN effective_scopes is read
        THEN the default URL (SaaS) yields the full ALL_SCOPES set
        """
        with patch.dict(os.environ, {}, clear=True):
            assert sorted(get_settings().effective_scopes) == sorted(ALL_SCOPES)


class TestEffectiveScopesSelfHostedCap:
    def test_non_local_self_hosted_caps_to_minimal_when_no_user_scopes(self):
        """
        GIVEN GITGUARDIAN_URL is a non-local self-hosted instance and no GITGUARDIAN_SCOPES
        WHEN effective_scopes is read
        THEN it is capped to MINIMAL_SCOPES
        """
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "https://gitguardian.mycompany.com"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted(MINIMAL_SCOPES)

    def test_non_local_self_hosted_intersects_with_user_scopes(self):
        """
        GIVEN GITGUARDIAN_SCOPES asks for a mix of minimal-allowed and disallowed scopes
        WHEN effective_scopes is read on a non-local self-hosted instance
        THEN only the minimal-allowed subset is returned
        """
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
        THEN the full ALL_SCOPES set is allowed (local dev runs treated as SaaS-like)
        """
        with patch.dict(
            os.environ,
            {"GITGUARDIAN_URL": "http://localhost:3000"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted(ALL_SCOPES)
