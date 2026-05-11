"""Test ``Settings.effective_scopes`` — the single readout combining
``GITGUARDIAN_SCOPES``, ``GITGUARDIAN_URL`` (self-hosted cap), and
``SERVER_PROFILE``."""

import os
from unittest.mock import patch

from gg_api_core.scopes import ALL_READ_SCOPES, ALL_SCOPES, MINIMAL_SCOPES, ServerProfile
from gg_api_core.settings import get_settings


class TestEffectiveScopesNoProfile:
    def test_no_profile_returns_requested_scopes_as_is(self):
        """
        GIVEN SERVER_PROFILE is unset
        WHEN Settings.effective_scopes is read
        THEN it returns the user's requested scopes unfiltered
        """
        with patch.dict(os.environ, {"GITGUARDIAN_SCOPES": "scan,incidents:read"}, clear=True):
            assert sorted(get_settings().effective_scopes) == ["incidents:read", "scan"]

    def test_no_profile_no_env_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            assert get_settings().effective_scopes == []


class TestEffectiveScopesDeveloperProfile:
    def test_full_set_when_no_user_scopes_on_saas(self):
        """
        GIVEN SERVER_PROFILE=developer and no GITGUARDIAN_SCOPES on SaaS
        WHEN Settings.effective_scopes is read
        THEN it returns the developer profile's full max-set
        """
        with patch.dict(
            os.environ,
            {"SERVER_PROFILE": "developer", "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted({*ALL_READ_SCOPES, "honeytokens:write"})

    def test_intersects_with_user_scopes(self):
        """
        GIVEN GITGUARDIAN_SCOPES contains a mix of dev-allowed and dev-forbidden scopes
        WHEN SERVER_PROFILE=developer
        THEN only dev-allowed scopes are returned
        """
        # ``incidents:write`` is in SECOPS but not in DEVELOPER's allowed set
        with patch.dict(
            os.environ,
            {
                "SERVER_PROFILE": "developer",
                "GITGUARDIAN_URL": "https://dashboard.gitguardian.com",
                "GITGUARDIAN_SCOPES": "scan,incidents:read,incidents:write",
            },
            clear=True,
        ):
            effective = set(get_settings().effective_scopes)
            assert "scan" in effective
            assert "incidents:read" in effective
            assert "incidents:write" not in effective


class TestEffectiveScopesSecopsProfile:
    def test_full_set_when_no_user_scopes_on_saas(self):
        with patch.dict(
            os.environ,
            {"SERVER_PROFILE": "secops", "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted(ALL_SCOPES)

    def test_passes_through_user_scope_unique_to_secops(self):
        with patch.dict(
            os.environ,
            {
                "SERVER_PROFILE": "secops",
                "GITGUARDIAN_URL": "https://dashboard.gitguardian.com",
                "GITGUARDIAN_SCOPES": "scan,incidents:write",
            },
            clear=True,
        ):
            assert "incidents:write" in get_settings().effective_scopes


class TestEffectiveScopesSelfHostedCap:
    def test_non_local_self_hosted_caps_to_minimal_regardless_of_profile(self):
        """
        GIVEN GITGUARDIAN_URL is a non-local self-hosted instance
        WHEN any profile is active
        THEN effective_scopes is capped to MINIMAL_SCOPES
        """
        for profile in ("developer", "secops"):
            with patch.dict(
                os.environ,
                {"SERVER_PROFILE": profile, "GITGUARDIAN_URL": "https://gitguardian.mycompany.com"},
                clear=True,
            ):
                assert sorted(get_settings().effective_scopes) == sorted(MINIMAL_SCOPES), (
                    f"Profile {profile} should be capped to MINIMAL_SCOPES on self-hosted"
                )

    def test_local_instance_is_not_treated_as_self_hosted(self):
        """
        GIVEN GITGUARDIAN_URL points at localhost
        WHEN SERVER_PROFILE=developer
        THEN the full developer scope set is allowed (local instances are treated as SaaS-like)
        """
        with patch.dict(
            os.environ,
            {"SERVER_PROFILE": "developer", "GITGUARDIAN_URL": "http://localhost:3000"},
            clear=True,
        ):
            assert sorted(get_settings().effective_scopes) == sorted({*ALL_READ_SCOPES, "honeytokens:write"})


class TestServerProfileEnumParsing:
    def test_empty_string_treated_as_unset(self):
        """``SERVER_PROFILE=""`` (e.g. from a test fixture clearing the var) is None, not an error."""
        with patch.dict(os.environ, {"SERVER_PROFILE": ""}, clear=True):
            assert get_settings().server_profile is None

    def test_profile_parsed_into_enum(self):
        with patch.dict(os.environ, {"SERVER_PROFILE": "developer"}, clear=True):
            assert get_settings().server_profile is ServerProfile.DEVELOPER
