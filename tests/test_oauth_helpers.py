"""Test OAuth helper semantics on the Settings class."""

import os
from unittest.mock import patch

from gg_api_core.settings import get_settings


class TestIsOAuthEnabled:
    """Test the Settings.is_oauth_enabled property."""

    def test_returns_false_when_set_to_empty_string(self):
        """Test that is_oauth_enabled returns False when ENABLE_LOCAL_OAUTH is empty."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": ""}):
            assert get_settings().is_oauth_enabled is False

    def test_returns_true_when_unset(self):
        """Test that is_oauth_enabled returns True when ENABLE_LOCAL_OAUTH is not set (default behavior for local-first usage)."""
        env = os.environ.copy()
        env.pop("ENABLE_LOCAL_OAUTH", None)
        with patch.dict(os.environ, env, clear=True):
            assert get_settings().is_oauth_enabled is True

    def test_returns_true_for_truthy_values(self):
        """Test that is_oauth_enabled returns True for any recognised truthy value."""
        truthy_values = ["true", "TRUE", "TrUe", "1", "yes", "YES"]

        for value in truthy_values:
            with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": value}):
                assert get_settings().is_oauth_enabled is True, f"Expected True for value: {value}"

    def test_returns_false_for_non_truthy_values(self):
        """Test that is_oauth_enabled returns False for values outside the truthy set."""
        non_truthy_values = ["on", "enabled", "True1", "tru", "t", "0", "no", "false"]

        for value in non_truthy_values:
            with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": value}):
                assert get_settings().is_oauth_enabled is False, f"Expected False for value: {value}"
