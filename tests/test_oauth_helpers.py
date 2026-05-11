"""Test OAuth helper semantics on the Settings class."""

import os
from unittest.mock import patch

from gg_api_core.settings import get_settings


class TestIsOAuthEnabled:
    """Test the Settings.is_oauth_enabled property."""

    def test_returns_true_when_set_to_true(self):
        """Test that is_oauth_enabled returns True when ENABLE_LOCAL_OAUTH=true."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            assert get_settings().is_oauth_enabled is True

    def test_returns_true_when_set_to_true_uppercase(self):
        """Test that is_oauth_enabled is case-insensitive for 'true'."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "TRUE"}):
            assert get_settings().is_oauth_enabled is True

    def test_returns_true_when_set_to_true_mixed_case(self):
        """Test that is_oauth_enabled handles mixed case."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "TrUe"}):
            assert get_settings().is_oauth_enabled is True

    def test_returns_false_when_set_to_false(self):
        """Test that is_oauth_enabled returns False when ENABLE_LOCAL_OAUTH=false."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}):
            assert get_settings().is_oauth_enabled is False

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

    def test_returns_false_for_invalid_values(self):
        """Test that is_oauth_enabled returns False for any value other than 'true'."""
        invalid_values = ["1", "yes", "on", "enabled", "True1", "tru", "t"]

        for value in invalid_values:
            with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": value}):
                assert get_settings().is_oauth_enabled is False, f"Expected False for value: {value}"

    def test_is_pure_function(self):
        """Test that is_oauth_enabled is a pure function (same input = same output)."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            result1 = get_settings().is_oauth_enabled
            result2 = get_settings().is_oauth_enabled
            result3 = get_settings().is_oauth_enabled

            assert result1 == result2 == result3
            assert result1

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}):
            result1 = get_settings().is_oauth_enabled
            result2 = get_settings().is_oauth_enabled
            result3 = get_settings().is_oauth_enabled

            assert result1 == result2 == result3
            assert not result1

    def test_no_side_effects(self):
        """Test that is_oauth_enabled has no side effects."""
        original_value = os.environ.get("ENABLE_LOCAL_OAUTH")

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            _ = get_settings().is_oauth_enabled
            assert os.environ.get("ENABLE_LOCAL_OAUTH") == "true"

        # After context exit, should be back to original
        assert os.environ.get("ENABLE_LOCAL_OAUTH") == original_value
