"""Test OAuth helper functions."""

import os
from unittest.mock import patch

from gg_api_core.client import is_oauth_enabled


class TestIsOAuthEnabled:
    """Test the is_oauth_enabled pure function."""

    def test_returns_true_when_set_to_true(self):
        """Test that is_oauth_enabled returns True when ENABLE_LOCAL_OAUTH=true."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            assert is_oauth_enabled() is True

    def test_returns_true_when_set_to_true_uppercase(self):
        """Test that is_oauth_enabled is case-insensitive for 'true'."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "TRUE"}):
            assert is_oauth_enabled() is True

    def test_returns_true_when_set_to_true_mixed_case(self):
        """Test that is_oauth_enabled handles mixed case."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "TrUe"}):
            assert is_oauth_enabled() is True

    def test_returns_false_when_set_to_false(self):
        """Test that is_oauth_enabled returns False when ENABLE_LOCAL_OAUTH=false."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}):
            assert is_oauth_enabled() is False

    def test_returns_false_when_set_to_empty_string(self):
        """Test that is_oauth_enabled returns False when ENABLE_LOCAL_OAUTH is empty."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": ""}):
            assert is_oauth_enabled() is False

    def test_returns_true_when_unset(self):
        """Test that is_oauth_enabled returns True when ENABLE_LOCAL_OAUTH is not set (default behavior for local-first usage)."""
        env = os.environ.copy()
        env.pop("ENABLE_LOCAL_OAUTH", None)
        with patch.dict(os.environ, env, clear=True):
            assert is_oauth_enabled() is True

    def test_returns_false_for_invalid_values(self):
        """Test that is_oauth_enabled returns False for any value other than 'true'."""
        invalid_values = ["1", "yes", "on", "enabled", "True1", "tru", "t"]

        for value in invalid_values:
            with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": value}):
                assert is_oauth_enabled() is False, f"Expected False for value: {value}"

    def test_is_pure_function(self):
        """Test that is_oauth_enabled is a pure function (same input = same output)."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            # Call multiple times
            result1 = is_oauth_enabled()
            result2 = is_oauth_enabled()
            result3 = is_oauth_enabled()

            assert result1 == result2 == result3
            assert result1

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}):
            # Call multiple times
            result1 = is_oauth_enabled()
            result2 = is_oauth_enabled()
            result3 = is_oauth_enabled()

            assert result1 == result2 == result3
            assert not result1

    def test_no_side_effects(self):
        """Test that is_oauth_enabled has no side effects."""
        original_value = os.environ.get("ENABLE_LOCAL_OAUTH")

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}):
            is_oauth_enabled()
            # Environment should still be the same
            assert os.environ.get("ENABLE_LOCAL_OAUTH") == "true"

        # After context exit, should be back to original
        assert os.environ.get("ENABLE_LOCAL_OAUTH") == original_value
