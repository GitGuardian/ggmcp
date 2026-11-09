"""Test OAuth helper semantics on the Settings class."""

import os
from unittest.mock import patch

from gg_api_core.settings import get_settings


class TestIsOAuthEnabled:
    """Test the Settings.is_oauth_enabled property."""

    def test_returns_true_for_truthy_values(self):
        """Test that is_oauth_enabled returns True for any recognised truthy value."""
        truthy_values = ["true", "TRUE", "TrUe", "1", "yes", "YES"]

        for value in truthy_values:
            with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": value}):
                assert get_settings().is_oauth_enabled is True, f"Expected True for value: {value}"
