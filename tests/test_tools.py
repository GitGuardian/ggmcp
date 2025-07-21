import os
from unittest.mock import MagicMock, patch

import pytest
from gg_api_core.utils import get_gitguardian_client


class TestGetGitGuardianClient:
    """Tests for the get_gitguardian_client function."""

    def test_successful_client_initialization(self):
        """Test successful OAuth client initialization."""
        # Mock environment variables for OAuth
        with patch.dict(os.environ, {"GITGUARDIAN_CLIENT_ID": "test_client_id"}):
            # Mock GitGuardianClient class
            with patch("gg_api_core.utils.GitGuardianClient") as mock_client_class:
                mock_client_instance = MagicMock()
                mock_client_class.return_value = mock_client_instance

                # Call the function
                client = get_gitguardian_client()

                # Assertions
                mock_client_class.assert_called_once()
                call_args = mock_client_class.call_args[1]
                assert call_args["use_oauth"]
                assert client == mock_client_instance

    def test_with_custom_url(self):
        """Test client initialization with custom URL."""
        # Mock environment variables
        with patch.dict(
            os.environ, {"GITGUARDIAN_CLIENT_ID": "test_client_id", "GITGUARDIAN_API_URL": "https://custom.api.url"}
        ):
            # Mock GitGuardianClient class
            with patch("gg_api_core.utils.GitGuardianClient") as mock_client_class:
                mock_client_instance = MagicMock()
                mock_client_class.return_value = mock_client_instance

                # Call the function
                client = get_gitguardian_client()

                # Assertions
                mock_client_class.assert_called_once()
                call_args = mock_client_class.call_args[1]
                assert call_args["use_oauth"]
                assert call_args["api_url"] == "https://custom.api.url"
                assert client == mock_client_instance

    def test_exception_handling(self):
        """Test exception handling during client initialization."""
        # Mock environment variables
        with patch.dict(os.environ, {"GITGUARDIAN_CLIENT_ID": "test_client_id"}):
            # Mock GitGuardianClient class to raise an exception
            with patch("gg_api_core.utils.GitGuardianClient") as mock_client_class:
                mock_client_class.side_effect = Exception("Test error")

                # Call the function
                with pytest.raises(Exception, match="Test error"):
                    get_gitguardian_client()
