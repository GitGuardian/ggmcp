import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_gitguardian_client():
    """Automatically mock the GitGuardian client for all tests to prevent OAuth flow."""
    # Create a mock client with common methods
    mock_client = MagicMock()
    mock_client.get_current_token_info = AsyncMock(
        return_value={
            "scopes": ["scan", "incidents:read", "sources:read", "honeytokens:read", "honeytokens:write"],
            "id": "test-token-id",
            "name": "Test Token",
        }
    )

    # Mock other common methods that tests might use
    mock_client.list_repo_incidents_directly = AsyncMock(return_value={"incidents": [], "total_count": 0})
    mock_client.list_occurrences = AsyncMock(return_value={"occurrences": [], "total_count": 0})
    mock_client.multiple_scan = AsyncMock(return_value=[])
    mock_client.get_source_by_name = AsyncMock(return_value=None)
    mock_client.list_source_incidents = AsyncMock(return_value={"data": [], "total_count": 0})
    mock_client.paginate_all = AsyncMock(return_value=[])
    mock_client.list_honeytokens = AsyncMock(return_value={"honeytokens": []})

    # Patch get_client() to return our mock - this prevents the singleton from creating a real client
    with patch("gg_api_core.utils.get_client", return_value=mock_client):
        # Also patch get_gitguardian_client to prevent any direct calls
        with patch("gg_api_core.utils.get_gitguardian_client", return_value=mock_client):
            # Reset the singleton to None before each test to ensure clean state
            import gg_api_core.utils
            gg_api_core.utils._client_singleton = None
            yield mock_client
            # Clean up singleton after test
            gg_api_core.utils._client_singleton = None


@pytest.fixture(autouse=True)
def mock_env_vars():
    """Automatically mock environment variables for all tests."""
    with patch.dict(
        os.environ, {"GITGUARDIAN_URL": "https://test.api.gitguardian.com"}
    ):
        yield


@pytest.fixture
def setup_test_env():
    """Set up and tear down environment variables for specific tests."""
    original_env = os.environ.copy()

    # Set test environment variables
    os.environ["GITGUARDIAN_URL"] = "https://test.api.gitguardian.com"

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
