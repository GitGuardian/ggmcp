import os
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_env_vars():
    """Automatically mock environment variables for all tests."""
    with patch.dict(
        os.environ, {"GITGUARDIAN_API_KEY": "test_api_key", "GITGUARDIAN_API_URL": "https://test.api.gitguardian.com"}
    ):
        yield


@pytest.fixture
def setup_test_env():
    """Set up and tear down environment variables for specific tests."""
    original_env = os.environ.copy()

    # Set test environment variables
    os.environ["GITGUARDIAN_API_KEY"] = "test_api_key"
    os.environ["GITGUARDIAN_API_URL"] = "https://test.api.gitguardian.com"

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
