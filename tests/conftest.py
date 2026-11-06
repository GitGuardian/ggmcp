import logging
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import structlog

from gg_api_core.logging_config import _DEMOTED_LOGGERS


@pytest.fixture()
def mock_gitguardian_client():
    """Mock the GitGuardian client wherever tools obtain it, so no test reaches the API or an OAuth flow."""
    # Create a mock client with common methods
    mock_client = MagicMock()
    mock_client.get_current_token_info = AsyncMock(
        return_value={
            "scopes": [
                "scan",
                "incidents:read",
                "sources:read",
                "honeytokens:read",
                "honeytokens:write",
            ],
            "id": "test-token-id",
            "name": "Test Token",
            "member_id": 480870,
        }
    )

    # Set dashboard_url for self-hosted detection - use SaaS by default for tests
    mock_client.dashboard_url = "https://dashboard.gitguardian.com"

    # Mock other common methods that tests might use
    mock_client.list_honeytokens = AsyncMock(return_value={"honeytokens": []})
    mock_client.list_occurrences = AsyncMock(return_value={"occurrences": [], "total_count": 0})
    mock_client.multiple_scan = AsyncMock(return_value=[])
    mock_client.paginate_all = AsyncMock(return_value={"data": [], "cursor": None, "has_more": False})
    mock_client.get_current_member = AsyncMock(return_value={"email": "test@example.com"})

    # List of all modules that import get_client directly with "from gg_api_core.utils import get_client"
    # We must patch where it's USED, not where it's DEFINED
    modules_using_get_client = [
        "gg_api_core.utils",
        "gg_api_core.mcp_server",
        "gg_api_core.tools.assign_incident",
        "gg_api_core.tools.count_incidents",
        "gg_api_core.tools.generate_honey_token",
        "gg_api_core.tools.get_incident",
        "gg_api_core.tools.get_public_incident",
        "gg_api_core.tools.get_remediation_workflow",
        "gg_api_core.tools.incident_notes",
        "gg_api_core.tools.list_incidents",
        "gg_api_core.tools.list_public_incidents",
        "gg_api_core.tools.list_public_occurrences",
        "gg_api_core.tools.list_repo_occurrences",
        "gg_api_core.tools.list_sources",
        "gg_api_core.tools.manage_incident",
        "gg_api_core.tools.scan_secret",
    ]

    with ExitStack() as stack:
        # Patch get_client in all modules that use it
        for module in modules_using_get_client:
            stack.enter_context(patch(f"{module}.get_client", return_value=mock_client))

        # Also patch GitGuardianClient constructor to prevent any direct instantiation
        stack.enter_context(patch("gg_api_core.utils.GitGuardianClient", return_value=mock_client))

        # Reset the singleton to None before each test to ensure clean state
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None
        yield mock_client
        # Clean up singleton after test
        gg_api_core.utils._client_singleton = None


@pytest.fixture(autouse=True)
def restore_logging_configuration():
    """Restore global logging state after each test."""
    root = logging.getLogger()
    saved_structlog_config = structlog.get_config()
    saved_handlers = list(root.handlers)
    saved_root_level = root.level
    saved_levels = {name: logging.getLogger(name).level for name in _DEMOTED_LOGGERS}

    yield

    structlog.configure(**saved_structlog_config)
    root.handlers = saved_handlers
    root.setLevel(saved_root_level)
    for name, level in saved_levels.items():
        logging.getLogger(name).setLevel(level)
