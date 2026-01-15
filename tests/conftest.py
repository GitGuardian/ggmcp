import json
import os
import re
from os.path import dirname, join, realpath
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import vcr

# =============================================================================
# VCR Configuration for Cassette-based Testing
# =============================================================================
# Following the same pattern as ggshield for recording and replaying HTTP interactions

CASSETTES_DIR = join(dirname(realpath(__file__)), "cassettes")

# Headers that are safe to keep in cassettes
ALLOWED_HEADERS = {
    "accept",
    "accept-encoding",
    "accepts",
    "connection",
    "content-length",
    "content-type",
    "date",
    "host",
    "user-agent",
}

# Placeholder for redacted values
REDACTED = "[REDACTED]"


def _filter_request_headers(request):
    """
    Remove headers not in ALLOWED_HEADERS to make sure we don't store secrets in
    cassettes.
    """
    for name in list(request.headers):
        if name.lower() not in ALLOWED_HEADERS:
            request.headers.pop(name)
    return request


def _redact_sensitive_fields(obj):
    """
    Recursively redact sensitive fields from response data.
    """
    if isinstance(obj, dict):
        redacted = {}
        for key, value in obj.items():
            # Redact known sensitive field names
            if key in (
                "secret_key",
                "access_token_id",
                "token",
                "api_key",
                "password",
                "secret",
                "credential",
                "share_url",
            ):
                redacted[key] = REDACTED
            # Redact share URLs that contain incident tokens
            elif key == "gitguardian_url" and isinstance(value, str) and "/share/" in value:
                # Redact the token part of share URLs: /share/incidents/<token>
                redacted[key] = re.sub(
                    r"(/share/incidents/)[a-f0-9-]+",
                    r"\1" + REDACTED,
                    value,
                )
            else:
                redacted[key] = _redact_sensitive_fields(value)
        return redacted
    elif isinstance(obj, list):
        return [_redact_sensitive_fields(item) for item in obj]
    else:
        return obj


def _before_record_response(response):
    """
    Redact sensitive data from response bodies before recording.
    """
    body = response.get("body", {}).get("string", b"")

    if not body:
        return response

    # Try to parse as JSON and redact sensitive fields
    try:
        if isinstance(body, bytes):
            body_str = body.decode("utf-8")
        else:
            body_str = body

        data = json.loads(body_str)
        redacted_data = _redact_sensitive_fields(data)
        redacted_body = json.dumps(redacted_data)

        response["body"]["string"] = redacted_body.encode("utf-8")
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON or couldn't decode, leave as-is
        pass

    return response


my_vcr = vcr.VCR(
    cassette_library_dir=CASSETTES_DIR,
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "scheme", "host", "port", "path", "query"],
    serializer="yaml",
    record_mode="once",
    before_record_request=_filter_request_headers,
    before_record_response=_before_record_response,
    filter_post_data_parameters=[
        "api_key",
        "secret",
        "client_id",
        "client_secret",
        "token",
        "password",
    ],
)


@pytest.fixture(scope="session")
def real_client():
    """
    Create a real GitGuardianClient for recording/replaying cassettes.

    This fixture creates a client for use with VCR cassettes.
    - When cassettes exist: VCR replays recorded responses (no real API calls)
    - When recording new cassettes: Requires GITGUARDIAN_API_KEY env var

    Environment variables (only needed for recording new cassettes):
        - GITGUARDIAN_API_KEY: Your GitGuardian API key (Personal Access Token)
        - GITGUARDIAN_URL: (Optional) Custom GitGuardian URL, defaults to SaaS

    Usage:
        @pytest.mark.asyncio
        async def test_something(real_client):
            with my_vcr.use_cassette("test_something"):
                result = await real_client.list_incidents()
                assert result is not None
    """
    from gg_api_core.client import GitGuardianClient

    # Use real key if available, otherwise use dummy key for cassette replay
    # VCR will intercept requests and replay from cassettes, so the key doesn't matter
    api_key = os.getenv("GITGUARDIAN_API_KEY", "dummy-key-for-cassette-replay")
    gitguardian_url = os.getenv("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")

    # Create client with PAT (bypasses OAuth)
    client = GitGuardianClient(
        gitguardian_url=gitguardian_url,
        personal_access_token=api_key,
    )

    return client


@pytest.fixture
def no_api_key(monkeypatch):
    """Remove GITGUARDIAN_API_KEY from the environment, useful to test anonymous use."""
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
    monkeypatch.delenv("GITGUARDIAN_PERSONAL_ACCESS_TOKEN", raising=False)


# =============================================================================
# Mock Fixtures for Unit Testing (without real API calls)
# =============================================================================


@pytest.fixture()
def mock_gitguardian_client(request):
    """Automatically mock the GitGuardian client for all tests to prevent OAuth flow.

    Tests using VCR cassettes should use the 'vcr_test' marker to disable this mock:

        @pytest.mark.vcr_test
        @pytest.mark.asyncio
        async def test_with_cassette(real_client):
            with my_vcr.use_cassette("test_name"):
                result = await real_client.some_method()
    """
    from contextlib import ExitStack

    # Skip mocking for tests marked with 'vcr_test' - they use real cassettes
    if request.node.get_closest_marker("vcr_test"):
        yield None
        return

    # Create a mock client with common methods
    mock_client = MagicMock()
    mock_client.get_current_token_info = AsyncMock(
        return_value={
            "scopes": ["scan", "incidents:read", "sources:read", "honeytokens:read", "honeytokens:write"],
            "id": "test-token-id",
            "name": "Test Token",
        }
    )

    # Set dashboard_url for self-hosted detection - use SaaS by default for tests
    mock_client.dashboard_url = "https://dashboard.gitguardian.com"

    # Mock other common methods that tests might use
    mock_client.list_incidents_directly = AsyncMock(return_value={"incidents": [], "total_count": 0})
    mock_client.list_occurrences = AsyncMock(return_value={"occurrences": [], "total_count": 0})
    mock_client.multiple_scan = AsyncMock(return_value=[])
    mock_client.get_source_by_name = AsyncMock(return_value=None)
    mock_client.list_source_incidents = AsyncMock(return_value={"data": [], "total_count": 0})
    mock_client.paginate_all = AsyncMock(return_value={"data": [], "cursor": None, "has_more": False})
    mock_client.list_honeytokens = AsyncMock(return_value={"honeytokens": []})
    mock_client.list_incidents = AsyncMock(return_value={"data": [], "total_count": 0})
    mock_client.get_current_member = AsyncMock(return_value={"email": "test@example.com"})

    # List of all modules that import get_client directly with "from gg_api_core.utils import get_client"
    # We must patch where it's USED, not where it's DEFINED
    modules_using_get_client = [
        "gg_api_core.utils",
        "gg_api_core.mcp_server",
        "gg_api_core.tools.scan_secret",
        "gg_api_core.tools.list_incidents",
        "gg_api_core.tools.list_honeytokens",
        "gg_api_core.tools.generate_honey_token",
        "gg_api_core.tools.find_current_source_id",
        "gg_api_core.tools.create_code_fix_request",
        "gg_api_core.tools.assign_incident",
        "gg_api_core.tools.manage_incident",
        "gg_api_core.tools.list_repo_occurrences",
        "gg_api_core.tools.write_custom_tags",
        "gg_api_core.tools.revoke_secret",
        "gg_api_core.tools.remediate_secret_incidents",
        "gg_api_core.tools.read_custom_tags",
        "gg_api_core.tools.list_users",
    ]

    with ExitStack() as stack:
        # Patch get_client in all modules that use it
        for module in modules_using_get_client:
            stack.enter_context(patch(f"{module}.get_client", return_value=mock_client))

        # Also patch GitGuardianClient constructor to prevent any direct instantiation
        stack.enter_context(patch("gg_api_core.utils.GitGuardianClient", return_value=mock_client))

        # Patch find_current_source_id to avoid real GitHub calls
        from gg_api_core.tools.find_current_source_id import FindCurrentSourceIdResult

        mock_find_source_result = FindCurrentSourceIdResult(
            repository_name="GitGuardian/test-repo",
            source_id="source_123",
            message="Found source",
        )
        stack.enter_context(
            patch(
                "gg_api_core.tools.list_incidents.find_current_source_id",
                new_callable=lambda: AsyncMock(return_value=mock_find_source_result),
            )
        )

        # Reset the singleton to None before each test to ensure clean state
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None
        yield mock_client
        # Clean up singleton after test
        gg_api_core.utils._client_singleton = None


@pytest.fixture()
def mock_env_vars(request):
    """Automatically mock environment variables for all tests.

    Tests using VCR cassettes (marked with 'vcr_test') skip this to use real env vars.
    """
    # Skip mocking for tests marked with 'vcr_test' - they need real env vars
    if request.node.get_closest_marker("vcr_test"):
        yield
        return

    env_overrides = {
        "GITGUARDIAN_URL": "https://test.api.gitguardian.com",
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "",  # Clear PAT to test OAuth paths
    }
    with patch.dict(os.environ, env_overrides):
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
