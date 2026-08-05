import hashlib
import json
import logging
import os
import re
from os.path import dirname, join, realpath
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, quote, unquote, urlparse

import pytest
import vcr

# Configure logging for VCR debugging
vcr_logger = logging.getLogger("vcr.debug")
vcr_logger.setLevel(logging.DEBUG)

# =============================================================================
# VCR Configuration for Cassette-based Testing
# =============================================================================
# Following the same pattern as ggshield for recording and replaying HTTP interactions
#
# Cassettes are stored mirroring the test file structure:
#   tests/tools/vcr/test_foo.py -> tests/cassettes/tools/vcr/test_foo_*.yaml
#   tests/client/vcr/test_bar.py -> tests/cassettes/client/vcr/test_bar_*.yaml
#
# Usage: Use the `use_cassette` fixture in tests:
#   @pytest.mark.vcr_test
#   async def test_something(real_client, use_cassette):
#       with use_cassette("test_something"):
#           ...

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
    "x-privacy-mode",
}

# Placeholder for redacted values
REDACTED = "[REDACTED]"

# GitGuardian product hostnames that may stay in cassettes as-is. Any other
# hostname that references the recording workspace's perimeter is anonymized.
PUBLIC_HOSTNAMES = {
    "gitguardian.com",
    "api.gitguardian.com",
    "dashboard.gitguardian.com",
    "docs.gitguardian.com",
    "hook.gitguardian.com",
    "www.gitguardian.com",
}

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HOSTNAME_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
# Tenant-scoped SaaS hosts: the tenant name identifies the recording workspace.
_SAAS_TENANT_SUFFIXES = (".atlassian.net", ".jfrog.io", ".sharepoint.com")


def _hash8(value: str) -> str:
    """Stable 8-char token so the same input maps to the same fake everywhere."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _anonymize_email(match: re.Match) -> str:
    email = match.group(0)
    local, _, domain = email.partition("@")
    # Keep already-fake addresses and ssh-style remotes (git@github.com).
    if domain.lower().endswith("example.com") or local.lower() == "git":
        return email
    return f"user-{_hash8(email.lower())}@example.com"


def _anonymize_hostname(match: re.Match) -> str:
    host = match.group(0)
    lowered = host.lower()
    if lowered in PUBLIC_HOSTNAMES:
        return host
    for suffix in _SAAS_TENANT_SUFFIXES:
        if lowered.endswith(suffix):
            tenant = lowered[: -len(suffix)]
            if _ANON_TENANT_RE.fullmatch(tenant):
                return host
            return f"tenant-{_hash8(lowered)}{suffix}"
    if "gitguardian" in lowered or lowered.endswith(".ovh"):
        return f"host-{_hash8(lowered)}.example.com"
    return host


# Every rule below must be idempotent: VCR runs before_record_request on
# outgoing requests at replay time too, so a value already anonymized in a
# cassette must survive a second pass unchanged or it stops matching.
_ANON_SEGMENT_RE = re.compile(r"ns-[0-9a-f]{8}")
_ANON_USER_RE = re.compile(r"user-[0-9a-f]{8}")
_ANON_TENANT_RE = re.compile(r"tenant-[0-9a-f]{8}")


def _anon_segment(segment: str) -> str:
    return segment if _ANON_SEGMENT_RE.fullmatch(segment) else f"ns-{_hash8(segment)}"


def _anon_user(name: str) -> str:
    return name if _ANON_USER_RE.fullmatch(name) else f"user-{_hash8(name)}"


_ANON_PERSON_RE = re.compile(r"User [0-9a-f]{8}")
_ANON_ENDPOINT_RE = re.compile(r"endpoint-[0-9a-f]{8}")


def _anon_person(name: str) -> str:
    return name if _ANON_PERSON_RE.fullmatch(name) else f"User {_hash8(name)}"


def _anon_endpoint(name: str) -> str:
    return name if _ANON_ENDPOINT_RE.fullmatch(name) else f"endpoint-{_hash8(name)}"


def _anonymize_namespace(value: str, keep_repo: bool) -> str:
    """Anonymize a namespaced repository name. Public GitHub repo names keep
    their repo segment (it is public data and search fixtures rely on it);
    other SCM projects are fully anonymized."""
    segments = [s.strip() for s in value.split("/")]
    if keep_repo and len(segments) > 1:
        return "/".join([_anon_segment(segments[0]), *segments[1:]])
    return "/".join(_anon_segment(s) for s in segments)


# github.com URL owners are user handles; keep the public GitGuardian org.
_GITHUB_OWNER_RE = re.compile(r"(github\.com/)(?!GitGuardian/)([A-Za-z0-9_.-]+)(?=[/\"?#])")
# Home directories in occurrence file paths are named after their user.
_HOMEDIR_RE = re.compile(r"/(Users|home)/([A-Za-z0-9._%+-]+)")
# The leading path segments on an anonymized host are a user/group namespace
# and a project name.
_ANON_HOST_NAMESPACE_RE = re.compile(r"(host-[0-9a-f]{8}\.example\.com)/([A-Za-z0-9._%+-]+)(/[A-Za-z0-9._%+-]+)?")
# Sources are re-fetched by searching for names taken from earlier responses,
# so search parameters must be anonymized the same way as the names they match.
_SEARCH_PARAM_RE = re.compile(r"([?&]search=)([^&#]+)")


def _anonymize_text(text: str) -> str:
    """Anonymize emails, non-public hostnames, and user paths in a serialized body."""
    text = _EMAIL_RE.sub(_anonymize_email, text)
    text = _HOSTNAME_RE.sub(_anonymize_hostname, text)
    text = _GITHUB_OWNER_RE.sub(lambda m: m.group(1) + _anon_segment(m.group(2)), text)
    text = _HOMEDIR_RE.sub(lambda m: f"/{m.group(1)}/{_anon_user(m.group(2))}", text)
    return _ANON_HOST_NAMESPACE_RE.sub(
        lambda m: f"{m.group(1)}/{_anon_segment(m.group(2))}"
        + (f"/{_anon_segment(m.group(3)[1:])}" if m.group(3) else ""),
        text,
    )


def _anonymize_uri(uri: str) -> str:
    """Anonymize a request URI: body-level rules plus search query values."""

    def _sub(match: re.Match) -> str:
        value = unquote(match.group(2))
        if "/" not in value:
            return match.group(0)
        return match.group(1) + quote(_anonymize_namespace(value, keep_repo=True), safe="")

    return _SEARCH_PARAM_RE.sub(_sub, _anonymize_text(uri))


def _redact_sensitive_fields(obj):
    """
    Recursively redact sensitive fields from response data.
    """
    if isinstance(obj, dict):
        redacted = {}
        # Person names: members/assignees carry an email sibling, commit
        # authors carry an info sibling. Emails themselves are anonymized by
        # _anonymize_text; names need this structural pass.
        person_key = "email" if "email" in obj else "info" if "info" in obj else None
        # Endpoint-type sources are named after the machine they run on.
        is_endpoint_source = obj.get("type") == "endpoints"
        # Repository sources are namespaced under a user or org handle.
        source_type = obj.get("type")
        is_repo_source = isinstance(source_type, str) and source_type.startswith(
            ("gh_", "github", "gitlab", "bitbucket", "azure")
        )
        for key, value in obj.items():
            if key == "name" and person_key and isinstance(value, str) and value:
                redacted[key] = _anon_person(value)
                continue
            if key in ("name", "path", "display_name") and is_endpoint_source and isinstance(value, str):
                redacted[key] = _anon_endpoint(value)
                continue
            if (
                key in ("name", "path", "full_name", "display_name")
                and is_repo_source
                and isinstance(value, str)
                and value
            ):
                redacted[key] = _anonymize_namespace(value, keep_repo=source_type.startswith(("gh_", "github")))
                continue
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
                "string_matched",
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


def _log_error_response(response, request=None):
    """
    Log details when an error response is received (4xx, 5xx).
    This helps debug API issues during VCR recording.
    """
    status_code = response.get("status", {}).get("code", 0)
    if status_code >= 400:
        vcr_logger.error("=" * 60)
        vcr_logger.error(f"HTTP ERROR: {status_code}")

        # Log request details if available
        if request:
            vcr_logger.error(f"Request URL: {request.uri}")
            vcr_logger.error(f"Request Method: {request.method}")

            # Parse and log query parameters for readability
            parsed = urlparse(request.uri)
            if parsed.query:
                vcr_logger.error("Query Parameters:")
                params = parse_qs(parsed.query)
                for key, values in sorted(params.items()):
                    vcr_logger.error(f"  {key}: {values}")

            # Log request body if present
            if request.body:
                vcr_logger.error(f"Request Body: {request.body}")

        # Log response body
        body = response.get("body", {}).get("string", b"")
        if body:
            try:
                if isinstance(body, bytes):
                    body_str = body.decode("utf-8")
                else:
                    body_str = body
                # Try to pretty-print JSON
                try:
                    body_json = json.loads(body_str)
                    vcr_logger.error(f"Response Body: {json.dumps(body_json, indent=2)}")
                except json.JSONDecodeError:
                    vcr_logger.error(f"Response Body: {body_str}")
            except UnicodeDecodeError:
                vcr_logger.error(f"Response Body: (binary data, {len(body)} bytes)")

        vcr_logger.error("=" * 60)


# Store the last request for error logging
_last_request = None


def _filter_request_headers_and_store(request):
    """
    Remove headers not in ALLOWED_HEADERS and store request for error logging.
    """
    global _last_request
    _last_request = request

    for name in list(request.headers):
        if name.lower() not in ALLOWED_HEADERS:
            request.headers.pop(name)

    request.uri = _anonymize_uri(request.uri)
    if request.body:
        body = request.body
        if isinstance(body, bytes):
            request.body = _anonymize_text(body.decode("utf-8", errors="replace")).encode("utf-8")
        elif isinstance(body, str):
            request.body = _anonymize_text(body)
    return request


def _before_record_response(response):
    """
    Redact sensitive data from response bodies before recording.
    Also log error responses for debugging.
    """
    global _last_request

    # Log error responses for debugging
    _log_error_response(response, _last_request)

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
        redacted_body = _anonymize_text(json.dumps(redacted_data))

        response["body"]["string"] = redacted_body.encode("utf-8")
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON or couldn't decode, leave as-is
        pass

    return response


# Common VCR options
_vcr_common_options = dict(
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "scheme", "host", "port", "path", "query"],
    serializer="yaml",
    record_mode="once",
    before_record_request=_filter_request_headers_and_store,
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


def _get_cassette_dir_for_test(test_file_path: str) -> str:
    """
    Get the cassette directory for a test file, mirroring its path structure.

    Example:
        tests/tools/vcr/test_list_users.py -> tests/cassettes/tools/vcr/
        tests/client/vcr/test_health.py -> tests/cassettes/client/vcr/
    """
    tests_dir = dirname(realpath(__file__))
    # Get relative path from tests/ directory
    rel_path = os.path.relpath(dirname(test_file_path), tests_dir)
    # Build cassette directory path
    return join(CASSETTES_DIR, rel_path)


@pytest.fixture
def use_cassette(request):
    """
    Fixture that provides a cassette context manager with auto-detected path.

    Cassettes are stored mirroring the test file structure:
        tests/tools/vcr/test_foo.py -> tests/cassettes/tools/vcr/

    Usage:
        @pytest.mark.vcr_test
        @pytest.mark.asyncio
        async def test_something(real_client, use_cassette):
            with use_cassette("test_something"):
                result = await some_tool(params)
    """
    test_file = request.fspath
    cassette_dir = _get_cassette_dir_for_test(str(test_file))

    # Ensure the cassette directory exists
    os.makedirs(cassette_dir, exist_ok=True)

    # Create VCR instance for this test's directory
    test_vcr = vcr.VCR(
        cassette_library_dir=cassette_dir,
        **_vcr_common_options,
    )

    return test_vcr.use_cassette


# Convenience module-level VCR for direct imports (backward compatibility)
# Prefer using the use_cassette fixture instead
my_vcr = vcr.VCR(
    cassette_library_dir=CASSETTES_DIR,
    **_vcr_common_options,
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
        "gg_api_core.tools.assign_public_incident",
        "gg_api_core.tools.activity_logs",
        "gg_api_core.tools.incident_notes",
        "gg_api_core.tools.manage_incident",
        "gg_api_core.tools.update_public_incident_status",
        "gg_api_core.tools.list_public_incidents",
        "gg_api_core.tools.list_public_occurrences",
        "gg_api_core.tools.list_repo_occurrences",
        "gg_api_core.tools.write_custom_tags",
        "gg_api_core.tools.revoke_secret",
        "gg_api_core.tools.remediate_secret_incidents",
        "gg_api_core.tools.read_custom_tags",
        "gg_api_core.tools.list_users",
        "gg_api_core.tools.list_incident_members",
        "gg_api_core.tools.list_incident_teams",
        "gg_api_core.tools.list_detectors",
        "gg_api_core.tools.list_sources",
        "gg_api_core.tools.get_incident",
        "gg_api_core.tools.get_public_incident",
        "gg_api_core.tools.get_member",
        "gg_api_core.tools.count_incidents",
    ]

    with ExitStack() as stack:
        # Patch get_client in all modules that use it
        for module in modules_using_get_client:
            stack.enter_context(patch(f"{module}.get_client", return_value=mock_client))

        # Also patch GitGuardianClient constructor to prevent any direct instantiation
        stack.enter_context(patch("gg_api_core.utils.GitGuardianClient", return_value=mock_client))

        # Note: find_current_source_id is no longer called by list_incidents
        # (repository_name param was removed), so no patching needed here

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
