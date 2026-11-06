import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Sequence
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, TypedDict, cast
from urllib.parse import quote_plus, unquote, urlparse
from uuid import UUID

import httpx
from pydantic import TypeAdapter, ValidationError

from gg_api_core.log_context import record_downstream_call, record_downstream_wait, record_truncation
from gg_api_core.settings import get_settings
from gg_api_core.version import APP_VERSION

# Setup logger
logger = logging.getLogger(__name__)


_UUID_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

_GG_REQUEST_ID_HEADERS = ("x-request-id", "x-gitguardian-request-id", "request-id")


def _path_template(endpoint: str) -> str:
    """Drop query strings and collapse ID path segments."""
    path = endpoint.split("?", 1)[0].split("#", 1)[0]
    segments = [
        "{id}" if segment.isdigit() or _UUID_SEGMENT_RE.match(segment) else segment for segment in path.split("/")
    ]
    return "/".join(segments)


def _log_api_request(
    method: str,
    endpoint: str,
    *,
    status: int | None,
    duration_ms: float,
    response: httpx.Response | None = None,
    retried: bool = False,
    error_class: str | None = None,
) -> None:
    """Log and account for one API request."""
    fields: dict[str, Any] = {
        "method": method.upper(),
        "path": _path_template(endpoint),
        "status": status,
        "duration_ms": round(duration_ms),
    }
    if response is not None:
        for header in _GG_REQUEST_ID_HEADERS:
            if value := response.headers.get(header):
                fields["gg_request_id"] = value
                break
    if error_class:
        fields["error_class"] = error_class

    logger.info("api_request", extra=fields)
    record_downstream_call(duration_ms=duration_ms, status=status, retried=retried)


async def _track_api_request(
    method: str,
    endpoint: str,
    request: Awaitable[httpx.Response],
    *,
    retried: bool = False,
) -> httpx.Response:
    """Execute and record one downstream API attempt."""
    request_started = time.perf_counter()
    try:
        response = await request
    except Exception as exc:
        _log_api_request(
            method,
            endpoint,
            status=None,
            duration_ms=(time.perf_counter() - request_started) * 1000,
            retried=retried,
            error_class=type(exc).__name__,
        )
        raise

    _log_api_request(
        method,
        endpoint,
        status=response.status_code,
        duration_ms=(time.perf_counter() - request_started) * 1000,
        response=response,
        retried=retried,
    )
    return response


DEFAULT_USER_AGENT = f"GitGuardian-MCP-Server/{APP_VERSION}" if APP_VERSION else "GitGuardian-MCP-Server"


def _to_date_only(value: str) -> str:
    """Normalize a date/datetime string to its ``YYYY-MM-DD`` portion."""
    try:
        return TypeAdapter(datetime).validate_python(value.strip()).date().isoformat()
    except ValidationError as exc:
        raise ValueError(f"Invalid date value: {value!r}") from exc


class DownstreamUnauthorizedError(Exception):
    """Raised when the downstream GitGuardian API returns 401.

    Bridged to an HTTP 401 + ``WWW-Authenticate`` response by middleware so
    the MCP client can re-run the OAuth flow.
    """


class IncidentSeverity(str, Enum):
    """Enum for incident severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    """Enum for incident statuses."""

    IGNORED = "IGNORED"
    TRIGGERED = "TRIGGERED"
    ASSIGNED = "ASSIGNED"
    RESOLVED = "RESOLVED"


class IncidentValidity(str, Enum):
    """Enum for incident validity values.

    Note: Different API endpoints accept different validity values:
    - /incidents-for-mcp: accepts NOT_CHECKED but not UNKNOWN
    - /occurrences/secrets: accepts UNKNOWN but not NOT_CHECKED
    """

    VALID = "valid"
    INVALID = "invalid"
    FAILED_TO_CHECK = "failed_to_check"
    NO_CHECKER = "no_checker"
    NOT_CHECKED = "not_checked"  # Valid for /incidents-for-mcp
    UNKNOWN = "unknown"  # Valid for /occurrences/secrets


class TagNames(str, Enum):
    REGRESSION = "REGRESSION"  # Issue is a regression
    HIST = "HIST"  # Occurrence is visible and its Kind is history
    PUBLICLY_EXPOSED = "PUBLICLY_EXPOSED"  # Occurrence is visible and source is a public GitHub
    TEST_FILE = "TEST_FILE"  # Occurrence is visible and one of its insights is `test_file`
    SENSITIVE_FILE = "SENSITIVE_FILE"  # Occurrence is visible and one of its insights is `sensitive_filepath`
    # DEPRECATED: Replaced by CHECK_RUN_SKIP_FALSE_POSITIVE but still there until we
    # remove it from the public_api
    DEPRECATED_IGNORED_IN_CHECK_RUN = "IGNORED_IN_CHECK_RUN"  # Occurrence is visible and its GitHub check run a ignored
    CHECK_RUN_SKIP_FALSE_POSITIVE = "CHECK_RUN_SKIP_FALSE_POSITIVE"
    CHECK_RUN_SKIP_LOW_RISK = "CHECK_RUN_SKIP_LOW_RISK"
    CHECK_RUN_SKIP_TEST_CRED = "CHECK_RUN_SKIP_TEST_CRED"
    DEFAULT_BRANCH = "DEFAULT_BRANCH"  # Occurrence is on the default branch of the repository
    PUBLICLY_LEAKED = "PUBLICLY_LEAKED"  # Issue's secret is publicly leaked outside the account perimeter
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REVOCABLE_BY_GG = "REVOCABLE_BY_GG"


class ListResponse(TypedDict):
    """Standardized response for list endpoints."""

    data: list[dict[str, Any]]
    cursor: str | None
    has_more: bool


# Default limit for paginate_all to prevent context bloat
DEFAULT_PAGINATION_MAX_BYTES = 20_000

# Hard cap on number of pages fetched during get_all pagination
# Prevents runaway loops regardless of byte limit effectiveness
MAX_PAGINATION_PAGES = 10

# Default HTTP timeout in seconds (to handle slow pagination)
DEFAULT_HTTP_TIMEOUT = 20


class PaginatedResult(TypedDict):
    """Result from paginate_all with size limit protection."""

    data: list[dict[str, Any]]
    cursor: str | None  # Use this cursor to fetch more results if has_more is True
    has_more: bool  # True if results were capped by size limit OR more pages exist


def _derive_urls_from_env() -> tuple[str, str]:
    """Derive dashboard_url and public_api_url from environment.

    Returns:
        Tuple of (dashboard_url, public_api_url)
    """
    # Create a temporary client just to get normalized URLs
    temp_client = GitGuardianClient.__new__(GitGuardianClient)
    temp_client._init_urls(get_settings().gitguardian_url)
    return temp_client.dashboard_url, temp_client.public_api_url


def _get_stored_oauth_token(dashboard_url: str) -> str | None:
    """Check for a stored OAuth token from a previous authentication flow.

    Args:
        dashboard_url: The dashboard URL to look up the token for

    Returns:
        The stored token if valid, None otherwise
    """
    try:
        from .oauth import FileTokenStorage

        file_storage = FileTokenStorage()
        token = file_storage.get_token(dashboard_url)
        if token:
            logger.debug(f"Found stored OAuth token for {dashboard_url}")
            return token
        return None
    except Exception as e:
        logger.debug(f"Could not load stored OAuth token: {e}")
        return None


async def _run_oauth_flow(dashboard_url: str, public_api_url: str) -> str:
    """Run the interactive OAuth flow to obtain a PAT.

    Args:
        dashboard_url: The dashboard URL for OAuth
        public_api_url: The public API URL for OAuth

    Returns:
        The obtained PAT

    Raises:
        RuntimeError: If OAuth flow fails
    """
    from .oauth import GitGuardianOAuthClient

    settings = get_settings()
    scopes = settings.effective_scopes
    login_path = settings.gitguardian_login_path
    token_name = settings.gitguardian_token_name

    oauth_client = GitGuardianOAuthClient(
        api_url=public_api_url,
        dashboard_url=dashboard_url,
        scopes=scopes,
        token_name=token_name,
    )

    try:
        # Check if OAuth client already has a valid token loaded from storage
        if oauth_client.access_token:
            logger.info("OAuth client loaded existing token from storage")
            return oauth_client.access_token

        # Run OAuth flow
        logger.info("Starting interactive OAuth authentication flow...")
        token = await oauth_client.oauth_process(login_path=login_path)
        logger.info("OAuth authentication successful")
        return token
    except Exception as e:
        raise RuntimeError(f"OAuth authentication failed: {e}") from e


async def acquire_single_tenant_token(
    dashboard_url: str | None = None,
    public_api_url: str | None = None,
) -> str:
    """Acquire a PAT for single-tenant mode.

    Token sources (in order of precedence):
    1. GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var
    2. Stored OAuth token from previous authentication flow
    3. Interactive OAuth flow (if ENABLE_LOCAL_OAUTH=true)

    Args:
        dashboard_url: Optional dashboard URL. If not provided, derived from env.
        public_api_url: Optional API URL. If not provided, derived from env.

    Returns:
        The acquired PAT

    Raises:
        RuntimeError: If no token source is available
    """
    # 1. Check env var first
    if env_pat := get_settings().gitguardian_personal_access_token:
        logger.info("Using PAT from GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var")
        return env_pat

    # Derive URLs if not provided
    if dashboard_url is None or public_api_url is None:
        dashboard_url, public_api_url = _derive_urls_from_env()

    # 2. Check for stored OAuth token from previous flow
    stored_token = _get_stored_oauth_token(dashboard_url)
    if stored_token:
        logger.info("Using stored OAuth token from previous authentication")
        return stored_token

    # 3. Trigger OAuth flow if enabled
    if get_settings().is_oauth_enabled:
        logger.info("No stored token, triggering OAuth flow")
        return await _run_oauth_flow(dashboard_url, public_api_url)

    # No token source available
    raise RuntimeError(
        "No API token available. Options: "
        "(1) Set GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var, "
        "(2) Set ENABLE_LOCAL_OAUTH=true to trigger interactive OAuth flow, "
        "(3) For HTTP deployments, set MULTI_TENANCY_ENABLED=true and MCP_PORT."
    )


def _serialize_enum_filter(value: Any) -> str:
    """Serialize a single enum/string or a list of them into a comma-separated API query value."""
    if isinstance(value, list):
        return ",".join(str(v.value) if isinstance(v, Enum) else str(v) for v in value)
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


class GitGuardianClient:
    """Client for interacting with the GitGuardian API.

    This client expects a PAT to be provided. Token acquisition (from env vars,
    stored OAuth tokens, or interactive OAuth flow) must be handled by the caller
    before this client is instantiated.
    """

    DEFAULT_USER_AGENT = DEFAULT_USER_AGENT

    def __init__(
        self,
        gitguardian_url: str | None = None,
        personal_access_token: str | None = None,
        allow_token_refresh: bool = False,
        user_agent: str | None = None,
    ):
        """Initialize the GitGuardian client.

        Args:
            gitguardian_url: GitGuardian URL, defaults to GITGUARDIAN_URL env var
                or https://dashboard.gitguardian.com
            personal_access_token: The PAT to use for authentication.
                In normal usage, this is provided by get_client() which handles
                token acquisition from various sources.
            allow_token_refresh: If True, the client can attempt to refresh the
                token when a 401 error occurs (via env var or OAuth flow).
                This enables self-healing when tokens expire or become invalid.
            user_agent: Custom User-Agent string to identify the MCP client.
                Defaults to DEFAULT_USER_AGENT if not provided.
        """
        logger.debug("Initializing GitGuardian client")

        self._init_urls(gitguardian_url)
        self._oauth_token = personal_access_token
        self._allow_token_refresh = allow_token_refresh
        self._user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._token_info: Any | None = None

    def _base_headers(self, *, privacy_mode: bool = True) -> dict[str, str]:
        """Build request-local headers, keeping privacy enabled by default."""
        return {
            "Authorization": f"Token {self._oauth_token}",
            "Content-Type": "application/json",
            "User-Agent": self._user_agent,
            "X-Privacy-Mode": "true" if privacy_mode else "false",
        }

    def _init_urls(self, gitguardian_url: str | None = None):
        from .urls import derive_public_api_url

        # Use provided raw URL or get from environment with default fallback
        raw_url = gitguardian_url or get_settings().gitguardian_url

        self.public_api_url = derive_public_api_url(raw_url)
        logger.info(f"Using API URL: {self.public_api_url}")

        # Extract the base URL for dashboard (needed for OAuth)
        self.dashboard_url = self._get_dashboard_url()
        logger.info(f"Using dashboard URL: {self.dashboard_url}")
        self.private_api_url = f"{self.dashboard_url}/api/v1"
        logger.info(f"Using private API URL: {self.private_api_url}")

    def _get_dashboard_url(self) -> str:
        """
        Get the GitGuardian dashboard URL by deriving it from the API URL.

        Returns:
            str: The GitGuardian dashboard URL
        """
        # Default GitGuardian dashboard URL
        default_dashboard_url = "https://dashboard.gitguardian.com"

        # If using SaaS API URLs, return the corresponding dashboard URL
        if self.public_api_url == "https://api.gitguardian.com/v1":
            logger.info(f"Using default dashboard URL: {default_dashboard_url}")
            return default_dashboard_url
        elif self.public_api_url == "https://api.eu1.gitguardian.com/v1":
            eu_dashboard_url = "https://dashboard.eu1.gitguardian.com"
            logger.info(f"Using EU dashboard URL: {eu_dashboard_url}")
            return eu_dashboard_url

        try:
            parsed_url = urlparse(self.public_api_url)

            # For local development (localhost or 127.0.0.1)
            if parsed_url.netloc.startswith("localhost") or parsed_url.netloc.startswith("127.0.0.1"):
                # For localhost, use the base URL without any path
                derived_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            else:
                # For custom domains, handle different patterns
                hostname = parsed_url.netloc
                # Replace 'api.' prefix with 'dashboard.' if it exists
                if hostname.startswith("api."):
                    # Replace 'api.' with 'dashboard.' (e.g., api.staging.gitguardian.tech -> dashboard.staging.gitguardian.tech)
                    hostname = "dashboard." + hostname[4:]
                derived_url = f"{parsed_url.scheme}://{hostname}"
            return derived_url
        except Exception as e:
            logger.warning(f"Failed to extract dashboard URL from API URL: {e}")
            return default_dashboard_url

    def clear_invalid_token_from_storage(self):
        """Clear invalid OAuth token from file storage.

        Call this when a 401 error indicates the stored token is invalid.
        After calling this, the client singleton should be reset so that
        the next call to get_client() triggers fresh token acquisition.
        """
        logger.info("Clearing invalid OAuth token from storage")

        # Clear in-memory token
        self._oauth_token = None
        self._token_info = None

        # Clear token from file storage
        try:
            from .oauth import FileTokenStorage

            file_storage = FileTokenStorage()
            tokens = file_storage.load_tokens()

            # Remove the token for this instance
            if self.dashboard_url in tokens:
                del tokens[self.dashboard_url]
                logger.info(f"Removed invalid token for {self.dashboard_url} from storage")

                # Save the updated tokens (without the invalid one)
                try:
                    with open(file_storage.token_file, "w") as f:
                        json.dump(tokens, f, indent=2)
                    file_storage.token_file.chmod(0o600)
                    logger.info(f"Updated token storage file: {file_storage.token_file}")
                except Exception as e:
                    logger.warning(f"Could not update token file: {str(e)}")
            else:
                logger.info("No token found in storage for current instance")

        except Exception as e:
            logger.warning(f"Could not clean up token storage: {str(e)}")

    async def _refresh_token(self) -> bool:
        """Attempt to refresh the token.

        This enables self-healing when the current token is invalid or expired.
        Uses acquire_single_tenant_token() to get a fresh token.

        Returns:
            True if token was successfully refreshed, False otherwise
        """
        if not self._allow_token_refresh:
            logger.debug("Token refresh not allowed for this client")
            return False

        logger.info("Attempting to refresh token...")

        try:
            new_token = await acquire_single_tenant_token(
                dashboard_url=self.dashboard_url,
                public_api_url=self.public_api_url,
            )
            self._oauth_token = new_token
            self._token_info = None
            logger.info("Token refreshed successfully")
            return True
        except RuntimeError as e:
            logger.warning(f"Could not refresh token: {e}")
            return False

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        privacy_mode: bool = True,
        expected_client_errors: Sequence[int] = (),
        **kwargs: Any,
    ) -> Any:
        """Make a request to the GitGuardian API (generic method).

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            privacy_mode: Mask credentials in API responses. Defaults to True.
                Opt-out requests do not follow redirects or log response bodies.
            expected_client_errors: Status codes (e.g. [400]) that this caller handles
                itself and surfaces to the user; they are logged at warning instead of
                exception so they don't become Sentry noise. List only the codes the
                caller truly expects — any other error stays visible via logger.exception.
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response data (typically dict[str, Any] or list[dict[str, Any]])

        Raises:
            httpx.HTTPStatusError: If the API returns an error
        """
        url = f"{self.public_api_url}/{endpoint.lstrip('/')}"
        logger.debug(f"Making {method} request to {url}")

        # Log params if present for easier debugging
        if "params" in kwargs and kwargs["params"]:
            logger.debug(f"Request params: {kwargs['params']}")

        # Log json body if present (without sensitive details)
        if "json" in kwargs and kwargs["json"]:
            # Create a copy to avoid modifying the original
            safe_json = dict(kwargs["json"])
            # Redact sensitive fields
            for key in safe_json:
                if any(sensitive in key.lower() for sensitive in ["token", "key", "secret", "password", "auth"]):
                    safe_json[key] = "[REDACTED]"
            logger.debug(f"Request body: {safe_json}")

        headers = self._base_headers(privacy_mode=privacy_mode)
        logger.debug("Using token for authorization")

        headers.update(kwargs.pop("headers", {}))
        logger.debug(
            f"Final request headers: {dict((k, '[REDACTED]' if k.lower() == 'authorization' else v) for k, v in headers.items())}"
        )

        # Initialize retry count
        max_retries = 3
        retry_count = 0
        retry_delay = 1  # initial delay in seconds

        while retry_count <= max_retries:
            try:
                async with httpx.AsyncClient(follow_redirects=privacy_mode, timeout=DEFAULT_HTTP_TIMEOUT) as client:
                    logger.debug(f"Sending {method} request to {url}")
                    response = await _track_api_request(
                        method,
                        endpoint,
                        client.request(method, url, headers=headers, **kwargs),
                        retried=retry_count > 0,
                    )

                # Log detailed response information
                logger.debug(f"Response status code: {response.status_code}")
                logger.debug(f"Response headers: {dict(response.headers)}")

                # Never log response bodies when privacy mode is disabled.
                if privacy_mode and response.content:
                    try:
                        # Limit content length for logging
                        content_str = response.content.decode()
                        if len(content_str) > 500:
                            logger.debug(f"Response content (truncated): {content_str[:500]}...")
                        else:
                            logger.debug(f"Response content: {content_str}")
                    except UnicodeDecodeError:
                        logger.debug("Response content could not be decoded as UTF-8")

                # Special handling for 500 errors - retry
                if response.status_code == 500 and retry_count < max_retries:
                    retry_count += 1
                    wait_time = retry_delay * (2 ** (retry_count - 1))  # exponential backoff
                    logger.warning(
                        f"Received 500 error, retrying in {wait_time}s (attempt {retry_count}/{max_retries})"
                    )
                    record_downstream_wait(duration_ms=wait_time * 1000)
                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()

                if response.status_code == 204:  # No content
                    logger.debug("Received 204 No Content response")
                    return cast(dict[str, Any], {})

                try:
                    if not response.content or response.content.strip() == b"":
                        logger.debug("Received empty response content")
                        return cast(dict[str, Any], {})

                    data = response.json()

                    # Log success response summary
                    if isinstance(data, dict):
                        keys_str = ", ".join(list(data.keys())[:10])
                        logger.debug(f"Parsed JSON response with keys: {keys_str + ('...' if len(data) > 10 else '')}")
                    elif isinstance(data, list):
                        logger.debug(f"Parsed JSON response as list with {len(data)} items")
                    else:
                        logger.debug(f"Parsed JSON response as {type(data).__name__}")

                    return data
                except json.JSONDecodeError as e:
                    logger.exception(f"Failed to parse JSON response: {str(e)}")
                    if privacy_mode:
                        logger.debug(f"Raw response content: {response.content!r}")
                    raise

            except httpx.HTTPStatusError as e:
                # Special handling for 401 errors - token might be invalid/expired
                if e.response.status_code == 401 and self._oauth_token is not None:
                    logger.warning("Received 401 Unauthorized - token may be invalid or expired")

                    # In single-tenant mode with token refresh enabled,
                    # attempt to clear the invalid token and acquire a new one.
                    # In multi-tenant mode (_allow_token_refresh=False), each request
                    # has its own token from the Authorization header — there is no
                    # shared storage to clear and no refresh flow to trigger.
                    if self._allow_token_refresh:
                        try:
                            error_response = e.response.json()
                            if error_response.get("detail") == "Invalid API key.":
                                logger.info("Detected invalid token, attempting to refresh...")

                                # Clear the invalid token from storage
                                self.clear_invalid_token_from_storage()

                                # Try to refresh the token and retry (only once)
                                if retry_count == 0 and await self._refresh_token():
                                    logger.info("Token refreshed, retrying request...")
                                    retry_count += 1
                                    continue
                                else:
                                    logger.exception("Could not refresh token, request will fail")
                        except (json.JSONDecodeError, AttributeError):
                            # If we can't parse the error response, continue with normal error handling
                            pass

                # 401/403 from the GitGuardian API are expected, handled client
                # conditions — the caller's token is invalid/expired/revoked or
                # lacks the required scope — not server faults. Log them at warning
                # level so they do not surface as Sentry errors (logger.exception
                # would). The 401 path still raises DownstreamUnauthorizedError,
                # which middleware rewrites to an MCP 401 so clients can re-auth.
                if e.response.status_code in (401, 403):
                    logger.warning(
                        f"GitGuardian API returned {e.response.status_code} "
                        f"{e.response.reason_phrase} for {url} - token may be invalid, "
                        "expired, revoked, or lacking the required scope"
                    )
                elif e.response.status_code in expected_client_errors:
                    # This caller declared this status as one it handles itself (e.g. a
                    # duplicate-name 400 on honeytoken creation) and surfaces to the user,
                    # so it is an expected client condition, not a server fault. Warn
                    # instead of logger.exception so it doesn't become Sentry noise. Any
                    # status not listed still hits logger.exception below.
                    logger.warning(
                        f"GitGuardian API returned {e.response.status_code} {e.response.reason_phrase} for {url}"
                    )
                else:
                    logger.exception(f"HTTP error occurred: {e.response.status_code} - {e.response.reason_phrase}")
                if privacy_mode:
                    logger.debug(f"Error response content: {e.response.text}")
                logger.debug(f"Failed URL: {url}")
                if e.response.status_code == 401:
                    raise DownstreamUnauthorizedError(f"GitGuardian API returned 401 for {url}") from e
                raise
            except httpx.RequestError as e:
                logger.exception(f"Request error occurred: {str(e)}")
                logger.debug(f"Failed URL: {url}")
                raise
            except Exception as e:
                logger.exception(f"Unexpected error during API request: {str(e)}")
                logger.debug(f"Failed URL: {url}")
                raise

            # If we got here with no exceptions, break out of the retry loop (should have returned above)
            break

        # This should never be reached, but required for type checking
        raise Exception(f"Request loop exited unexpectedly for {url}")

    def _extract_next_cursor(self, headers: Dict[str, Any]) -> Optional[str]:
        """Extract the next cursor from the Link header.

        Args:
            headers: Response headers containing Link header

        Returns:
            Next cursor if available, None otherwise (URL-decoded)
        """
        link_header = headers.get("link")
        if not link_header:
            return None

        # Extract the URL from the link header
        next_url_match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if not next_url_match:
            return None

        next_url = next_url_match.group(1)

        # Extract cursor from the URL
        cursor_match = re.search(r"cursor=([^&]+)", next_url)
        if not cursor_match:
            return None

        # URL-decode the cursor since it comes URL-encoded from the Link header
        # This prevents double-encoding when it's used in the next request
        cursor_encoded = cursor_match.group(1)
        cursor_decoded = unquote(cursor_encoded)
        logger.debug(f"Extracted and decoded cursor: {cursor_encoded} -> {cursor_decoded}")
        return cursor_decoded

    async def _request_get(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make a GET request to the GitGuardian API.

        Args:
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to the request

        Returns:
            Response data as dictionary

        Raises:
            httpx.HTTPStatusError: If the API returns an error
        """
        return cast(dict[str, Any], await self._request("GET", endpoint, **kwargs))

    async def _request_post(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make a POST request to the GitGuardian API.

        Args:
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to the request

        Returns:
            Response data as dictionary

        Raises:
            httpx.HTTPStatusError: If the API returns an error
        """
        return cast(dict[str, Any], await self._request("POST", endpoint, **kwargs))

    async def _request_patch(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make a PATCH request to the GitGuardian API.

        Args:
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to the request

        Returns:
            Response data as dictionary

        Raises:
            httpx.HTTPStatusError: If the API returns an error
        """
        return cast(dict[str, Any], await self._request("PATCH", endpoint, **kwargs))

    async def _request_list(self, endpoint: str, *, privacy_mode: bool = True, **kwargs: Any) -> ListResponse:
        """Make a request to a list endpoint that returns standardized ListResponse.

        This method handles list endpoints that may return either a list directly or
        a dict with a "results" or "data" key. It always returns a standardized structure
        with the data, cursor, and has_more flag.

        Args:
            endpoint: API endpoint path
            privacy_mode: Mask credentials in API responses. Defaults to True.
                Opt-out requests do not follow redirects.
            **kwargs: Additional arguments to pass to the request

        Returns:
            ListResponse with data, cursor, and has_more fields
        """
        url = f"{self.public_api_url}/{endpoint.lstrip('/')}"
        logger.debug(f"Making list request to {url}")

        headers = self._base_headers(privacy_mode=privacy_mode)
        headers.update(kwargs.pop("headers", {}))

        async with httpx.AsyncClient(follow_redirects=privacy_mode, timeout=DEFAULT_HTTP_TIMEOUT) as client:
            response = await _track_api_request(
                "GET",
                endpoint,
                client.get(url, headers=headers, **kwargs),
            )
            response.raise_for_status()

            data: Any = response.json() if response.content else {}
            response_headers = dict(response.headers)

        # Handle both direct list and dict with "results" or "data" key
        items: list[dict[str, Any]]
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            raw_items = data.get("results", data.get("data", []))
            items = raw_items if isinstance(raw_items, list) else []
        else:
            items = []

        cursor = self._extract_next_cursor(response_headers)

        return {
            "data": items,
            "cursor": cursor,
            "has_more": cursor is not None,
        }

    async def paginate_all(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_bytes: int = DEFAULT_PAGINATION_MAX_BYTES,
        *,
        privacy_mode: bool = True,
    ) -> PaginatedResult:
        """Fetch all pages of results using cursor-based pagination.

        Pagination stops when either all data is fetched or the size limit is reached.

        Args:
            endpoint: API endpoint path
            params: Query parameters to include in the request
            max_bytes: Maximum total bytes of JSON data to accumulate (default: 20KB).
                      When this limit is reached, pagination stops and truncated=True is returned.
            privacy_mode: Privacy policy applied to every page. Defaults to True.

        Returns:
            PaginatedResult with data, cursor, has_more, truncated info, and total_bytes
        """
        params = params or {}
        all_items: list[dict[str, Any]] = []
        total_bytes = 0
        cursor: str | None = None
        truncated = False
        has_more = False
        page_count = 0

        logger.debug(f"Starting pagination for endpoint '{endpoint}' with initial params: {params}")

        while True:
            page_count += 1
            if page_count > MAX_PAGINATION_PAGES:
                logger.warning(
                    f"Pagination stopped: reached max page limit ({MAX_PAGINATION_PAGES}) for endpoint '{endpoint}'"
                )
                truncated = True
                has_more = True
                break

            # If we have a cursor, add it to params
            if cursor:
                params["cursor"] = cursor
                logger.debug(f"Using pagination cursor: {cursor}")

            # Build query string with proper URL encoding
            query_parts = []
            for k, v in params.items():
                if v is not None:
                    original_value = str(v)
                    encoded_value = quote_plus(original_value)
                    query_parts.append(f"{k}={encoded_value}")

                    # Log if encoding actually changed the value (important for debugging)
                    if original_value != encoded_value:
                        logger.debug(f"URL-encoded parameter '{k}': '{original_value}' -> '{encoded_value}'")

            query_string = "&".join(query_parts) if query_parts else ""
            full_endpoint = f"{endpoint}?{query_string}" if query_string else endpoint

            logger.debug(f"Making paginated request to: {full_endpoint}")

            # Use _request_list for standardized response handling
            response = await self._request_list(full_endpoint, privacy_mode=privacy_mode)

            # Handle empty responses
            if not response["data"]:
                cursor = response["cursor"]
                logger.debug("Received empty response data, stopping pagination")
                break

            # Calculate size of this page's data
            page_bytes = len(json.dumps(response["data"]).encode("utf-8"))

            # Check if adding this page would exceed the limit
            if total_bytes + page_bytes > max_bytes and all_items:
                # We already have some data, stop here to avoid exceeding limit
                logger.warning(
                    f"Pagination stopped due to size limit: {total_bytes} bytes accumulated, "
                    f"next page would add {page_bytes} bytes (limit: {max_bytes} bytes)"
                )
                truncated = True
                has_more = True
                # Keep the cursor for this unreturned page. Advancing to the
                # response's next cursor would silently skip its occurrences.
                break

            logger.debug(f"Received page with {len(response['data'])} items ({page_bytes} bytes)")
            all_items.extend(response["data"])
            total_bytes += page_bytes
            logger.debug(f"Total items collected so far: {len(all_items)} ({total_bytes} bytes)")

            # Check for next cursor
            cursor = response["cursor"]
            if cursor:
                logger.debug(f"Found next cursor: {cursor}")
            else:
                logger.debug("No next cursor found, pagination complete")
                break

        if truncated:
            record_truncation()

        logger.info(
            "pagination_complete",
            extra={
                "path": _path_template(endpoint),
                "items": len(all_items),
                "response_bytes": total_bytes,
                "truncated": truncated,
                "pages": page_count,
            },
        )
        return {
            "data": all_items,
            "cursor": cursor,
            "has_more": has_more or (cursor is not None),
        }

    async def get_incident(
        self,
        incident_id: int,
        with_occurrences: int = 20,
    ) -> dict[str, Any]:
        """Get detailed information about a specific incident.

        Args:
            incident_id: ID of the incident to retrieve
            with_occurrences: Number of occurrences to retrieve (0-100, default: 20)

        Returns:
            Detailed incident data including occurrences
        """
        logger.info(f"Getting details for incident ID: {incident_id}")
        params: dict[str, Any] = {}
        if with_occurrences != 20:
            params["with_occurrences"] = with_occurrences
        return await self._request_get(f"/incidents/secrets/{incident_id}", params=params)

    async def get_current_token_info(self) -> dict[str, Any]:
        """Get information about the current API token.

        This endpoint retrieves details about the API token being used,
        including its name, creation date, expiration, and scopes.

        Returns:
            Dictionary containing token information including scopes
        """
        logger.info("Getting current API token information")

        # If we already have token info, return it
        if self._token_info is not None:
            # Convert Pydantic model to dict if needed
            if hasattr(self._token_info, "model_dump"):
                return dict(self._token_info.model_dump())
            elif isinstance(self._token_info, dict):
                return self._token_info
            else:
                return await self._request_get("/api_tokens/self")

        # Otherwise fetch from the API
        return await self._request_get("/api_tokens/self")

    async def multiple_scan(self, documents: list[dict[str, str]]) -> dict[str, Any]:
        """Scan multiple documents for secrets and policy breaks.

        Args:
            documents: List of documents to scan, each with 'document' and optional 'filename'
                      Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]

        Returns:
            Scan results for all documents
        """
        logger.info(f"Scanning {len(documents)} documents for secrets")

        # Validate input format
        for i, doc in enumerate(documents):
            if "document" not in doc:
                raise ValueError(f"Document at index {i} is missing required 'document' field")

        return await self._request_post("/multiscan", json=documents)

    # Secret Incident management endpoints
    async def assign_incident(
        self, incident_id: str, assignee_id: str | None = None, email: str | None = None
    ) -> dict[str, Any]:
        """Assign a secret incident to a member.

        Args:
            incident_id: ID of the secret incident
            assignee_id: ID of the member to assign the incident to

        Returns:
            Status of the operation
        """
        if assignee_id and email:
            raise ValueError("either email or assignee_id should be provided. Not both")
        logger.info(f"Assigning incident {incident_id} to member {assignee_id or email}")
        return await self._request_post(
            f"/incidents/secrets/{incident_id}/assign",
            json={"member_id": assignee_id, "email": email},
        )

    async def unassign_incident(self, incident_id: str) -> dict[str, Any]:
        """Unassign a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Unassigning incident {incident_id}")
        return await self._request_post(f"/incidents/secrets/{incident_id}/unassign")

    async def resolve_incident(self, incident_id: str, secret_revoked: bool = True) -> dict[str, Any]:
        """Resolve a secret incident.

        Args:
            incident_id: ID of the secret incident
            secret_revoked: Whether the secret has been revoked/rotated (default: True)

        Returns:
            Status of the operation
        """
        logger.info(f"Resolving incident {incident_id} (secret_revoked={secret_revoked})")
        payload = {"secret_revoked": secret_revoked}
        return await self._request_post(f"/incidents/secrets/{incident_id}/resolve", json=payload)

    async def ignore_incident(self, incident_id: str, ignore_reason: str | None = None) -> dict[str, Any]:
        """Ignore a secret incident.

        Args:
            incident_id: ID of the secret incident
            ignore_reason: Reason for ignoring (test_credential, false_positive, low_risk, invalid)

        Returns:
            Status of the operation
        """
        logger.info(f"Ignoring incident {incident_id} with reason: {ignore_reason}")
        payload = {}
        if ignore_reason:
            payload["ignore_reason"] = ignore_reason
        return await self._request_post(f"/incidents/secrets/{incident_id}/ignore", json=payload)

    async def reopen_incident(self, incident_id: str) -> dict[str, Any]:
        """Reopen a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Reopening incident {incident_id}")
        return await self._request_post(f"/incidents/secrets/{incident_id}/reopen")

    # Secret Incident Notes (comments) management
    #
    # Notes are free-form comments left by members or API tokens on an incident.
    # The public API exposes them under ``.../notes`` and the comment body is
    # carried in the ``comment`` field (1-10000 characters). Internal incidents
    # live under ``/incidents/secrets/{id}/notes`` while Public Monitoring
    # incidents live under ``/public-incidents/secrets/{id}/notes``; the note ids
    # are not interchangeable between the two perimeters.
    async def create_incident_note(self, incident_id: int | str, comment: str) -> dict[str, Any]:
        """Create a note (comment) on an internal secret incident.

        Wraps POST /v1/incidents/secrets/{incident_id}/notes.

        Args:
            incident_id: ID of the secret incident
            comment: Content of the comment (1-10000 characters)

        Returns:
            Created note details
        """
        logger.info(f"Creating note for incident {incident_id}")
        return await self._request_post(f"/incidents/secrets/{incident_id}/notes", json={"comment": comment})

    async def update_incident_note(self, incident_id: int | str, note_id: int | str, comment: str) -> dict[str, Any]:
        """Update a note (comment) on an internal secret incident.

        Wraps PATCH /v1/incidents/secrets/{incident_id}/notes/{note_id}.

        Args:
            incident_id: ID of the secret incident
            note_id: ID of the note to update
            comment: New content for the comment (1-10000 characters)

        Returns:
            Updated note details
        """
        logger.info(f"Updating note {note_id} for incident {incident_id}")
        return await self._request_patch(
            f"/incidents/secrets/{incident_id}/notes/{note_id}",
            json={"comment": comment},
        )

    async def list_occurrences(
        self,
        from_date: str | None = None,
        to_date: str | None = None,
        source_name: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
        presence: str | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[TagNames] | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
        severity: list[IncidentSeverity] | None = None,
        validity: list[IncidentValidity] | None = None,
        status: list[IncidentStatus] | None = None,
        with_sources: bool | None = None,
        member_assignee_id: int | None = None,
        incident_id: int | None = None,
    ) -> ListResponse:
        """List secret occurrences with optional filtering and cursor-based pagination.

        Args:
            from_date: Filter occurrences created after this date (ISO format: YYYY-MM-DD)
            to_date: Filter occurrences created before this date (ISO format: YYYY-MM-DD)
            source_name: Filter by source name
            source_type: Filter by source type
            source_id: Filter by specific source ID
            presence: Filter by presence status
            tags: Filter by tags (list of tag names)
            exclude_tags: Exclude occurrences with these tag names
            per_page: Number of results per page (default: 20)
            cursor: Pagination cursor (for cursor-based pagination)
            ordering: Sort field (e.g., 'date', '-date' for descending)
            get_all: If True, fetch all results using cursor-based pagination
            severity: Filter by severity (list of severity names)
            validity: Filter by validity (list of validity names)
            status: Filter by status (list of status names)
            with_sources: Whether to include source details in the response
            member_assignee_id: Filter by the incident's assigned member
            incident_id: Filter by a specific incident across sources

        Returns:
            List of occurrences matching the criteria or an empty dict/list if no results
        """
        logger.info("Listing secret occurrences with filters")

        # Build parameters
        params = {}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if source_name:
            params["source_name"] = source_name
        if source_type:
            params["source_type"] = source_type
        if source_id:
            params["source_id"] = source_id
        if presence:
            params["presence"] = presence
        if tags:
            params["tags"] = ",".join(tags)
        if exclude_tags:
            params["exclude_tags"] = ",".join(exclude_tags) if isinstance(exclude_tags, list) else exclude_tags
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor
        if ordering:
            params["ordering"] = ordering
        if severity:
            params["severity"] = ",".join(severity)
        if validity:
            params["validity"] = ",".join(validity)
        if status:
            params["status"] = ",".join(status)
        if with_sources is not None:
            params["with_sources"] = str(with_sources).lower()
        if member_assignee_id is not None:
            params["incident_assignee_id"] = str(member_assignee_id)
        if incident_id is not None:
            params["incident_id"] = str(incident_id)

        # If get_all is True, use paginate_all to get all results with truncation metadata
        if get_all:
            logger.info("Getting all occurrences using cursor-based pagination")
            return await self.paginate_all("occurrences/secrets", params)

        # Otherwise, get a single page
        logger.info(f"Getting occurrences with params: {params}")
        return await self._request_list("occurrences/secrets", params=params)

    async def list_public_occurrences(
        self,
        incident_id: int,
        cursor: str | None = None,
        per_page: int = 20,
        date_before: str | None = None,
        date_after: str | None = None,
        source_id: int | None = None,
        presence: str | None = None,
        sha: str | None = None,
        filepath: str | None = None,
        attachment_reason: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        validity: str | None = None,
        tags: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
    ) -> ListResponse:
        """List occurrences of a public secret incident.

        Wraps GET /v1/public-incidents/secrets/{incident_id}/occurrences.

        Args:
            incident_id: The id of the public incident to list occurrences for.
            cursor: Pagination cursor.
            per_page: Number of results per page (1-100, default 20).
            date_before: Entries found before this date (ISO datetime).
            date_after: Entries found after this date (ISO datetime).
            source_id: Filter by source ID.
            presence: Filter by presence status (present, removed).
            sha: Filter by commit sha (>=3 characters).
            filepath: Filter by filepath (>=3 characters).
            attachment_reason: Filter by attachment reason
                (by_dev_from_perimeter, on_github_org_in_perimeter, from_secret_grasper).
                Multiple values can be comma-separated.
            severity: Filter by incident severity (comma-separated allowed).
            status: Filter by incident status (comma-separated allowed).
            validity: Filter by secret validity (comma-separated allowed).
            tags: Filter by tags (comma-separated, or "NONE" for occurrences without tags).
            ordering: Sort field (id, -id, date, -date).
            get_all: If True, fetch all results using cursor-based pagination.

        Returns:
            ListResponse with occurrence data, cursor, and has_more flag.
        """
        logger.info(f"Listing public occurrences for incident {incident_id}")

        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        if per_page:
            params["per_page"] = str(per_page)
        if date_before:
            params["date_before"] = date_before
        if date_after:
            params["date_after"] = date_after
        if source_id is not None:
            params["source_id"] = str(source_id)
        if presence:
            params["presence"] = presence
        if sha:
            params["sha"] = sha
        if filepath:
            params["filepath"] = filepath
        if attachment_reason:
            params["attachment_reason"] = attachment_reason
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if validity:
            params["validity"] = validity
        if tags:
            params["tags"] = tags
        if ordering:
            params["ordering"] = ordering

        endpoint = f"/public-incidents/secrets/{incident_id}/occurrences"

        if get_all:
            return await self.paginate_all(endpoint, params)

        return await self._request_list(endpoint, params=params)

    async def list_sources(
        self,
        search: str | None = None,
        last_scan_status: str | None = None,
        health: str | None = None,
        type: str | None = None,
        ordering: str | None = None,
        visibility: str | None = None,
        external_id: str | None = None,
        source_criticality: str | None = None,
        monitored: bool | None = None,
        team_id: int | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        get_all: bool = False,
    ) -> ListResponse:
        """List sources known by GitGuardian with optional filtering and cursor-based pagination.

        Args:
            search: Sources matching this search string
            last_scan_status: Filter sources based on the status of their latest historical scan
            health: Filter sources based on their health status
            type: Filter by source type (e.g., 'github', 'gitlab')
            ordering: Sort field (e.g., 'last_scan_date', '-last_scan_date' for descending)
            visibility: Filter by visibility status ('public', 'private', 'internal')
            external_id: Filter by specific external id
            source_criticality: Filter by source criticality ('critical', 'high', 'medium', 'low', 'unknown')
            monitored: Filter by monitored value (true/false)
            team_id: Filter by team id (sources within the given team's perimeter)
            per_page: Number of results per page (default: 20, min: 1, max: 100)
            cursor: Pagination cursor (for cursor-based pagination)
            get_all: If True, fetch all results using cursor-based pagination

        Returns:
            List of sources matching the criteria or an empty dict/list if no results
        """
        logger.info("Listing sources with filters")

        # Build query parameters
        params = {}
        if search:
            params["search"] = search
        if last_scan_status:
            params["last_scan_status"] = last_scan_status
        if health:
            params["health"] = health
        if type:
            params["type"] = type
        if ordering:
            params["ordering"] = ordering
        if visibility:
            params["visibility"] = visibility
        if external_id:
            params["external_id"] = external_id
        if source_criticality:
            params["source_criticality"] = source_criticality
        if monitored is not None:
            params["monitored"] = str(monitored).lower()
        if team_id is not None:
            params["team_id"] = str(team_id)
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor

        endpoint = "/sources"

        if get_all:
            # When get_all=True, return paginated result with truncation metadata
            return await self.paginate_all(endpoint, params)

        return await self._request_list(endpoint, params=params)

    async def get_member(self, member_id: int) -> dict[str, Any]:
        """Get a specific user's information.

        Args:
            member_id: ID of the member to retrieve

        Returns:
            Member information including id, name, email, role, access_level, active status
        """
        logger.info(f"Getting member details for ID: {member_id}")
        return await self._request_get(f"/members/{member_id}")

    async def get_current_member(self):
        """Get the current user's information."""
        data = await self.get_current_token_info()
        member_id = data["member_id"]
        return await self.get_member(member_id)

    async def list_incidents_for_mcp(
        self,
        page: int = 1,
        page_size: int = 20,
        ordering: str | None = None,
        # Search
        search: str | None = None,
        # Status and assignment filters
        status: str | list[str] | None = None,
        assignee_id: int | list[int] | None = None,
        # Severity, score, and validity filters
        severity: str | list[str] | None = None,
        score__ge: int | None = None,
        score__le: int | None = None,
        validity: str | list[str] | None = None,
        # Secret type filters
        detector_group_name: str | list[str] | None = None,
        detector_type: str | list[str] | None = None,
        detector_category: str | list[str] | None = None,
        issue_name: str | list[str] | None = None,
        secret_category: str | list[str] | None = None,
        secret_family: str | list[str] | None = None,
        secret_provider: str | list[str] | None = None,
        # Source filters
        source: int | list[int] | None = None,
        source_type: str | list[str] | None = None,
        source_criticality: str | list[str] | None = None,
        # Occurrence and presence filters
        occurrence_count: str | None = None,  # Supports operators like >=10
        presence: str | list[str] | None = None,
        # Date filters
        opened_for: str | None = None,  # Days open, supports operators like >=30
        # Tags and exposure filters
        tags: str | list[str] | None = None,
        public_exposure: str | list[str] | None = None,
        # Integration filters
        integration: str | list[str] | None = None,
        issue_tracker: str | list[str] | None = None,
        # Boolean filters
        has_related_issues: bool | None = None,
        location: bool | None = None,
        feedback: bool | None = None,
        publicly_shared: bool | None = None,
        # Vault/Secret Manager filters
        secret_manager_type: str | list[str] | None = None,
        secret_manager_instance: int | list[int] | None = None,
        # NHI (Non-Human Identity) filters
        nhi_env: str | list[str] | None = None,
        nhi_policy: str | list[str] | None = None,
        # Team filters
        teams: int | list[int] | None = None,
        # Similar issues filter
        similar_to: int | None = None,
        # Date filters
        date_before: str | None = None,  # ISO format: YYYY-MM-DD
        date_after: str | None = None,  # ISO format: YYYY-MM-DD
        # Secret scope filter
        secret_scope: str | list[str] | None = None,
        # Analyzer status filter
        analyzer_status: str | list[str] | None = None,
        # Custom tags filter
        custom_tags: int | list[int] | None = None,
        # Custom filters with operators
        custom_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """List secret incidents using the MCP-optimized endpoint with page-based pagination.

        This endpoint provides more filtering options than the standard incidents endpoint.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page (default: 20)
            ordering: Sort field (e.g., '-date' for newest first)
            search: Search term to filter incidents
            status: Filter by status (TRIGGERED, ASSIGNED, RESOLVED, IGNORED)
            assignee_id: Filter by assignee member ID(s), use 0 for unassigned
            severity: Filter by severity level(s) - uses numeric values (10=critical, 20=high, etc.)
            score__ge: Filter incidents with score >= this value (0-100)
            score__le: Filter incidents with score <= this value (0-100)
            validity: Filter by validity status
            detector_group_name: Filter by detector group name(s)
            detector_type: Filter by detector type/nature
            detector_category: Filter by detector category
            issue_name: Filter by issue/incident name
            secret_category: Filter by secret category
            secret_family: Filter by secret family
            secret_provider: Filter by secret provider
            source: Filter by source ID(s)
            source_type: Filter by source type(s)
            source_criticality: Filter by source criticality
            occurrence_count: Filter by occurrence count (supports operators: >=, <=, =)
            presence: Filter by presence status (present, removed)
            opened_for: Filter by days open (supports operators: >=, <=, =)
            tags: Filter by tag names
            public_exposure: Filter by public exposure status
            integration: Filter by integration type
            issue_tracker: Filter by issue tracker type (jira_cloud_notifier, jira_data_center_notifier, servicenow)
            has_related_issues: Filter to incidents with/without related issues
            location: Filter to incidents with/without location information
            feedback: Filter to incidents with/without feedback
            publicly_shared: Filter to incidents that are/aren't publicly shared
            secret_manager_type: Filter by vault type (hashicorpvault, awssecretsmanager, azurekeyvault, gcpsecretmanager, cyberarksaas, cyberarkselfhosted, akeyless, delineasecretserver)
            secret_manager_instance: Filter by vault instance ID(s)
            nhi_env: Filter by NHI environment name(s)
            nhi_policy: Filter by NHI policy breach name(s)
            teams: Filter by team ID(s)
            similar_to: Filter incidents similar to the given incident ID
            date_before: Filter incidents detected before this date (YYYY-MM-DD)
            date_after: Filter incidents detected after this date (YYYY-MM-DD)
            secret_scope: Filter by secret scope name(s)
            analyzer_status: Filter by analyzer status (no_checker, not_checked, checked, invalid, failed_to_check)
            custom_tags: Filter by custom tag ID(s)
            custom_filters: Additional filters with operators (e.g., {"severity__in": [10, 20]})

        Returns:
            Paginated response with results, count, next/previous page URLs
        """
        logger.info(f"Listing incidents for MCP (page={page}, page_size={page_size})")

        params: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
        }

        # Helper to format list parameters
        def format_param(value: Any) -> str:
            if isinstance(value, list):
                return ",".join(str(v) for v in value)
            return str(value)

        # Add basic filters
        if ordering:
            params["ordering"] = ordering
        if search:
            params["search"] = search
        if status:
            params["status__in"] = format_param(status)
        if assignee_id is not None:
            # assignee_id is a *member* id (the public-API identity). The MCP
            # incidents endpoint resolves it to the underlying user id via the
            # dedicated assignee_member_id filter; the raw assignee__in filter
            # would expect a user id and silently match nothing.
            params["assignee_member_id"] = format_param(assignee_id)
        if severity:
            params["severity__in"] = format_param(severity)
        if score__ge is not None:
            params["score__ge"] = score__ge
        if score__le is not None:
            params["score__le"] = score__le
        if validity:
            params["validity__in"] = format_param(validity)

        # Secret type filters
        if detector_group_name:
            params["detector_group_name__in"] = format_param(detector_group_name)
        if detector_type:
            params["detector_type__in"] = format_param(detector_type)
        if detector_category:
            params["detector_category__in"] = format_param(detector_category)
        if issue_name:
            params["issue_name__in"] = format_param(issue_name)
        if secret_category:
            params["secret_category__in"] = format_param(secret_category)
        if secret_family:
            params["secret_family__in"] = format_param(secret_family)
        if secret_provider:
            params["secret_provider__in"] = format_param(secret_provider)

        # Source filters
        if source:
            params["source__in"] = format_param(source)
        if source_type:
            params["source_type__in"] = format_param(source_type)
        if source_criticality:
            params["source_criticality__in"] = format_param(source_criticality)

        # Occurrence and presence filters
        if occurrence_count:
            params["occurrence_count"] = occurrence_count
        if presence:
            params["presence__in"] = format_param(presence)

        # Date filters
        if opened_for:
            params["opened_for"] = opened_for

        # Tags and exposure
        if tags:
            params["tags__in"] = format_param(tags)
        if public_exposure:
            params["public_exposure__in"] = format_param(public_exposure)

        # Integration filters
        if integration:
            params["integration__in"] = format_param(integration)
        if issue_tracker:
            params["issue_tracker__in"] = format_param(issue_tracker)

        # Boolean filters
        if has_related_issues is not None:
            params["has_related_issues"] = str(has_related_issues).lower()
        if location is not None:
            params["location"] = str(location).lower()
        if feedback is not None:
            params["feedback"] = str(feedback).lower()
        if publicly_shared is not None:
            params["publicly_shared"] = str(publicly_shared).lower()

        # Vault/Secret Manager filters
        if secret_manager_type:
            params["secret_manager_type__in"] = format_param(secret_manager_type)
        if secret_manager_instance:
            params["secret_manager_instance__in"] = format_param(secret_manager_instance)

        # NHI filters
        if nhi_env:
            params["nhi_env__in"] = format_param(nhi_env)
        if nhi_policy:
            params["nhi_policy__in"] = format_param(nhi_policy)

        # Team filters
        if teams:
            params["teams__in"] = format_param(teams)

        # Similar issues filter
        if similar_to is not None:
            params["similar_to"] = similar_to

        # Date filters
        if date_before:
            params["date__le"] = _to_date_only(date_before)
        if date_after:
            params["date__ge"] = _to_date_only(date_after)

        # Secret scope filter
        if secret_scope:
            params["secret_scope__in"] = format_param(secret_scope)

        # Analyzer status filter
        if analyzer_status:
            params["analyzer_status__in"] = format_param(analyzer_status)

        # Custom tags filter
        if custom_tags:
            params["custom_tags__in"] = format_param(custom_tags)

        # Add any custom filters
        if custom_filters:
            params.update(custom_filters)

        return await self._request_get("/incidents-for-mcp", params=params)

    async def count_incidents_for_mcp(
        self,
        # Search
        search: str | None = None,
        # Status and assignment filters
        status: str | list[str] | None = None,
        assignee_id: int | list[int] | None = None,
        # Severity, score, and validity filters
        severity: str | list[str] | None = None,
        score__ge: int | None = None,
        score__le: int | None = None,
        validity: str | list[str] | None = None,
        # Secret type filters
        detector_group_name: str | list[str] | None = None,
        detector_type: str | list[str] | None = None,
        detector_category: str | list[str] | None = None,
        issue_name: str | list[str] | None = None,
        secret_category: str | list[str] | None = None,
        secret_family: str | list[str] | None = None,
        secret_provider: str | list[str] | None = None,
        # Source filters
        source: int | list[int] | None = None,
        source_type: str | list[str] | None = None,
        source_criticality: str | list[str] | None = None,
        # Occurrence and presence filters
        occurrence_count: str | None = None,
        presence: str | list[str] | None = None,
        # Date filters
        opened_for: str | None = None,
        # Tags and exposure filters
        tags: str | list[str] | None = None,
        public_exposure: str | list[str] | None = None,
        # Integration filters
        integration: str | list[str] | None = None,
        issue_tracker: str | list[str] | None = None,
        # Boolean filters
        has_related_issues: bool | None = None,
        location: bool | None = None,
        feedback: bool | None = None,
        publicly_shared: bool | None = None,
        # Vault/Secret Manager filters
        secret_manager_type: str | list[str] | None = None,
        secret_manager_instance: int | list[int] | None = None,
        # NHI (Non-Human Identity) filters
        nhi_env: str | list[str] | None = None,
        nhi_policy: str | list[str] | None = None,
        # Team filters
        teams: int | list[int] | None = None,
        # Similar issues filter
        similar_to: int | None = None,
        # Date filters
        date_before: str | None = None,
        date_after: str | None = None,
        # Secret scope filter
        secret_scope: str | list[str] | None = None,
        # Analyzer status filter
        analyzer_status: str | list[str] | None = None,
        # Custom tags filter
        custom_tags: int | list[int] | None = None,
        # Custom filters with operators
        custom_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Count secret incidents using the MCP-optimized count endpoint.

        Accepts the same filters as list_incidents_for_mcp but returns only
        the total count of matching incidents.

        Returns:
            Dictionary with a single "count" key, e.g. {"count": 42}
        """
        logger.info("Counting incidents for MCP")

        params: dict[str, Any] = {}

        def format_param(value: Any) -> str:
            if isinstance(value, list):
                return ",".join(str(v) for v in value)
            return str(value)

        if search:
            params["search"] = search
        if status:
            params["status__in"] = format_param(status)
        if assignee_id is not None:
            # assignee_id is a *member* id (the public-API identity). The MCP
            # incidents endpoint resolves it to the underlying user id via the
            # dedicated assignee_member_id filter; the raw assignee__in filter
            # would expect a user id and silently match nothing.
            params["assignee_member_id"] = format_param(assignee_id)
        if severity:
            params["severity__in"] = format_param(severity)
        if score__ge is not None:
            params["score__ge"] = score__ge
        if score__le is not None:
            params["score__le"] = score__le
        if validity:
            params["validity__in"] = format_param(validity)
        if detector_group_name:
            params["detector_group_name__in"] = format_param(detector_group_name)
        if detector_type:
            params["detector_type__in"] = format_param(detector_type)
        if detector_category:
            params["detector_category__in"] = format_param(detector_category)
        if issue_name:
            params["issue_name__in"] = format_param(issue_name)
        if secret_category:
            params["secret_category__in"] = format_param(secret_category)
        if secret_family:
            params["secret_family__in"] = format_param(secret_family)
        if secret_provider:
            params["secret_provider__in"] = format_param(secret_provider)
        if source:
            params["source__in"] = format_param(source)
        if source_type:
            params["source_type__in"] = format_param(source_type)
        if source_criticality:
            params["source_criticality__in"] = format_param(source_criticality)
        if occurrence_count:
            params["occurrence_count"] = occurrence_count
        if presence:
            params["presence__in"] = format_param(presence)
        if opened_for:
            params["opened_for"] = opened_for
        if tags:
            params["tags__in"] = format_param(tags)
        if public_exposure:
            params["public_exposure__in"] = format_param(public_exposure)
        if integration:
            params["integration__in"] = format_param(integration)
        if issue_tracker:
            params["issue_tracker__in"] = format_param(issue_tracker)
        if has_related_issues is not None:
            params["has_related_issues"] = str(has_related_issues).lower()
        if location is not None:
            params["location"] = str(location).lower()
        if feedback is not None:
            params["feedback"] = str(feedback).lower()
        if publicly_shared is not None:
            params["publicly_shared"] = str(publicly_shared).lower()
        if secret_manager_type:
            params["secret_manager_type__in"] = format_param(secret_manager_type)
        if secret_manager_instance:
            params["secret_manager_instance__in"] = format_param(secret_manager_instance)
        if nhi_env:
            params["nhi_env__in"] = format_param(nhi_env)
        if nhi_policy:
            params["nhi_policy__in"] = format_param(nhi_policy)
        if teams:
            params["teams__in"] = format_param(teams)
        if similar_to is not None:
            params["similar_to"] = similar_to
        # Date filters
        if date_before:
            params["date__le"] = _to_date_only(date_before)
        if date_after:
            params["date__ge"] = _to_date_only(date_after)
        if secret_scope:
            params["secret_scope__in"] = format_param(secret_scope)
        if analyzer_status:
            params["analyzer_status__in"] = format_param(analyzer_status)
        if custom_tags:
            params["custom_tags__in"] = format_param(custom_tags)
        if custom_filters:
            params.update(custom_filters)

        return await self._request_get("/incidents-for-mcp/count", params=params)

    async def get_remediation_workflow(self) -> dict[str, Any]:
        """Get the workspace's remediation workflow.

        Wraps GET /v1/remediation-workflow. Returns the account's custom
        remediation workflow if one is configured, otherwise a default workflow.

        Returns:
            Remediation workflow data including the ordered ``steps`` and, for a
            configured custom workflow, ``id``/``created_at``/``updated_at``.
        """
        logger.info("Getting remediation workflow")
        return await self._request_get("/remediation-workflow")

    async def list_public_incidents(
        self,
        cursor: str | None = None,
        per_page: int = 20,
        date_before: str | None = None,
        date_after: str | None = None,
        triggered_at_before: str | None = None,
        triggered_at_after: str | None = None,
        assignee_email: str | None = None,
        assignee_id: int | None = None,
        status: IncidentStatus | str | Sequence[IncidentStatus | str] | None = None,
        severity: IncidentSeverity | str | Sequence[IncidentSeverity | str] | None = None,
        validity: IncidentValidity | str | Sequence[IncidentValidity | str] | None = None,
        tags: str | None = None,
        custom_tags: str | None = None,
        custom_tag_key: str | None = None,
        custom_tag_value: str | None = None,
        ordering: str | None = None,
        detector_group_name: str | None = None,
        ignorer_id: int | None = None,
        ignorer_api_token_id: str | None = None,
        resolver_id: int | None = None,
        resolver_api_token_id: str | None = None,
        feedback: bool | None = None,
        declarative_secret_status: str | None = None,
        risk_score_min: int | None = None,
        risk_score_max: int | None = None,
        get_all: bool = False,
    ) -> ListResponse:
        """List public secret incidents (from public sources like public GitHub).

        Wraps GET /v1/public-incidents/secrets.

        Args:
            cursor: Pagination cursor.
            per_page: Number of results per page (1-100, default 20).
            date_before: Entries found before this date (ISO datetime).
            date_after: Entries found after this date (ISO datetime).
            triggered_at_before: Incidents triggered before this date (ISO datetime).
            triggered_at_after: Incidents triggered after this date (ISO datetime).
            assignee_email: Incidents assigned to this email.
            assignee_id: Incidents assigned to this user id.
            status: Filter by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED).
                Accepts a single value or a list (sent as comma-separated; the API
                accepts multi-value filters here, like the sibling /incidents/secrets endpoint).
            severity: Filter by severity (critical, high, medium, low, info, unknown).
                Accepts a single value or a list (comma-separated).
            validity: Filter by validity (valid, invalid, failed_to_check, no_checker, unknown).
                Accepts a single value or a list (comma-separated).
            tags: Filter by tags (comma-separated tag names, or "NONE" for incidents without tags).
            custom_tags: Filter by custom tag UUIDs (comma-separated).
            custom_tag_key: Filter by custom tag key.
            custom_tag_value: Filter by custom tag value.
            ordering: Sort field (date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at,
                risk_score, -risk_score).
            detector_group_name: Filter by detector group name.
            ignorer_id: Incidents ignored by this user id.
            ignorer_api_token_id: Incidents ignored by this API token id.
            resolver_id: Incidents resolved by this user id.
            resolver_api_token_id: Incidents resolved by this API token id.
            feedback: Filter by presence of feedback.
            declarative_secret_status: Filter by declarative secret status (revoked, active,
                test_credential, false_positive, low_risk).
            risk_score_min: Minimum risk score (0-100).
            risk_score_max: Maximum risk score (0-100).
            get_all: If True, fetch all results using cursor-based pagination.

        Returns:
            ListResponse with public incident data, cursor, and has_more flag.
        """
        logger.info("Listing public secret incidents")

        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        if per_page:
            params["per_page"] = str(per_page)
        if date_before:
            params["date_before"] = date_before
        if date_after:
            params["date_after"] = date_after
        if triggered_at_before:
            params["triggered_at_before"] = triggered_at_before
        if triggered_at_after:
            params["triggered_at_after"] = triggered_at_after
        if assignee_email:
            params["assignee_email"] = assignee_email
        if assignee_id is not None:
            params["assignee_id"] = str(assignee_id)
        if status:
            params["status"] = _serialize_enum_filter(status)
        if severity:
            params["severity"] = _serialize_enum_filter(severity)
        if validity:
            params["validity"] = _serialize_enum_filter(validity)
        if tags:
            params["tags"] = tags
        if custom_tags:
            params["custom_tags"] = custom_tags
        if custom_tag_key:
            params["custom_tag_key"] = custom_tag_key
        if custom_tag_value:
            params["custom_tag_value"] = custom_tag_value
        if ordering:
            params["ordering"] = ordering
        if detector_group_name:
            params["detector_group_name"] = detector_group_name
        if ignorer_id is not None:
            params["ignorer_id"] = str(ignorer_id)
        if ignorer_api_token_id:
            params["ignorer_api_token_id"] = ignorer_api_token_id
        if resolver_id is not None:
            params["resolver_id"] = str(resolver_id)
        if resolver_api_token_id:
            params["resolver_api_token_id"] = resolver_api_token_id
        if feedback is not None:
            params["feedback"] = str(feedback).lower()
        if declarative_secret_status:
            params["declarative_secret_status"] = declarative_secret_status
        if risk_score_min is not None:
            params["risk_score_min"] = str(risk_score_min)
        if risk_score_max is not None:
            params["risk_score_max"] = str(risk_score_max)

        endpoint = "/public-incidents/secrets"

        if get_all:
            return await self.paginate_all(endpoint, params)

        return await self._request_list(endpoint, params=params)

    async def get_public_incident(self, incident_id: int) -> dict[str, Any]:
        """Retrieve a single public secret incident by id.

        Wraps GET /v1/public-incidents/secrets/{incident_id}.

        Args:
            incident_id: The id of the public incident to retrieve.

        Returns:
            Detailed public incident data.
        """
        logger.info(f"Getting public incident {incident_id}")
        return await self._request_get(f"/public-incidents/secrets/{incident_id}")

    async def list_honeytokens(
        self,
        status: str | None = None,
        search: str | None = None,
        ordering: str | None = None,
        show_token: bool = False,
        creator_id: str | None = None,
        creator_api_token_id: str | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        get_all: bool = False,
    ) -> ListResponse:
        """List all honeytokens with optional filtering and cursor-based pagination.

        Args:
            status: Filter by status (active, triggered, or revoked)
            search: Search string to filter results
            ordering: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
            show_token: Whether to include token details in the response
            creator_id: Filter by creator ID
            creator_api_token_id: Filter by creator API token ID
            per_page: Number of results per page (default: 20)
            cursor: Pagination cursor (for cursor-based pagination)
            get_all: If True, fetch all results using cursor-based pagination

        Returns:
            List of honeytokens matching the criteria or an empty dict/list if no results
        """
        logger.info(
            f"Listing honeytokens with filters: status={status}, search={search}, ordering={ordering}, creator_id={creator_id}, creator_api_token_id={creator_api_token_id}"
        )

        # Build query parameters
        params = {}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        if ordering:
            params["ordering"] = ordering
        if show_token is not None:
            params["show_token"] = str(show_token).lower()
        if creator_id:
            params["creator_id"] = creator_id
        if creator_api_token_id:
            params["creator_api_token_id"] = creator_api_token_id
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor

        endpoint = "/honeytokens"

        if get_all:
            # When get_all=True, return paginated result with truncation metadata
            return await self.paginate_all(endpoint, params, privacy_mode=False)

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        if query_string:
            endpoint = f"{endpoint}?{query_string}"

        return await self._request_list(endpoint, privacy_mode=False)

    async def get_honeytoken(self, honeytoken_id: str, show_token: bool = True) -> dict[str, Any]:
        """Get details for a specific honeytoken.

        Args:
            honeytoken_id: ID of the honeytoken
            show_token: Whether to include token details

        Returns:
            Honeytoken data
        """
        honeytoken_id = str(UUID(honeytoken_id))
        logger.info(f"Getting honeytoken details for ID: {honeytoken_id}")
        return await self._request_get(
            f"/honeytokens/{honeytoken_id}?show_token={str(show_token).lower()}", privacy_mode=False
        )

    async def create_honeytoken(
        self, name: str, description: str = "", custom_tags: list[dict[str, str | None]] | None = None
    ) -> dict[str, Any]:
        """Create a new honeytoken in GitGuardian.

        Args:
            name: Name of the honeytoken
            description: Description of the honeytoken
            custom_tags: List of custom tags to apply to the honeytoken

        Returns:
            Honeytoken data
        """
        logger.info(f"Creating honeytoken: {name}")
        data = {
            "name": name,
            "description": description,
            "type": "AWS",
            "custom_tags": custom_tags or [],
        }

        # The generate_honeytoken tool handles a duplicate-name 400 and surfaces it to
        # the caller, so it should not be logged as a server fault.
        return await self._request_post("/honeytokens", json=data, expected_client_errors=[400], privacy_mode=False)
