import asyncio
import json
import logging
import os
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote_plus, unquote

import httpx

# Setup logger
logger = logging.getLogger(__name__)

# Global OAuth lock to prevent parallel OAuth flows
_oauth_lock = asyncio.Lock()


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

    VALID = "valid"
    INVALID = "invalid"
    IGNORED = "IGNORED"
    FIXED = "fixed"
    TRIGGERED = "TRIGGERED"
    ASSIGNED = "ASSIGNED"
    RESOLVED = "RESOLVED"


class IncidentValidity(str, Enum):
    """Enum for incident validity values."""

    VALID = "valid"
    INVALID = "invalid"
    FAILED_TO_CHECK = "failed_to_check"
    NO_CHECKER = "no_checker"
    UNKNOWN = "unknown"


class GitGuardianClient:
    """Client for interacting with the GitGuardian API."""

    # Define User-Agent as a class constant
    USER_AGENT = "GitGuardian-MCP-Server/1.0"

    def __init__(self, api_url: str | None = None):
        """Initialize the GitGuardian client.

        Args:
            api_url: GitGuardian URL, defaults to GITGUARDIAN_URL env var or https://dashboard.gitguardian.com
                    Supported formats:
                    - SaaS US: https://dashboard.gitguardian.com (default)
                    - SaaS EU: https://dashboard.eu1.gitguardian.com
                    - Self-hosted dashboard URL: https://dashboard.your-gitguardian.com
                    - Legacy API URLs are also supported for backward compatibility
        """
        logger.info("Initializing GitGuardian client")

        self._oauth_token = None
        self._token_info = None

        # Use provided API URL or get from environment with default fallback
        raw_api_url = api_url or os.environ.get("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")
        self.api_url = self._normalize_api_url(raw_api_url)
        logger.info(f"Using API URL: {self.api_url}")

        # Extract the base URL for dashboard (needed for OAuth)
        self.dashboard_url = self._get_dashboard_url()
        logger.info(f"Using dashboard URL: {self.dashboard_url}")

        logger.info("GitGuardian client initialized for OAuth authentication (token will be obtained via OAuth flow)")

    def _normalize_api_url(self, api_url: str) -> str:
        """
        Normalize the API URL for different GitGuardian instance types.

        Args:
            api_url: Raw API URL or base URL

        Returns:
            str: Normalized API URL
        """
        from urllib.parse import urlparse

        # Strip trailing slashes
        api_url = api_url.rstrip("/")

        try:
            parsed = urlparse(api_url)

            # Check if this is a SaaS URL (dashboard or API)
            if (
                "dashboard.gitguardian.com" in parsed.netloc
                or "dashboard.eu1.gitguardian.com" in parsed.netloc
                or "api.gitguardian.com" in parsed.netloc
                or "api.eu1.gitguardian.com" in parsed.netloc
            ):
                # Convert dashboard URLs to API URLs with /v1 suffix
                if "dashboard" in parsed.netloc:
                    api_netloc = parsed.netloc.replace("dashboard", "api")
                    normalized_url = f"{parsed.scheme}://{api_netloc}/v1"
                    logger.debug(f"Normalized SaaS dashboard URL: {api_url} -> {normalized_url}")
                    return normalized_url
                # For API URLs, ensure they have /v1 suffix
                elif not parsed.path.endswith("/v1"):
                    normalized_url = f"{api_url}/v1"
                    logger.debug(f"Normalized SaaS API URL: {api_url} -> {normalized_url}")
                    return normalized_url
                else:
                    logger.debug(f"SaaS API URL already has /v1: {api_url}")
                    return api_url

            # Check if this already has the API path structure
            path = parsed.path.lower()
            if path.endswith("/v1") or path.endswith("/exposed/v1"):
                logger.debug(f"API URL already has API path: {api_url}")
                return api_url

            # This appears to be a self-hosted base URL - append the API path
            if not path or path == "/" or not path.startswith("/exposed"):
                normalized_url = f"{api_url}/exposed/v1"
                logger.info(f"Normalized self-hosted base URL: {api_url} -> {normalized_url}")
                return normalized_url

            # If it has /exposed but no /v1, append /v1
            if path.startswith("/exposed") and not path.endswith("/v1"):
                normalized_url = f"{api_url}/v1"
                logger.info(f"Normalized self-hosted API URL: {api_url} -> {normalized_url}")
                return normalized_url

            # Default: return as-is
            logger.debug(f"Using API URL as provided: {api_url}")
            return api_url

        except Exception as e:
            logger.warning(f"Failed to parse API URL '{api_url}': {e}")
            logger.warning("Using API URL as provided")
            return api_url

    def _get_dashboard_url(self) -> str:
        """
        Get the GitGuardian dashboard URL by deriving it from the API URL.

        Returns:
            str: The GitGuardian dashboard URL
        """
        # Default GitGuardian dashboard URL
        default_dashboard_url = "https://dashboard.gitguardian.com"

        # If using SaaS API URLs, return the corresponding dashboard URL
        if self.api_url == "https://api.gitguardian.com/v1":
            logger.info(f"Using default dashboard URL: {default_dashboard_url}")
            return default_dashboard_url
        elif self.api_url == "https://api.eu1.gitguardian.com/v1":
            eu_dashboard_url = "https://dashboard.eu1.gitguardian.com"
            logger.info(f"Using EU dashboard URL: {eu_dashboard_url}")
            return eu_dashboard_url

        # For custom API URLs, derive the dashboard URL from the API URL
        try:
            # Parse the URL to get the components
            from urllib.parse import urlparse

            parsed_url = urlparse(self.api_url)

            # For local development (localhost or 127.0.0.1)
            if parsed_url.netloc.startswith("localhost") or parsed_url.netloc.startswith("127.0.0.1"):
                # For localhost, use the base URL without any path
                derived_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            else:
                # For custom domains, handle different patterns
                hostname = parsed_url.netloc

                # Remove 'api.' prefix if it exists (e.g., api.example.com -> example.com)
                # Special handling for GitGuardian EU instance
                if hostname == "api.eu1.gitguardian.com":
                    derived_url = f"{parsed_url.scheme}://dashboard.eu1.gitguardian.com"
                elif hostname.startswith("api."):
                    hostname = hostname[4:]  # Remove 'api.' prefix
                    derived_url = f"{parsed_url.scheme}://{hostname}"
                else:
                    # For self-hosted instances like dashboard.gitguardian.mycorp.local/exposed/v1
                    # Use the base URL without the path
                    derived_url = f"{parsed_url.scheme}://{hostname}"

            logger.info(f"Derived dashboard URL from API URL: {derived_url}")
            return derived_url
        except Exception as e:
            logger.warning(f"Failed to extract dashboard URL from API URL: {e}")
            return default_dashboard_url

    async def _ensure_oauth_token(self):
        """Ensure we have a valid OAuth token, initiating the OAuth flow if needed."""

        # Use a global lock to prevent parallel OAuth flows across all client instances
        async with _oauth_lock:
            # Double-check pattern: another thread might have completed OAuth while we waited for the lock
            if self._oauth_token is not None:
                logger.debug("OAuth token already available after waiting for lock")
                return

            logger.warning("Acquired OAuth lock, proceeding with authentication")
            logger.info(f"   Client API URL: {self.api_url}")
            logger.info(f"   Client Dashboard URL: {self.dashboard_url}")
            logger.info(f"   Client Server Name: {getattr(self, 'server_name', 'None')}")

            # Import here to avoid circular imports
            from .oauth import GitGuardianOAuthClient
            from .scopes import DEFAULT_SCOPES, validate_scopes

            default_scopes = ",".join(DEFAULT_SCOPES)
            # Check for both GITGUARDIAN_SCOPES and GITGUARDIAN_REQUESTED_SCOPES for backward compatibility
            scopes_str = os.environ.get("GITGUARDIAN_SCOPES") or os.environ.get(
                "GITGUARDIAN_REQUESTED_SCOPES", default_scopes
            )

            logger.info(f"   Using scopes: {scopes_str}")

            # Validate scopes to ensure only valid ones are used
            try:
                scopes = validate_scopes(scopes_str)
            except ValueError as e:
                logger.error(f"Invalid scopes in OAuth client: {e}")
                raise

            # Get custom login path if specified
            login_path = os.environ.get("GITGUARDIAN_LOGIN_PATH", "auth/login")

            # Get token name from environment or use default
            token_name = os.environ.get("GITGUARDIAN_TOKEN_NAME")

            # Create OAuth client and run the OAuth flow
            # The dashboard_url is used for OAuth, not the API URL
            # Use server name in token name if available with proper prefixes
            if not token_name and hasattr(self, "server_name") and self.server_name:
                # Use distinct token names for different MCP server types
                if "secops" in self.server_name.lower():
                    token_name = "SecOps MCP Token"
                elif "developer" in self.server_name.lower():
                    token_name = "Developer MCP Token"
                else:
                    token_name = f"{self.server_name} MCP Token"
            else:
                token_name = token_name or "MCP Token"

            logger.info(f"   Final token name: {token_name}")

            oauth_client = GitGuardianOAuthClient(
                api_url=self.api_url, dashboard_url=self.dashboard_url, scopes=scopes, token_name=token_name
            )

            try:
                # Check if we already have a valid token loaded
                if oauth_client.access_token and oauth_client.token_info:
                    logger.info("Using existing OAuth token")
                    self._oauth_token = oauth_client.access_token
                    self._token_info = oauth_client.token_info
                else:
                    # No valid token exists, start the OAuth flow
                    logger.info("Starting OAuth authentication flow...")
                    self._oauth_token = await oauth_client.oauth_process(login_path=login_path)
                    self._token_info = oauth_client.get_token_info()
                    logger.info("OAuth authentication successful")
            except Exception as e:
                logger.error(f"OAuth authentication failed: {e}")
                raise

    async def _clear_invalid_oauth_token(self):
        """Clear invalid OAuth token from memory and storage, forcing a new OAuth flow."""

        logger.info("Clearing invalid OAuth token from memory and storage")

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

        # Force new OAuth flow on next request
        await self._ensure_oauth_token()

    async def _request(
        self, method: str, endpoint: str, return_headers: bool = False, **kwargs
    ) -> Union[Dict[str, Any], Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Make a request to the GitGuardian API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            return_headers: Whether to return headers along with data
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response data as dictionary, or tuple of (data, headers) if return_headers=True

        Raises:
            requests.HTTPError: If the API returns an error
        """
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
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

        # Ensure we have a valid OAuth token
        await self._ensure_oauth_token()
        headers = {
            "Authorization": f"Token {self._oauth_token}",
            "Content-Type": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        logger.debug("Using OAuth token for authorization")

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
                async with httpx.AsyncClient() as client:
                    logger.debug(f"Sending {method} request to {url}")
                    response = await client.request(method, url, headers=headers, **kwargs)

                # Log detailed response information
                logger.debug(f"Response status code: {response.status_code}")
                logger.debug(f"Response headers: {dict(response.headers)}")

                # Log response content if present
                if response.content:
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
                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()

                if response.status_code == 204:  # No content
                    logger.debug("Received 204 No Content response")
                    return ({}, response.headers) if return_headers else {}

                try:
                    if not response.content or response.content.strip() == b"":
                        logger.debug("Received empty response content")
                        return ({}, response.headers) if return_headers else {}

                    data = response.json()

                    # Log success response summary
                    if isinstance(data, dict):
                        keys_str = ", ".join(list(data.keys())[:10])
                        logger.debug(f"Parsed JSON response with keys: {keys_str + ('...' if len(data) > 10 else '')}")
                    elif isinstance(data, list):
                        logger.debug(f"Parsed JSON response as list with {len(data)} items")
                    else:
                        logger.debug(f"Parsed JSON response as {type(data).__name__}")

                    # Handle empty array responses properly
                    if data == [] and return_headers:
                        logger.debug("Received empty array response")
                        return ([], response.headers)

                    return (data, response.headers) if return_headers else data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON response: {str(e)}")
                    logger.error(f"Raw response content: {response.content}")
                    raise

            except httpx.HTTPStatusError as e:
                # Special handling for 401 errors - OAuth token might be invalid/expired
                if e.response.status_code == 401 and self._oauth_token is not None:
                    logger.warning("Received 401 Unauthorized - OAuth token may be invalid or expired")

                    # Check if this is an "Invalid API key" error
                    try:
                        error_response = e.response.json()
                        if error_response.get("detail") == "Invalid API key.":
                            logger.info("Detected invalid OAuth token, attempting to refresh...")

                            # Clear the invalid token and remove it from storage
                            await self._clear_invalid_oauth_token()

                            # If this is the first retry attempt, try to get a new token
                            if retry_count == 0:
                                logger.info("Retrying request with fresh OAuth token...")
                                retry_count += 1
                                continue
                            else:
                                logger.error("Failed to authenticate even after token refresh")
                    except (json.JSONDecodeError, AttributeError):
                        # If we can't parse the error response, continue with normal error handling
                        pass

                logger.error(f"HTTP error occurred: {e.response.status_code} - {e.response.reason_phrase}")
                logger.error(f"Error response content: {e.response.text}")
                logger.error(f"Failed URL: {url}")
                raise
            except httpx.RequestError as e:
                logger.error(f"Request error occurred: {str(e)}")
                logger.error(f"Failed URL: {url}")
                raise
            except Exception as e:
                logger.exception(f"Unexpected error during API request: {str(e)}")
                logger.error(f"Failed URL: {url}")
                raise

            # If we got here with no exceptions, break out of the retry loop
            break

        # If we exhausted all retries and still have issues
        if retry_count > max_retries:
            logger.error(f"Exhausted all {max_retries} retries for {url}")

    def _extract_next_cursor(self, headers: Dict[str, str]) -> Optional[str]:
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

    async def paginate_all(self, endpoint: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Fetch all pages of results using cursor-based pagination.

        Args:
            endpoint: API endpoint path
            params: Query parameters to include in the request

        Returns:
            List of all items from all pages
        """
        params = params or {}
        all_items = []
        cursor = None

        logger.debug(f"Starting pagination for endpoint '{endpoint}' with initial params: {params}")

        while True:
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

            # Make request with headers
            data, headers = await self._request("GET", full_endpoint, return_headers=True)

            # Handle empty responses or empty arrays
            if not data:
                logger.debug("Received empty response data, stopping pagination")
                break

            # Log response size
            if isinstance(data, dict):
                result_count = len(data.get("results", [])) if "results" in data else "N/A"
                logger.debug(f"Received page with {result_count} results")
            elif isinstance(data, list):
                logger.debug(f"Received page with {len(data)} items")

            # Add items to our collection
            if isinstance(data, dict) and "results" in data:
                items = data.get("results", [])
            elif isinstance(data, dict) and "data" in data:
                items = data.get("data", [])
            elif isinstance(data, list):
                items = data
            else:
                items = []

            all_items.extend(items)
            logger.debug(f"Total items collected so far: {len(all_items)}")

            # Check for next cursor
            cursor = self._extract_next_cursor(headers)
            if cursor:
                logger.debug(f"Found next cursor: {cursor}")
            else:
                logger.debug("No next cursor found, pagination complete")
                break

        logger.info(f"Pagination complete for {endpoint}: collected {len(all_items)} total items")
        return all_items

    async def create_honeytoken(
        self, name: str, description: str = "", custom_tags: list | None = None
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
        data = {"name": name, "description": description, "type": "AWS", "custom_tags": custom_tags or []}

        return await self._request("POST", "/honeytokens", json=data)

    async def create_honeytoken_with_context(
        self,
        name: str,
        description: str = "",
        custom_tags: list | None = None,
        language: str | None = None,
        filename: str | None = None,
        project_extensions: str | None = None,
    ) -> dict[str, Any]:
        """Create a honeytoken with context for smart injection into code.

        Args:
            name: Name of the honeytoken
            description: Description of the honeytoken
            custom_tags: List of custom tags to apply to the honeytoken
            language: Programming language for context
            filename: Suggested filename
            project_extensions: Comma-separated string of file extensions in the project (e.g. 'py,yml,json')

        Returns:
            Honeytoken context data including content, filepath, and honeytoken_id
        """
        logger.info(f"Creating honeytoken with context: {name}")
        logger.debug(f"Context: language={language}, filename={filename}, extensions={project_extensions}")

        data = {"name": name, "description": description, "type": "AWS", "custom_tags": custom_tags or []}

        if language:
            data["language"] = language
        if filename:
            data["filename"] = filename
        if project_extensions:
            data["project_extensions"] = project_extensions

        return await self._request("POST", "/honeytokens/with-context", json=data)

    async def get_honeytoken(self, honeytoken_id: str, show_token: bool = True) -> dict[str, Any]:
        """Get details for a specific honeytoken.

        Args:
            honeytoken_id: ID of the honeytoken
            show_token: Whether to include token details

        Returns:
            Honeytoken data
        """
        logger.info(f"Getting honeytoken details for ID: {honeytoken_id}")
        return await self._request("GET", f"/honeytokens/{honeytoken_id}?show_token={str(show_token).lower()}")

    async def list_incidents(
        self,
        severity: IncidentSeverity | str | None = None,
        status: IncidentStatus | str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        assignee_email: str | None = None,
        assignee_id: str | None = None,
        validity: IncidentValidity | str | None = None,
        source_id: str | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
    ) -> dict[str, Any]:
        """List secrets incidents with optional filtering and cursor-based pagination.

        Args:
            severity: Filter by severity level (IncidentSeverity enum or string: critical, high, medium, low)
            status: Filter by status (IncidentStatus enum or string: IGNORED, TRIGGERED, ASSIGNED, RESOLVED)
            from_date: Filter incidents created after this date (ISO format: YYYY-MM-DD)
            to_date: Filter incidents created before this date (ISO format: YYYY-MM-DD)
            assignee_email: Filter incidents assigned to a specific email address
            assignee_id: Filter incidents assigned to a specific member ID
            validity: Filter by validity status (IncidentValidity enum or string: valid, invalid, failed_to_check, no_checker, unknown)
            source_id: Filter by specific source ID
            per_page: Number of results per page (default: 20)
            cursor: Pagination cursor (for cursor-based pagination)
            ordering: Sort field (Enum: date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at)
                     Default is ASC, DESC if preceded by '-'
            get_all: If True, fetch all results using cursor-based pagination

        Returns:
            List of incidents matching the criteria or an empty dict/list if no results
        """
        logger.info(
            f"Listing incidents with filters: severity={severity}, status={status}, assignee_email={assignee_email}, assignee_id={assignee_id}, validity={validity}, source_id={source_id}, ordering={ordering}"
        )

        # Build query parameters
        params = {}

        # Process severity parameter
        if severity:
            # If it's already an enum, use its value
            if isinstance(severity, IncidentSeverity):
                params["severity"] = severity.value
            # If it's a string, validate and convert
            elif isinstance(severity, str):
                try:
                    # Convert to enum to validate, then get the value
                    params["severity"] = IncidentSeverity(severity.lower()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentSeverity]
                    logger.warning(f"Invalid severity value: {severity}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid severity value: {severity}. Must be one of {valid_values}")
            else:
                raise TypeError("severity must be a string or IncidentSeverity enum")

        # Process status parameter
        if status:
            # If it's already an enum, use its value
            if isinstance(status, IncidentStatus):
                params["status"] = status.value
            # If it's a string, validate and convert
            elif isinstance(status, str):
                try:
                    # For status, we need to check if it's uppercase already
                    if status in [e.value for e in IncidentStatus]:
                        params["status"] = status
                    else:
                        # Try with uppercase for compatibility
                        params["status"] = IncidentStatus(status.upper()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentStatus]
                    logger.warning(f"Invalid status value: {status}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid status value: {status}. Must be one of {valid_values}")
            else:
                raise TypeError("status must be a string or IncidentStatus enum")

        # Process validity parameter
        if validity:
            # If it's already an enum, use its value
            if isinstance(validity, IncidentValidity):
                params["validity"] = validity.value
            # If it's a string, validate and convert
            elif isinstance(validity, str):
                try:
                    # Convert to enum to validate, then get the value
                    params["validity"] = IncidentValidity(validity.lower()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentValidity]
                    logger.warning(f"Invalid validity value: {validity}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid validity value: {validity}. Must be one of {valid_values}")
            else:
                raise TypeError("validity must be a string or IncidentValidity enum")

        # Add other parameters
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if assignee_email:
            params["assignee_email"] = assignee_email
        if assignee_id:
            params["assignee_id"] = assignee_id
        if source_id:
            params["source_id"] = source_id
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor
        if ordering:
            params["ordering"] = ordering

        endpoint = "/incidents/secrets"

        if get_all:
            return await self.paginate_all(endpoint, params)

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        if query_string:
            endpoint = f"{endpoint}?{query_string}"

        return await self._request("GET", endpoint)

    async def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Get detailed information about a specific incident.

        Args:
            incident_id: ID of the incident to retrieve

        Returns:
            Detailed incident data
        """
        logger.info(f"Getting details for incident ID: {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}")

    async def get_incidents(self, incident_ids: list[str]) -> list[dict[str, Any]]:
        """Get detailed information about multiple incidents in a single batch.

        This method optimizes API usage by fetching multiple incidents in parallel
        rather than making separate serial requests for each one.

        Args:
            incident_ids: List of incident IDs to retrieve

        Returns:
            List of detailed incident data objects
        """
        logger.info(f"Batch fetching {len(incident_ids)} incidents")

        # Use asyncio.gather to fetch incidents in parallel
        tasks = []
        for incident_id in incident_ids:
            tasks.append(self.get_incident(incident_id))

        # Wait for all requests to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out any exceptions that occurred
        incidents = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Failed to fetch incident {incident_ids[i]}: {str(result)}")
            else:
                incidents.append(result)

        return incidents

    async def update_incident(self, incident_id: str, status: str = None, custom_tags: list = None) -> dict[str, Any]:
        """Update a secret incident.

        Args:
            incident_id: ID of the incident
            status: New status (e.g., "IGNORED", "TRIGGERED", "ASSIGNED", "RESOLVED")
            custom_tags: List of custom tags to apply to the incident
                         Format: [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}]

        Returns:
            Updated incident data
        """
        logger.info(f"Updating incident {incident_id} with status={status}, custom_tags={custom_tags}")

        payload = {}
        if status:
            payload["status"] = status
        if custom_tags:
            payload["custom_tags"] = custom_tags

        if not payload:
            raise ValueError("At least one of status or custom_tags must be provided")

        return await self._request("PATCH", f"/incidents/secrets/{incident_id}", json=payload)

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
    ) -> dict[str, Any]:
        """List all honeytokens with optional filtering and cursor-based pagination.

        Args:
            status: Filter by status (ACTIVE or REVOKED)
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
            return await self.paginate_all(endpoint, params)

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        if query_string:
            endpoint = f"{endpoint}?{query_string}"

        return await self._request("GET", endpoint)

    async def revoke_honeytoken(self, honeytoken_id: str) -> dict[str, Any]:
        """Revoke a honeytoken.

        Args:
            honeytoken_id: ID of the honeytoken

        Returns:
            Result of the operation
        """
        logger.info(f"Revoking honeytoken: {honeytoken_id}")
        return await self._request("POST", f"/honeytokens/{honeytoken_id}/revoke")

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
            return self._token_info

        # Otherwise fetch from the API
        return await self._request("GET", "/api_tokens/self")

    async def list_api_tokens(self) -> dict[str, Any]:
        """List all API tokens for the account.

        Returns:
            List of API tokens
        """
        logger.info("Listing API tokens")
        return await self._request("GET", "/api_tokens")

    async def revoke_current_token(self) -> dict[str, Any]:
        """Revoke the current API token.

        This endpoint revokes the API token being used for the current request,
        effectively invalidating it immediately.

        Returns:
            Dictionary containing the revocation status
        """
        logger.info("Revoking current API token")
        return await self._request("DELETE", "/api_tokens/self")

    async def multiple_scan(self, documents: list[dict[str, str]]) -> dict[str, Any]:
        """Scan multiple documents for secrets and policy breaks.

        Args:
            documents: List of documents to scan, each with 'content' and optional 'filename'
                      Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]

        Returns:
            Scan results for all documents
        """
        logger.info(f"Scanning {len(documents)} documents for secrets")

        # Validate input format
        for i, doc in enumerate(documents):
            if "document" not in doc:
                raise ValueError(f"Document at index {i} is missing required 'document' field")

        return await self._request("POST", "/multiscan", json=documents)

    async def get_audit_logs(self, limit: int = 100) -> dict[str, Any]:
        """Get audit logs for the organization.

        Args:
            limit: Maximum number of logs to return

        Returns:
            List of audit log entries
        """
        logger.info(f"Getting audit logs (limit: {limit})")
        return await self._request("GET", f"/audit_logs?per_page={limit}")

    async def list_custom_tags(self) -> dict[str, Any]:
        """List all custom tags.

        Returns:
            List of custom tags
        """
        logger.info("Listing custom tags")
        return await self._request("GET", "/custom-tags")

    async def create_custom_tag(self, key: str, value: str) -> dict[str, Any]:
        """Create a custom tag.

        Args:
            key: Tag key
            value: Tag value

        Returns:
            Created custom tag data
        """
        logger.info(f"Creating custom tag with key={key}, value={value}")
        return await self._request("POST", "/custom-tags", json={"key": key, "value": value})

    async def update_custom_tag(self, tag_id: str, key: str = None, value: str = None) -> dict[str, Any]:
        """Update a custom tag.

        Args:
            tag_id: ID of the custom tag to update
            key: New tag key (optional)
            value: New tag value (optional)

        Returns:
            Updated custom tag data
        """
        logger.info(f"Updating custom tag {tag_id} with key={key}, value={value}")

        payload = {}
        if key is not None:
            payload["key"] = key
        if value is not None:
            payload["value"] = value

        if not payload:
            raise ValueError("At least one of key or value must be provided")

        return await self._request("PATCH", f"/custom-tags/{tag_id}", json=payload)

    async def delete_custom_tag(self, tag_id: str) -> dict[str, Any]:
        """Delete a custom tag.

        Args:
            tag_id: ID of the custom tag to delete

        Returns:
            Empty dict on success
        """
        logger.info(f"Deleting custom tag {tag_id}")
        return await self._request("DELETE", f"/custom-tags/{tag_id}")

    async def get_custom_tag(self, tag_id: str) -> dict[str, Any]:
        """Get a specific custom tag by ID.

        Args:
            tag_id: ID of the custom tag to retrieve

        Returns:
            Custom tag data
        """
        logger.info(f"Getting custom tag {tag_id}")
        return await self._request("GET", f"/custom-tags/{tag_id}")

    # Secret Incident management endpoints
    async def assign_incident(self, incident_id: str, assignee_id: str) -> dict[str, Any]:
        """Assign a secret incident to a member.

        Args:
            incident_id: ID of the secret incident
            assignee_id: ID of the member to assign the incident to

        Returns:
            Status of the operation
        """
        logger.info(f"Assigning incident {incident_id} to member {assignee_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/assign", json={"member_id": assignee_id})

    async def unassign_incident(self, incident_id: str) -> dict[str, Any]:
        """Unassign a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Unassigning incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/unassign")

    async def resolve_incident(self, incident_id: str) -> dict[str, Any]:
        """Resolve a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Resolving incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/resolve")

    async def ignore_incident(self, incident_id: str, ignore_reason: str = None) -> dict[str, Any]:
        """Ignore a secret incident.

        Args:
            incident_id: ID of the secret incident
            ignore_reason: Reason for ignoring (test_credential, false_positive, etc.)

        Returns:
            Status of the operation
        """
        logger.info(f"Ignoring incident {incident_id} with reason: {ignore_reason}")
        payload = {}
        if ignore_reason:
            payload["ignore_reason"] = ignore_reason
        return await self._request("POST", f"/incidents/secrets/{incident_id}/ignore", json=payload)

    async def reopen_incident(self, incident_id: str) -> dict[str, Any]:
        """Reopen a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Reopening incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/reopen")

    async def share_incident(self, incident_id: str) -> dict[str, Any]:
        """Share a secret incident (create a share link).

        Args:
            incident_id: ID of the secret incident

        Returns:
            Share information including share URL
        """
        logger.info(f"Creating share link for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/share")

    async def unshare_incident(self, incident_id: str) -> dict[str, Any]:
        """Unshare a secret incident (remove share link).

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Removing share link for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/unshare")

    async def grant_incident_access(self, incident_id: str, member_id: str = None) -> dict[str, Any]:
        """Grant access to a secret incident to a member.

        Args:
            incident_id: ID of the secret incident
            member_id: ID of the member to grant access to

        Returns:
            Status of the operation
        """
        if not member_id:
            raise ValueError("member_id must be provided")

        payload = {"member_id": member_id}
        logger.info(f"Granting access to incident {incident_id} for member {member_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/grant_access", json=payload)

    async def revoke_incident_access(self, incident_id: str, member_id: str) -> dict[str, Any]:
        """Revoke access to a secret incident from a member.

        Args:
            incident_id: ID of the secret incident
            member_id: ID of the member to revoke access from

        Returns:
            Status of the operation
        """
        payload = {"member_id": member_id}
        logger.info(f"Revoking access to incident {incident_id} from member {member_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/revoke_access", json=payload)

    async def list_incident_members(self, incident_id: str) -> dict[str, Any]:
        """List members having access to a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of members with access to the incident
        """
        logger.info(f"Listing members with access to incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/members")

    async def get_incident_impacted_perimeter(self, incident_id: str) -> dict[str, Any]:
        """Retrieve the impacted perimeter of a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Information about the impacted perimeter
        """
        logger.info(f"Getting impacted perimeter for incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/perimeter")

    # Secret Incident Notes management
    async def list_incident_notes(self, incident_id: str) -> dict[str, Any]:
        """List notes on a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of notes attached to the incident
        """
        logger.info(f"Listing notes for incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/notes")

    async def create_incident_note(self, incident_id: str, content: str) -> dict[str, Any]:
        """Create a note on a secret incident.

        Args:
            incident_id: ID of the secret incident
            content: Content of the note

        Returns:
            Created note details
        """
        logger.info(f"Creating note for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/notes", json={"content": content})

    async def update_incident_note(self, incident_id: str, note_id: str, content: str) -> dict[str, Any]:
        """Update a note on a secret incident.

        Args:
            incident_id: ID of the secret incident
            note_id: ID of the note to update
            content: New content for the note

        Returns:
            Updated note details
        """
        logger.info(f"Updating note {note_id} for incident {incident_id}")
        return await self._request(
            "PATCH", f"/incidents/secrets/{incident_id}/notes/{note_id}", json={"content": content}
        )

    async def delete_incident_note(self, incident_id: str, note_id: str) -> dict[str, Any]:
        """Delete a note from a secret incident.

        Args:
            incident_id: ID of the secret incident
            note_id: ID of the note to delete

        Returns:
            Status of the operation
        """
        logger.info(f"Deleting note {note_id} from incident {incident_id}")
        return await self._request("DELETE", f"/incidents/secrets/{incident_id}/notes/{note_id}")

    # Secret Occurrences management
    async def list_secret_occurrences(self, incident_id: str) -> dict[str, Any]:
        """List secret occurrences for an incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of secret occurrences
        """
        logger.info(f"Listing secret occurrences for incident ID: {incident_id}")
        return await self._request("GET", f"/incidents/{incident_id}/secret-occurrences")

    async def list_occurrences(
        self,
        from_date: str | None = None,
        to_date: str | None = None,
        source_name: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
        presence: str | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
    ) -> dict[str, Any] | list[dict[str, Any]]:
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
            params["per_page"] = per_page
        if cursor:
            params["cursor"] = cursor
        if ordering:
            params["ordering"] = ordering

        # If get_all is True, use paginate_all to get all results
        if get_all:
            logger.info("Getting all occurrences using cursor-based pagination")
            return await self.paginate_all("occurrences/secrets", params)

        # Otherwise, get a single page
        logger.info(f"Getting occurrences with params: {params}")
        return await self._request("GET", "occurrences/secrets", params=params)

    async def list_source_incidents(self, source_id: str, **kwargs) -> dict[str, Any]:
        """List secret incidents of a source.

        Args:
            source_id: ID of the source
            **kwargs: Additional filtering parameters

        Returns:
            List of incidents for the source
        """
        logger.info(f"Listing incidents for source {source_id}")

        # Convert kwargs to query parameters
        query_params = "&".join([f"{k}={v}" for k, v in kwargs.items()])
        endpoint = f"/sources/{source_id}/incidents/secrets"
        if query_params:
            endpoint = f"{endpoint}?{query_params}"

        return await self._request("GET", endpoint)

    async def list_member_incidents(self, member_id: str, **kwargs) -> dict[str, Any]:
        """List secret incidents a member has access to.

        Args:
            member_id: ID of the member
            **kwargs: Additional filtering parameters

        Returns:
            List of incidents the member has access to
        """
        logger.info(f"Listing incidents for member {member_id}")

        # Convert kwargs to query parameters
        query_params = "&".join([f"{k}={v}" for k, v in kwargs.items()])
        endpoint = f"/members/{member_id}/secret-incidents"
        if query_params:
            endpoint = f"{endpoint}?{query_params}"

        return await self._request("GET", endpoint)

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
        per_page: int = 20,
        cursor: str | None = None,
        get_all: bool = False,
    ) -> dict[str, Any] | list[dict[str, Any]]:
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
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor

        endpoint = "/sources"

        if get_all:
            return await self.paginate_all(endpoint, params)

        return await self._request("GET", endpoint, params=params)

    async def get_source_by_name(self, source_name: str, return_all_on_no_match: bool = False) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Get a source by its name (repository name).

        Args:
            source_name: Name of the source/repository to find
            return_all_on_no_match: If True and no exact match is found, return all search results
                                   instead of None. This allows the caller to choose from candidates.

        Returns:
            - If exact match found: Single source object (dict)
            - If no exact match and return_all_on_no_match=True: List of all matching sources
            - If no exact match and return_all_on_no_match=False: None
        """
        logger.info(f"Looking up source ID for repository name: {source_name}")

        # Fetch all sources matching the search term
        params = {
            "search": source_name,
            "per_page": 50,  # Get more results for better matching
        }

        try:
            # Get sources matching the search term
            response = await self._request("GET", "/sources", params=params)

            # Extract sources from the response
            if isinstance(response, dict) and "data" in response:
                sources = response["data"]
            else:
                sources = response

            if not sources:
                logger.warning(f"No sources found matching search term: {source_name}")
                return None

            # Try to find exact match by name
            for source in sources:
                # Check for both the full name (org/repo) and just the repo name
                if source.get("name") == source_name or source.get("full_name") == source_name:
                    logger.info(f"Found exact match - source ID {source.get('id')} for {source_name}")
                    return source

            # No exact match found
            logger.info(f"No exact match found for '{source_name}'. Found {len(sources)} potential matches.")

            if return_all_on_no_match:
                logger.info(f"Returning all {len(sources)} candidates for manual selection")
                return sources
            else:
                logger.warning(f"No exact match found for: {source_name}")
                return None

        except Exception as e:
            logger.error(f"Error getting source by name: {str(e)}")
            return None

    async def list_repo_incidents_directly(
        self,
        repository_name: str,
        from_date: str | None = None,
        to_date: str | None = None,
        presence: str | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
        mine: bool = True,
    ) -> dict[str, Any]:
        """List incidents for a repository in a single API call.

        This method offers better performance than the two-step process of
        getting occurrences first and then incidents separately.

        Args:
            repository_name: Name of the repository
            from_date: Filter incidents created after this date (ISO format)
            to_date: Filter incidents created before this date (ISO format)
            presence: Filter by presence status
            tags: Filter by tags
            exclude_tags: Exclude incidents with these tag names
            per_page: Number of results per page
            cursor: Pagination cursor
            ordering: Sort field
            get_all: Whether to fetch all results using pagination
            mine: If True, only show incidents assigned to the current user

        Returns:
            Dictionary containing the incidents and pagination info
        """
        logger.info(f"Directly listing incidents for repository: {repository_name}")

        # First get the source ID for the repository name
        source = await self.get_source_by_name(repository_name)

        if not source:
            return {
                "repository_info": {"name": repository_name},
                "incidents": [],
                "message": f"Repository '{repository_name}' not found or not accessible",
            }

        source_id = source.get("id")
        logger.info(f"Found source ID {source_id} for repository {repository_name}")

        # Prepare parameters for the API call
        params = {}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if presence:
            params["presence"] = presence
        if tags:
            params["tags"] = ",".join(tags) if isinstance(tags, list) else tags
        if exclude_tags:
            params["exclude_tags"] = ",".join(exclude_tags) if isinstance(exclude_tags, list) else exclude_tags
        if per_page:
            params["per_page"] = per_page
        if cursor:
            params["cursor"] = cursor
        if ordering:
            params["ordering"] = ordering
        if mine:
            params["assigned_to_me"] = "true"

        try:
            if get_all:
                # Use pagination to get all results
                incidents_result = await self.paginate_all(f"/sources/{source_id}/incidents/secrets", params)
                if isinstance(incidents_result, list):
                    return {
                        "repository_info": source,
                        "incidents": incidents_result,
                        "total_count": len(incidents_result),
                    }
                # If it's already a dict with structure, return it
                return incidents_result

            # Get a single page of results
            incidents_result = await self.list_source_incidents(source_id, **params)

            # Make sure incidents_result is a dictionary before using .get()
            if isinstance(incidents_result, dict):
                return {
                    "repository_info": source,
                    "incidents": incidents_result.get("data", []),
                    "next_cursor": incidents_result.get("next_cursor"),
                    "total_count": incidents_result.get("total_count", 0),
                }
            elif isinstance(incidents_result, list):
                return {
                    "repository_info": source,
                    "incidents": incidents_result,
                    "total_count": len(incidents_result),
                }
            else:
                return {
                    "repository_info": source,
                    "incidents": [],
                    "total_count": 0,
                    "error": "Unexpected response format from API",
                }

        except Exception as e:
            logger.error(f"Error listing repository incidents directly: {str(e)}")
            return {"error": f"Failed to list repository incidents: {str(e)}"}
