import logging

from fastmcp.exceptions import ValidationError
from fastmcp.server.dependencies import get_http_headers

from .client import GitGuardianClient, acquire_single_tenant_token
from .settings import get_settings

# Setup logger
logger = logging.getLogger(__name__)


# Singleton client instance - only used in single-tenant mode
_client_singleton: GitGuardianClient | None = None


async def get_client(personal_access_token: str | None = None, user_agent: str | None = None) -> GitGuardianClient:
    """Get GitGuardian client for the current context.

    **Single-tenant is the DEFAULT** (local stdio usage).
    Multi-tenant requires explicit opt-in via MULTI_TENANCY_ENABLED=true.

    Authentication modes (in order of precedence):

    1. **Explicit PAT provided** → Use it directly, no caching
       - For programmatic usage where caller manages the token

    2. **Multi-tenant mode** (MULTI_TENANCY_ENABLED=true) → Per-request from headers
       - Requires MCP_PORT to be set
       - Token MUST come from Authorization header
       - No caching (new client per request)

    3. **Single-tenant mode** (DEFAULT) → Singleton pattern, token sources:
       a. GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var
       b. Stored OAuth token from previous authentication flow
       c. ENABLE_LOCAL_OAUTH=true → trigger interactive OAuth flow
       - Same identity for entire server lifetime

    Args:
        personal_access_token: Optional PAT for explicit authentication.
        user_agent: Optional explicit User-Agent string. The default is built
            from live MCP context when each outgoing API request is sent.

    Returns:
        GitGuardianClient: Client instance configured with appropriate authentication

    Raises:
        ValidationError: In multi-tenant mode, if MCP_PORT not set or Authorization header missing
        RuntimeError: In single-tenant mode, if no token source is available
    """
    # 1. Explicit PAT provided - caller manages the token (no caching, no automatic refresh)
    if personal_access_token:
        return GitGuardianClient(personal_access_token=personal_access_token, user_agent=user_agent)

    # 2. Multi-tenant mode (explicit opt-in via MULTI_TENANCY_ENABLED=true) : no caching, no automatic refresh
    settings = get_settings()
    if settings.is_multi_tenant:
        if not settings.mcp_port:
            raise ValidationError(
                "MULTI_TENANCY_ENABLED=true requires MCP_PORT to be set. "
                "Multi-tenant mode only works with HTTP transport."
            )
        token = _get_token_from_request_headers()
        return GitGuardianClient(personal_access_token=token, user_agent=user_agent)

    # 3. Single-tenant mode (DEFAULT) - use singleton pattern to cache the PAT
    global _client_singleton
    if _client_singleton is not None:
        return _client_singleton

    # Acquire token for single-tenant mode
    token = await acquire_single_tenant_token()
    # Enable token refresh for self-healing on 401 errors
    _client_singleton = GitGuardianClient(
        personal_access_token=token,
        allow_token_refresh=True,
        user_agent=user_agent,
    )
    return _client_singleton


def _get_token_from_request_headers() -> str:
    """Extract personal access token from HTTP request headers.

    Used in multi-tenant mode where each request must provide its own token.

    Returns:
        The extracted token

    Raises:
        ValidationError: If headers are missing or invalid
    """
    try:
        headers = get_http_headers(include={"authorization"})
    except Exception as e:
        raise ValidationError(
            f"Failed to retrieve HTTP headers in multi-tenant mode. "
            f"Ensure the HTTP transport is properly configured. Error: {e}"
        )

    if not headers:
        raise ValidationError(
            "No HTTP headers available in multi-tenant mode. "
            "Requests must include Authorization header with a valid PAT."
        )

    auth_header = headers.get("authorization")
    if not auth_header:
        raise ValidationError(
            "Missing Authorization header in multi-tenant mode. "
            "Each request must include 'Authorization: Bearer <PAT>' header."
        )

    token = _extract_token_from_auth_header(auth_header)
    if not token:
        raise ValidationError("Invalid Authorization header format. Expected: 'Bearer <token>' or 'Token <token>'")

    return token


def _extract_token_from_auth_header(auth_header: str) -> str | None:
    """Extract token from Authorization header.

    Supports formats:
    - Bearer <token>
    - Token <token>
    - <token> (raw)
    """
    auth_header = auth_header.strip()

    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    if auth_header.lower().startswith("token "):
        return auth_header[6:].strip()

    if auth_header:
        return auth_header

    return None
