"""Simplified GitGuardian MCP Server with scope-based tool filtering."""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from enum import Enum
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ValidationError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware
from fastmcp.tools import Tool

from gg_api_core.client import (
    GitGuardianClient,
    get_personal_access_token_from_env,
    is_oauth_enabled,
)
from gg_api_core.utils import get_client

# Configure logger
logger = logging.getLogger(__name__)


class AuthenticationMode(Enum):
    """Available authentication modes for the MCP server."""

    # Trigger a local OAuth flow to obtain a Personal Access Token
    LOCAL_OAUTH_FLOW = "LOCAL_OAUTH_FLOW"
    # Read Access Token from environment variable
    PERSONAL_ACCESS_TOKEN_ENV_VAR = "PERSONAL_ACCESS_TOKEN_ENV_VAR"
    # Use per-request Authorization header
    AUTHORIZATION_HEADER = "AUTHORIZATION_HEADER"


class CachedTokenInfoMixin:
    """Mixin for MCP servers that are mono-tenant (only one authenticated identity from startup to close of the server)

    Note: This mixin expects to be used with AbstractGitGuardianFastMCP which provides
    _fetch_token_scopes_from_api() and _fetch_token_info_from_api() methods.
    """

    _token_scopes: set[str] = set()
    _token_info: dict[str, Any] | None = None

    def __init__(self, *args, **kwargs):
        # Add a custom lifespan contextmanager that fetches and cache token scopes and infos
        original_lifespan = kwargs.get("lifespan")
        kwargs["lifespan"] = self._create_token_scope_lifespan(original_lifespan)
        # Call parent __init__ in the MRO chain
        super().__init__(*args, **kwargs)

    def clear_cache(self) -> None:
        """Clear cached token information and scopes."""
        self._token_scopes = set()
        self._token_info = None

    def _create_token_scope_lifespan(self, original_lifespan=None):
        """Create a lifespan context manager that fetches token scopes."""

        @asynccontextmanager
        async def token_scope_lifespan(fastmcp) -> AsyncIterator[dict]:
            """Lifespan context manager that fetches token scopes on startup."""
            context_result = {}

            # Call the original lifespan if provided
            if original_lifespan:
                logger.debug("Calling original lifespan")
                async with original_lifespan(fastmcp) as original_context:
                    context_result = original_context

            # Cache scopes at startup (single token throughout lifespan).
            # Use a timeout to avoid blocking MCP server startup indefinitely
            # (e.g., when an expired token triggers an interactive OAuth re-auth flow).
            try:
                self._token_scopes = await asyncio.wait_for(
                    self._fetch_token_scopes_from_api(),  # type: ignore[attr-defined]
                    timeout=30,
                )
                logger.debug(f"Retrieved token scopes: {self._token_scopes}")
            except asyncio.TimeoutError:
                logger.warning(
                    "Timed out fetching token scopes during startup (30s). "
                    "This may happen when an expired token triggers re-authentication. "
                    "Tools requiring scopes will not be available until scopes are fetched."
                )
            except Exception as e:
                logger.warning(f"Failed to fetch token scopes during startup: {str(e)}")
                logger.warning("Some tools may not be available if scope detection fails")
                # Continue with startup even if scope fetching fails

            # Yield the context (from original lifespan if provided)
            yield context_result

        return token_scope_lifespan

    async def get_token_info(self) -> dict[str, Any]:
        """Return the token info dictionary."""
        if self._token_info is not None:
            return self._token_info

        self._token_info = await self._fetch_token_info_from_api()  # type: ignore[attr-defined]
        return self._token_info


class ScopeFilteringMiddleware(Middleware):
    """Middleware to filter tools based on token scopes."""

    def __init__(self, mcp_server: "AbstractGitGuardianFastMCP"):
        self._mcp_server = mcp_server

    async def on_list_tools(
        self,
        context,
        call_next,
    ) -> Sequence[Tool]:
        """Filter tools based on the user's API token scopes."""
        # Get all tools from the next middleware/handler
        all_tools = await call_next(context)

        # Filter tools by scopes
        scopes = await self._mcp_server.get_scopes()
        filtered_tools: list[Tool] = []
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._mcp_server._tool_scopes.get(tool_name, set())

            if not required_scopes or required_scopes.issubset(scopes):
                filtered_tools.append(tool)
            else:
                missing_scopes = required_scopes - scopes
                logger.info(f"Removing tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        return filtered_tools


class AbstractGitGuardianFastMCP(FastMCP, ABC):
    """Abstract base class for GitGuardian MCP servers with scope-based tool filtering.

    This class contains the core functionality shared by all authentication modes.
    Subclasses implement authentication-specific behavior.
    """

    authentication_mode: AuthenticationMode

    def __init__(self, *args, default_scopes: list[str] | None = None, **kwargs):
        """
        Initialize the GitGuardian MCP server.
        """
        # Initialize the parent class FIRST (required for FastMCP attributes)
        super().__init__(*args, **kwargs)

        # Map each tool to its required scopes (instance attribute)
        self._tool_scopes: dict[str, set[str]] = {}

        self.add_middleware(ScopeFilteringMiddleware(self))

    def clear_cache(self) -> None:
        """Clear cached data. Override in subclasses that cache."""
        pass

    @abstractmethod
    def get_personal_access_token(self) -> str | None:
        """Get the personal access token for the current request"""
        pass

    @abstractmethod
    async def get_token_info(self) -> dict[str, Any]:
        """Return the token info dictionary."""
        pass

    def _get_caller_user_agent(self) -> str | None:
        """Try to extract User-Agent from the incoming MCP request headers.

        Returns None if not available (e.g. stdio transport).
        """
        try:
            headers = get_http_headers(include={"user-agent"})
            return headers.get("user-agent") if headers else None
        except Exception:
            logger.exception("Error when trying to extract User-Agent from headers")
            return None

    async def get_client(self) -> GitGuardianClient:
        return await get_client(
            personal_access_token=self.get_personal_access_token(),
            user_agent=self._get_caller_user_agent(),
        )

    async def revoke_current_token(self) -> dict[str, Any]:
        """Revoke the current API token via GitGuardian API."""
        try:
            logger.debug("Revoking current API token")
            # Call the DELETE /api_tokens/self endpoint
            client = await self.get_client()
            result = await client.revoke_current_token()
            logger.debug("API token revoked")
            return result
        except Exception as e:
            logger.exception(f"Error revoking current API token: {str(e)}")
            raise

    def tool(self, *args, required_scopes: list[str] | None = None, **kwargs):
        """
        Extended tool decorator that tracks required scopes.

        Usage:
            @mcp.tool(required_scopes=["scan"])
            def my_tool():
                pass

            # Or with function passed directly
            mcp.tool(my_func, required_scopes=["scan"])
        """
        # In FastMCP v3, @mcp.tool() returns the original function, not a Tool object.
        # Derive the tool name from the explicit kwarg or from the function itself.

        if args and callable(args[0]):
            # Direct call: mcp.tool(fn, required_scopes=...)
            fn = args[0]
            name = kwargs.get("name", fn.__name__)
            result = super().tool(*args, **kwargs)
            if required_scopes:
                self._tool_scopes[name] = set(required_scopes)
            return result
        else:
            # Decorator usage: @mcp.tool(required_scopes=...)
            parent_decorator = super().tool(*args, **kwargs)

            def wrapper(fn):
                name = kwargs.get("name", fn.__name__)
                result = parent_decorator(fn)
                if required_scopes:
                    self._tool_scopes[name] = set(required_scopes)
                return result

            return wrapper

    async def _fetch_token_scopes_from_api(self, client=None) -> set[str]:
        """Fetch token scopes from the GitGuardian API.

        Args:
            client: Optional GitGuardianClient to use. If None, uses self.client.
                    In HTTP mode, a per-request client should be passed.

        Returns:
            set: The fetched scopes, or empty set on error
        """
        client_to_use = await self.get_client()

        # Fetch the complete token info
        logger.debug("Attempting to fetch token scopes from GitGuardian API")
        token_info = await client_to_use.get_current_token_info()

        # Extract scopes
        scopes = token_info.get("scopes", [])
        logger.debug(f"Retrieved token scopes: {scopes}")

        return set(scopes)

    async def _fetch_token_info_from_api(self) -> dict[str, Any]:
        client = await self.get_client()
        return await client.get_current_token_info()

    async def get_scopes(self) -> set[str]:
        cached_scopes: set[str] | None = getattr(self, "_token_scopes", None)
        if cached_scopes:
            logger.debug("reading from cached scopes")
            return cached_scopes

        scopes = await self._fetch_token_scopes_from_api()
        logger.debug(f"scopes: {scopes}")
        return scopes


# Common MCP tools for user information and token management
def register_common_tools(mcp_instance: AbstractGitGuardianFastMCP):
    """Register common MCP tools for user information and token management."""

    logger.debug("Registering common MCP tools...")

    @mcp_instance.tool(
        name="get_authenticated_user_info",
        description="Get comprehensive information about the authenticated user and current API token including scopes and authentication method",
    )
    async def get_authenticated_user_info() -> dict[str, Any]:
        """Get information about the authenticated user and current API token."""
        logger.debug("Getting authenticated user information")

        token_info = await mcp_instance.get_token_info()
        scopes = await mcp_instance.get_scopes()
        return {
            "token_info": token_info,
            "authentication_mode": mcp_instance.authentication_mode.value,
            "available_scopes": list(scopes),
        }

    @mcp_instance.tool(
        name="revoke_current_token",
        description="Revoke the current API token and clean up stored credentials",
    )
    async def revoke_current_token() -> dict[str, Any]:
        """Revoke the current API token and clean up stored credentials."""
        logger.debug("Starting token revocation process")

        try:
            await mcp_instance.revoke_current_token()
            logger.debug("Token revoked via API")

            # Clear cached data
            mcp_instance.clear_cache()

            return {
                "success": True,
                "message": "Token revoked and credentials cleaned up",
                "authentication_method": mcp_instance.authentication_mode.value,
            }

        except Exception as e:
            logger.exception(f"Error during token revocation: {str(e)}")
            return {"success": False, "error": f"Failed to revoke token: {str(e)}"}

    logger.debug("Registered common MCP tools")


# Concrete implementations for different authentication modes


class GitGuardianLocalOAuthMCP(CachedTokenInfoMixin, AbstractGitGuardianFastMCP):
    """GitGuardian MCP server using local OAuth flow (stdio mode)."""

    authentication_mode = AuthenticationMode.LOCAL_OAUTH_FLOW

    def get_personal_access_token(self) -> str | None:
        # It will be actually provided within the client by the OAuth flow, or from the filesystem storage
        return None


class GitGuardianPATEnvMCP(CachedTokenInfoMixin, AbstractGitGuardianFastMCP):
    """GitGuardian MCP server using Personal Access Token from environment variable."""

    authentication_mode = AuthenticationMode.PERSONAL_ACCESS_TOKEN_ENV_VAR

    def __init__(self, *args, personal_access_token: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.personal_access_token = personal_access_token

    def get_personal_access_token(self) -> str:
        return self.personal_access_token


class GitGuardianAuthorizationHeaderMCP(AbstractGitGuardianFastMCP):
    """GitGuardian MCP server using per-request Authorization header (HTTP/SSE mode)."""

    authentication_mode = AuthenticationMode.AUTHORIZATION_HEADER

    def get_personal_access_token(self) -> str:
        headers = get_http_headers(include={"authorization"})
        if not headers:
            raise ValidationError("No HTTP headers available - Authorization header required")

        auth_header = headers.get("authorization")
        if not auth_header:
            raise ValidationError("Missing Authorization header")

        token = self._default_extract_token(auth_header)
        if not token:
            raise ValidationError("Invalid Authorization header format")

        return token

    @staticmethod
    def _default_extract_token(auth_header: str) -> str | None:
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

    async def get_token_info(self) -> dict[str, Any]:
        return await self._fetch_token_info_from_api()


def get_mcp_server(*args, **kwargs) -> AbstractGitGuardianFastMCP:
    if is_oauth_enabled():
        return GitGuardianLocalOAuthMCP(*args, **kwargs)

    if personal_access_token := get_personal_access_token_from_env():
        return GitGuardianPATEnvMCP(*args, personal_access_token=personal_access_token, **kwargs)

    return GitGuardianAuthorizationHeaderMCP(*args, **kwargs)
