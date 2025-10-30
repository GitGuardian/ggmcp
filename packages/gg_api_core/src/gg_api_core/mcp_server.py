"""Simplified GitGuardian MCP Server with scope-based tool filtering."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import MiddlewareContext
from mcp.types import AnyFunction
from mcp.types import Tool as MCPTool

from gg_api_core.tools import manage_incident
from gg_api_core.utils import get_client

# Configure logger
logger = logging.getLogger(__name__)


class GitGuardianFastMCP(FastMCP):
    """FastMCP extension with GitGuardian API scope-based tool filtering."""

    def __init__(self, *args, **kwargs):
        # Extract our custom parameters before passing to parent
        default_scopes = kwargs.pop("default_scopes", None)

        # Add a custom lifespan that fetches token scopes
        original_lifespan = kwargs.get("lifespan")
        kwargs["lifespan"] = self._create_token_scope_lifespan(original_lifespan)

        # Initialize the parent class first
        super().__init__(*args, **kwargs)

        # Map each tool to its required scopes
        self._tool_scopes: dict[str, set[str]] = {}
        # Storage for token scopes
        self._token_scopes: set[str] = set()
        # Store the complete token info
        self._token_info = None

        # Store the authentication method (OAuth only)
        self._auth_method = "web"  # Always use OAuth authentication
        logger.debug(f"Using authentication method: {self._auth_method}")

        # Set default scopes for demonstration or development
        if default_scopes:
            self._token_scopes = set(default_scopes)
            logger.debug(f"Using default scopes: {self._token_scopes}")

        # Register scope filtering middleware
        self.add_middleware(self._scope_filtering_middleware)

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

            # Fetch token scopes at server startup - but don't crash if it fails
            try:
                logger.debug("Fetching token scopes during server startup")
                await self._fetch_token_scopes()
                logger.debug(f"Retrieved token scopes: {self._token_scopes}")
            except Exception as e:
                logger.warning(f"Failed to fetch token scopes during startup: {str(e)}")
                logger.warning("Some tools may not be available if scope detection fails")
                # Continue with startup even if scope fetching fails

            # Yield the context (from original lifespan if provided)
            yield context_result

        return token_scope_lifespan

    async def _fetch_token_scopes(self):
        """Fetch token scopes from the GitGuardian API."""
        try:
            logger.debug("Getting GitGuardian client for scope fetching")
            # Store the client in the instance variable

            try:
                logger.debug("Attempting to fetch token scopes from GitGuardian API")
                # Store the complete token info
                self._token_info = await self.client.get_current_token_info()

                # Extract and store scopes
                scopes = self._token_info.get("scopes", [])
                logger.debug(f"Retrieved token scopes: {scopes}")

                # Store scopes for later use
                self._token_scopes = set(scopes)

                # Log authentication method used
                logger.debug("Using OAuth authentication")

            except Exception as e:
                logger.warning(f"Error fetching token scopes from /api_tokens/self endpoint: {str(e)}")
                # Try alternative approach - check what endpoints we can access

        except Exception as e:
            logger.error(f"Error fetching token scopes: {str(e)}")
            # Don't re-raise the exception, let the server start anyway

    def get_client(self):
        """
        Return the GitGuardian client instance.

        This method checks for a Personal Access Token in the Authorization header
        of the current HTTP request using FastMCP 2.0's get_http_headers().
        If found, it extracts and uses that token. Otherwise, it returns the
        default singleton client.

        Returns:
            GitGuardianClient: A client instance configured with the appropriate auth
        """
        # Use FastMCP 2.0's get_http_headers() to access HTTP headers
        try:
            headers = get_http_headers()
            if headers:
                # Look for Authorization header
                auth_header = headers.get("authorization") or headers.get("Authorization")
                if auth_header:
                    # Extract token from Authorization header
                    token = self._extract_token_from_header(auth_header)
                    if token:
                        logger.debug("Using Personal Access Token from Authorization header")
                        return get_client(personal_access_token=token)
        except Exception as e:
            # get_http_headers() will return None if not in HTTP context
            # This is expected for stdio transport
            logger.debug(f"No HTTP headers available (expected for stdio transport): {e}")

        return get_client()

    def _extract_token_from_header(self, auth_header: str) -> str | None:
        """Extract token from Authorization header."""
        auth_header = auth_header.strip()

        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()

        if auth_header.lower().startswith("token "):
            return auth_header[6:].strip()

        if auth_header:
            return auth_header

        return None

    @property
    def client(self):
        """Property for backward compatibility."""
        return self.get_client()

    def get_token_info(self):
        """Return the token info dictionary."""
        return self._token_info

    async def revoke_current_token(self) -> dict:
        """Revoke the current API token via GitGuardian API."""
        try:
            logger.debug("Revoking current API token")
            # Call the DELETE /api_tokens/self endpoint
            result = await self._client._request("DELETE", "/api_tokens/self")
            logger.debug("API token revoked")
            return result
        except Exception as e:
            logger.error(f"Error revoking current API token: {str(e)}")
            raise

    def tool(self, *args, required_scopes: list[str] = None, **kwargs):
        """
        Extended tool decorator that tracks required scopes.

        Usage:
            @mcp.tool(required_scopes=["scan"])
            def my_tool():
                pass

            # Or with function passed directly
            mcp.tool(my_func, required_scopes=["scan"])
        """
        # Call parent's tool decorator
        result = super().tool(*args, **kwargs)

        # Store scopes if this is a tool instance (not a decorator)
        if hasattr(result, 'name') and required_scopes:
            self._tool_scopes[result.name] = set(required_scopes)
            return result

        # If it's a decorator, wrap it to track scopes
        if callable(result):
            def wrapper(fn):
                tool = result(fn)
                if required_scopes:
                    self._tool_scopes[tool.name] = set(required_scopes)
                return tool
            return wrapper

        return result

    async def _scope_filtering_middleware(
        self, context: MiddlewareContext, call_next: Callable
    ) -> Any:
        """
        Middleware to filter tools based on token scopes.

        This middleware intercepts tools/list requests and filters the tools
        based on the user's API token scopes.
        """
        # Only apply filtering to tools/list requests
        if context.method != "tools/list":
            return await call_next(context)

        # Get all tools from the next middleware/handler
        all_tools = await call_next(context)

        # Log token scopes for debugging
        if self._token_scopes:
            logger.debug(f"User has the following scopes: {', '.join(self._token_scopes)}")
        else:
            try:
                # Try to fetch scopes if not already stored
                logger.debug("No stored scopes found, fetching from API")
                await self._fetch_token_scopes()
                logger.debug(f"Retrieved token scopes: {self._token_scopes}")
            except Exception as e:
                logger.warning(f"Could not fetch token scopes: {str(e)}")

        # Filter tools by scopes
        filtered_tools = []
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._tool_scopes.get(tool_name, set())

            if not required_scopes or required_scopes.issubset(self._token_scopes):
                filtered_tools.append(tool)
            else:
                missing_scopes = required_scopes - self._token_scopes
                logger.info(f"Removing tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        return filtered_tools

    async def list_tools(self) -> list[MCPTool]:
        """
        Public method to list tools (for compatibility with tests and external code).

        This calls _list_tools_mcp which applies middleware and converts to MCP format.
        """
        return await self._list_tools_mcp()


# Common MCP tools for user information and token management
def register_common_tools(mcp_instance: "GitGuardianFastMCP"):
    """Register common MCP tools for user information and token management."""

    logger.debug("Registering common MCP tools...")

    @mcp_instance.tool(
        name="get_authenticated_user_info",
        description="Get comprehensive information about the authenticated user and current API token including scopes and authentication method",
    )
    async def get_authenticated_user_info() -> dict:
        """Get information about the authenticated user and current API token."""
        logger.debug("Getting authenticated user information")

        token_info = mcp_instance.get_token_info()

        if not token_info:
            try:
                client = mcp_instance.get_client()
                token_info = await client.get_current_token_info()
                mcp_instance._token_info = token_info
            except Exception as e:
                logger.error(f"Error fetching token info: {str(e)}")
                return {"error": f"Failed to fetch token info: {str(e)}"}

        return {
            "token_info": token_info,
            "authentication_method": mcp_instance._auth_method,
            "available_scopes": list(mcp_instance._token_scopes),
        }

    @mcp_instance.tool(
        name="revoke_current_token",
        description="Revoke the current API token and clean up stored credentials",
    )
    async def revoke_current_token() -> dict:
        """Revoke the current API token and clean up stored credentials."""
        logger.debug("Starting token revocation process")

        try:
            client = mcp_instance.client
            await client._request("DELETE", "/api_tokens/self")
            logger.debug("Token revoked via API")

            # Clear cached client and token info
            mcp_instance._client = None
            mcp_instance._token_info = None
            mcp_instance._token_scopes = set()

            return {
                "success": True,
                "message": "Token revoked and credentials cleaned up",
                "authentication_method": mcp_instance._auth_method,
            }

        except Exception as e:
            logger.error(f"Error during token revocation: {str(e)}")
            return {"success": False, "error": f"Failed to revoke token: {str(e)}"}

    logger.debug("Registered common MCP tools")
