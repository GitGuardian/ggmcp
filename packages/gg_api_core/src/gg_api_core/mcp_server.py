"""GitGuardian MCP Server with scope-based tool filtering."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cached_property

from mcp.server.fastmcp import FastMCP
from mcp.types import AnyFunction
from mcp.types import Tool as MCPTool

from gg_api_core.utils import get_client

# Configure logger
logger = logging.getLogger(__name__)


class GitGuardianFastMCP(FastMCP):
    """FastMCP extension with GitGuardian API scope-based tool filtering."""

    def __init__(self, *args, **kwargs):
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
        if kwargs.get("default_scopes"):
            self._token_scopes = set(kwargs.get("default_scopes"))
            logger.debug(f"Using default scopes: {self._token_scopes}")

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

    @cached_property
    def client(self):
        """Return the GitGuardian client instance."""
        return get_client()

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

    def tool(self, name: str = None, description: str = None, required_scopes: list[str] = None, **kwargs):
        """Extended tool decorator that tracks required scopes."""
        # Get the actual name that will be used for the tool
        actual_name = name

        decorator = super().tool(name=name, description=description, **kwargs)

        # Wrap the original decorator to track scope requirements
        def wrapped_decorator(fn):
            nonlocal actual_name
            self._store_tool_scopes(actual_name or fn.__name__, required_scopes)
            return decorator(fn)

        return wrapped_decorator

    def _store_tool_scopes(self, name: str, required_scopes: list[str]):
        if required_scopes:
            self._tool_scopes[name] = set(required_scopes)

    def add_tool(
        self,
        fn: AnyFunction,
        name: str | None = None,
        description: str | None = None,
        required_scopes: list[str] | None = None,
        **kwargs,
    ) -> None:
        name = name or fn.__name__
        self._store_tool_scopes(name, required_scopes)
        super().add_tool(fn=fn, name=name, **kwargs)

    async def list_tools(self) -> list[MCPTool]:
        """Return all tools, filtering out those requiring unavailable scopes."""
        all_tools = await super().list_tools()

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

        # Special handling for optimized tools
        # We want to show either the optimized version (with _optimized suffix) or
        # the fallback version (without suffix) based on available scopes
        has_sources_read = "sources:read" in self._token_scopes
        logger.debug(f"User has sources:read scope: {has_sources_read}")

        # Keep track of which optimized tools we've seen to avoid showing both versions
        optimized_tool_base_names = set()

        # Tools filtered by scopes and optimized vs fallback version selection
        final_tools = []
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._tool_scopes.get(tool_name, set())

            # Special handling for optimized tools (with _optimized suffix)
            if tool_name.endswith("_optimized"):
                base_name = tool_name.replace("_optimized", "")
                optimized_tool_base_names.add(base_name)

                # Only include optimized version if we have sources:read scope
                if has_sources_read and required_scopes.issubset(self._token_scopes):
                    # Modify the tool name to remove the _optimized suffix for display
                    # This makes it appear as the regular tool to consumers
                    tool.name = base_name
                    final_tools.append(tool)
                    logger.debug(f"Using optimized version for tool: {base_name}")
                else:
                    logger.debug(f"Skipping optimized tool {tool_name} due to missing sources:read scope")
            else:
                # For regular (non-optimized) tools, check if we have an optimized version
                # If this is a fallback version and we already have the optimized version, skip it
                if tool_name in optimized_tool_base_names and has_sources_read:
                    logger.debug(f"Skipping fallback version of {tool_name} as optimized version will be used")
                    continue

                # Otherwise, include the tool if we have the required scopes
                if not required_scopes or required_scopes.issubset(self._token_scopes):
                    final_tools.append(tool)
                else:
                    missing_scopes = required_scopes - self._token_scopes
                    logger.info(f"Removing tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        return final_tools


# Common MCP tools for user information and token management
def register_common_tools(mcp_instance: GitGuardianFastMCP):
    """Register common MCP tools for user information and token management."""

    logger.debug("Registering common MCP tools...")

    # Simple approach - just register the tools and let the scope filtering handle visibility
    # The tool names are different enough that conflicts should be rare

    @mcp_instance.tool(
        name="get_authenticated_user_info",
        description="Get comprehensive information about the authenticated user and current API token including scopes and authentication method",
    )
    async def get_authenticated_user_info() -> dict:
        """
        Get information about the authenticated user and current API token.

        Returns comprehensive information about the current user including:
        - Token details (name, ID, creation date, expiration)
        - Token scopes and permissions
        - User/member information
        - Authentication method being used

        Returns:
            dict: Dictionary containing user and token information
        """
        logger.debug("Getting authenticated user information")

        # Get token info (either from stored cache or fetch fresh)
        token_info = mcp_instance.get_token_info()

        if not token_info:
            # Try to fetch token info if not already cached
            try:
                client = mcp_instance.get_client()
                token_info = await client.get_current_token_info()
                # Cache it in the instance
                mcp_instance._token_info = token_info
            except Exception as e:
                logger.error(f"Error fetching token info: {str(e)}")
                return {"error": f"Failed to fetch token info: {str(e)}"}

        logger.debug(f"Retrieved user info for token ID: {token_info.get('id', 'unknown')}")

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
        """
        Revoke the current API token and clean up stored credentials.

        This tool will:
        1. Revoke the current API token via the GitGuardian API
        2. Clean up any stored OAuth tokens or credentials
        3. Provide confirmation of successful revocation

        Returns:
            dict: Confirmation of token revocation and cleanup status
        """
        logger.debug("Starting token revocation process")

        try:
            client = mcp_instance.client
            # Revoke the token via API
            await client._request("DELETE", "/api_tokens/self")
            logger.debug("Token revoked via API")

            # Clean up stored OAuth tokens
            if hasattr(client, "oauth_handler") and client.oauth_handler:
                try:
                    oauth_handler = client.oauth_handler
                    dashboard_url = oauth_handler.dashboard_url

                    # Clear from memory
                    oauth_handler.token_info = None
                    oauth_handler.token_name = None

                    # Get file storage and clean up stored tokens
                    file_storage = oauth_handler._get_file_storage()
                    stored_tokens = file_storage.get_all_tokens()

                    # Remove tokens for this dashboard URL
                    tokens_to_remove = []
                    for instance_url, tokens in stored_tokens.items():
                        if instance_url == dashboard_url:
                            tokens_to_remove.extend(tokens.keys())

                    for token_name in tokens_to_remove:
                        try:
                            file_storage.remove_token(dashboard_url, token_name)
                            logger.debug(f"Cleaned up OAuth token file: {file_storage.token_file}")
                        except Exception as e:
                            logger.warning(f"Could not clean up token file: {str(e)}")

                except Exception as cleanup_error:
                    logger.warning(f"OAuth token cleanup failed: {str(cleanup_error)}")
                    # Don't fail the entire operation if cleanup fails

            # Clear cached client and token info
            mcp_instance._client = None
            mcp_instance._token_info = None
            mcp_instance._token_scopes = set()

            logger.debug("Token revocation and cleanup completed")

            return {
                "success": True,
                "message": "Token revoked and credentials cleaned up",
                "authentication_method": mcp_instance._auth_method,
            }

        except Exception as e:
            logger.error(f"Error during token revocation: {str(e)}")
            return {"success": False, "error": f"Failed to revoke token: {str(e)}"}

    logger.debug("Registered common MCP tools: get_authenticated_user_info, revoke_current_token")
