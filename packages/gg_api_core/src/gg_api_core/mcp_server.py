"""GitGuardian MCP Server with scope-based tool filtering."""

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool

from gg_api_core.utils import get_gitguardian_client

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
        # Store the GitGuardian client
        self._client = None
        # Store the complete token info
        self._token_info = None

        # Store the authentication method
        self._auth_method = os.environ.get("GITGUARDIAN_AUTH_METHOD", "token").lower()
        logger.info(f"Using authentication method: {self._auth_method}")

        # Set default scopes for demonstration or development
        if kwargs.get("default_scopes"):
            self._token_scopes = set(kwargs.get("default_scopes"))
            logger.info(f"Using default scopes: {self._token_scopes}")

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
                logger.info("Fetching token scopes during server startup")
                await self._fetch_token_scopes()
                logger.info(f"Successfully retrieved token scopes: {self._token_scopes}")
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
            logger.info("Getting GitGuardian client for scope fetching")
            # Store the client in the instance variable
            self._client = get_gitguardian_client()

            try:
                logger.info("Attempting to fetch token scopes from GitGuardian API")
                # Store the complete token info
                self._token_info = await self._client.get_current_token_info()

                # Extract and store scopes
                scopes = self._token_info.get("scopes", [])
                logger.info(f"Retrieved token scopes: {scopes}")

                # Store scopes for later use
                self._token_scopes = set(scopes)

                # Log authentication method used
                if self._auth_method == "web":
                    logger.info("Using OAuth authentication")
                else:
                    logger.info("Using token authentication")

            except Exception as e:
                logger.warning(f"Error fetching token scopes from /api_tokens/self endpoint: {str(e)}")
                # Try alternative approach - check what endpoints we can access

        except Exception as e:
            logger.error(f"Error fetching token scopes: {str(e)}")
            # Don't re-raise the exception, let the server start anyway

    def get_client(self):
        """Return the GitGuardian client instance."""
        if self._client is None:
            self._client = get_gitguardian_client()
        return self._client

    def get_token_info(self):
        """Return the token info dictionary."""
        return self._token_info

    async def revoke_current_token(self) -> dict:
        """Revoke the current API token via GitGuardian API."""
        try:
            logger.info("Revoking current API token")
            # Call the DELETE /api_tokens/self endpoint
            result = await self._client._request("DELETE", "/api_tokens/self")
            logger.info("Successfully revoked current API token")
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
            result = decorator(fn)

            # If name wasn't provided, it defaults to function name
            if actual_name is None:
                actual_name = fn.__name__

            # Store required scopes for this tool
            if required_scopes:
                self._tool_scopes[actual_name] = set(required_scopes)

            return result

        return wrapped_decorator

    async def list_tools(self) -> list[MCPTool]:
        """Return all tools, filtering out those requiring unavailable scopes."""
        all_tools = await super().list_tools()

        # Log token scopes for debugging
        if self._token_scopes:
            logger.info(f"User has the following scopes: {', '.join(self._token_scopes)}")
        else:
            try:
                # Try to fetch scopes if not already stored
                logger.info("No stored scopes found, fetching from API")
                await self._fetch_token_scopes()
                logger.info(f"Retrieved token scopes: {self._token_scopes}")
            except Exception as e:
                logger.warning(f"Could not fetch token scopes: {str(e)}")

        # Special handling for optimized tools
        # We want to show either the optimized version (with _optimized suffix) or
        # the fallback version (without suffix) based on available scopes
        has_sources_read = "sources:read" in self._token_scopes
        logger.info(f"User has sources:read scope: {has_sources_read}")

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
                    logger.info(f"Using optimized version for tool: {base_name}")
                else:
                    logger.info(f"Skipping optimized tool {tool_name} due to missing sources:read scope")
            else:
                # For regular (non-optimized) tools, check if we have an optimized version
                # If this is a fallback version and we already have the optimized version, skip it
                if tool_name in optimized_tool_base_names and has_sources_read:
                    logger.info(f"Skipping fallback version of {tool_name} as optimized version will be used")
                    continue

                # Otherwise, include the tool if we have the required scopes
                if not required_scopes or required_scopes.issubset(self._token_scopes):
                    final_tools.append(tool)
                else:
                    missing_scopes = required_scopes - self._token_scopes
                    logger.info(f"Hiding tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        return final_tools


# Common MCP tools for user information and token management
def register_common_tools(mcp_instance: GitGuardianFastMCP):
    """Register common MCP tools for user information and token management."""

    logger.info("Registering common MCP tools...")

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
        logger.info("Getting authenticated user information")

        # Get token info (either from stored cache or fetch fresh)
        token_info = mcp_instance.get_token_info()

        if not token_info:
            # Try to fetch token info if not already cached
            try:
                client = mcp_instance.get_client()
                token_info = await client.get_current_token_info()
            except Exception as e:
                logger.error(f"Error fetching user info: {str(e)}")
                return {
                    "error": f"Unable to fetch user information: {str(e)}",
                    "authentication_method": mcp_instance._auth_method,
                }

        # Prepare response with all available information
        user_info = {
            "authentication_method": mcp_instance._auth_method,
            "token_scopes": list(mcp_instance._token_scopes),
            "token_info": token_info,
        }

        logger.info(f"Retrieved user info for token ID: {token_info.get('id', 'unknown')}")
        return user_info

    @mcp_instance.tool(
        name="revoke_current_token",
        description="Revoke the current API token and clean up stored credentials",
    )
    async def revoke_current_token() -> dict:
        """
        Revoke the current API token and clean up stored credentials.

        This tool will:
        1. Call the GitGuardian API to revoke the current token
        2. Remove the token from local storage files
        3. Clear cached token information

        After calling this tool, you will need to re-authenticate to continue using the MCP server.

        Returns:
            dict: Status of the revocation operation
        """
        logger.info("Starting token revocation process")

        try:
            # Step 1: Revoke token via API
            revocation_result = await mcp_instance.revoke_current_token()
            logger.info("Token successfully revoked via API")

            # Step 2: Clean up stored token files
            cleanup_results = []

            # For OAuth tokens, clean up the stored OAuth token file
            if mcp_instance._auth_method == "web":
                try:
                    from .oauth import FileTokenStorage

                    # Get the token storage instance
                    file_storage = FileTokenStorage()

                    # Get the instance URL from client
                    client = mcp_instance.get_client()
                    instance_url = client._get_dashboard_url()

                    # Load current tokens
                    tokens = file_storage.load_tokens()

                    # Remove the token for this instance
                    if instance_url in tokens:
                        del tokens[instance_url]

                        # Save the updated tokens (without the revoked one)
                        import json

                        try:
                            with open(file_storage.token_file, "w") as f:
                                json.dump(tokens, f, indent=2)
                            file_storage.token_file.chmod(0o600)
                            cleanup_results.append(f"Removed OAuth token from {file_storage.token_file}")
                            logger.info(f"Cleaned up OAuth token file: {file_storage.token_file}")
                        except Exception as e:
                            cleanup_results.append(f"Warning: Could not update token file: {str(e)}")
                            logger.warning(f"Could not update OAuth token file: {str(e)}")
                    else:
                        cleanup_results.append("No OAuth token found in storage for current instance")

                except Exception as e:
                    cleanup_results.append(f"Warning: Could not clean up OAuth token storage: {str(e)}")
                    logger.warning(f"Could not clean up OAuth token storage: {str(e)}")

            # Step 3: Clear cached token information in the MCP server
            mcp_instance._token_info = None
            mcp_instance._token_scopes = set()
            cleanup_results.append("Cleared cached token information from MCP server")

            result = {
                "status": "success",
                "message": "Token successfully revoked and credentials cleaned up",
                "api_revocation": revocation_result,
                "cleanup_actions": cleanup_results,
                "next_steps": [
                    "The MCP server will need to re-authenticate for future requests",
                    "Restart the MCP server to initiate a new authentication flow",
                ],
            }

            logger.info("Token revocation and cleanup completed successfully")
            return result

        except Exception as e:
            logger.error(f"Error during token revocation: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to revoke token: {str(e)}",
                "next_steps": [
                    "You may need to manually revoke the token via the GitGuardian dashboard",
                    "Check the GitGuardian API documentation for manual token management",
                ],
            }

    logger.info("Successfully registered common MCP tools: get_authenticated_user_info, revoke_current_token")
