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
