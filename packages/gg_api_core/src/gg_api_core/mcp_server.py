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
        """Return all tools, with scope information added to those requiring unavailable scopes."""
        # Get all tools from parent implementation
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

        # Add information to tools that require unavailable scopes
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._tool_scopes.get(tool_name, set())

            # Check if this tool has required scopes that the user doesn't have
            if required_scopes and not required_scopes.issubset(self._token_scopes):
                missing_scopes = required_scopes - self._token_scopes
                scope_warning = (
                    f"⚠️ DO NOT USE THIS TOOL - Missing required scopes: {', '.join(missing_scopes)}. "
                    f"This tool requires GitGuardian API permissions that your token doesn't have."
                )

                # Add warning to the tool description
                if tool.description:
                    tool.description = f"{scope_warning}\n\n{tool.description}"
                else:
                    tool.description = scope_warning

        return all_tools
