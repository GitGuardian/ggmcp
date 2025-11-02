# GitGuardian API Core

This package provides core functionality for GitGuardian MCP servers, including:

- GitGuardian API client for both API key and OAuth authentication
- Base MCP server class with scope-aware tool registration
- OAuth implementation for web-based authentication
- Shared utilities and helper functions

## Features

- Authentication support for both API key and OAuth 2.0 PKCE flows
- Automatic token scope detection and tool availability management
- Comprehensive GitGuardian API client with full endpoint coverage
- Core utilities for common operations

## Usage

This package is intended to be used as a dependency for other GitGuardian MCP server implementations:

```python
from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.client import GitGuardianClient

# Create a custom MCP server
mcp = get_mcp_server("My Custom Server")


# Register tools that use the GitGuardian API
@mcp.tool(required_scopes=["honeytokens:read"])
async def my_custom_tool():
    client = mcp.get_client()
    # Use the client to make API calls
    result = await client.list_honeytokens()
    return result
```

## Authentication

This package uses OAuth authentication, configured via environment variables:

- `GITGUARDIAN_URL`: Optional GitGuardian instance URL (defaults to `https://dashboard.gitguardian.com`)
- `GITGUARDIAN_CLIENT_ID`: Optional OAuth client ID (defaults to `ggshield_oauth`)
- `GITGUARDIAN_SCOPES`: Optional space-separated list of scopes for OAuth
