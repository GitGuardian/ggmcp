# GitGuardian Developer MCP Server

This package provides a focused MCP server for developers, containing remediation tools for secrets detected in code and honeytoken management capabilities. It's designed to be lightweight and focused on the developer workflow.

## Features

- Detect and remediate secret incidents in code repositories
- Get detailed remediation steps for each detected secret
- Generate environment file examples with placeholders for secrets
- Optionally generate git commands to help clean git history
- Generate and manage honeytokens for security monitoring

## Usage

### Installation

```bash
uv sync -g packages/developer_mcp_server
```

### Running the server

```bash
developer-mcp-server
```

## Authentication

This server supports both API key and OAuth 2.0 PKCE authentication methods:

1. **API Key Authentication**: Set `GITGUARDIAN_AUTH_METHOD=token` and provide your API key with `GITGUARDIAN_API_KEY=your-api-key`

2. **OAuth Authentication**: Set `GITGUARDIAN_AUTH_METHOD=web` and provide your client ID with `GITGUARDIAN_CLIENT_ID=your-client-id`

The required API token scopes for this tool are:
- `incidents:read`
- `incidents:write`
- `honeytokens:read`
- `honeytokens:write`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITGUARDIAN_AUTH_METHOD` | Authentication method ('token' or 'web') | 'token' |
| `GITGUARDIAN_API_KEY` | Your GitGuardian API key (required for token auth) | - |
| `GITGUARDIAN_CLIENT_ID` | Your OAuth client ID (required for web auth) | - |
| `GITGUARDIAN_API_URL` | GitGuardian base URL or API URL | `https://api.gitguardian.com/v1` (SaaS) `https://dashboard.gitguardian.mycorp.local` (Self-Hosted) |
| `MCP_SERVER_HOST` | Host for the MCP server (used for OAuth redirect) | `localhost` |
| `MCP_SERVER_PORT` | Port for the MCP server | `8000` |

## Honeytoken Management

The server provides functions to create and manage honeytokens, which are fake credentials that can be used to detect unauthorized access to your systems.

### Examples

#### Generate a new honeytoken

```python
# Create a brand new honeytoken
result = await generate_honeytoken(
    name="aws-prod-database",
    description="Monitoring access to production database credentials",
    new_token=True  # Explicitly request a new token
)

# Reuse an existing active honeytoken if available
result = await generate_honeytoken(
    name="aws-prod-database",
    description="Monitoring access to production database credentials",
    new_token=False  # Default - will reuse an existing token if available
)
```

The result contains the honeytoken details, including the token itself and injection recommendations for various platforms.

#### List existing honeytokens

```python
tokens = await list_honeytokens(
    status="ACTIVE",
    mine=True,
    per_page=50
)
```

This returns a list of honeytokens with filtering options:
- `status`: Filter by token status ("ACTIVE" or "REVOKED")
- `search`: Search by name or description
- `mine`: Set to True to only show tokens created by the current user
- `get_all`: Set to True to paginate through all results automatically
