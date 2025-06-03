# GitGuardian SecOps MCP Server

This package provides a comprehensive MCP server for security operations teams, containing a full suite of GitGuardian security tools. It enables security teams to manage incidents, monitor honeytokens, scan for secrets, and manage custom tags.

## Features

- Honeytoken generation and management
- Secret incident listing and management
- Custom tag management
- Repository incident analysis
- Secret scanning for code files

## Usage

### Installation

```bash
uv sync -g packages/gg_secops_mcp_server
```

### Running the server

```bash
gg-secops-mcp
```

## Authentication

This server supports both API key and OAuth 2.0 PKCE authentication methods:

1. **API Key Authentication**: Set `GITGUARDIAN_AUTH_METHOD=token` and provide your API key with `GITGUARDIAN_API_KEY=your-api-key`

2. **OAuth Authentication**: Set `GITGUARDIAN_AUTH_METHOD=web` and provide your client ID with `GITGUARDIAN_CLIENT_ID=your-client-id`

The tools in this server require various API token scopes including:
- `honeytokens:read`
- `honeytokens:write`
- `incidents:read`
- `incidents:write`
- `custom_tags:read`
- `custom_tags:write`
- `token:read`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITGUARDIAN_AUTH_METHOD` | Authentication method ('token' or 'web') | 'token' |
| `GITGUARDIAN_API_KEY` | Your GitGuardian API key (required for token auth) | - |
| `GITGUARDIAN_CLIENT_ID` | Your OAuth client ID (required for web auth) | - |
| `GITGUARDIAN_SCOPES` | Space-separated list of scopes (for OAuth) | All available scopes |
| `GITGUARDIAN_INSTANCE_URL` | Base URL for GitGuardian instance | `https://dashboard.gitguardian.com` |
| `MCP_SERVER_HOST` | Host for the MCP server (used for OAuth redirect) | `localhost` |
| `MCP_SERVER_PORT` | Port for the MCP server | `8000` |
