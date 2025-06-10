# GitGuardian Developer MCP Server

This package provides a focused MCP server for developers, containing only the remediation tool for secrets detected in code. It's designed to be lightweight and focused on the developer workflow.

## Features

- Detect and remediate secret incidents in code repositories
- Get detailed remediation steps for each detected secret
- Generate environment file examples with placeholders for secrets
- Optionally generate git commands to help clean git history

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

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITGUARDIAN_AUTH_METHOD` | Authentication method ('token' or 'web') | 'token' |
| `GITGUARDIAN_API_KEY` | Your GitGuardian API key (required for token auth) | - |
| `GITGUARDIAN_CLIENT_ID` | Your OAuth client ID (required for web auth) | - |
| `GITGUARDIAN_INSTANCE_URL` | Base URL for GitGuardian instance | `https://dashboard.gitguardian.com` |
| `MCP_SERVER_HOST` | Host for the MCP server (used for OAuth redirect) | `localhost` |
| `MCP_SERVER_PORT` | Port for the MCP server | `8000` |
