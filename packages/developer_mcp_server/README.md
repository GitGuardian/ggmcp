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

This server uses OAuth 2.0 PKCE authentication. No API key is required - the server will automatically open a browser for authentication when needed.

A Personal Access Token (PAT) called "Developer MCP Token" will be created automatically with scopes appropriate for your GitGuardian instance:

- `scan` - Core scanning functionality
- `incidents:read` - Read incidents
- `sources:read` - Read source repositories
- `honeytokens:read` - Read honeytokens (only if Honeytoken is activated when Self-Hosted)
- `honeytokens:write` - Manage honeytokens (same as honeytokens:read)

Note: Honeytoken scopes are omitted for self-hosted instances as they require the honeytoken module to be enabled and minimum "manager" role, which often causes permission issues.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITGUARDIAN_URL` | GitGuardian base URL | `https://dashboard.gitguardian.com` (SaaS US), `https://dashboard.eu1.gitguardian.com` (SaaS EU), `https://dashboard.gitguardian.mycorp.local` (Self-Hosted) |
| `GITGUARDIAN_SCOPES` | Comma-separated list of OAuth scopes | Auto-detected based on instance type |
| `SENTRY_DSN` | Sentry Data Source Name for error tracking (optional) | None |
| `SENTRY_ENVIRONMENT` | Environment name for Sentry (optional) | `production` |
| `SENTRY_RELEASE` | Release version or commit SHA for Sentry (optional) | None |
| `SENTRY_TRACES_SAMPLE_RATE` | Performance traces sampling rate 0.0-1.0 (optional) | `0.1` |
| `SENTRY_PROFILES_SAMPLE_RATE` | Profiling sampling rate 0.0-1.0 (optional) | `0.1` |

**OAuth Callback Server**: The OAuth authentication flow uses a local callback server on port range 29170-29998 (same as ggshield). This ensures compatibility with self-hosted GitGuardian instances where the `ggshield_oauth` client is pre-configured with these redirect URIs.

**Scope Auto-detection**: The server automatically detects appropriate scopes based on your GitGuardian instance:
- **SaaS instances**: `scan,incidents:read,sources:read,honeytokens:read,honeytokens:write`
- **Self-hosted instances**: `scan,incidents:read,sources:read`

To override auto-detection, set `GITGUARDIAN_SCOPES` explicitly in your MCP configuration.

## Optional Integrations

### Sentry Error Tracking

The MCP server supports optional Sentry integration for error tracking and performance monitoring. This is completely optional and designed to avoid vendor lock-in.

**Installation:**

```bash
# Install with pip
pip install 'developer-mcp-server[sentry]'

# Install with uv (in a project)
uv add 'developer-mcp-server[sentry]'

# Run with uvx (from Git)
uvx --from 'git+https://github.com/GitGuardian/ggmcp.git@main#egg=developer-mcp-server[sentry]' developer-mcp-server

# Or install Sentry SDK separately (works with any installation method)
pip install sentry-sdk>=2.0.0
uv pip install sentry-sdk>=2.0.0
```

**Configuration:**

Set the `SENTRY_DSN` environment variable to enable Sentry:

```bash
export SENTRY_DSN="https://your-key@sentry.io/project-id"
export SENTRY_ENVIRONMENT="development"
export SENTRY_RELEASE="1.0.0"

# Then run the server as usual
developer-mcp-server
```

**Features:**

- Automatic exception tracking
- Performance monitoring with configurable sampling
- Logging integration (INFO+ as breadcrumbs, ERROR+ as events)
- Optional profiling support
- Privacy-focused (PII not sent by default)

If `SENTRY_DSN` is not set, the server runs normally without any error tracking overhead.

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
