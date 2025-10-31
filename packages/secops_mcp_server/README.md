# GitGuardian SecOps MCP Server

> **⚠️ BETA WARNING ⚠️**
> 
> This SecOps MCP Server is currently in **BETA** status. While functional, it may contain bugs, have incomplete features, or undergo breaking changes. Use with caution in production environments and expect potential issues or API changes.

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
uv sync -g packages/secops_mcp_server
```

### Running the server

```bash
secops-mcp-server
```

## Authentication

This server uses OAuth 2.0 PKCE authentication. No API key is required - the server will automatically open a browser for authentication when needed.

A Personal Access Token (PAT) called "MCP Token" will be created automatically with scopes appropriate for your GitGuardian instance:

- `scan` - Core scanning functionality
- `incidents:read` - Read incidents
- `sources:read` - Read source repositories
- `honeytokens:read` - Read honeytokens (only if Honeytoken is activated when Self-Hosted)
- `honeytokens:write` - Manage honeytokens (same as honeytokens:read)

Note: Extended scopes (honeytokens, audit logs, etc.) are omitted for self-hosted instances as they often require special permissions or workspace configurations that may cause authentication issues.

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
- **Self-hosted instances**: `scan,incidents:read,sources:read` (honeytokens omitted to avoid permission issues)

To override auto-detection, set `GITGUARDIAN_SCOPES` explicitly in your MCP configuration.

## Optional Integrations

### Sentry Error Tracking

The MCP server supports optional Sentry integration for error tracking and performance monitoring. This is completely optional and designed to avoid vendor lock-in.

**Installation:**

```bash
# Install with pip
pip install 'secops-mcp-server[sentry]'

# Install with uv (in a project)
uv add 'secops-mcp-server[sentry]'

# Run with uvx (from Git)
uvx --from 'secops-mcp-server[sentry]' --from 'git+https://github.com/GitGuardian/ggmcp.git@main' secops-mcp-server

# Or install Sentry SDK separately (works with any installation method)
pip install sentry-sdk>=2.0.0
uv pip install sentry-sdk>=2.0.0
```

**Configuration:**

Set the `SENTRY_DSN` environment variable to enable Sentry:

```bash
export SENTRY_DSN="https://your-key@sentry.io/project-id"
export SENTRY_ENVIRONMENT="production"
export SENTRY_RELEASE="1.0.0"

# Then run the server as usual
secops-mcp-server
# or
uvx --from git+https://github.com/GitGuardian/ggmcp.git@main secops-mcp-server
```

**Note:** If you're using `uvx` and want Sentry support, you have two options:

1. **Include the extra in the --from option:**
   ```bash
   uvx --from 'git+https://github.com/GitGuardian/ggmcp.git@main#egg=secops-mcp-server[sentry]' secops-mcp-server
   ```

2. **Install sentry-sdk in the same environment** (simpler approach):
   ```bash
   # First, ensure sentry-sdk is available
   uv pip install sentry-sdk
   # Then run the server
   uvx --from git+https://github.com/GitGuardian/ggmcp.git@main secops-mcp-server
   ```

**Features:**

- Automatic exception tracking
- Performance monitoring with configurable sampling
- Logging integration (INFO+ as breadcrumbs, ERROR+ as events)
- Optional profiling support
- Privacy-focused (PII not sent by default)

If `SENTRY_DSN` is not set, the server runs normally without any error tracking overhead.
