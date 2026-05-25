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
- **HIL (High Impact Leak) triage and qualification** — atomic ownership-evidence
  tools (DNS, RDAP, TLS certificate, GitHub) plus orchestration prompts that
  ship the same decision logic GitGuardian's internal HIL agents follow.

### HIL atomic tools

All HIL atomic tools have `required_scopes=[]` (they don't hit the GG API).

| Tool | Purpose |
|---|---|
| `dns_lookup` | Resolve A/AAAA/CNAME/MX/TXT/NS records for a hostname. |
| `reverse_dns_lookup` | PTR lookup for an IP address. |
| `rdap_domain_lookup` | Registrant org / country / NS for a domain (modern WHOIS). |
| `rdap_ip_lookup` | Network owner / ASN / country for an IP. |
| `check_host_reachability` | DNS → TCP → HTTPS probe, with WAF (Cloudflare/CloudFront/Akamai/Fastly) detection. |
| `check_ssl_certificate` | Subject O / CN / SANs / issuer for a host's TLS cert. |
| `search_github_issues` | Search GitHub issues, optionally scoped to a repo. |
| `search_github_code` | Search GitHub code (requires `GITHUB_TOKEN`). |
| `get_github_repo_metadata` | Repo + owner metadata, incl. `owner.company` for orgs. |
| `list_github_repo_contributors` | Top contributors + their public profile data. |

`GITHUB_TOKEN` (optional, no scope required) raises the GitHub anonymous
rate limit from 60 req/h to 5000 req/h and unlocks `search_github_code`.

### HIL prompts

| Prompt | Inputs | Purpose |
|---|---|---|
| `triage_public_secret_leak` | `incident_id`, optional `target_company` | One-shot classifier mirroring the upstream `SecretTriageOutput` schema. |
| `qualify_high_impact_leak` | `incident_id`, optional `triage_summary`, optional `target_company` | Multi-step DNS→SSL→RDAP→repo→validity playbook with a hard 8-call budget, returning `DeepIncidentAnalysisOutput`. |
| `investigate_secret_repository` | `repo`, `task`, optional `incident_id` | Reader playbook for a single repo under a 6-call budget, returning `ReaderTaskResult`. |

These prompts embed the full output schema and decision rules — the client's
model does the orchestration.

### Deferred (not yet shipped)

- `check_secret_validity`, `list_secret_checkers` — pending confirmation of the
  public GG API endpoint that exposes single-secret validity checking.
- `get_public_occurrence_patch` — pending confirmation of a per-occurrence
  patch endpoint on the public GG API. `list_public_occurrences` already
  returns filepath/commit/repo, which is enough for the current prompts.

See `docs/HIL_PLAN.md` and the `# TODO(HIL)` notes in
`packages/gg_api_core/src/gg_api_core/tools/{check_secret_validity,list_secret_checkers,get_public_occurrence_patch}.py`.

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
