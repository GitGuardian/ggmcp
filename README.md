# GitGuardian MCP Server

Bring GitGuardian's secret detection and incident management into your AI agent.
Scan code for credentials before they leak, triage existing incidents, generate
honeytokens, and remediate findings — all from inside your IDE or chat client,
backed by GitGuardian's 500+ detectors.

> [!CAUTION]
> MCP servers are an emerging technology. Agents act on your behalf and under
> your responsibility. Use trusted MCP servers and review agent actions when
> they interact with tools. To limit blast radius the server defaults to
> read-only-leaning permissions; what is actually exposed is determined by
> the OAuth scopes your access token holds.

## What it does

- **Secret scanning**: proactively scan files for leaked credentials (`scan_secrets`).
- **Incident triage**: list, count and inspect internal incidents (`list_incidents`,
  `count_incidents`, `get_incident`, which can include an incident's comments and
  history), and drill into their exact locations (`list_repo_occurrences`, `list_sources`).
- **Incident links and IDs**: open an incident from a pasted dashboard or public API
  link, or from a bare incident ID (`get_gitguardian_resource`). It works out whether
  the incident is internal or from Public Monitoring and returns its details. Links
  must come from the configured instance and the token's workspace. For share links,
  supply the authenticated dashboard link.
- **Incident management**: assign, unassign, resolve, ignore, reopen, and comment
  on internal incidents (`assign_incident`, `manage_private_incident`,
  `manage_incident_comment`).
- **Public Monitoring**: list and inspect public incidents and their occurrences
  (`list_public_incidents`, `get_public_incident`, `list_public_occurrences`), and
  resolve, ignore, reopen, assign, or comment on them (`manage_public_incident`).
- **Remediation**: fetch your workspace's remediation workflow
  (`get_remediation_workflow`).
- **Honeytokens**: generate honeytokens (`generate_honeytoken`).
- **Identity**: see who the token belongs to, their role, and the token's scopes and
  expiry (`get_my_identity`).

The exact set of tools exposed to your agent depends on the OAuth scopes
granted to your access token.

## Prompt examples

```
Scan this codebase for any leaked secrets or credentials.
```

```
Remediate all incidents related to my project.
```

```
Check if there are any new security incidents assigned to me.
```

```
Help me understand this security incident and provide remediation steps.
```

```
Generate a new honeytoken for monitoring AWS credential access.
```

```
Create a honeytoken named 'dev-database' and hide it in config files.
```

## Quick start

The recommended way to run the GitGuardian MCP server is to point your MCP
client at the hosted server. The MCP client handles OAuth automatically; no
local install, no token to manage, no `uvx`.

Pick the URL that matches your GitGuardian region:

| Region      | URL                                                             |
|-------------|-----------------------------------------------------------------|
| US SaaS     | `https://mcp.gitguardian.com/mcp`                               |
| EU SaaS     | `https://mcp.eu1.gitguardian.com/mcp`                           |
| Self-hosted | See [Self-hosting the MCP server](#self-hosting-the-mcp-server) |

### Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "type": "http",
      "url": "https://mcp.gitguardian.com/mcp"
    }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude Desktop/mcp.json` (macOS) or
`%APPDATA%\Claude Desktop\mcp.json` (Windows). Same JSON as Cursor. Claude
Desktop versions that pre-date HTTP MCP support can run the server
[locally over stdio](#local-stdio-mode).

### Claude.ai (web)

Add the server in **Settings → Connectors → Add custom connector** with the
URL above. OAuth is handled in the browser tab.

### Windsurf

Edit `~/Library/Application Support/Windsurf/mcp.json` (or
`~/.config/Windsurf/mcp.json` on Linux):

```json
{
  "mcp": {
    "servers": {
      "GitGuardian": {
        "type": "http",
        "url": "https://mcp.gitguardian.com/mcp"
      }
    }
  }
}
```

### Zed

Edit `~/Library/Application Support/Zed/mcp.json` (or
`~/.config/Zed/mcp.json` on Linux) with the same `type: http` snippet.

## Choosing a deployment

Three deployment paths are supported. Pick based on where your GitGuardian
instance lives and what tradeoffs you accept.

| Deployment                                              | When to use                                                                                                              |
|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Hosted MCP** (Quick start above)                      | GitGuardian SaaS (US/EU) and you accept that requests transit `mcp.gitguardian.com` in addition to `api.gitguardian.com` |
| **Self-hosted MCP** ([§](#self-hosting-the-mcp-server)) | Self-hosted GitGuardian, airgapped environments, or you want the MCP server on your own infrastructure                   |
| **Local stdio** ([§](#local-stdio-mode))                | MCP clients without `type: http` support, CI/CD and scripts, or you want the server to run on your own machine          |

## Authentication

> Most users do not need to touch this. The [Quick start](#quick-start)
> config uses the **OAuth proxy** mode on the hosted server, and
> [Local stdio](#local-stdio-mode) uses **Browser OAuth** or **PAT env**.

There are four authentication modes the server can run in; you pick one via
env vars.

| Mode                                   | Configuration                                                          | Used by                                                                                                             |
|----------------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| **OAuth proxy** (HTTP)                 | `MCP_OAUTH_PROXY_ENABLED=true` + `MULTI_TENANCY_ENABLED=true` + `MCP_PORT` + `ENABLE_LOCAL_OAUTH=false` | The hosted MCP server. MCP client runs OAuth against `/authorize`+`/token`; the server proxies to the GG dashboard. |
| **Raw bearer** (HTTP)                  | `MULTI_TENANCY_ENABLED=true` + `MCP_PORT` + `ENABLE_LOCAL_OAUTH=false` | Self-hosted deployments without OAuth. Client sends `Authorization: Bearer <PAT>` on every request.                 |
| **PAT env** (stdio)                    | `GITGUARDIAN_PERSONAL_ACCESS_TOKEN=<pat>` + `ENABLE_LOCAL_OAUTH=false` | CI, scripts, local stdio. Server uses the env-var PAT for every GG API call.                                        |
| **Browser OAuth** (stdio)              | `ENABLE_LOCAL_OAUTH=true` (the default in stdio)                       | Local stdio without a PAT. The server opens a GitGuardian login in the browser and stores the PAT it receives on disk. |

## Local stdio mode

Run the server on your own machine over stdio, with
[`uvx`](https://docs.astral.sh/uv/). Use it for MCP clients without
`type: http` support, for CI/CD and scripts, or when you want requests to go
straight from your machine to the GitGuardian API.

### Sign in with your browser

By default the server opens a GitGuardian login in your browser the first time
a tool runs, then stores the PAT it receives on disk and reuses it on later
starts:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "gg-mcp-server"
      ],
      "env": {
        "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"
      }
    }
  }
}
```

Set `GITGUARDIAN_URL` to your own dashboard URL if you are not on US SaaS. Each
login creates a new PAT in your GitGuardian account.

### Use a PAT

For CI/CD, headless machines, or when you manage the token yourself, pass a PAT
and turn the browser login off:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "gg-mcp-server"
      ],
      "env": {
        "ENABLE_LOCAL_OAUTH": "false",
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "your_pat_here",
        "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"
      }
    }
  }
}
```

Create a PAT in your GitGuardian dashboard under **API → Personal Access
Tokens**.

In both cases the set of tools the server exposes depends on the token's
scopes.

For Claude Desktop on macOS, the `command` field needs the **absolute path**
to `uvx` (e.g. `/Users/you/.local/bin/uvx`): Claude Desktop does not resolve
`$PATH` for MCP servers.

## Self-hosting the MCP server

> The MCP server will be soon available out of the box as part of your GitGuardian self-hosted deployment (Helm chart).
> This section is only meant to describe how it works, but you don't have to set it up.

A Docker image is published at `ghcr.io/gitguardian/mcp-server`. Run it behind a
reverse proxy that terminates TLS, then point your MCP clients at it. The
container exposes the StreamableHTTP transport on port 8000 by default.

Minimum configuration:

```bash
docker run -p 8000:8000 \
  -e GITGUARDIAN_URL=https://dashboard.gitguardian.mycorp.local \
  -e IS_ON_PREM=true \
  -e MCP_BASE_URL=https://mcp.mycorp.local \
  -e MCP_OAUTH_PROXY_ENABLED=true \
  -e MULTI_TENANCY_ENABLED=true \
  -e MCP_PORT=8000 \
  -e ENABLE_LOCAL_OAUTH=false \
  ghcr.io/gitguardian/mcp-server:latest \
  gunicorn --workers=4 --worker-class=uvicorn.workers.UvicornWorker \
           -b 0.0.0.0:8000 gg_mcp_server.http_app:app
```

`IS_ON_PREM=true` tells the server it talks to a self-hosted GIM instance
(API served under `/exposed/v1`, self-hosted scope set). When unset, the
server guesses from the `GITGUARDIAN_URL` hostname, which fails for
self-hosted instances deployed under a `gitguardian.com`/`gitguardian.tech`
domain — set it explicitly for any self-hosted deployment.

`MCP_OAUTH_PROXY_ENABLED=true` makes the server advertise itself as an OAuth
Protected Resource (RFC 9728) and proxy `/authorize`, `/token`, `/register`
to your GitGuardian dashboard. MCP clients then run the OAuth flow against
your domain.

`MULTI_TENANCY_ENABLED=true` (with `MCP_PORT` set) makes the server use the
token each request carries in its `Authorization` header. Without it, the
server refuses to start over HTTP, since every caller would otherwise act under
a single server-wide token.

## Configuration reference

| Variable                            | Description                                      | Default                             |
|-------------------------------------|--------------------------------------------------|-------------------------------------|
| `GITGUARDIAN_URL`                   | GitGuardian dashboard URL                        | `https://dashboard.gitguardian.com` |
| `IS_ON_PREM`                        | `true` => self-hosted; `false` => SaaS; unset ⇒ guess from hostname | Unset            |
| `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` | PAT (overrides OAuth)                            | Unset                               |
| `GITGUARDIAN_SCOPES`                | Comma-separated OAuth scopes to request          | The scopes the tools use            |
| `GITGUARDIAN_CLIENT_ID`             | OAuth client ID                                  | `ggshield_oauth`                    |
| `GITGUARDIAN_TOKEN_NAME`            | Display name for OAuth-issued PATs               | `MCP Token`                         |
| `GITGUARDIAN_TOKEN_LIFETIME`        | PAT lifetime in days (or `never`)                | `30`                                |
| `MCP_PORT`                          | Port for HTTP transport (unset ⇒ stdio)          | Unset                               |
| `MULTI_TENANCY_ENABLED`             | Use each request's `Authorization` token; required over HTTP | `false`                 |
| `MCP_HOST`                          | Bind address for HTTP transport                  | `127.0.0.1`                         |
| `MCP_BASE_URL`                      | Public URL of this MCP server (OAuth proxy mode) | `http://localhost:8000`             |
| `MCP_OAUTH_PROXY_ENABLED`           | Advertise OAuth Protected Resource metadata      | `false`                             |
| `ENABLE_LOCAL_OAUTH`                | Browser login flow in stdio                      | `true`                              |
| `LOG_LEVEL`                         | Log level                                        | `INFO`                              |
| `LOG_FORMAT`                        | `json` or `console`                              | `console` on a TTY, else `json`     |

## Migration notes

- Tool arguments are passed at the top level, `{"incident_id": 123}`, instead of
  inside a `params` object, `{"params": {"incident_id": 123}}`. A call in the old
  shape is refused with an error that says so. MCP clients that read the tool list
  pick this up on their own.
- The server now exposes the 15 tools listed in [What it does](#what-it-does).
  These tools were removed: `assign_public_incident`, `create_code_fix_request`,
  `find_current_source_id`, `get_authenticated_user_info`, `get_current_token_info`,
  `get_member`, `list_detectors`, `list_honeytokens`, `list_incident_activity_logs`,
  `list_incident_comments`, `list_incident_members`, `list_incident_teams`,
  `list_public_incident_activity_logs`, `list_public_incident_comments`,
  `list_remediation_targets`, `list_users`, `manage_public_incident_comment`,
  `read_custom_tags`, `revoke_current_token`, `revoke_secret`,
  `update_incident_severity`, `update_or_create_incident_custom_tags`,
  `update_public_incident_status`, `write_custom_tags`. Use the GitGuardian
  dashboard for those actions.
- The SSE app (`gg_mcp_server.sse_app:app`) was removed. Serve
  `gg_mcp_server.http_app:app` instead.
- The `developer-mcp-server` and `secops-mcp-server` console scripts were
  removed. Update your MCP client configuration to invoke `gg-mcp-server`.

## Want more?

Have a use case that isn't covered? [Open an issue](https://github.com/GitGuardian/ggmcp/issues)
with your idea.

## Development

See [`DEVELOPMENT.md`](DEVELOPMENT.md) for contributing, running tests, and
adding new tools.
