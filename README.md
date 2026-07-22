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

- **Secret scanning** — proactively scan files for leaked credentials.
- **Incident management** — list, filter, assign, resolve, and tag incidents
  (both internal and Public Monitoring incidents).
- **Honeytokens** — generate honeytokens and list existing ones.
- **Code-fix automation** — open pull requests that remediate secrets in
  repositories your workspace monitors.

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
List all my active honeytokens.
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
Desktop versions that pre-date HTTP MCP support need the
[Local stdio fallback](#local-stdio-mode-pat-only).

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

Two deployment paths are supported. Pick based on where your GitGuardian
instance lives and what tradeoffs you accept.

| Deployment                                                 | When to use                                                                                                              |
|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Hosted MCP** (Quick start above)                         | GitGuardian SaaS (US/EU) and you accept that requests transit `mcp.gitguardian.com` in addition to `api.gitguardian.com` |
| **Self-hosted MCP** ([§](#self-hosting-the-mcp-server))    | Self-hosted GitGuardian, airgapped environments, or you want the MCP server on your own infrastructure                   |
| **Local stdio with PAT** ([§](#local-stdio-mode-pat-only)) | CI/CD, scripts, one-off invocations, or older MCP clients without `type: http` support                                   |

## Authentication

> Most users do not need to touch this — the [Quick start](#quick-start)
> config implicitly uses the **OAuth proxy** mode on the hosted server, and the
[Local stdio](#local-stdio-mode-pat-only) config uses **PAT env**.

There are four authentication modes the server can run in; you pick one via
env vars.

| Mode                                   | Configuration                                                          | Used by                                                                                                             |
|----------------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| **OAuth proxy** (HTTP)                 | `MCP_OAUTH_PROXY_ENABLED=true` + `ENABLE_LOCAL_OAUTH=false`            | The hosted MCP server. MCP client runs OAuth against `/authorize`+`/token`; the server proxies to the GG dashboard. |
| **Raw bearer** (HTTP)                  | `ENABLE_LOCAL_OAUTH=false` + `MCP_PORT` set                            | Self-hosted deployments without OAuth. Client sends `Authorization: Bearer <PAT>` on every request.                 |
| **PAT env** (any transport)            | `GITGUARDIAN_PERSONAL_ACCESS_TOKEN=<pat>` + `ENABLE_LOCAL_OAUTH=false` | CI, scripts, local stdio. Server uses the env-var PAT for every GG API call.                                        |
| **Browser-OAuth stdio** *(deprecated)* | `ENABLE_LOCAL_OAUTH=true` (today's default in stdio)                   | Legacy `uvx --from …` flow that opens a localhost callback and stores the PAT on disk.                              |

> [!NOTE]
> Browser-driven OAuth in stdio mode is **deprecated**. New stdio deployments
> should authenticate with a PAT; OAuth-driven flows should use the hosted or
> self-hosted HTTP server. The stdio OAuth code path will be removed in a
> future release; until then it remains the default in stdio for backward
> compatibility.

## Local stdio mode (PAT-only)

For CI/CD, airgapped environments, or older MCP clients, run the server
locally over stdio with a PAT:

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
Tokens**. The set of tools the server exposes depends on the PAT's scopes.

For Claude Desktop on macOS, the `command` field needs the **absolute path**
to `uvx` (e.g. `/Users/you/.local/bin/uvx`) — Claude Desktop does not resolve
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

## Configuration reference

| Variable                            | Description                                      | Default                             |
|-------------------------------------|--------------------------------------------------|-------------------------------------|
| `GITGUARDIAN_URL`                   | GitGuardian dashboard URL                        | `https://dashboard.gitguardian.com` |
| `IS_ON_PREM`                        | `true` => self-hosted; `false` => SaaS; unset ⇒ guess from hostname | Unset            |
| `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` | PAT (overrides OAuth)                            | Unset                               |
| `GITGUARDIAN_SCOPES`                | Comma-separated OAuth scopes to request          | Auto                                |
| `GITGUARDIAN_CLIENT_ID`             | OAuth client ID                                  | `ggshield_oauth`                    |
| `GITGUARDIAN_TOKEN_NAME`            | Display name for OAuth-issued PATs               | `MCP Token`                         |
| `GITGUARDIAN_TOKEN_LIFETIME`        | PAT lifetime in days (or `never`)                | `30`                                |
| `MCP_PORT`                          | Port for HTTP transport (unset ⇒ stdio)          | Unset                               |
| `MCP_HOST`                          | Bind address for HTTP transport                  | `127.0.0.1`                         |
| `MCP_BASE_URL`                      | Public URL of this MCP server (OAuth proxy mode) | `http://localhost:8000`             |
| `MCP_OAUTH_PROXY_ENABLED`           | Advertise OAuth Protected Resource metadata      | `false`                             |
| `ENABLE_LOCAL_OAUTH`                | Legacy: enable stdio OAuth flow (deprecated)     | `true`                              |

## Migration notes

The `developer-mcp-server` and `secops-mcp-server` console scripts are
deprecated and re-export the unified `gg-mcp-server`. Update your MCP client
configuration to invoke `gg-mcp-server` directly; both old scripts will be
removed in a future release.

## Want more?

Have a use case that isn't covered? [Open an issue](https://github.com/GitGuardian/ggmcp/issues)
with your idea.

## Development

See [`DEVELOPMENT.md`](DEVELOPMENT.md) for contributing, running tests, and
adding new tools.
