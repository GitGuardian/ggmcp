[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/gitguardian-ggmcp-badge.png)](https://mseep.ai/app/gitguardian-ggmcp)

# GitGuardian MCP Server

Stay focused on building your product while your AI assistant handles the security heavy lifting with GitGuardian's comprehensive protection.

This MCP server enables your AI agent to scan projects using GitGuardian's industry-leading API, featuring over 500 secret detectors to prevent credential leaks before they reach public repositories.

Resolve security incidents without context switching to the GitGuardian console. Take advantage of rich contextual data to enhance your agent's remediation capabilities, enabling rapid resolution and automated removal of hardcoded secrets.

## Disclaimer

> [!CAUTION]
> MCP servers are an emerging and rapidly evolving technology. While they can significantly boost productivity and improve the developer experience, their use with various agents and models should always be supervised.
>
> Agents act on your behalf and under your responsibility. Always use MCP servers from trusted sources (just as you would with any dependency), and carefully review agent actions when they interact with MCP server tools.
>
> To better assist you in safely using this server, we have:
>
> (1) Designed our MCP server to operate with "read-only" permissions, minimizing the access level granted to your agent. This helps ensure that, even if the agent tries to perform unintended actions, its capabilities remain limited to safe, non-destructive operations.
>
> (2) Released this official MCP server to ensure you are using a legitimate and trusted implementation.

## Features supported

- **Secret Scanning**: Scan code for leaked secrets, credentials, and API keys
- **Incident Management**: View security incidents related to the project you are currently working.
- **Honeytokens**: Create honeytokens to detect unauthorized access
- **Authentication Management**: Get authenticated user information and token details
- **Token Management**: Revoke current API tokens

> **Want more features?** Have a use case that's not covered? We'd love to hear from you! Submit your ideas and feedback by [opening an issue on GitHub](https://github.com/GitGuardian/ggmcp/issues) to help us prioritize new MCP server capabilities.

## Prompts examples

`Remediate all incidents related to my project`

`Scan this codebase for any leaked secrets or credentials`

`Check if there are any new security incidents assigned to me`

`Help me understand this security incident and provide remediation steps`

`List all my active honeytokens`

`Generate a new honeytoken for monitoring AWS credential access`

`Show me my most recent honeytoken and help me embed it in my codebase`

`Create a honeytoken named 'dev-database' and hide it in config files`

## Prerequisites

Before installing the GitGuardian MCP servers, ensure you have the following prerequisites:

- **uv**: This project uses uv for package installation and dependency management.
  Install uv by following the instructions at: https://docs.astral.sh/uv/getting-started/installation/

## Installation

Below are instructions for installing the GitGuardian MCP servers with various AI editors and interfaces.

The MCP server supports both GitGuardian SaaS and self-hosted instances.

### Installation with Cursor

**Quick Install with One-Click Buttons** (Cursor >= 1.0):

For Developer MCP Server:

[![Install Developer MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=GitGuardianDeveloper&config=eyJjb21tYW5kIjoidXZ4IC0tZnJvbSBnaXQraHR0cHM6Ly9naXRodWIuY29tL0dpdEd1YXJkaWFuL2dnLW1jcC5naXQgZGV2ZWxvcGVyLW1jcC1zZXJ2ZXIiLCJlbnYiOnt9fQ%3D%3D)

> **Note**: The one-click install sets up the default US SaaS configuration. For EU SaaS or self-hosted instances, you'll need to manually add environment variables as shown in the [Configuration section](#configuration-for-different-gitguardian-instances).

**Manual Configuration**:

1. Edit your Cursor MCP configuration file located at `~/.cursor/mcp.json`

2. Add the GitGuardian MCP server configuration:

   ```json
   {
     "mcpServers": {
       "GitGuardianDeveloper": {
         "command": "uvx",
         "args": [
           "--from",
           "git+https://github.com/GitGuardian/ggmcp.git",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```

### Installation with Claude Desktop

1. Edit your Claude Desktop MCP configuration file located at:

   - macOS: `~/Library/Application Support/Claude Desktop/mcp.json`
   - Windows: `%APPDATA%\Claude Desktop\mcp.json`

2. Add the GitGuardian MCP server configuration:

   ```json
   {
     "mcpServers": {
       "GitGuardianDeveloper": {
         "command": "/path/to/uvx",
         "args": [
           "--from",
           "git+https://github.com/GitGuardian/ggmcp.git",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```

3. Replace `/path/to/uvx` with the **absolute path** to the uvx executable on your system.

   > ⚠️ **WARNING**: For Claude Desktop, you must specify the full absolute path to the `uvx` executable, not just `"command": "uvx"`. This is different from other MCP clients.

4. Restart Claude Desktop to apply the changes.

### Installation with Windsurf

To use the GitGuardian MCP server with [Windsurf](https://www.windsurf.ai/):

1. Edit your Windsurf MCP configuration file located at:

   - macOS: `~/Library/Application Support/Windsurf/mcp.json`
   - Windows: `%APPDATA%\Windsurf\mcp.json`
   - Linux: `~/.config/Windsurf/mcp.json`

2. Add the following entry to the configuration file:

   ```json
   {
     "mcp": {
       "servers": {
         "GitGuardianDeveloper": {
           "type": "stdio",
           "command": "uvx",
           "args": [
             "--from",
             "git+https://github.com/GitGuardian/ggmcp.git",
             "developer-mcp-server"
           ]
         }
       }
     }
   }
   ```

### Installation with Zed Editor

1. Edit your Zed MCP configuration file located at:

   - macOS: `~/Library/Application Support/Zed/mcp.json`
   - Linux: `~/.config/Zed/mcp.json`

2. Add the GitGuardian MCP server configuration:

   ```json
   {
     "GitGuardianDeveloper": {
       "command": {
         "path": "uvx",
         "args": [
           "--from",
           "git+https://github.com/GitGuardian/ggmcp.git",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```

## Authentication

The GitGuardian MCP server supports multiple authentication methods depending on your deployment mode.

### OAuth Authentication (Default for stdio transport)

When using stdio transport (the default for desktop IDE integrations), the server uses OAuth for authentication by default:

1. OAuth is **enabled by default** (`ENABLE_LOCAL_OAUTH=true`) for local-first usage
2. When you start the server, it will automatically open a browser window to authenticate with GitGuardian
3. After you log in to GitGuardian and authorize the application, you'll be redirected back to the local server
4. The authentication token will be securely stored in `~/.gitguardian/` for future use
5. The next time you start the server, it will reuse the stored token without requiring re-authentication

**Example configuration (OAuth is enabled by default, no need to specify):**

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "developer-mcp-server"
      ]
    }
  }
}
```

**To disable OAuth** (e.g., for using PAT instead):

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "developer-mcp-server"
      ],
      "env": {
        "ENABLE_LOCAL_OAUTH": "false",
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "your_pat_here"
      }
    }
  }
}
```

### Personal Access Token (PAT) Authentication

For non-interactive environments, CI/CD pipelines, or when you prefer not to use OAuth, you can authenticate using a Personal Access Token:

1. Create a Personal Access Token in your GitGuardian dashboard
2. Set the `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` environment variable

**Example configuration with PAT:**

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "developer-mcp-server"
      ],
      "env": {
        "GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "your_personal_access_token_here"
      }
    }
  }
}
```

### Per-Request Authentication (HTTP/SSE transport)

When using HTTP/SSE transport (with `MCP_PORT` set), the server expects authentication via the `Authorization` header in each HTTP request. This is the recommended approach for server deployments.

**Important:** Since `ENABLE_LOCAL_OAUTH` defaults to `true`, you **must explicitly set it to `false`** when using HTTP/SSE mode:

```bash
# Start server with HTTP transport (OAuth must be disabled)
ENABLE_LOCAL_OAUTH=false MCP_PORT=8000 MCP_HOST=127.0.0.1 uvx --from git+https://github.com/GitGuardian/ggmcp.git developer-mcp-server

# Make authenticated request
curl -X POST http://127.0.0.1:8000/tools/list \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Configuration validation:** The server will raise an error if both `MCP_PORT` and `ENABLE_LOCAL_OAUTH=true` are set, as HTTP/SSE mode requires per-request authentication for security reasons.

## Configuration for Different GitGuardian Instances

The MCP server uses OAuth authentication and defaults to GitGuardian SaaS (US region) at `https://dashboard.gitguardian.com`. For other instances, you'll need to specify the URL:

### Environment Variables

The following environment variables can be configured:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `GITGUARDIAN_URL` | GitGuardian instance URL | `https://dashboard.gitguardian.com` | `https://dashboard.eu1.gitguardian.com` |
| `GITGUARDIAN_CLIENT_ID` | OAuth client ID | `ggshield_oauth` | `my-custom-oauth-client` |
| `GITGUARDIAN_SCOPES` | OAuth scopes to request | Auto-detected based on instance type | `scan,incidents:read,sources:read,honeytokens:read,honeytokens:write` |
| `GITGUARDIAN_TOKEN_NAME` | Name for the OAuth token | Auto-generated based on server type | `"Developer MCP Token"` |
| `GITGUARDIAN_TOKEN_LIFETIME` | Token lifetime in days | `30` | `60` or `never` |
| `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` | Personal Access Token for authentication (alternative to OAuth) | Not set | `YOUR_PAT_TOKEN` |
| `ENABLE_LOCAL_OAUTH` | Enable local OAuth flow (stdio mode only, cannot be used with `MCP_PORT`) | `true` (enabled by default for local-first usage) | `false` |
| `MCP_PORT` | Port for HTTP/SSE transport (when set, enables HTTP transport instead of stdio, requires `ENABLE_LOCAL_OAUTH=false`) | Not set (uses stdio) | `8000` |
| `MCP_HOST` | Host address for HTTP/SSE transport | `127.0.0.1` | `0.0.0.0` |

### HTTP/SSE Transport

By default, the MCP server uses **stdio transport** for local IDE integrations. If you need to expose the MCP server over HTTP (for remote access or custom integrations), you can use the `MCP_PORT` and `MCP_HOST` environment variables.

#### Enabling HTTP Transport

To enable HTTP/SSE transport, set the `MCP_PORT` environment variable. **Important:** You must also set `ENABLE_LOCAL_OAUTH=false` since OAuth defaults to enabled:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "developer-mcp-server"
      ],
      "env": {
        "ENABLE_LOCAL_OAUTH": "false",
        "MCP_PORT": "8000",
        "MCP_HOST": "127.0.0.1"
      }
    }
  }
}
```

#### Running the server directly with HTTP transport

You can also run the server directly with HTTP transport:

```bash
# Run with HTTP transport (must disable OAuth)
ENABLE_LOCAL_OAUTH=false MCP_PORT=8000 MCP_HOST=127.0.0.1 uvx --from git+https://github.com/GitGuardian/ggmcp.git developer-mcp-server
```

The server will automatically start on `http://127.0.0.1:8000` and be accessible for remote integrations.

#### Authentication via Authorization Header

When using HTTP/SSE transport, authentication is done via the `Authorization` header on each request. See the [Per-Request Authentication](#per-request-authentication-httpsse-transport) section for detailed configuration.

**Supported header formats:**
- `Authorization: Bearer <token>`
- `Authorization: Token <token>`
- `Authorization: <token>`

**Example using curl:**

```bash
# List available tools
curl -X POST http://127.0.0.1:8000/tools/list \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Call a tool
curl -X POST http://127.0.0.1:8000/tools/call \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "get_authenticated_user_info", "arguments": {}}'
```

**Example using Python:**

```python
import httpx

headers = {
    "Authorization": "Bearer YOUR_PERSONAL_ACCESS_TOKEN",
    "Content-Type": "application/json"
}

async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://127.0.0.1:8000/tools/list",
        headers=headers,
        json={}
    )
    tools = response.json()
```

**Authentication Priority:**

When using HTTP transport, the authentication priority is:
1. **Authorization header** (if present in the HTTP request) - recommended for HTTP/SSE mode
2. **GITGUARDIAN_PERSONAL_ACCESS_TOKEN** environment variable - fallback option

Note that OAuth (`ENABLE_LOCAL_OAUTH=true`) is not supported in HTTP/SSE mode for security reasons. Each HTTP request must include its own authentication credentials.

**Notes:**
- `uvicorn` is included as a dependency - no additional installation needed.
- When `MCP_PORT` is not set, the server uses stdio transport (default behavior).
- `MCP_HOST` defaults to `127.0.0.1` (localhost only). Use `0.0.0.0` to allow connections from any network interface.
- The HTTP/SSE transport is useful for remote access, but stdio is recommended for local IDE integrations.
- Each HTTP request can have its own Authorization header, allowing multi-tenant use cases.

### Self-Hosted GitGuardian

For self-hosted GitGuardian instances, add the `GITGUARDIAN_URL` environment variable to your MCP configuration:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GitGuardian/ggmcp.git", "developer-mcp-server"],
      "env": {
        "GITGUARDIAN_URL": "https://dashboard.gitguardian.mycorp.local"
      }
    }
  }
}
```

### Self-Hosted with Honeytoken Support

If your self-hosted instance has honeytokens enabled and your user has the required permissions ("manager" role), you can explicitly request honeytoken scopes:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GitGuardian/ggmcp.git", "developer-mcp-server"],
      "env": {
        "GITGUARDIAN_URL": "https://dashboard.gitguardian.mycorp.local",
        "GITGUARDIAN_SCOPES": "scan,incidents:read,sources:read,honeytokens:read,honeytokens:write"
      }
    }
  }
}
```

### GitGuardian EU Instance

For the GitGuardian EU instance, use:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GitGuardian/ggmcp.git", "developer-mcp-server"],
      "env": {
        "GITGUARDIAN_URL": "https://dashboard.eu1.gitguardian.com"
      }
    }
  }
}
```

### Custom OAuth Client

If you have your own OAuth application configured in GitGuardian, you can specify a custom client ID:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GitGuardian/ggmcp.git", "developer-mcp-server"],
      "env": {
        "GITGUARDIAN_CLIENT_ID": "my-custom-oauth-client"
      }
    }
  }
}
```

## Development

If you want to contribute to this project or add new tools, please see the [Development Guide](DEVELOPMENT.md).

## Testing

This project includes a comprehensive test suite to ensure functionality and prevent regressions.

### Running Tests

1. Install development dependencies:
   ```bash
   uv sync --dev
   ```

2. Run the test suite:
   ```bash
   ENABLE_LOCAL_OAUTH=false uv run pytest
   ```

   Note: Tests disable OAuth by default via the `ENABLE_LOCAL_OAUTH=false` environment variable to prevent OAuth prompts during test execution.

3. Run tests with verbose output:
   ```bash
   ENABLE_LOCAL_OAUTH=false uv run pytest -v
   ```

4. Run tests with coverage:
   ```bash
   ENABLE_LOCAL_OAUTH=false uv run pytest --cov=packages --cov-report=html
   ```

This will run all tests and generate a coverage report showing which parts of the codebase are covered by tests.
