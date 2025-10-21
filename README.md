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

> **Want more features?** Have a use case that's not covered? We'd love to hear from you! Submit your ideas and feedback by [opening an issue on GitHub](https://github.com/GitGuardian/gg-mcp/issues) to help us prioritize new MCP server capabilities.

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
           "git+https://github.com/GitGuardian/gg-mcp.git",
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
           "git+https://github.com/GitGuardian/gg-mcp.git",
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
             "git+https://github.com/GitGuardian/gg-mcp.git",
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
           "git+https://github.com/GitGuardian/gg-mcp.git",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```

## Authentication Process

1. When you start the server, it will automatically open a browser window to authenticate with GitGuardian
2. After you log in to GitGuardian and authorize the application, you'll be redirected back to the local server
3. The authentication token will be securely stored for future use
4. The next time you start the server, it will reuse the stored token without requiring re-authentication

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

### Self-Hosted GitGuardian

For self-hosted GitGuardian instances, add the `GITGUARDIAN_URL` environment variable to your MCP configuration:

```json
{
  "mcpServers": {
    "GitGuardianDeveloper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/GitGuardian/gg-mcp.git", "developer-mcp-server"],
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
      "args": ["--from", "git+https://github.com/GitGuardian/gg-mcp.git", "developer-mcp-server"],
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
      "args": ["--from", "git+https://github.com/GitGuardian/gg-mcp.git", "developer-mcp-server"],
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
      "args": ["--from", "git+https://github.com/GitGuardian/gg-mcp.git", "developer-mcp-server"],
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
   uv run pytest
   ```

3. Run tests with verbose output:
   ```bash
   uv run pytest -v
   ```

4. Run tests with coverage:
   ```bash
   uv run pytest --cov=packages --cov-report=html
   ```

This will run all tests and generate a coverage report showing which parts of the codebase are covered by tests.
