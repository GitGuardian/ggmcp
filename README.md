# GitGuardian MCP Server

A specialized MCP server workspace that brings GitGuardian API features to your AI assistants, enabling powerful security capabilities wherever you use MCP.

## Available Servers

This project provides a specialized MCP server:

- **Developer MCP Server**: A lightweight server focused on developer needs, providing remediation tools without the full security suite

## Key Features

- **Secret Scanning**: Scan code for leaked secrets, credentials, and API keys
- **Incident Management**: View, assign, and resolve security incidents
- **Honeytokens**: Create and manage honeytokens to detect unauthorized access
- **Custom Tagging**: Organize incidents with custom tags

## Installation

Below are instructions for installing the GitGuardian MCP servers with various AI editors and interfaces.




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
     "mcpServers": {
       "GitGuardianDeveloper": {
         "command": "uvx",
         "args": [
           "--env-file",
           "/path/to/.env",
           "--from",
           "git+https://github.com/GitGuardian/gg-mcp.git",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```



3. Replace `/path/to/.env` with the absolute path to your `.env` file if you're using one.

4. Restart Windsurf to apply the changes.

### Installation with Cursor

**Quick Install with One-Click Buttons** (Cursor >= 1.0):

For Developer MCP Server:
[![Install Developer MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=GitGuardianDeveloper&config=eyJjb21tYW5kIjoidXZ4IC0tZnJvbSBnaXQraHR0cHM6Ly9naXRodWIuY29tL0dpdEd1YXJkaWFuL2dnLW1jcC5naXQgZGV2ZWxvcGVyLW1jcC1zZXJ2ZXIifQ%3D%3D)


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

3. Restart Cursor to apply the changes.


### Installation with Zed Editor

1. Edit your Zed MCP configuration file located at:

   - macOS: `~/Library/Application Support/Zed/mcp.json`
   - Linux: `~/.config/Zed/mcp.json`

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



3. Restart Zed to apply the changes.

### Local Installation

If you want to run the server from a local clone of the repository:

1. Clone the repository:
   ```bash
   git clone https://github.com/GitGuardian/gg-mcp-server.git
   cd gg-mcp-server
   ```

2. Install dependencies:
   ```bash
   uv sync
   ```

3. Run the server:
   ```bash
   python -m packages.developer_mcp_server.src.developer_mcp_server.server
   ```

#### Local Installation with Cursor

To use a local clone with Cursor:

```json
{
  "mcpServers": {
    "GitGuardianDeveloperLocal": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/your/workspace/gg-mcp-server",
        "run",
        "--env-file",
        ".env",
        "packages.developer_mcp_server.src.developer_mcp_server.server"
      ]
    }
  }
}
```

Replace `/path/to/your/workspace/gg-mcp-server` with the absolute path to your local repository.

## Running the Server

To run the MCP server:

```bash
python -m packages.developer_mcp_server.src.developer_mcp_server.server
```

### Authentication Process

1. When you start the server, it will automatically open a browser window to authenticate with GitGuardian
2. After you log in to GitGuardian and authorize the application, you'll be redirected back to the local server
3. The authentication token will be securely stored for future use
4. The next time you start the server, it will reuse the stored token without requiring re-authentication

## Development Setup

If you want to contribute to the MCP server development, follow these steps:

### Prerequisites

- [mise](https://mise.jdx.dev/) (recommended for Python version management)
- [uv](https://github.com/astral-sh/uv) (required for package management)

### Setting up the Development Environment

1. Clone this repository:

   ```bash
   git clone https://github.com/GitGuardian/gg-mcp-server.git
   cd gg-mcp-server
   ```

2. Install the required Python version (3.13+) using mise:

   ```bash
   mise install
   ```

3. Install dependencies including development tools:
   ```bash
   uv sync --with dev
   ```

4. Run the server in development mode:
   ```bash
   python -m packages.developer_mcp_server.src.developer_mcp_server.server
   ```

By default, the server will use OAuth authentication, automatically opening a browser window for you to authenticate with GitGuardian. No configuration file is needed for the basic setup.

## Authentication Methods

The GitGuardian MCP server supports two authentication methods:

1. **OAuth Authentication** (default): Uses the OAuth flow to authenticate with GitGuardian
2. **Token Authentication**: Uses a GitGuardian API key for authentication

### When to Use Environment Variables

The server works out-of-the-box without any configuration. However, you might want to use an `.env` file in the following cases:

- To use token-based authentication instead of OAuth
- To configure custom OAuth settings (token lifetime, scopes, etc.)
- To connect to a different GitGuardian instance (like a local development environment)
- To customize other server behavior

In these cases, you would use the `--env-file` option when running the server:

```bash
python -m packages.developer_mcp_server.src.developer_mcp_server.server --env-file /path/to/.env
```

Or when using with `uvx`:

```bash
uvx --env-file /path/to/.env --from=git+https://github.com/GitGuardian/gg-mcp.git developer-mcp-server
```

This approach keeps sensitive API keys separate from your configuration files and follows security best practices.

## Environment Variables Reference

Below is a complete reference of environment variables you can use to configure the GitGuardian MCP server. None of these are required for basic usage as the server uses sensible defaults.

### Complete .env Example

```bash
# Authentication Method (default: 'web')
# GITGUARDIAN_AUTH_METHOD=web

# API Configuration
# GITGUARDIAN_API_KEY=your_api_key_here               # Required only for token authentication
# GITGUARDIAN_API_URL=https://api.gitguardian.com/v1  # Default API URL
# GITGUARDIAN_DASHBOARD_URL=https://dashboard.gitguardian.com  # Dashboard URL

# OAuth Configuration
# GITGUARDIAN_LOGIN_PATH=auth/login                   # Custom login path
# GITGUARDIAN_REQUESTED_SCOPES=scan,incidents:read    # Limit requested scopes
# GITGUARDIAN_USE_DASHBOARD_AUTHENTICATED_PAGE=true   # Use dashboard page after auth
# GITGUARDIAN_TOKEN_LIFETIME=30                       # Token lifetime in days (or 'never')
# GITGUARDIAN_TOKEN_NAME=MCP server token             # Custom token name
```

### Authentication Variables

- `GITGUARDIAN_AUTH_METHOD`: Authentication method (`web` for OAuth or `token` for API key)
- `GITGUARDIAN_API_KEY`: Your GitGuardian API key (required only for token authentication)

### API and URL Configuration

- `GITGUARDIAN_API_URL`: GitGuardian API URL (default: https://api.gitguardian.com/v1)
- `GITGUARDIAN_DASHBOARD_URL`: GitGuardian dashboard URL (default: https://dashboard.gitguardian.com)

### OAuth Configuration

- `GITGUARDIAN_LOGIN_PATH`: Custom login path (default: auth/login)
- `GITGUARDIAN_TOKEN_LIFETIME`: OAuth token lifetime in days (default: 30, use 'never' for no expiration)
- `GITGUARDIAN_TOKEN_NAME`: Custom name for the OAuth token (default: "MCP server token")
- `GITGUARDIAN_USE_DASHBOARD_AUTHENTICATED_PAGE`: If true, redirects to GitGuardian dashboard after authentication (default: false)

### Scope Configuration

- `GITGUARDIAN_REQUESTED_SCOPES`: Comma-separated list of OAuth scopes to request

#### Available OAuth Scopes

- `scan`: For scanning content for secrets
- `incidents:read`: For reading incidents
- `incidents:write`: For updating incidents
- `api_tokens:read`: For reading API token information
- `honeytokens:read`: For reading honeytokens
- `honeytokens:write`: For creating honeytokens
- `custom_tags:read`: For reading custom tags
- `custom_tags:write`: For creating/updating custom tags

By default, the server will request all available scopes.

Example:

```
GITGUARDIAN_REQUESTED_SCOPES=scan,incidents:read,incidents:write
```

5. Run the MCP server locally:
   ```bash
   uv run --env-file .env developer-mcp-server
   ```

   If using OAuth authentication, the server will open a browser window for you to log in to GitGuardian.

6. For local development with Cursor, update your Cursor MCP configuration file at `~/.cursor/mcp.json`:
   ```json
   {
     "mcpServers": {
       "GitGuardianDeveloperLocal": {
         "command": "uv",
         "args": [
           "--directory",
           "/path/to/your/workspace/gg-mcp-server",
           "run",
           "--env-file",
           ".env",
           "developer-mcp-server"
         ]
       }
     }
   }
   ```
   
   Replace `/path/to/your/workspace/gg-mcp-server` with the absolute path to your cloned repository.

7. Restart Cursor to apply the changes.

## Running the Server

Start the MCP server:

```bash
mcp dev packages.developer_mcp_server.src.developer_mcp_server.server.py
```

This runs the server using MCP's native server capabilities (no external web server needed).

## API Token Scopes

The GitGuardian MCP server implements scope-based access control for its tools. Each tool requires specific API token scopes to execute. If your API token lacks the necessary scopes, you'll receive a helpful message explaining which scopes are needed.

### How Scopes Work

1. When the server starts, it automatically detects the scopes associated with your GitGuardian API token
2. All tools are visible to the LLM (Claude, GPT, etc.) regardless of scope permissions
3. When a tool is invoked, the server checks if your token has the required scopes
4. If the required scopes are missing, the tool returns a helpful message indicating which scopes are needed

### Required Scopes for Tools

| Tool                                    | Required Scopes            |
| --------------------------------------- | -------------------------- |
| `generate_honeytoken`                   | `honeytokens:write`        |
| `list_honeytokens`                      | `honeytokens:read`         |
| `list_incidents`                        | `incidents:read`           |
| `manage_incident`                       | `incidents:write`          |
| `update_incident_status`                | `incidents:write`          |
| `update_or_create_incident_custom_tags` | `incidents:write`          |
| `get_current_token_info`                | `api_tokens:read`          |
| `read_custom_tags`                      | `custom_tags:read`         |
| `write_custom_tags`                     | `custom_tags:write`        |
| `scan_secrets`                          | `scan`                     |

### Obtaining a Token with Additional Scopes

To get a GitGuardian API token with the necessary scopes:

1. Go to the GitGuardian Dashboard
2. Navigate to Settings > API
3. Create a new API token with the required scopes
4. Update your environment variables with the new token

## Available Tools

This repository hosts multiple MCP tools that can be used by AI assistants. Each tool is documented below.

### GitGuardian Honeytokens

#### generate_honeytoken

Generates fake AWS credentials using GitGuardian's API that can alert you when they are leaked or discovered.

##### Parameters
- `name`: Name for the honeytoken (required)
- `description`: Description of what the honeytoken is used for (optional)

##### Response
- `id`: ID of the created honeytoken
- `name`: Name of the honeytoken
- `token`: The honeytoken value
- `created_at`: Creation timestamp
- `status`: Current status
- `type`: Always "AWS"
- `injection_recommendations`: Usage instructions

#### list_honeytokens

Lists honeytokens from the GitGuardian dashboard with filtering options.

##### Parameters
- `status`: Filter by status (ACTIVE or REVOKED)
- `search`: Search string to filter results by name or description
- `ordering`: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
- `show_token`: Whether to include token details in the response (default: false)
- `creator_id`: Filter by creator ID
- `creator_api_token_id`: Filter by creator API token ID
- `per_page`: Number of results per page (default: 20, min: 1, max: 100)
- `get_all`: Fetch all results using cursor-based pagination (default: false)
- `mine`: Fetch honeytokens created by the current user (default: false)

### Incident Management

#### list_incidents

Lists secret incidents detected by the GitGuardian dashboard with filtering options.

##### Parameters
- `severity`: Filter by severity level (critical, high, medium, low)
- `status`: Filter by status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED)
- `from_date`: Filter incidents created after this date (ISO format: YYYY-MM-DD)
- `to_date`: Filter incidents created before this date (ISO format: YYYY-MM-DD)
- `assignee_email`: Filter incidents assigned to a specific email address
- `assignee_id`: Filter incidents assigned to a specific member ID
- `validity`: Filter by validity status (valid, invalid, failed_to_check, no_checker, unknown)
- `ordering`: Sort field (date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at)
- `per_page`: Number of results per page (default: 20, min: 1, max: 100)
- `get_all`: Fetch all results using cursor-based pagination (default: false)
- `mine`: Fetch incidents assigned to the current user (default: false)

#### manage_incident

Manage a secret incident (assign, unassign, resolve, ignore, reopen).

##### Parameters
- `incident_id`: ID of the secret incident to manage (required)
- `action`: Action to perform on the incident (assign, unassign, resolve, ignore, reopen) (required)
- `assignee_id`: ID of the member to assign the incident to (required for 'assign' action)
- `ignore_reason`: Reason for ignoring (test_credential, false_positive, etc.) (used with 'ignore' action)
- `mine`: Use the current user's ID for the assignee_id (default: false)

#### update_incident_status

Update a secret incident's status.

##### Parameters
- `incident_id`: ID of the secret incident (required)
- `status`: New status (IGNORED, TRIGGERED, ASSIGNED, RESOLVED) (required)

#### update_or_create_incident_custom_tags

Update or create custom tags for a secret incident.

##### Parameters
- `incident_id`: ID of the secret incident (required)
- `custom_tags`: List of custom tags to apply to the incident (required)

### Token Management

#### get_current_token_info

Get information about the current API token.

##### Response
- Information about the current API token, including scopes and member ID

### Custom Tags Management

#### read_custom_tags

Read custom tags from the GitGuardian dashboard.

##### Parameters
- `action`: Action to perform (list_tags, get_tag) (required)
- `tag_id`: ID of the custom tag to retrieve (used with 'get_tag' action)

#### write_custom_tags

Create or delete custom tags in the GitGuardian dashboard.

##### Parameters
- `action`: Action to perform (create_tag, delete_tag) (required)
- `key`: Key for the new tag (used with 'create_tag' action)
- `value`: Value for the new tag (used with 'create_tag' action)
- `tag_id`: ID of the custom tag to delete (used with 'delete_tag' action)

### Security Scanning

#### scan_secrets

Scan multiple content items for secrets and policy breaks.

##### Parameters
- `documents`: List of documents to scan, each with 'document' and optional 'filename' (required)
  Format: `[{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]`

##### Important Notes
- 'document' is the content of the file (not the filename) and is mandatory
- Do not send documents that are not related to the codebase or are in .gitignore
- Send batches of less than 20 documents at a time

## Integration Examples

### Example: Generate a Honeytoken

```python
# Example LLM prompt: "Generate a new AWS honeytoken for monitoring"
await mcp.invoke_tool("generate_honeytoken", {"name": "aws-monitoring-token", "description": "Production monitoring token"})
```

### Example: List Recent Incidents

```python
# Example LLM prompt: "Show me my recent security incidents"
await mcp.invoke_tool("list_incidents", {"mine": True, "ordering": "-date", "per_page": 5})
```

### Example: Scan for Secrets

```python
# Example LLM prompt: "Scan my code files for secrets"
await mcp.invoke_tool("scan_secrets", {"documents": [{"document": file_content, "filename": "config.py"}]})
```

## Development

If you want to contribute to this project or add new tools, please see the [Development Guide](DEVELOPMENT.md).

## Testing

This project includes a comprehensive test suite to ensure functionality and prevent regressions.

### Running Tests

1. Run the test suite:
   ```bash
   uv run pytest
   ```

This will run all tests and generate a coverage report showing which parts of the codebase are covered by tests.
