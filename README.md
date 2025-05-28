# GG MCP Server

A Model Context Protocol (MCP) server implementation based on the [official Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Prerequisites

- [mise](https://mise.jdx.dev/) (recommended for Python version management)
- [uv](https://github.com/astral-sh/uv) (required for package management)

## Setup with mise

1. Clone this repository:

   ```bash
   git clone https://github.com/GitGuardian/gg-mcp.git
   cd gg-mcp
   ```

2. Install the required Python version using mise:

   ```bash
   mise install
   ```

3. Install dependencies with uv (required):
   ```bash
   uv sync
   ```

## Development Setup

If you want to contribute to the MCP server development, follow these steps:

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

4. Create a `.env` file in the project root with your GitGuardian API credentials:
   ```
   GITGUARDIAN_API_KEY=your_api_key_here
   GITGUARDIAN_API_URL=https://api.gitguardian.com/v1
   ```

### OAuth Authentication

OAuth authentication allows you to authenticate with GitGuardian using the web flow without providing an API key directly. This method opens a browser window for authentication and creates a token automatically.

1. Create an `.env` file with OAuth configuration:

   ```
   GITGUARDIAN_AUTH_METHOD=web
   GITGUARDIAN_API_URL=https://api.gitguardian.com/v1
   # Optional - customize the base URL for authentication (for local development)
   # GITGUARDIAN_DASHBOARD_URL=http://localhost:3000
   # Optional - customize the login path
   # GITGUARDIAN_LOGIN_PATH=auth/login
   # Optional - specify which scopes to request (comma-separated)
   # GITGUARDIAN_REQUESTED_SCOPES=scan,incidents:read,incidents:write
   # Optional - use the GitGuardian dashboard authenticated page instead of the local success page
   # GITGUARDIAN_USE_DASHBOARD_AUTHENTICATED_PAGE=true
   ```

2. Run the MCP server:

   ```bash
   uv run --env-file .env gg-mcp-server
   ```

3. The server will open a browser window for you to log in to GitGuardian. After successful authentication, the token will be stored and used for API requests.

#### Available OAuth Scopes

You can restrict which scopes are requested during OAuth authentication by setting the `GITGUARDIAN_REQUESTED_SCOPES` environment variable. The available scopes are:

- `scan`: For scanning content for secrets
- `incidents:read`: For reading incidents
- `incidents:write`: For updating incidents
- `api_tokens:read`: For reading API token information
- `honeytokens:read`: For reading honeytokens
- `honeytokens:write`: For creating honeytokens
- `custom_tags:read`: For reading custom tags
- `custom_tags:write`: For creating/updating custom tags
- `teams:read`: For reading team information
- `teams:write`: For updating team information

By default, the server will request all available scopes. To request specific scopes, set the `GITGUARDIAN_REQUESTED_SCOPES` environment variable to a comma-separated list of scopes.

Example:

```
GITGUARDIAN_REQUESTED_SCOPES=scan,incidents:read,incidents:write
```

5. Run the MCP server locally:
   ```bash
   uv run --env-file .env gg-mcp-server
   ```

   If using OAuth authentication, the server will open a browser window for you to log in to GitGuardian.

6. For local development with Cursor, update your Cursor MCP configuration file at `~/.cursor/mcp.json`:
   ```json
   {
     "mcpServers": {
       "GitGuardianLocal": {
         "command": "uv",
         "args": [
           "--directory",
           "/path/to/your/workspace/gg-mcp-server",
           "run",
           "--env-file",
           ".env",
           "gg-mcp-server"
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
mcp dev src/gg_api_mcp_server/server.py
```

This runs the server using MCP's native server capabilities (no external web server needed).

## Authentication Methods

The GitGuardian MCP server supports two authentication methods:

1. **OAuth Authentication** (default): Uses the OAuth flow to authenticate with GitGuardian
2. **Token Authentication**: Uses a GitGuardian API key for authentication

### Token Authentication

Token authentication requires an API key to authenticate with the GitGuardian API. The recommended approach is to use an `.env` file to manage your environment variables:

1. Create an `.env` file with your GitGuardian API credentials for token authentication:

   ```
   GITGUARDIAN_API_KEY=your_api_key_here
   GITGUARDIAN_API_URL=https://api.gitguardian.com/v1
   ```

2. When configuring your MCP client, use the `--env-file` option with `uvx` to load these environment variables:
   ```
   uvx --env-file /path/to/.env --from=git+https://github.com/GitGuardian/gg-mcp.git gg-mcp
   ```

This approach keeps sensitive API keys separate from your configuration files and follows security best practices.

## Installation Options

<details>
<summary><strong>Local Installation</strong></summary>

To install and run the GitGuardian MCP server locally:

1. Clone the repository:

   ```bash
   git clone https://github.com/GitGuardian/gg-mcp.git
   cd gg-mcp
   ```

2. Install the required Python version using mise:

   ```bash
   mise install
   ```

3. Install dependencies with uv (required):

   ```bash
   uv sync
   ```

4. Run the server:
   ```bash
   mcp dev src/gg_api_mcp_server/server.py
   ```
   </details>

<details>
<summary><strong>Installing in Cursor</strong></summary>

To use the GitGuardian MCP server with Cursor directly from GitHub:

1. Update your Cursor MCP configuration file located at `~/.cursor/mcp.json`. Add the following entry:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "command": "uvx",
      "args": [
        "--env-file",
        "/path/to/.env",
        "--from",
        "git+https://github.com/GitGuardian/gg-mcp.git",
        "gg-mcp"
      ]
    }
  }
}
```

2. Replace `/path/to/.env` with the absolute path to your `.env` file.

3. Restart Cursor to apply the changes.
</details>

<details>
<summary><strong>Installing with Claude Desktop</strong></summary>

To use the GitGuardian MCP server with [Claude Desktop](https://modelcontextprotocol.io/quickstart/user):

1. Edit your Claude Desktop MCP configuration file located at:

   - macOS: `~/Library/Application Support/Claude/mcp.json`
   - Windows: `%APPDATA%\Claude\mcp.json`
   - Linux: `~/.config/Claude/mcp.json`

2. Add the following entry to the configuration file:

   ```json
   {
     "mcpServers": {
       "GitGuardian": {
         "command": "/path/to/uvx",
         "args": [
           "--env-file",
           "/path/to/.env",
           "--from",
           "git+https://github.com/GitGuardian/gg-mcp.git",
           "gg-mcp"
         ]
       }
     }
   }
   ```

3. Replace:

   - `/path/to/uvx` with the full absolute path to the uvx executable (e.g., `/usr/local/bin/uvx` or `C:\Users\username\AppData\Local\Programs\Python\Python311\Scripts\uvx.exe`)
   - `/path/to/.env` with the absolute path to your `.env` file

4. Restart Claude Desktop to apply the changes.

> **Note**: Claude Desktop requires the full absolute path to the `uvx` executable, not just the command name.

</details>

<details>
<summary><strong>Installing with Zed Editor</strong></summary>

To use the GitGuardian MCP server with [Zed Editor](https://zed.dev/docs/ai/mcp#bring-your-own-mcp-server):

1. Edit your Zed MCP configuration file located at:

   - macOS: `~/Library/Application Support/Zed/mcp.json`
   - Linux: `~/.config/Zed/mcp.json`

2. Add the following entry to the configuration file:

   ```json
   {
     "context_servers": {
       "GitGuardian": {
         "command": {
           "path": "uvx",
           "args": [
             "--env-file",
             "/path/to/.env",
             "--from",
             "git+https://github.com/GitGuardian/gg-mcp.git",
             "gg-mcp"
           ]
         }
       }
     }
   }
   ```

3. Replace `/path/to/.env` with the absolute path to your `.env` file.

4. Restart Zed to apply the changes.
</details>

<details>
<summary><strong>Installing with Windsurf</strong></summary>

To use the GitGuardian MCP server with [Windsurf](https://www.windsurf.ai/):

1. Edit your Windsurf MCP configuration file located at:

   - macOS: `~/Library/Application Support/Windsurf/mcp.json`
   - Windows: `%APPDATA%\Windsurf\mcp.json`
   - Linux: `~/.config/Windsurf/mcp.json`

2. Add the following entry to the configuration file:

   ```json
   {
     "mcpServers": {
       "GitGuardian": {
         "command": "uvx",
         "args": [
           "--env-file",
           "/path/to/.env",
           "--from",
           "git+https://github.com/GitGuardian/gg-mcp.git",
           "gg-mcp"
         ]
       }
     }
   }
   ```

3. Replace `/path/to/.env` with the absolute path to your `.env` file.

4. Restart Windsurf to apply the changes.
</details>

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
| `search_team`                           | `teams:read`               |
| `add_member_to_team`                    | `teams:write`              |
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

### Team Management

#### search_team

Search for teams and team members.

##### Parameters
- `action`: Action to perform (list_teams, search_team, list_members, search_member) (required)
- `team_name`: The name of the team to search for (used with 'search_team' action)
- `member_name`: The name of the member to search for (used with 'search_member' action)

#### add_member_to_team

Add a member to a team.

##### Parameters
- `team_id`: ID of the team to add the member to (required)
- `member_id`: ID of the member to add to the team (required)

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
