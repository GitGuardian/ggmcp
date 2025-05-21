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

5. Run the MCP server locally:
   ```bash
   uv run --env-file .env gg-mcp-server
   ```

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

## Environment Variables and Best Practices

The GitGuardian MCP server requires an API key to authenticate with the GitGuardian API. The recommended approach is to use an `.env` file to manage your environment variables:

1. Create an `.env` file with your GitGuardian API credentials:

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
| `list_my_honeytokens`                   | `honeytokens:read`         |
| `list_incidents`                        | `incidents:read`           |
| `list_my_incidents`                     | `incidents:read`           |
| `list_all_incidents`                    | `incidents:read`           |
| `manage_incident`                       | `incidents:write`          |
| `update_incident_status`                | `incidents:write`          |
| `update_or_create_incident_custom_tags` | `incidents:write`          |
| `get_current_token_info`                | No specific scope required |
| `search_team`                           | `teams:read`               |
| `add_member_to_team`                    | `teams:write`              |
| `read_custom_tags`                      | `incidents:read`           |
| `write_custom_tags`                     | `incidents:write`          |
| `scan_multiple_contents`                | `scan`                     |

### Obtaining a Token with Additional Scopes

To get a GitGuardian API token with the necessary scopes:

1. Go to the GitGuardian Dashboard
2. Navigate to Settings > API
3. Create a new API token with the required scopes
4. Update your environment variables with the new token

## Available Tools

This repository hosts multiple MCP tools that can be used by AI assistants. Each tool is documented below.

### GitGuardian Honeytokens

The Honeytoken tool generates fake credentials using GitGuardian's API that can alert you when they are leaked or discovered outside your secure environment.

#### Required Environment Variables

- `GITGUARDIAN_API_KEY`: Your GitGuardian API key
- `GITGUARDIAN_API_URL`: GitGuardian API URL (optional, defaults to https://api.gitguardian.com/v1)

##### Parameters

- `status`: Filter by status (ACTIVE or REVOKED)
- `search`: Search string to filter results by name or description
- `ordering`: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
- `show_token`: Whether to include token details in the response (default: false)
- `creator_id`: Filter honeytokens by creator ID
- `creator_api_token_id`: Filter honeytokens by the API token ID used to create them
- `per_page`: Number of results per page (default: 20)
- `page`: Page number (default: 1)

##### Response

The tool returns a list of honeytokens matching the specified criteria, including:

- `id`: The unique ID of the honeytoken
- `name`: Name of the honeytoken
- `description`: Description of the honeytoken
- `created_at`: Creation timestamp
- `status`: Current status (ACTIVE or REVOKED)
- `type`: Type of honeytoken (e.g., "AWS")
- `token`: The actual token value (only if show_token is true)

#### Integration with LLM

Example prompt for AI assistants:
"List all active honeytokens in my GitGuardian workspace."

#### Important Notes

- Never check your actual GITGUARDIAN_API_KEY into source control
- Honeytokens are designed to look like real credentials but don't provide actual access
- GitGuardian will alert you if these tokens are discovered outside your secure environment

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
