# GitGuardian MCP Server

Stay focused on building your product while your AI assistant handles the security heavy lifting with GitGuardian's comprehensive protection.

This MCP server enables your AI agent to scan projects using GitGuardian's industry-leading API, featuring over 500 secret detectors to prevent credential leaks before they reach public repositories.

Resolve security incidents without context switching to the GitGuardian console. Take advantage of rich contextual data to enhance your agent's remediation capabilities, enabling rapid resolution and automated removal of hardcoded secrets.

## Key Features

- **Secret Scanning**: Scan code for leaked secrets, credentials, and API keys
- **Incident Management**: View, assign, and resolve security incidents related to the project you are currently working.
- **Honeytokens**: Create and manage honeytokens to detect unauthorized access

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

## Authentication Process

1. When you start the server, it will automatically open a browser window to authenticate with GitGuardian
2. After you log in to GitGuardian and authorize the application, you'll be redirected back to the local server
3. The authentication token will be securely stored for future use
4. The next time you start the server, it will reuse the stored token without requiring re-authentication

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
