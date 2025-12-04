from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.generate_honey_token import generate_honeytoken
from gg_api_core.tools.list_honeytokens import list_honeytokens
from gg_api_core.tools.list_incidents import list_incidents
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences
from gg_api_core.tools.list_users import list_users
from gg_api_core.tools.remediate_secret_incidents import remediate_secret_incidents
from gg_api_core.tools.scan_secret import scan_secrets

DEVELOPER_INSTRUCTIONS = """
# GitGuardian Developer Tools for Secret Detection & Remediation

This server provides GitGuardian's secret detection and remediation capabilities through MCP for developers working within IDE environments like Cursor, Windsurf, or Zed.

## Secret Management Capabilities

This server focuses on helping developers manage secrets in their repositories through:

1. **Finding Existing Secret Incidents**:
   - Detect secrets already identified as GitGuardian incidents in your repository
   - Use `list_incidents` to view all secret incidents in a repository
   - Filter incidents by various criteria including those assigned to you

2. **Proactive Secret Scanning**:
   - Use `scan_secrets` to detect secrets in code before they're committed
   - Identify secrets that haven't yet been reported as GitGuardian incidents
   - Prevent accidental secret commits before they happen

3. **Complete Secret Remediation**:
   - Use `remediate_secret_incidents` for guided secret removal
   - Get best practice recommendations for different types of secrets
   - Replace hardcoded secrets with environment variables
   - Create .env.example files with placeholders for detected secrets
   - Get optional git commands to repair git history containing secrets

4. **Generate and hide honey tokens**:
   - Use `generate_honey_tokens` to generate and hide honey tokens
   - If you want to create a new token, you must pass new_token=True to generate_honey_tokens
   - hide the generated token in the codebase


All tools operate within your IDE environment to provide immediate feedback and remediation steps for secret management.
"""


def register_developer_tools(mcp: AbstractGitGuardianFastMCP):
    mcp.tool(
        remediate_secret_incidents,
        description="Find and fix secrets in the current repository using exact match locations (file paths, line numbers, character indices). "
        "This tool leverages the occurrences API to provide precise remediation instructions without needing to search for secrets in files. "
        "By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
        required_scopes=["incidents:read", "sources:read"],
    )

    mcp.tool(
        scan_secrets,
        description="""
        Scan multiple content items for secrets and policy breaks.

        This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
        Each document must have a 'document' field and can optionally include a 'filename' field for better context.
        Do not send documents that are not related to the codebase, only send files that are part of the codebase.
        Do not send documents that are in the .gitignore file.
        """,
        required_scopes=["scan"],
    )

    mcp.tool(
        list_incidents,
        description="List secret incidents or occurrences related to a specific repository"
        "With mine=True, this tool only shows incidents assigned to the current user.",
        required_scopes=["incidents:read", "sources:read"],
    )

    mcp.tool(
        list_repo_occurrences,
        description="List secret occurrences for a specific repository with exact match locations. "
        "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
        "Use this tool when you need to locate and remediate secrets in the codebase with precise file locations.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        find_current_source_id,
        description="Find the GitGuardian source_id for the current repository. "
        "This tool automatically detects the current git repository and searches for its source_id in GitGuardian. "
        "Useful when you need to reference the repository in other API calls.",
        required_scopes=["sources:read"],
    )

    mcp.tool(
        generate_honeytoken,
        description="Generate an AWS GitGuardian honeytoken and get injection recommendations",
        required_scopes=["honeytokens:write"],
    )

    mcp.tool(
        list_honeytokens,
        description="List honeytokens from the GitGuardian dashboard with filtering options",
        required_scopes=["honeytokens:read"],
    )

    mcp.tool(
        list_users,
        description="List users on the workspace/account",
        required_scopes=["members:read"],
    )
