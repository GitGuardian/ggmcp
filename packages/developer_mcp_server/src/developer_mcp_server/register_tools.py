from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.count_incidents import count_incidents
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.generate_honey_token import generate_honeytoken
from gg_api_core.tools.get_incident import get_incident
from gg_api_core.tools.get_member import get_member
from gg_api_core.tools.list_detectors import list_detectors
from gg_api_core.tools.list_honeytokens import list_honeytokens
from gg_api_core.tools.list_incidents import list_incidents
from gg_api_core.tools.list_public_incidents import list_public_incidents
from gg_api_core.tools.list_public_occurrences import list_public_occurrences
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences
from gg_api_core.tools.list_sources import list_sources
from gg_api_core.tools.list_users import list_users
from gg_api_core.tools.remediate_secret_incidents import remediate_secret_incidents
from gg_api_core.tools.scan_secret import scan_secrets

DEVELOPER_INSTRUCTIONS = """
# GitGuardian Developer Tools for Secret Detection & Remediation

This server provides GitGuardian's secret detection and remediation capabilities through MCP for developers working within IDE environments like Cursor, Windsurf, or Zed.

## Two incident categories — pick the right tool

GitGuardian surfaces two distinct, non-overlapping categories of secret incidents:

- **Internal incidents** — detected in sources the workspace has explicitly integrated:
  private/org Git repos, Slack, Jira, Confluence, container registries, SharePoint, etc.
  Identified by a `source_id`. Default category for most customer workflows.
  Tools: `list_incidents`, `count_incidents`, `get_incident`, `list_repo_occurrences`,
  `remediate_secret_incidents`, `list_sources`, `find_current_source_id`.
- **Public incidents** — detected by GitGuardian Public Monitoring on the worldwide public
  perimeter: public GitHub repos/gists, Docker Hub, etc. Not linked to a workspace source.
  Tools: `list_public_incidents`, `list_public_occurrences`.

Incident IDs are **not** interchangeable between the two categories. If the user's intent is
about leaks "on public GitHub / outside the org / on Docker Hub / found by Public Monitoring",
use the `list_public_*` tools. Otherwise default to the internal tools.

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
        description="(Internal sources only) List secrets in a given source (identified by source_id) and return exact match locations (file paths, line numbers, character indices). "
        "along with precise remediation instructions. This tool leverages the occurrences API."
        "By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this source.",
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
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_incidents) "
        "List secret incidents detected in sources the workspace has integrated (private/org Git repos, Slack, Jira, "
        "container registries, etc.) with advanced filtering including detector type, secret category, source criticality, "
        "and public exposure. Filter by repository (via source_ids), detector type, severity, status "
        "(TRIGGERED, ASSIGNED, RESOLVED, IGNORED), secret category, source criticality, public exposure, and more. "
        "With mine=True, this tool only shows incidents assigned to the current user. Uses page-based pagination.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        count_incidents,
        description="(Internal sources only — for public GitHub/gists/Docker Hub there is no equivalent count tool) "
        "Count internal secret incidents matching the given filters without fetching the full list. "
        "Accepts the same filters as list_incidents (status, severity, detector type, source, tags, etc.) "
        "but returns only the total count. Useful for getting an overview of incident volume or checking filter results before paginating.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_repo_occurrences,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_occurrences) "
        "List secret occurrences for a specific internal repository with exact match locations. "
        "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
        "Use this tool when you need to locate and remediate secrets in the codebase with precise file locations.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_public_incidents,
        description="(Public Monitoring only — for internal sources use list_incidents) "
        "List public secret incidents detected by GitGuardian Public Monitoring on the worldwide public perimeter "
        "(public GitHub repositories, public GitHub gists, Docker Hub, etc.). Use this when investigating secrets "
        "leaked outside the organization perimeter. Incident IDs here are NOT interchangeable with internal incident IDs. "
        "Uses cursor-based pagination.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_public_occurrences,
        description="(Public Monitoring only — for internal sources use list_repo_occurrences) "
        "List occurrences of a specific public secret incident detected by GitGuardian Public Monitoring on "
        "public sources, including filepath, commit sha, source repository, actor, and attachment reasons. "
        "Use this after list_public_incidents to drill into a specific public incident.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        find_current_source_id,
        description="(Internal sources only) Find the GitGuardian source_id for the current repository in the workspace's "
        "internal perimeter. This tool automatically detects the current git repository and searches for its source_id "
        "among the sources the workspace monitors. Useful when you need to reference the repository in other internal-incident "
        "API calls. Does not apply to public GitHub / Public Monitoring.",
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

    mcp.tool(
        list_detectors,
        description="List secret detectors available in the GitGuardian detection engine. Returns information about detectors including name, category, type",
        required_scopes=["scan"],
    )

    mcp.tool(
        list_sources,
        description="(Internal perimeter only) List sources (repositories, integrations) the workspace monitors — "
        "private/org Git repos, Slack, Jira, container registries, etc. Filter by type, health, visibility, criticality, "
        "and scan status. The worldwide public perimeter scanned by Public Monitoring is not represented here.",
        required_scopes=["sources:read"],
    )

    mcp.tool(
        get_incident,
        description="(Internal sources only — for public GitHub/gists/Docker Hub incidents there is no equivalent retrieval tool yet) "
        "Retrieve a specific internal secret incident by its ID with detailed information including occurrences, "
        "detector info, assignee details, and custom tags.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        get_member,
        description="Retrieve a specific member by their ID with information including name, email, role, access level, and activity status.",
        required_scopes=["members:read"],
    )
