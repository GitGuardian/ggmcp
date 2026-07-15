"""Tool registration for the unified GitGuardian MCP server.

Every tool is declared here with its ``required_scopes``. At runtime the
``ScopeFilteringMiddleware`` (see ``gg_api_core.mcp_server``) hides tools
the current access token cannot satisfy, so a single registration list
serves both developer and SecOps audiences.
"""

from typing import Any

from fastmcp.exceptions import ToolError
from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.activity_logs import (
    list_incident_activity_logs,
    list_public_incident_activity_logs,
)
from gg_api_core.tools.assign_incident import assign_incident
from gg_api_core.tools.assign_public_incident import assign_public_incident
from gg_api_core.tools.count_incidents import count_incidents
from gg_api_core.tools.create_code_fix_request import create_code_fix_request
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.generate_honey_token import generate_honeytoken
from gg_api_core.tools.get_incident import get_incident
from gg_api_core.tools.get_member import get_member
from gg_api_core.tools.get_public_incident import get_public_incident
from gg_api_core.tools.get_remediation_workflow import get_remediation_workflow
from gg_api_core.tools.incident_notes import (
    list_incident_comments,
    list_public_incident_comments,
    manage_incident_comment,
    manage_public_incident_comment,
)
from gg_api_core.tools.list_detectors import list_detectors
from gg_api_core.tools.list_honeytokens import list_honeytokens
from gg_api_core.tools.list_incident_members import list_incident_members
from gg_api_core.tools.list_incident_teams import list_incident_teams
from gg_api_core.tools.list_incidents import list_incidents
from gg_api_core.tools.list_public_incidents import list_public_incidents
from gg_api_core.tools.list_public_occurrences import list_public_occurrences
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences
from gg_api_core.tools.list_sources import list_sources
from gg_api_core.tools.list_users import list_users
from gg_api_core.tools.manage_incident import (
    manage_private_incident,
    update_incident_severity,
)
from gg_api_core.tools.read_custom_tags import read_custom_tags
from gg_api_core.tools.remediate_secret_incidents import remediate_secret_incidents
from gg_api_core.tools.revoke_secret import revoke_secret
from gg_api_core.tools.scan_secret import scan_secrets
from gg_api_core.tools.update_public_incident_status import update_public_incident_status
from gg_api_core.tools.write_custom_tags import (
    update_or_create_incident_custom_tags,
    write_custom_tags,
)

GITGUARDIAN_INSTRUCTIONS = """
# GitGuardian MCP Tools

This server exposes GitGuardian's secret detection, incident management, and
honeytoken capabilities through MCP. Tools require specific API token scopes;
tools whose scopes the current token does not satisfy are hidden automatically.
If a tool you expect is missing, your token is likely missing the required
scope — re-authenticate or issue a new token rather than substituting another
tool.

## Two incident categories — pick the right tool

GitGuardian surfaces two distinct, non-overlapping categories of secret incidents:

- **Internal incidents** — detected in sources the workspace has explicitly integrated:
  private/org Git repos, Slack, Jira, Confluence, container registries, SharePoint, etc.
  Identified by a `source_id`. Default category for most customer workflows.
  Read tools: `list_incidents`, `count_incidents`, `get_incident`, `list_repo_occurrences`,
  `remediate_secret_incidents`, `list_sources`, `find_current_source_id`, `list_incident_comments`,
  `list_incident_activity_logs`.
  Write tools: `manage_private_incident`, `update_incident_severity`, `assign_incident`,
  `update_or_create_incident_custom_tags`, `create_code_fix_request`, `manage_incident_comment`.
- **Public incidents** — detected by GitGuardian Public Monitoring on the worldwide public
  perimeter: public GitHub repos/gists, Docker Hub, etc. Not linked to a workspace source.
  Read tools: `list_public_incidents`, `get_public_incident`, `list_public_occurrences`,
  `list_public_incident_comments`, `list_public_incident_activity_logs`.
  Write tools: `assign_public_incident`, `update_public_incident_status`, `manage_public_incident_comment`.

Incident IDs are **not** interchangeable between the two categories. If the user's intent is
about leaks "on public GitHub / outside the org / on Docker Hub / found by Public Monitoring",
use the `list_public_*` tools. Otherwise default to the internal tools. Invoking an internal
write tool with a public incident ID (or vice versa) will silently 404.

## Capabilities

1. **Proactive Secret Scanning** (`scan_secrets`) — detect secrets in code before they're
   committed. Use to prevent accidental secret commits.

2. **Incident Management** — list and filter incidents (internal and public), assign,
   resolve, ignore, reopen, and tag.

3. **Repository Analysis** — drill into a specific repository's occurrences with file paths,
   line numbers, and character indices.

4. **Remediation** (`remediate_secret_incidents`, `create_code_fix_request`) — guided
   secret removal with best-practice recommendations and automated pull requests.

5. **Honeytoken Management** — generate honeytokens, list and inspect existing ones.

6. **Workspace metadata** — list users, members, teams, sources, detectors, custom tags.

## Behavioural notes

- If a prompt is asking to filter results for the current user, you MUST use the `mine`
  parameter. Examples: "list incidents assigned to me", "list my incidents",
  "list my honeytokens".
"""


def register_tools(mcp: AbstractGitGuardianFastMCP) -> None:
    """Register every GitGuardian tool on ``mcp``.

    Tools are gated by ``required_scopes``; the runtime scope filter hides
    tools the access token cannot satisfy.
    """
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
        get_public_incident,
        description="(Public Monitoring only — for internal sources use get_incident) "
        "Retrieve a single public secret incident by id, with detector, status, severity, "
        "validity, risk_score, tags, timestamps, assignee, and share_url. Incident IDs here "
        "are NOT interchangeable with internal incident IDs.",
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
        "internal perimeter, searching among the sources the workspace monitors. Useful when you need to reference the "
        "repository in other internal-incident API calls. This server runs remotely and cannot access your local "
        "repository: run `git config --get remote.origin.url` yourself and pass the result as the `remote_url` argument. "
        "If you call it without `remote_url`, it returns a suggestion telling you to do exactly that. "
        "Does not apply to public GitHub / Public Monitoring.",
        required_scopes=["sources:read"],
    )

    mcp.tool(
        generate_honeytoken,
        description="Generate an AWS GitGuardian honeytoken and get injection recommendations. "
        "Honeytoken names must be unique among the workspace's active honeytokens.",
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
        description="(Internal sources only - for public GitHub/gists/Docker Hub incidents use get_public_incident)"
        "Retrieve a specific internal secret incident by its ID with detailed information including occurrences, "
        "detector info, assignee details, and custom tags.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        get_member,
        description="Retrieve a specific member by their ID with information including name, email, role, access level, and activity status.",
        required_scopes=["members:read"],
    )

    mcp.tool(
        get_remediation_workflow,
        description="Retrieve the workspace remediation workflow — the ordered, step-by-step guidance shown for secret "
        "incidents. Returns the configured custom workflow if one exists, otherwise the default workflow. Use this to "
        "remediate an incident following the same instructions a human sees in the dashboard.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_incident_members,
        description="(Internal sources only)"
        "List members with access to a secret incident. Filter by access level, search by name/email,"
        " and filter on direct or indirect accesses.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_incident_teams,
        description="(Internal sources only)"
        "List teams with access to a secret incident."
        " Search by team name/description and filter on direct or indirect accesses.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_incident_comments,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_incident_comments) "
        "List the comments (notes) left on an internal secret incident. Use this to read the discussion on an "
        "incident and to find the comment_id of a comment you want to edit with manage_incident_comment.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_public_incident_comments,
        description="(Public Monitoring only — for internal sources use list_incident_comments) "
        "List the comments (notes) left on a public secret incident detected by GitGuardian Public Monitoring. "
        "Use this to read the discussion and to find the comment_id to edit with manage_public_incident_comment. "
        "Public incident IDs are NOT interchangeable with internal incident IDs.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_incident_activity_logs,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_incident_activity_logs) "
        "List the full activity log of an internal secret incident: both user notes (comments) and system actions "
        "(status changes, assignments, severity edits, new locations detected, etc.) in one timeline. Broader than "
        "list_incident_comments, which returns notes only. Filter by content_key (action type) or member_id.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        list_public_incident_activity_logs,
        description="(Public Monitoring only — for internal sources use list_incident_activity_logs) "
        "List the full activity log of a public secret incident detected by GitGuardian Public Monitoring: both user "
        "notes (comments) and system actions in one timeline. Broader than list_public_incident_comments, which "
        "returns notes only. Public incident IDs are NOT interchangeable with internal incident IDs.",
        required_scopes=["incidents:read"],
    )

    # Write tools — previously SecOps-only.

    @mcp.tool(
        name="get_current_token_info",
        description="Get information about the current API token",
        required_scopes=["api_tokens:read"],
    )
    async def get_current_token_info() -> dict[str, Any]:
        """Return the current API token's metadata (scopes, member, expiry...)."""
        client = await mcp.get_client()
        try:
            result = await client.get_current_token_info()
            assert isinstance(result, dict)
            return result
        except Exception as e:
            raise ToolError(f"Error: {str(e)}")

    mcp.tool(
        update_or_create_incident_custom_tags,
        description="(Internal sources only) Update or create custom tags for an internal secret incident. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write", "custom_tags:write"],
    )

    mcp.tool(
        update_incident_severity,
        description="(Internal sources only) Set the severity of an internal secret incident. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        read_custom_tags,
        description="Read custom tags from the GitGuardian dashboard.",
        required_scopes=["custom_tags:read"],
    )

    mcp.tool(
        write_custom_tags,
        description="Create or delete custom tags in the GitGuardian dashboard.",
        required_scopes=["custom_tags:write"],
    )

    mcp.tool(
        manage_private_incident,
        description="(Internal sources only) Manage an internal secret incident (assign, unassign, resolve, ignore, reopen). "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        revoke_secret,
        description="Revoke a secret by its ID through the GitGuardian API. Operates on a secret_id regardless of whether "
        "the incident surfaced on an internal source or via Public Monitoring.",
        required_scopes=["secrets:write"],
    )

    mcp.tool(
        assign_incident,
        description="(Internal sources only) Assign an internal secret incident to a specific member or to the current user. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        assign_public_incident,
        description="(Public Monitoring only — for internal sources use assign_incident) "
        "Assign a public secret incident detected by GitGuardian Public Monitoring to a specific "
        "member or to the current user. Public incident IDs are NOT interchangeable with internal "
        "incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        update_public_incident_status,
        description="(Public Monitoring only — for internal sources use manage_private_incident) "
        "Update the status of a public secret incident (resolve, ignore, reopen) detected by "
        "GitGuardian Public Monitoring. Public incident IDs are NOT interchangeable with internal "
        "incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        create_code_fix_request,
        description="(Internal sources only) Create code fix requests for multiple internal secret incidents with their "
        "locations. This will generate pull requests to automatically remediate detected secrets in the repositories the "
        "workspace monitors. Does not apply to public-monitoring incidents.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        manage_incident_comment,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use manage_public_incident_comment) "
        "Add a comment (note) to an internal secret incident, or edit an existing one. Use action='add' to create a "
        "new comment, or action='edit' with a comment_id (from list_incident_comments) to replace a comment's body. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        manage_public_incident_comment,
        description="(Public Monitoring only — for internal sources use manage_incident_comment) "
        "Add a comment (note) to a public secret incident detected by GitGuardian Public Monitoring, or edit an "
        "existing one. Use action='add' to create a new comment, or action='edit' with a comment_id (from "
        "list_public_incident_comments) to replace a comment's body. Public incident IDs are NOT interchangeable "
        "with internal incident IDs.",
        required_scopes=["incidents:write"],
    )
