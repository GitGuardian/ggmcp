"""Tool registration for the GitGuardian MCP server.

Every tool is declared here with its ``required_scopes``. At runtime the
``ScopeFilteringMiddleware`` (see ``gg_api_core.mcp_server``) hides tools
the current access token cannot satisfy.

The tools below are the ten that carry real traffic plus the four that
GitGuardian's published agent skills depend on (remediation workflow, public
incidents, honeytokens). Their names, input schemas and outputs are kept
identical to the previous 38-tool server, so existing agents, prompts and
skills keep working.
"""

from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.assign_incident import assign_incident
from gg_api_core.tools.count_incidents import count_incidents
from gg_api_core.tools.generate_honey_token import generate_honeytoken
from gg_api_core.tools.get_incident import get_incident
from gg_api_core.tools.get_public_incident import get_public_incident
from gg_api_core.tools.get_remediation_workflow import get_remediation_workflow
from gg_api_core.tools.incident_notes import manage_incident_comment
from gg_api_core.tools.list_incidents import list_incidents
from gg_api_core.tools.list_public_incidents import list_public_incidents
from gg_api_core.tools.list_public_occurrences import list_public_occurrences
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences
from gg_api_core.tools.list_sources import list_sources
from gg_api_core.tools.manage_incident import manage_private_incident
from gg_api_core.tools.scan_secret import scan_secrets

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
  `list_sources`.
  Write tools: `manage_private_incident`, `assign_incident`, `manage_incident_comment`.
- **Public incidents** — detected by GitGuardian Public Monitoring on the worldwide public
  perimeter: public GitHub repos/gists, Docker Hub, etc. Not linked to a workspace source.
  Read tools: `list_public_incidents`, `get_public_incident`, `list_public_occurrences`.

Incident IDs are **not** interchangeable between the two categories. If the user's intent is
about leaks "on public GitHub / outside the org / on Docker Hub / found by Public Monitoring",
use the `list_public_*` tools. Otherwise default to the internal tools. Invoking an internal
write tool with a public incident ID (or vice versa) will silently 404.

## Capabilities

1. **Proactive Secret Scanning** (`scan_secrets`) — detect secrets in code before they're
   committed. Use to prevent accidental secret commits.

2. **Incident Management** — list and filter incidents (internal and public); assign,
   unassign, resolve, ignore, reopen, and comment on internal incidents.

3. **Repository Analysis** — drill into a specific repository's occurrences with file paths,
   line numbers, and character indices.

4. **Remediation** — follow the triage-incidents skill when available and call
   `get_remediation_workflow` for the workspace's instructions.

5. **Honeytokens** — generate honeytokens with `generate_honeytoken`.

## Behavioural notes

- If a prompt is asking to filter results for the current user, you MUST use the `mine`
  parameter. Examples: "list incidents assigned to me", "list my incidents".
"""


def register_tools(mcp: AbstractGitGuardianFastMCP) -> None:
    """Register every GitGuardian tool on ``mcp``.

    Tools are gated by ``required_scopes``; the runtime scope filter hides
    tools the access token cannot satisfy.
    """
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
        "List secret occurrences for an internal repository (source_id) or incident (incident_id) with exact match locations. "
        "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
        "Follow cursor with the same filters until has_more is false. To enumerate every known occurrence of one incident, "
        "pass incident_id, omit source_id, and set tags, exclude_tags, status, severity, and validity to []. "
        "Use get_incident for incident metadata and get_remediation_workflow for remediation instructions.",
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
        generate_honeytoken,
        description="Generate an AWS GitGuardian honeytoken and get injection recommendations. "
        "Honeytoken names must be unique among the workspace's active honeytokens.",
        required_scopes=["honeytokens:write"],
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
        get_remediation_workflow,
        description="Retrieve the workspace remediation workflow — the ordered, step-by-step guidance shown for secret "
        "incidents. Returns the configured custom workflow if one exists, otherwise the default workflow. Use this to "
        "remediate an incident following the same instructions a human sees in the dashboard.",
        required_scopes=["incidents:read"],
    )

    mcp.tool(
        manage_private_incident,
        description="(Internal sources only) Manage an internal secret incident (assign, unassign, resolve, ignore, reopen). "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        assign_incident,
        description="(Internal sources only) Assign an internal secret incident to a specific member or to the current user. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )

    mcp.tool(
        manage_incident_comment,
        description="(Internal sources only) "
        "Add a comment (note) to an internal secret incident, or edit an existing one. Use action='add' to create a "
        "new comment, or action='edit' with the comment_id of an existing comment to replace its body. "
        "Does not work on public-monitoring incident IDs.",
        required_scopes=["incidents:write"],
    )
