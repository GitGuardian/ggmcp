"""Tool registration for the GitGuardian MCP server.

Every tool is declared here with its ``required_scopes``. At runtime the
``ScopeFilteringMiddleware`` (see ``gg_api_core.mcp_server``) hides tools
the current access token cannot satisfy.

The tools below cover secret scanning, incident management, remediation and
honeytokens. The URL entry point routes incident links to the matching internal
or Public Monitoring read endpoint.
Each tool function takes one pydantic model, whose fields are the tool's
top-level arguments (see ``gg_api_core.model_arguments``).
"""

from mcp.types import ToolAnnotations

from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.count_internal_incidents import count_internal_incidents
from gg_api_core.tools.generate_honey_token import generate_honeytoken
from gg_api_core.tools.get_gitguardian_resource import get_gitguardian_resource
from gg_api_core.tools.get_internal_incident import get_internal_incident
from gg_api_core.tools.get_my_identity import get_my_identity
from gg_api_core.tools.get_public_incident import get_public_incident
from gg_api_core.tools.get_remediation_workflow import get_remediation_workflow
from gg_api_core.tools.incident_assignment import (
    assign_internal_incident,
    assign_public_incident,
    unassign_internal_incident,
    unassign_public_incident,
)
from gg_api_core.tools.incident_comments import (
    add_internal_incident_comment,
    add_public_incident_comment,
    edit_internal_incident_comment,
    edit_public_incident_comment,
)
from gg_api_core.tools.incident_status import (
    ignore_internal_incident,
    ignore_public_incident,
    reopen_internal_incident,
    reopen_public_incident,
    resolve_internal_incident,
    resolve_public_incident,
)
from gg_api_core.tools.list_internal_incidents import list_internal_incidents
from gg_api_core.tools.list_internal_occurrences import list_internal_occurrences
from gg_api_core.tools.list_public_incidents import list_public_incidents
from gg_api_core.tools.list_public_occurrences import list_public_occurrences
from gg_api_core.tools.list_sources import list_sources
from gg_api_core.tools.scan_secret import scan_secrets

# Every tool talks only to the GitGuardian API, so none is open-world.
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
# Assign, unassign, resolve, ignore and reopen replace the incident's current state.
# Repeating the same call changes nothing further: the API answers 409.
CHANGES_INCIDENT_STATE = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False
)
# Adding a comment changes nothing that exists, but each call adds another comment.
ADDS_COMMENT = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
)
# Editing a comment replaces its body; the same edit twice leaves the same body.
EDITS_COMMENT = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False
)
# Each call creates a new honeytoken and changes nothing that exists.
CREATES_HONEYTOKEN = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
)

GITGUARDIAN_INSTRUCTIONS = """
# GitGuardian MCP Tools

This server exposes GitGuardian's secret detection, incident management, and
honeytoken capabilities through MCP. Tools require specific API token scopes;
tools whose scopes the current token does not satisfy are hidden automatically.
If a tool you expect is missing, your token is likely missing the required
scope — re-authenticate or issue a new token rather than substituting another
tool.

## Incident links and IDs

Start with `get_gitguardian_resource` when the user gives a GitGuardian incident link, or an
incident ID without saying whether it is internal or public. It works out which kind of
incident it is and fetches it. A link must belong to this server's configured instance and
the token's workspace; for a share-token link, ask for the authenticated dashboard link.

## Two incident categories — pick the right tool

GitGuardian surfaces two distinct, non-overlapping categories of secret incidents:

- **Internal incidents** — detected in sources the workspace has explicitly integrated:
  private/org Git repos, Slack, Jira, Confluence, container registries, SharePoint, etc.
  Identified by a `source_id`. Default category for most customer workflows.
  Read tools: `list_internal_incidents`, `count_internal_incidents`, `get_internal_incident`, `list_internal_occurrences`,
  `list_sources`.
  Write tools: `resolve_internal_incident`, `ignore_internal_incident`, `reopen_internal_incident`,
  `assign_internal_incident`, `unassign_internal_incident`, `add_internal_incident_comment`,
  `edit_internal_incident_comment`.
- **Public incidents** — detected by GitGuardian Public Monitoring on the worldwide public
  perimeter: public GitHub repos/gists, Docker Hub, etc. Not linked to a workspace source.
  Read tools: `list_public_incidents`, `get_public_incident`, `list_public_occurrences`.
  Write tools: `resolve_public_incident`, `ignore_public_incident`, `reopen_public_incident`,
  `assign_public_incident`, `unassign_public_incident`, `add_public_incident_comment`,
  `edit_public_incident_comment`.

Incident IDs are **not** interchangeable between the two categories. If the user's intent is
about leaks "on public GitHub / outside the org / on Docker Hub / found by Public Monitoring",
use the `list_public_*` tools. Otherwise default to the internal tools. Invoking an internal
write tool with a public incident ID (or vice versa) will silently 404.

## Capabilities

1. **Proactive Secret Scanning** (`scan_secrets`) — detect secrets in code before they're
   committed. Use to prevent accidental secret commits.

2. **Incident Management** — list and filter incidents (internal and public); resolve,
   ignore, reopen, assign, unassign, and comment on either kind.

3. **Repository Analysis** — drill into a specific repository's occurrences with file paths,
   line numbers, and character indices.

4. **Remediation** — follow the triage-incidents skill when available and call
   `get_remediation_workflow` for the workspace's instructions.

5. **Honeytokens** — generate honeytokens with `generate_honeytoken`.

6. **Identity** — `get_my_identity` says who the token belongs to, their role, and the token's
   scopes and expiry. Use it when a call is refused for permissions.

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

        Every secret found is reported, including ones whose GitGuardian incident was already resolved
        or ignored. Those policy breaks have is_excluded=true and an exclude_reason: the secret is still
        present in the scanned content, so do not report the content as clean.
        """,
        required_scopes=["scan"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_incidents,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_incidents) "
        "List secret incidents detected in sources the workspace has integrated (private/org Git repos, Slack, Jira, "
        "container registries, etc.) with advanced filtering including detector type, secret category, source criticality, "
        "and public exposure. Filter by repository (via source_ids), detector type, severity, status "
        "(TRIGGERED, ASSIGNED, RESOLVED, IGNORED), secret category, source criticality, public exposure, and more. "
        "With mine=True, this tool only shows incidents assigned to the current user. Uses page-based pagination. "
        "Each incident's secret and displayed occurrence are summarized; call get_internal_incident for an incident's full details.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        count_internal_incidents,
        description="(Internal sources only — for public GitHub/gists/Docker Hub there is no equivalent count tool) "
        "Count internal secret incidents matching the given filters without fetching the full list. "
        "Accepts the same filters as list_internal_incidents (status, severity, detector type, source, tags, etc.) "
        "but returns only the total count. Useful for getting an overview of incident volume or checking filter results before paginating.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_occurrences,
        description="(Internal sources only — for public GitHub/gists/Docker Hub use list_public_occurrences) "
        "List secret occurrences for an internal repository (source_id) or incident (incident_id) with exact match locations. "
        "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
        "Follow cursor with the same filters until has_more is false. To enumerate every known occurrence of one incident, "
        "pass incident_id, omit source_id, and set tags, exclude_tags, status, severity, and validity to []. "
        "Use get_internal_incident for incident metadata and get_remediation_workflow for remediation instructions.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_public_incidents,
        description="(Public Monitoring only — for internal sources use list_internal_incidents) "
        "List public secret incidents detected by GitGuardian Public Monitoring on the worldwide public perimeter "
        "(public GitHub repositories, public GitHub gists, Docker Hub, etc.). Use this when investigating secrets "
        "leaked outside the organization perimeter. Incident IDs here are NOT interchangeable with internal incident IDs. "
        "Uses cursor-based pagination.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_public_incident,
        description="(Public Monitoring only — for internal sources use get_internal_incident) "
        "Retrieve a single public secret incident by id, with detector, status, severity, "
        "validity, risk_score, tags, timestamps, assignee, and share_url. Incident IDs here "
        "are NOT interchangeable with internal incident IDs.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_public_occurrences,
        description="(Public Monitoring only — for internal sources use list_internal_occurrences) "
        "List occurrences of a specific public secret incident detected by GitGuardian Public Monitoring on "
        "public sources, including filepath, commit sha, source repository, actor, and attachment reasons. "
        "Use this after list_public_incidents to drill into a specific public incident.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        generate_honeytoken,
        description="Generate an AWS GitGuardian honeytoken and get injection recommendations. "
        "Honeytoken names must be unique among the workspace's active honeytokens.",
        required_scopes=["honeytokens:write"],
        annotations=CREATES_HONEYTOKEN,
    )

    mcp.tool(
        list_sources,
        description="(Internal perimeter only) List sources (repositories, integrations) the workspace monitors — "
        "private/org Git repos, Slack, Jira, container registries, etc. Filter by type, health, visibility, criticality, "
        "and scan status. The worldwide public perimeter scanned by Public Monitoring is not represented here.",
        required_scopes=["sources:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_gitguardian_resource,
        description="Open a GitGuardian incident from a pasted link or a bare incident ID. Start here when the user "
        "gives an incident link, or an incident ID without saying whether it is internal or public. "
        "A dashboard or public API incident link is read as the internal or Public Monitoring incident it points to. "
        "A bare ID is looked up as both, and the result says which matched, or that the ID is ambiguous. "
        "Returns the incident with its kind, ID and dashboard link. A link to an incidents list points to the list "
        "tools. Links for other instances or workspaces are refused; query strings and fragments are ignored; "
        "share-token links are unsupported.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_internal_incident,
        description="(Internal sources only - for public GitHub/gists/Docker Hub incidents use get_public_incident)"
        "Retrieve a specific internal secret incident by its ID with detailed information including occurrences, "
        "detector info, assignee details, and custom tags. Set with_history to also get its comments and the "
        "record of its status changes and assignments.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_remediation_workflow,
        description="Retrieve the workspace remediation workflow — the ordered, step-by-step guidance shown for secret "
        "incidents. Returns the configured custom workflow if one exists, otherwise the default workflow. Use this to "
        "remediate an incident following the same instructions a human sees in the dashboard.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_my_identity,
        description="Describe the caller: the workspace member the token belongs to (name, email, role) and the "
        "token itself (scopes, expiry). Use it when the user asks who they are signed in as or what this server "
        "lets them do, or when a call was refused for permissions.",
        annotations=READ_ONLY,
    )

    mcp.tool(
        resolve_internal_incident,
        description="(Internal incidents only; for Public Monitoring use resolve_public_incident) Resolve an internal secret incident. "
        "secret_revoked must come from the user: ask whether the secret was revoked or rotated. Returns the "
        "incident's new status and the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        ignore_internal_incident,
        description="(Internal incidents only; for Public Monitoring use ignore_public_incident) Ignore an internal secret incident. "
        "The ignore_reason must come from the user: ask, do not choose. Returns the incident's new status and the "
        "incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        reopen_internal_incident,
        description="(Internal incidents only; for Public Monitoring use reopen_public_incident) Reopen a resolved or ignored "
        "internal secret incident. Returns the incident's new status and the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        resolve_public_incident,
        description="(Public Monitoring only; for internal incidents use resolve_internal_incident) Resolve a public secret incident. "
        "The resolve_reason must come from the user: ask, do not choose. Returns the incident's new status and the "
        "incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        ignore_public_incident,
        description="(Public Monitoring only; for internal incidents use ignore_internal_incident) Ignore a public secret incident. "
        "The ignore_reason must come from the user: ask, do not choose. Returns the incident's new status and the "
        "incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        reopen_public_incident,
        description="(Public Monitoring only; for internal incidents use reopen_internal_incident) Reopen a resolved or ignored public "
        "secret incident. Returns the incident's new status and the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        assign_internal_incident,
        description="(Internal incidents only; for Public Monitoring use assign_public_incident) Assign an internal "
        "secret incident to one member, by member ID, by email, or to the current user with mine. Returns the new "
        "assignee and the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        unassign_internal_incident,
        description="(Internal incidents only; for Public Monitoring use unassign_public_incident) Remove the "
        "assignee of an internal secret incident. Returns the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        assign_public_incident,
        description="(Public Monitoring only; for internal incidents use assign_internal_incident) Assign a public "
        "secret incident to one member, by member ID, by email, or to the current user with mine. Returns the new "
        "assignee and the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        unassign_public_incident,
        description="(Public Monitoring only; for internal incidents use unassign_internal_incident) Remove the "
        "assignee of a public secret incident. Returns the incident.",
        required_scopes=["incidents:write"],
        annotations=CHANGES_INCIDENT_STATE,
    )

    mcp.tool(
        add_internal_incident_comment,
        description="(Internal incidents only; for Public Monitoring use add_public_incident_comment) Add a comment "
        "to an internal secret incident. Returns the comment and its comment_id, which "
        "edit_internal_incident_comment takes.",
        required_scopes=["incidents:write"],
        annotations=ADDS_COMMENT,
    )

    mcp.tool(
        edit_internal_incident_comment,
        description="(Internal incidents only; for Public Monitoring use edit_public_incident_comment) Replace the "
        "body of a comment on an internal secret incident. Returns the comment.",
        required_scopes=["incidents:write"],
        annotations=EDITS_COMMENT,
    )

    mcp.tool(
        add_public_incident_comment,
        description="(Public Monitoring only; for internal incidents use add_internal_incident_comment) Add a "
        "comment to a public secret incident. Returns the comment and its comment_id, which "
        "edit_public_incident_comment takes.",
        required_scopes=["incidents:write"],
        annotations=ADDS_COMMENT,
    )

    mcp.tool(
        edit_public_incident_comment,
        description="(Public Monitoring only; for internal incidents use edit_internal_incident_comment) Replace the "
        "body of a comment on a public secret incident. Returns the comment.",
        required_scopes=["incidents:write"],
        annotations=EDITS_COMMENT,
    )
