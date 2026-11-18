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
from gg_api_core.tools.catalog_reads import list_detectors, list_honeytokens
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
from gg_api_core.tools.incident_custom_tags import (
    add_internal_incident_custom_tag,
    add_public_incident_custom_tag,
    list_custom_tags,
    remove_internal_incident_custom_tag,
    remove_public_incident_custom_tag,
)
from gg_api_core.tools.incident_locations import (
    create_internal_incident_code_fix_request,
    list_internal_incident_locations,
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
from gg_api_core.tools.members import (
    get_member,
    list_internal_incident_members,
    list_internal_incident_teams,
    list_members,
)
from gg_api_core.tools.scan_secret import scan_secrets

# Every tool talks only to the GitGuardian API, so none is open-world. Every hint is set,
# even where the spec gives a default, so no client has to guess.
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
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
# Adding a tag keeps the incident's other tags; adding it again changes nothing.
ADDS_TAG = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
# Removing a tag deletes it from the incident; removing it again changes nothing.
REMOVES_TAG = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False)
# A code fix request opens pull requests and changes nothing that exists; GitGuardian refuses
# a second request for locations already being fixed.
REQUESTS_CODE_FIX = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
)
# Each call creates a new honeytoken and changes nothing that exists.
CREATES_HONEYTOKEN = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
)

GITGUARDIAN_INSTRUCTIONS = """
GitGuardian finds secrets in code and tracks each leak as an incident. Incidents are
internal, from the sources the workspace integrates (Git repositories, Slack, Jira,
registries), or public, found by Public Monitoring (public GitHub, gists, Docker Hub). The
two kinds have separate IDs, and each tool's name says its kind. Use the public tools for
leaks outside the organization, the internal ones otherwise. For an incident link, or an
ID of unknown kind, call get_gitguardian_resource first.

- Resolving and ignoring take an answer only the user has: whether the secret was revoked,
  or why the incident is resolved or ignored. Ask; never choose one.
- For the user's own incidents ("my incidents", "assigned to me"), pass mine=true.
- List tools return next_arguments: call the tool again with them for the next page.
- A write result's changed=false means the incident already was in the requested state.
- Tools the token's scopes do not allow are hidden. If one is missing, the user needs a
  token with more scopes; get_my_identity shows the token's scopes and the user's role.
- Scan code with scan_secrets before it is committed. To fix an incident, follow the steps
  from get_remediation_workflow, and the triage-incidents skill when it is available.
"""


def register_tools(mcp: AbstractGitGuardianFastMCP) -> None:
    """Register every GitGuardian tool on ``mcp``.

    Tools are gated by ``required_scopes``; the runtime scope filter hides
    tools the access token cannot satisfy.
    """
    mcp.tool(
        scan_secrets,
        description=(
            "Scan file contents for secrets, before they are committed. Returns, for each document, the secrets "
            "found in it (policy breaks). A secret whose incident was already resolved or ignored is still reported, with "
            "is_excluded=true and an exclude_reason: it is still in the content, so do not report the content as clean."
        ),
        required_scopes=["scan"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_incidents,
        description=(
            "(Internal incidents only; for Public Monitoring use list_public_incidents) List the secret incidents "
            "found in the sources the workspace integrates: Git repositories, Slack, Jira, container registries and more. "
            "Filters narrow by status, severity, validity, source, detector, tags and more; by default, ignored incidents, "
            "low and info severities, invalid secrets and test files are left out. mine=true lists the incidents assigned "
            "to the current user. Each incident's secret and occurrence are summarized; call get_internal_incident for the "
            "full incident."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        count_internal_incidents,
        description=(
            "(Internal incidents only; Public Monitoring has no count tool) Count the internal incidents that "
            "match the filters list_internal_incidents takes, with the same defaults, without listing them."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_occurrences,
        description=(
            "(Internal incidents only; for Public Monitoring use list_public_occurrences) List where secrets "
            "were found, with file paths, lines and character positions, in one source (source_id) or for one incident "
            "(incident_id). By default, occurrences of ignored incidents, low and info severities, invalid secrets and test "
            "files are left out; to list every occurrence of one incident, pass incident_id and [] for tags, exclude_tags, "
            "status, severity and validity."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_public_incidents,
        description=(
            "(Public Monitoring only; for internal incidents use list_internal_incidents) List the incidents "
            "Public Monitoring found outside the organization: public GitHub repositories and gists, Docker Hub and other "
            "public sources. By default, ignored incidents, low and info severities and invalid secrets are left out."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_public_incident,
        description=(
            "(Public Monitoring only; for internal incidents use get_internal_incident) Get one public incident: "
            "its detector, status, severity, validity, risk score, tags, dates and assignee."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_public_occurrences,
        description=(
            "(Public Monitoring only; for internal incidents use list_internal_occurrences) List where a public "
            "incident's secret was found: file path, commit, repository, author, and why it was attached to the incident."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        generate_honeytoken,
        description=(
            "Get an AWS honeytoken to plant as a decoy, with advice on where to put it. Without new_token, "
            "returns your most recent active honeytoken rather than creating one. Names must be unique among the "
            "workspace's active honeytokens."
        ),
        required_scopes=["honeytokens:write"],
        annotations=CREATES_HONEYTOKEN,
    )

    mcp.tool(
        list_sources,
        description=(
            "(Internal incidents only) List the sources the workspace monitors: Git repositories, Slack, Jira, "
            "container registries and other integrations, by type, health, visibility, criticality, team or scan status. "
            "Public Monitoring's sources are not listed."
        ),
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
        description=(
            "(Internal incidents only; for Public Monitoring use get_public_incident) Get one internal incident: "
            "its detector, status, severity, assignee and tags, and up to with_occurrences of its occurrences; "
            "occurrences_count gives how many it has. with_history adds its comments and the record of its status changes "
            "and assignments."
        ),
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_remediation_workflow,
        description=(
            "Get the workspace's remediation workflow: the ordered steps the dashboard shows for fixing a "
            "secret incident, the workspace's own if it has one, otherwise the default."
        ),
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
        add_internal_incident_custom_tag,
        description="(Internal incidents only; for Public Monitoring use add_public_incident_custom_tag) Add one "
        "custom tag, a key with an optional value, to an internal secret incident. Its other tags stay. Returns the "
        "incident's tags.",
        required_scopes=["incidents:write"],
        annotations=ADDS_TAG,
    )

    mcp.tool(
        remove_internal_incident_custom_tag,
        description="(Internal incidents only; for Public Monitoring use remove_public_incident_custom_tag) Remove "
        "one custom tag from an internal secret incident, or every tag with a key when no value is given. Its other "
        "tags stay. Returns the incident's tags.",
        required_scopes=["incidents:write"],
        annotations=REMOVES_TAG,
    )

    mcp.tool(
        add_public_incident_custom_tag,
        description="(Public Monitoring only; for internal incidents use add_internal_incident_custom_tag) Add one "
        "custom tag, a key and a value, to a public secret incident. Its other tags stay. Returns the incident's "
        "tags.",
        required_scopes=["incidents:write"],
        annotations=ADDS_TAG,
    )

    mcp.tool(
        remove_public_incident_custom_tag,
        description="(Public Monitoring only; for internal incidents use remove_internal_incident_custom_tag) Remove "
        "one custom tag from a public secret incident, or every tag with a key when no value is given. Its other "
        "tags stay. Returns the incident's tags.",
        required_scopes=["incidents:write"],
        annotations=REMOVES_TAG,
    )

    mcp.tool(
        list_custom_tags,
        description="List the custom tags defined in the workspace, with their IDs, keys and values.",
        required_scopes=["custom_tags:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_incident_locations,
        description="(Internal incidents only) List the files that still hold an internal incident's secret, one "
        "location per file of a source, on its default branch: the lines of each match, and the pull requests "
        "already opened to fix it. These are the places to remediate, and their IDs are what "
        "create_internal_incident_code_fix_request takes.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        create_internal_incident_code_fix_request,
        description="(Internal incidents only) Ask GitGuardian to open pull requests that remove an internal "
        "incident's secret from the given locations, one pull request per source. The workspace must have code fixes "
        "enabled. Opening pull requests is visible to the repositories' owners: confirm with the user first.",
        required_scopes=["incidents:write"],
        annotations=REQUESTS_CODE_FIX,
    )

    mcp.tool(
        list_members,
        description="List the workspace's members, by name or email, role and activity: to find the member to "
        "assign an incident to, or who a member ID is.",
        required_scopes=["members:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        get_member,
        description="Get one workspace member by ID, such as an incident's assignee_id: name, email, role and "
        "whether the member is active.",
        required_scopes=["members:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_incident_members,
        description="(Internal incidents only) List the members who can see an internal incident, with their "
        "permission on it.",
        required_scopes=["incidents:read", "members:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_internal_incident_teams,
        description="(Internal incidents only) List the teams that can see an internal incident, with their "
        "permission on it.",
        required_scopes=["incidents:read", "teams:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_honeytokens,
        description="List the workspace's honeytokens: their name, status (active, triggered when someone used one, "
        "or revoked), dates and creator. Their credentials are not included.",
        required_scopes=["honeytokens:read"],
        annotations=READ_ONLY,
    )

    mcp.tool(
        list_detectors,
        description="List GitGuardian's secret detectors: their name, display name, category, and whether they are "
        "enabled in the workspace.",
        required_scopes=["incidents:read"],
        annotations=READ_ONLY,
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
