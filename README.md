# GitGuardian MCP Server

Remediate leaked secrets from your AI agent, from a single repository to your whole organization.

The GitGuardian MCP server connects any MCP client to GitGuardian's secrets detection and incident management. Your agent gets the same view of your incidents as the GitGuardian dashboard, and can act on them for you.

## Built for two jobs
 
### SecOps and AppSec: orchestrate remediation at scale
 
- **Triage the backlog.** List, count and prioritize internal and Public Monitoring
  incidents by severity, validity, source, tag or assignee.
- **Route the work.** Assign incidents to the right developer or team, set severity,
  add tags and comments, across the whole workspace.
- **Close the loop.** Resolve, ignore or reopen incidents, revoke exposed secrets,
  and deploy honeytokens.
  
### Developers: fix incidents in the repository you work on
 
- **See what's yours.** Get the incidents assigned to you and the leaks in the current
  repository, with their exact locations and history.
- **Fix them in place.** Follow GitGuardian’s remediation workflow, or your organization’s own, to remove the secret from the code and get it rotated.

> [!CAUTION]
> Agents act with your permissions. Review actions that modify incidents, create
> credentials, or revoke secrets, and grant only the scopes you need.

## Quick start: hosted server

Add the URL for your GitGuardian region through your client's remote MCP setup
and complete the OAuth sign-in:

| Region | URL |
|---|---|
| US | `https://mcp.gitguardian.com/mcp` |
| EU | `https://mcp.eu1.gitguardian.com/mcp` |

Example for clients using an `mcpServers` configuration:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "type": "http",
      "url": "https://mcp.gitguardian.com/mcp"
    }
  }
}
```

Hosted requests pass through the GitGuardian MCP service. To run the server on
your own machine or infrastructure, use [local stdio](#local-stdio) or
[self-hosting](#self-hosting).

Try asking your agent:

- "Scan this codebase for leaked credentials."
- "Explain the security incidents assigned to me and suggest remediation steps."
- "Generate an AWS honeytoken named dev-database."

## Local stdio

Install [uv](https://docs.astral.sh/uv/) and add this local-server configuration
to your MCP client. Requests go from your machine to the configured GitGuardian API.

```json
{
  "mcpServers": {
    "GitGuardian": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/GitGuardian/ggmcp.git",
        "gg-mcp-server"
      ],
      "env": {
        "GITGUARDIAN_URL": "https://dashboard.gitguardian.com"
      }
    }
  }
}
```

Set `GITGUARDIAN_URL` to your dashboard URL. Browser login is enabled by default;
the first tool call opens a login flow and stores the resulting PAT locally for reuse.
Each login creates a new PAT in your GitGuardian account.

For headless use, add `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` and
`ENABLE_LOCAL_OAUTH=false` to `env`. Create a PAT under **API → Personal Access
Tokens** in your GitGuardian dashboard. Keep real tokens out of committed configuration.

Clients that cannot find `uvx` through `PATH` need its absolute path in `command`.
For optional Sentry support, use
`ggmcp[sentry] @ git+https://github.com/GitGuardian/ggmcp.git` as the `--from` value
and configure `SENTRY_DSN`.

## Self-hosting

Run the published Docker image behind a reverse proxy that terminates TLS, then
connect your MCP clients to its `/mcp` endpoint:

```bash
docker run -p 8000:8000 \
  -e GITGUARDIAN_URL=https://dashboard.gitguardian.mycorp.local \
  -e IS_ON_PREM=true \
  -e MCP_BASE_URL=https://mcp.mycorp.local \
  -e MCP_OAUTH_PROXY_ENABLED=true \
  -e MULTI_TENANCY_ENABLED=true \
  -e MCP_PORT=8000 \
  -e ENABLE_LOCAL_OAUTH=false \
  ghcr.io/gitguardian/mcp-server:latest \
  gunicorn --workers=4 --worker-class=uvicorn.workers.UvicornWorker \
           -b 0.0.0.0:8000 gg_mcp_server.http_app:app
```

- `IS_ON_PREM=true` selects the self-hosted GitGuardian API path and supported scopes,
  overriding hostname detection. Set it explicitly for self-hosted GitGuardian instances.
- `MCP_BASE_URL` is the public URL of your MCP server.
- `MCP_OAUTH_PROXY_ENABLED=true` enables OAuth discovery and proxies authorization
  to your GitGuardian dashboard.
- **HTTP requires `MULTI_TENANCY_ENABLED=true` and `MCP_PORT`.** Every request uses
  its own bearer token; the server refuses HTTP startup without multi-tenancy.

For HTTP clients that send a PAT directly, leave `MCP_OAUTH_PROXY_ENABLED` unset,
keep `ENABLE_LOCAL_OAUTH=false`, and send `Authorization: Bearer <PAT>` with each request.

## Configuration

<details>
<summary>Environment variables</summary>

| Variable | Purpose | Default |
|---|---|---|
| `GITGUARDIAN_URL` | GitGuardian dashboard URL | `https://dashboard.gitguardian.com` |
| `IS_ON_PREM` | `true`: self-hosted; `false`: SaaS; unset: detect from hostname | Unset |
| `GITGUARDIAN_PERSONAL_ACCESS_TOKEN` | PAT for local stdio | Unset |
| `GITGUARDIAN_SCOPES` | Comma-separated OAuth scopes to request | Scopes used by the tools |
| `GITGUARDIAN_CLIENT_ID` | OAuth client ID | `ggshield_oauth` |
| `GITGUARDIAN_TOKEN_NAME` | Name for a local OAuth-issued PAT | `MCP Token` |
| `GITGUARDIAN_TOKEN_LIFETIME` | Local OAuth PAT lifetime in days, or `never` | `30` |
| `MCP_PORT` | Enable HTTP on this port; unset selects stdio | Unset |
| `MULTI_TENANCY_ENABLED` | Use each request's bearer token; required for HTTP | `false` |
| `MCP_HOST` | HTTP bind address | `127.0.0.1` |
| `MCP_BASE_URL` | Public MCP server URL for OAuth discovery | `http://localhost:8000` |
| `MCP_OAUTH_PROXY_ENABLED` | Enable OAuth proxy mode | `false` |
| `ENABLE_LOCAL_OAUTH` | Enable local browser login | `true` |
| `LOG_LEVEL` | Log level | `INFO` |
| `LOG_FORMAT` | `json` or `console` | Console on a TTY; JSON otherwise |

</details>

## Development

Install Python 3.13, [uv](https://docs.astral.sh/uv/), and Make, then run:

```bash
git clone https://github.com/GitGuardian/ggmcp.git
cd ggmcp
uv sync --frozen --all-groups
make test
make lint
make typecheck
make format
```

Install the linting, commit-message, and secret-scanning hooks with
`uvx pre-commit install` and `uvx pre-commit install --hook-type pre-push`.

Tools live in `src/gg_api_core/tools/` and are registered with their required
scopes in `src/gg_mcp_server/register_tools.py`. Cover new tools in `tests/e2e/`.
See [PUBLISHING.md](PUBLISHING.md) for the release process.

[`tool-contracts.json`](tool-contracts.json) describes every tool: its name,
description, input and output JSON Schemas, annotations, and the token scopes that
gate it. It is committed here and attached to each GitHub release, so consumers such as
[GitGuardian/agent-skills](https://github.com/GitGuardian/agent-skills/issues/157)
can check against a version's contracts without installing the server. After changing
a tool, run `make tool-contracts`; a test fails until the file is regenerated.

## Migration notes

<details>
<summary>Upgrading from 0.7.x</summary>

Agents discover the current tool names and arguments from the tool list. Update
scripts and prompts that reference the previous names or argument shapes.

### Tools

| 0.7.x tool | Now |
|---|---|
| `list_incidents` | `list_internal_incidents` |
| `count_incidents` | `count_internal_incidents` |
| `get_incident` | `get_internal_incident` |
| `list_repo_occurrences` | `list_internal_occurrences` |
| `list_remediation_targets` | `list_internal_incident_locations`, or `list_internal_occurrences` with `tags: ["DEFAULT_BRANCH"]` |
| `list_incident_activity_logs`, `list_incident_comments` | `get_internal_incident` with `with_history` |
| `list_public_incident_activity_logs`, `list_public_incident_comments` | `get_public_incident` with `with_history` |
| `manage_private_incident` | `resolve_internal_incident`, `ignore_internal_incident`, `reopen_internal_incident`, `unassign_internal_incident` |
| `assign_incident` | `assign_internal_incident` |
| `manage_incident_comment` | `add_internal_incident_comment`, `edit_internal_incident_comment` |
| `update_public_incident_status` | `resolve_public_incident`, `ignore_public_incident`, `reopen_public_incident` |
| `assign_public_incident` | `assign_public_incident`, and `unassign_public_incident`, which is new |
| `manage_public_incident_comment` | `add_public_incident_comment`, `edit_public_incident_comment` |
| `update_or_create_incident_custom_tags` | `add_internal_incident_custom_tag`, `remove_internal_incident_custom_tag`, and the `_public_` pair, which are new. Each changes one tag and keeps the others |
| `read_custom_tags` | `list_custom_tags` |
| `update_incident_severity` | `set_internal_incident_severity`, and `set_public_incident_severity`, which is new |
| `create_code_fix_request` | `create_internal_incident_code_fix_request`, with location IDs from `list_internal_incident_locations` |
| `list_users` | `list_members` |
| `list_incident_members`, `list_incident_teams` | `list_internal_incident_members`, `list_internal_incident_teams` |
| `get_authenticated_user_info`, `get_current_token_info` | `get_my_identity` |
| `find_current_source_id` | `list_sources`, filtered by `search` or `external_id` |
| `scan_secrets`, `list_public_incidents`, `get_public_incident`, `list_public_occurrences`, `list_sources`, `get_remediation_workflow`, `generate_honeytoken`, `get_member`, `list_honeytokens`, `list_detectors`, `revoke_secret` | Same name |
| `write_custom_tags`, `revoke_current_token` | Removed. Use the GitGuardian dashboard |

`get_gitguardian_resource` is new: it opens an incident from a link or an ID of either kind.

### Arguments and results

- Arguments are passed at the top level, `{"incident_id": 123}`. Calls using the old
  `{"params": {"incident_id": 123}}` shape receive a validation error.
- Every list tool takes `page_size`, `cursor` and `get_all`, and returns `page_size`,
  `has_more`, `stop_reason` and `next_arguments`; call the tool again with
  `next_arguments` for the next page. `page` and `per_page` are gone, and so are
  `cursor`, `next_cursor`, `has_next`, `has_previous` and the result counts in results.
- List and count results are no longer wrapped in a `result` object.
- Multi-value filters take lists. Severities are named (`critical` to `unknown`) in
  every tool, and the unknown validity is `unknown` everywhere.
- `list_internal_occurrences` takes `date_after`, `date_before` and `assignee_id`, which
  replace `from_date`, `to_date` and `member_assignee_id`.
- Assigning by email takes `assignee_email` for both incident kinds, which replaces
  `email` on internal incidents.
- Write tools return the incident's kind and ID, the change, whether it changed
  anything (`changed`), and the incident.
- `scan_secrets` reports secrets whose incident was already resolved or ignored, with
  `is_excluded: true`, and refuses document fields other than `document` and `filename`.

### Deployment

- Serve HTTP with `gg_mcp_server.http_app:app`; `gg_mcp_server.sse_app:app` was removed.
- Invoke `gg-mcp-server`; the `developer-mcp-server` and `secops-mcp-server` console
  scripts were removed.

</details>
