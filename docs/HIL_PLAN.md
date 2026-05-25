# Plan — Expose HIL-style capabilities on gg-mcp

## Goal

Make the value of GitGuardian's HIL (High Impact Leak) qualification feature reusable by any MCP client. HIL is implemented in the `gg_ai` library as two LangGraph agents (Secret Triage + Deep Incident Analysis); their value splits cleanly in two:

1. **Atomic tools** — DNS / RDAP / SSL / GitHub / validity-check primitives the orchestrator and reader agents call. These are the agents' "eyes".
2. **Orchestration intent** — system prompts, output schemas, and the choreography that decides *when* to call *which* tool and what counts as evidence. These cannot be reduced to tools.

This plan adds (1) as MCP **tools** and (2) as MCP **prompts** in `gg-mcp`. Clients (Claude Code, Cursor, etc.) can then either compose the tools manually or invoke a prompt to get the HIL playbook injected into their context.

Reference: full structural analysis of the agents lives in the basalt conversation that produced this plan. The agents themselves live in the installed `gg_ai` package (e.g. `~/.cache/uv/archive-v0/<hash>/gg_ai/llm/{secret_triage,deep_incident_analysis,shared}/`); the basalt orchestration is in `basalt_dagster/ud_release/assets/projects/high_impact_leak.py`.

## Non-goals

- Reimplementing the LangGraph agents in MCP. The whole point is to ship value *atomically* (tools) and *declaratively* (prompts) instead.
- Hosting LLMs. Prompts are returned as text — the client's model executes them.
- Exposing terminal tools (`submit_verdict`, `submit_findings`, `delegate_investigation`). These are LangGraph plumbing, not capabilities.
- Adding a third MCP server. The new tools and prompts live alongside existing tools in `gg_api_core` and are registered by both `developer_mcp_server` and `secops_mcp_server` (or whichever profile makes sense per tool — see "Server registration" below).

## Repo conventions to respect

- Each tool is a function in `packages/gg_api_core/src/gg_api_core/tools/<name>.py`.
- It is registered via `mcp.tool(fn, description=..., required_scopes=[...])` in each server's `register_tools.py`.
- Pydantic `BaseModel` is used for input filters when there are more than a couple of args.
- Tests go under `tests/tools/` with pytest, using `vcrpy` cassettes for HTTP-backed tools (see `tests/cassettes/`).
- Python 3.13, ruff + commitizen via pre-commit. FastMCP `~=3.0`.

## Server registration (which profile gets what)

| Profile | Tools added |
|---|---|
| `developer_mcp_server` | None of the new tools (devs scanning their own repos don't need DNS/RDAP/etc.) |
| `secops_mcp_server` | All new tools + all new prompts (SecOps investigates leaks) |

The prompts are registered on `secops_mcp_server` only. Rationale: triage/qualification is a SecOps workflow.

## Part A — Tools to add

All tools live in `packages/gg_api_core/src/gg_api_core/tools/`. Naming follows existing convention (snake_case, verb_object).

Auth model:
- **Network primitives** (DNS, RDAP, SSL, reachability) — no auth, no GG scope. Pass `required_scopes=[]`.
- **Validity check & GitHub** — see per-tool notes.

### A.1 Network primitives (no auth)

New module: `packages/gg_api_core/src/gg_api_core/tools/network/__init__.py` plus one file per tool. Group them in a `network/` subdir so they don't clutter the GG-API tool list.

#### `dns_lookup`

- File: `tools/network/dns_lookup.py`
- Args: `hostname: str`, `record_types: list[Literal["A","AAAA","CNAME","MX","TXT","NS"]] = ["A","CNAME"]`
- Returns: `{record_type: [values]}` or `{"error": "NXDOMAIN" | "timeout" | ...}`
- Impl: `dnspython` (already widely available, add to deps). 5-second timeout per query.
- Description for MCP: "Resolve DNS records for a hostname. Use this to map a domain found in a leaked secret (host, URL) to an IP, CNAME, or mail server, which can then be RDAP-looked-up to identify the owning organization."

#### `reverse_dns_lookup`

- File: `tools/network/reverse_dns_lookup.py`
- Args: `ip_address: str`
- Returns: `{"hostname": str | None, "error": str | None}`
- Impl: `socket.gethostbyaddr` with timeout via `socket.setdefaulttimeout`.

#### `rdap_domain_lookup`

- File: `tools/network/rdap_domain_lookup.py`
- Args: `domain: str`
- Returns: `{"registrant_organization": str | None, "registrant_country": str | None, "registrar": str | None, "registration_date": str | None, "name_servers": list[str], "raw_excerpt": dict}`
- Impl: query `https://rdap.org/domain/{domain}` (rdap.org is a redirector to the right RDAP server). Parse `entities[].vcardArray`. 10-second timeout.
- Description: "Look up the registrant organization of a domain via RDAP (modern WHOIS). Primary signal for tying a leaked URL/host back to a company."

#### `rdap_ip_lookup`

- File: `tools/network/rdap_ip_lookup.py`
- Args: `ip_address: str`
- Returns: `{"network_name": str | None, "organization": str | None, "country": str | None, "asn": int | None, "raw_excerpt": dict}`
- Impl: `https://rdap.org/ip/{ip}`. Same parsing approach.

#### `check_host_reachability`

- File: `tools/network/check_host_reachability.py`
- Args: `host: str`, `port: int = 443`, `try_http: bool = True`
- Returns: `{"dns_ok": bool, "tcp_ok": bool, "http_status": int | None, "tls_ok": bool, "waf_detected": bool, "error": str | None}`
- Impl: sequential DNS → TCP connect (3 s timeout) → optional `GET /` with `httpx` (5 s timeout). Detect WAF/blocking via response headers (`cf-ray`, `x-amz-cf-id`, `server: cloudflare`, etc.).
- Description: "Probe whether a host is reachable and detect whether a WAF (Cloudflare, CloudFront) is in front of it. Useful when assessing whether a leaked endpoint is live production infrastructure."

#### `check_ssl_certificate`

- File: `tools/network/check_ssl_certificate.py`
- Args: `hostname: str`, `port: int = 443`
- Returns: `{"subject_cn": str | None, "subject_organization": str | None, "issuer_cn": str | None, "issuer_organization": str | None, "sans": list[str], "valid_from": str, "valid_to": str, "self_signed": bool, "error": str | None}`
- Impl: `ssl.create_default_context().wrap_socket(...)`. Parse with `cryptography.x509`. 5-second timeout.
- Description: "Fetch the TLS certificate for a hostname and extract Subject Organization, CN, SANs, and issuer. The cert's Subject Organization is a strong ownership signal: if the leaked secret hits `api.acme.com` and the cert says `O=Acme Corp`, that's near-conclusive."

### A.2 GitHub primitives

New module: `packages/gg_api_core/src/gg_api_core/tools/github/__init__.py`.

Auth: optional `GITHUB_TOKEN` env var. Without one, GitHub anonymous rate limit applies (60 req/h). With one, 5000 req/h. The tool surfaces the rate-limit headers in its response so callers know.

#### `search_github_issues`

- File: `tools/github/search_github_issues.py`
- Args: `query: str`, `repo: str | None = None` (optional `owner/name` scope), `state: Literal["open","closed","all"] = "all"`, `limit: int = 20`
- Returns: list of `{"number": int, "title": str, "body_excerpt": str, "state": str, "html_url": str, "created_at": str, "author": str}`
- Impl: `GET /search/issues` with `q=<query>+repo:<repo>` if scoped, otherwise raw query. Cap `limit` at 100.
- Description: "Search GitHub issues (optionally scoped to a repo). Useful to check whether a leaked secret was already reported, or to find context tying a repo to a company (e.g., issues mentioning company employees)."

#### `search_github_code`

- File: `tools/github/search_github_code.py`
- Args: `query: str`, `repo: str | None = None`, `limit: int = 20`
- Returns: list of `{"path": str, "repo": str, "html_url": str, "text_matches": list[str]}`
- Impl: `GET /search/code` (requires auth — surface a clear error if `GITHUB_TOKEN` is unset).
- Description: "Search GitHub code, optionally scoped to a repo. Use to find additional occurrences of a leaked value, or files (e.g. `README.md`, `CODEOWNERS`) that tie a repo to a company."

#### `get_github_repo_metadata`

- File: `tools/github/get_github_repo_metadata.py`
- Args: `repo: str` (`owner/name`)
- Returns: `{"description": str, "homepage": str | None, "owner_type": Literal["User","Organization"], "owner_login": str, "owner_company": str | None, "stars": int, "fork": bool, "archived": bool, "topics": list[str], "default_branch": str, "license": str | None, "created_at": str, "pushed_at": str}`
- Impl: `GET /repos/{owner}/{repo}` + (if Organization) `GET /orgs/{owner}` for `company` field.
- Description: "Fetch repo + owner metadata from GitHub. The owner's `company` field and the repo `description` / `homepage` are direct ownership signals."

#### `list_github_repo_contributors`

- File: `tools/github/list_github_repo_contributors.py`
- Args: `repo: str`, `limit: int = 20`
- Returns: list of `{"login": str, "contributions": int, "company": str | None, "email": str | None, "name": str | None}`
- Impl: `GET /repos/{owner}/{repo}/contributors` + per-user `GET /users/{login}` for company/email/name (cap at `limit` to avoid rate burn; allow `limit=0` to skip user enrichment).
- Description: "List top contributors with their public profile data (company, email). Strong signal for tying a repo to a specific organization."

### A.3 GitGuardian validity check (auth: GG token)

#### `list_secret_checkers`

- File: `tools/list_secret_checkers.py`
- Args: none, optional `provider_filter: str | None = None` (fuzzy substring)
- Returns: list of `{"detector_name": str, "checker_supported": bool, "provider": str}`
- Impl: thin wrapper over `list_detectors` (already exists) — filter to those with a checker. May share code with `list_detectors.py`.
- `required_scopes=["scan"]`

#### `check_secret_validity`

- File: `tools/check_secret_validity.py`
- Args: `detector_name: str`, `secret_values: dict[str, str]` (the matches as `{name: value}` — e.g. `{"api_key": "..."}` for a 1-part secret, or `{"client_id": "...", "client_secret": "..."}` for compound).
- Returns: `{"checked_at": str, "status": Literal["valid","invalid","failed_to_check","no_checker","unknown"], "validity_details": dict}`
- Impl: POST to GG public API validity endpoint (verify exact endpoint exists in `gg_api_core.urls`; if not, surface clearly in the implementation step). Mark secret values as sensitive in logging.
- `required_scopes=["scan"]`
- Description: "Check whether a leaked secret is currently valid against the issuing provider's API. Returns one of valid/invalid/failed_to_check/no_checker. Use sparingly — this hits the third-party provider's API."

### A.4 Public-occurrence reader (auth: GG token)

The HIL reader sub-agent reads file contents via the internal `anvil` extension. That isn't appropriate for a public MCP. Instead, surface the same value through the existing GG SaaS public-occurrences API.

#### `get_public_occurrence_patch`

- File: `tools/get_public_occurrence_patch.py`
- Args: `occurrence_id: str`, `context_lines: int = 20`
- Returns: `{"filepath": str, "patch": str, "commit_sha": str, "repository": str, "occurred_at": str}`
- Impl: extend `list_public_occurrences` flow with a per-occurrence fetch. Verify the GG public API exposes a single-occurrence endpoint with the patch field; if it doesn't, this tool is **deferred** — call out in implementation, do not stub.
- `required_scopes=["incidents:read"]`
- Description: "Fetch the code patch (with surrounding context) for a single public occurrence. Use after `list_public_occurrences` to inspect the actual code surrounding a leak."

If the patch endpoint isn't available, drop this tool from the implementation; the existing `list_public_occurrences` already returns filepath/commit/repo, which is enough for the prompts below.

## Part B — Prompts to add

MCP prompts (`@mcp.prompt` in FastMCP 3.x) are parameterized text the client can fetch and inject into a model's context. They are the right primitive for shipping orchestration intent: schema-as-text + decision tree + when-to-stop rules, without dictating a specific LLM or graph framework.

All prompts live in `packages/gg_api_core/src/gg_api_core/prompts/`. New module — create `__init__.py` and a `register_prompts.py` analogous to `register_tools.py`. `secops_mcp_server` calls both registration helpers in its `server.py`.

Each prompt embeds:
1. A short role statement.
2. The structured-output schema, as a JSON-Schema-ish block.
3. The decision/choreography rules.
4. The list of MCP tools the prompt expects the client to have access to (names only — the client resolves them from its tool list).

### B.1 `triage_public_secret_leak`

Mirrors `SecretTriageService`. One-shot classifier, no tool calls expected (but the client *may* call tools if it wants to).

Parameters:
- `incident_id: str` (mandatory) — feeds `get_public_incident` and `list_public_occurrences`
- `target_company: str | None = None` — if provided, switches to "targeted" mode

Prompt body outline:
- Role: "You are a security analyst triaging a single public secret leak."
- Inputs to gather: call `get_public_incident({incident_id})` and `list_public_occurrences({incident_id})`. Optionally call `get_github_repo_metadata` / `list_github_repo_contributors` for the top-listed repo if `company_confidence` would otherwise be ≤ 4.
- Output schema (verbatim, mirroring `SecretTriageOutput`): `company_rationale`, `company_verification_hints`, `company_confidence` (1–10), `company_name`, `detected_environment` enum, `risk_key_points`, `potential_actions`, `potential_risks`, `risk_score` (0–100), `risk_severity` enum, `summary`.
- Stop rule: one pass. Do not invoke RDAP/SSL/validity-check at this stage — those belong to qualification.

### B.2 `qualify_high_impact_leak`

Mirrors the Deep Incident Analysis orchestrator. Tool-driven, multi-step.

Parameters:
- `incident_id: str`
- `triage_summary: str | None = None` — if the caller already ran triage, paste it here
- `target_company: str | None = None`

Prompt body outline:
- Role: "You are qualifying whether a leaked secret is a high-impact leak (HIL) for a specific company."
- Inputs: `get_public_incident`, `list_public_occurrences`, optionally `get_public_occurrence_patch` if available.
- Tool playbook (cheap → expensive):
  1. Extract candidate hostnames / domains / IPs from URLs in the patch and from detector metadata.
  2. For each candidate: `dns_lookup` → if resolvable, `check_ssl_certificate` and `rdap_domain_lookup` (or `rdap_ip_lookup` if IP literal).
  3. If still inconclusive: `get_github_repo_metadata` and `list_github_repo_contributors` for the source repo.
  4. If the candidate company is testable: `check_secret_validity` (gated on user consent — this *touches the provider's API*; emit a warning in the prompt that the client should confirm).
  5. Optional deep dive: `search_github_code` / `search_github_issues` scoped to the repo to find code paths that name the candidate company.
- Stop rule: stop as soon as evidence is sufficient OR after N (default 8) tool calls. Avoid `check_secret_validity` unless other signals are insufficient.
- Output schema (verbatim, mirroring `DeepIncidentAnalysisOutput`): `verdict` ∈ {confirmed, rejected, inconclusive}, `company_name`, `relationship_type` ∈ {owned, uses, unknown}, `evidence_chain: list[{tool_used, finding, supports_company: bool, reasoning}]`, `rejection_reason?`, `agrees_with_triage`, `triage_disagreement_reason?`.

### B.3 `investigate_secret_repository`

Mirrors the Reader sub-agent. Designed to be called by `qualify_high_impact_leak`'s playbook OR standalone.

Parameters:
- `repo: str` (`owner/name`)
- `task: str` — what evidence is being looked for, in natural language
- `incident_id: str | None = None` — for cross-referencing occurrences

Prompt body outline:
- Role: "You are investigating a GitHub repository to gather evidence about ownership or impact of a leaked secret."
- Tool playbook:
  1. `get_github_repo_metadata({repo})` — read description, homepage, owner.company.
  2. `list_github_repo_contributors({repo})` — collect contributor companies.
  3. `search_github_code({task}, repo={repo})` — look for code paths matching the task description.
  4. `search_github_issues({task}, repo={repo})` — look for prior reports.
- Stop rule: bounded by step budget. The prompt explicitly says "stop after 6 tool calls and submit findings even if uncertain". This mirrors `_StepBudgetMiddleware`.
- Output schema (verbatim, mirroring `ReaderTaskResult`): `evidence_items: list[EvidenceItem]`, `conclusion: str`, `files_examined: list[str]`.

### Prompt-shared resources

Optional: expose the three Pydantic-derived JSON schemas as MCP **resources** (`resource://gg/schemas/secret_triage_output`, `.../deep_analysis_output`, `.../reader_task_result`) so a client can fetch them programmatically. **Skip for v1** — embed the schema in the prompt text. Add resources only if a client asks.

## Part C — Dependencies to add (in `gg_api_core/pyproject.toml`)

- `dnspython>=2.6` — DNS lookups
- `cryptography>=42` — TLS cert parsing (likely already transitively present)
- `httpx` — already present
- RDAP is hit via plain HTTP, no new lib needed

No new GG-internal dependencies. The validity-check tool calls the existing GG SaaS API via the existing `GitGuardianClient`.

## Part D — Tests

For each tool, add a test under `tests/tools/<group>/test_<name>.py`:

- **Network tools** — mock the network via `respx` (for HTTP) and `unittest.mock` for `socket`/`ssl`. Don't hit the live internet in CI. Include at least one happy-path and one error-path (NXDOMAIN, timeout, refused connection).
- **GitHub tools** — `vcrpy` cassettes (existing convention in `tests/cassettes/`).
- **Validity check** — `vcrpy` cassette against the GG API; cassette must have secret values scrubbed.
- **Prompts** — render each prompt with sample args and snapshot the output (golden file under `tests/prompts/snapshots/`). Assert key sections are present (schema block, stop rule, expected tool names).

Add a smoke test that loads the secops server and lists all tools + prompts, asserting the new ones show up.

## Part E — Documentation

- Update `packages/secops_mcp_server/README.md` with the new tool list and prompts.
- Add a short section to the top-level `README.md` under "Features supported" mentioning HIL-style triage/qualification.
- Add an example transcript in `examples/` showing a client calling `qualify_high_impact_leak` and walking through the tool playbook.

## Suggested implementation order

1. Network primitives (smallest, no auth, no GG dep) — A.1 + tests.
2. GitHub primitives — A.2 + tests with cassettes.
3. Prompts — Part B (depends on tool names from 1 + 2).
4. Validity check + secret-checker listing — A.3 (needs GG API endpoint confirmation).
5. Public-occurrence patch reader — A.4 (deferred if API endpoint missing).
6. README / examples / smoke tests.

## Open questions for the implementer

1. **Validity check endpoint** — confirm which path on the GG public API exposes single-secret validity check, and what scope it requires. If the only path is internal-only, drop A.3 from v1.
2. **Patch endpoint** — same question for `get_public_occurrence_patch`. If only `list_public_occurrences` exposes patches (in bulk), make A.4 a no-op and adjust the prompts to use the list endpoint directly.
3. **Per-server filtering** — should *any* of the new tools go into `developer_mcp_server` too? Default in this plan: no. Revisit if a developer-side use case appears.
4. **Rate limiting on the network tools** — should the server cache results (e.g. RDAP for an hour)? Default in this plan: no caching; let the client manage repeated calls. Revisit if abuse becomes a concern.
