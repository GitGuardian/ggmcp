"""GitGuardian API scope definitions for different server types."""

# All available GitGuardian API scopes as per documentation
# https://docs.gitguardian.com/api-docs/authentication#scopes
ALL_SCOPES = [
    "scan",
    "incidents:read",
    "incidents:write",
    "incidents:share",
    "audit_logs:read",
    "honeytokens:read",
    "honeytokens:write",
    "api_tokens:write",
    "api_tokens:read",
    "ip_allowlist:read",
    "ip_allowlist:write",
    # Uncomment if needed and available
    # "sources:read",
    # "sources:write",
    # "custom_tags:read",
    # "custom_tags:write",
]

# Scopes needed for the developer MCP server (minimal)
DEVELOPER_SCOPES = [
    "incidents:read",
]

# Scopes needed for the SecOps MCP server (full access)
SECOPS_SCOPES = ALL_SCOPES
