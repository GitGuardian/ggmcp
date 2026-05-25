# secops-mcp-server (deprecated)

This package now re-exports the unified [`gg-mcp-server`](../gg_mcp_server). The
`secops-mcp-server` console script still works for one release but emits a
`DeprecationWarning` — update your MCP client configuration to invoke
`gg-mcp-server` instead.

The tools exposed at runtime depend on the OAuth scopes granted to the access
token, so the previous "developer" vs "secops" split is no longer meaningful at
the package level.
