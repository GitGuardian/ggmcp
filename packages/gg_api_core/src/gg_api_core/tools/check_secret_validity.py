"""DEFERRED — single-secret validity check tool.

# TODO(HIL): Implement once the public GG API exposes a single-secret validity
# check endpoint.
#
# Plan reference: docs/HIL_PLAN.md §A.3.
#
# At implementation time, ``GitGuardianClient`` in ``gg_api_core.client`` does
# not expose any validity-check helper, and ``gg_api_core.urls`` does not name
# such a path. The HIL agents rely on an internal Anvil extension to hit a
# checker — that is not appropriate to surface on a public MCP.
#
# When the endpoint becomes available:
#   1. Add a ``check_secret_validity`` method on ``GitGuardianClient`` that
#      POSTs to the confirmed path with the detector name + secret values.
#   2. Build this tool around it. Pydantic params should mark
#      ``secret_values`` as sensitive (do not log the dict).
#   3. Required scope is expected to be ``["scan"]`` — confirm with the API.
#   4. Wire it into ``secops_mcp_server.server`` next to the other GG tools.
#
# Not registered on any server until the above is done.
"""
