"""DEFERRED — public-occurrence patch reader.

# TODO(HIL): Implement once the GG public API exposes a single-occurrence
# endpoint that returns the code patch.
#
# Plan reference: docs/HIL_PLAN.md §A.4.
#
# At implementation time:
#   * The HIL reader sub-agent reads file contents via the internal Anvil
#     extension — not appropriate for a public MCP.
#   * ``GitGuardianClient.list_public_occurrences`` already returns filepath,
#     commit sha, source repo and actor for each occurrence, which is enough
#     for the qualification prompt. The plan calls out that if the patch
#     endpoint is not exposed publicly, "drop this tool from the implementation;
#     the existing list_public_occurrences already returns filepath/commit/repo,
#     which is enough for the prompts below."
#
# When the endpoint becomes available:
#   1. Add ``get_public_occurrence_patch(occurrence_id, context_lines)`` to
#      ``GitGuardianClient``.
#   2. Build this tool around it. Required scope: ``["incidents:read"]``.
#   3. Register on ``secops_mcp_server``.
#
# Not registered on any server until the above is done.
"""
