"""revoke_secret: ask a secret's provider to revoke it."""

import httpx

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output


async def test_a_revocation_is_requested_with_the_workspace_credentials(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a secret whose detector has a revoker
    WHEN revoke_secret is called with its secret_id
    THEN the revocation is requested with an empty body, so the workspace's default credentials apply,
         and the provider's answer is returned
    """
    route = gg_api.post("/secrets/9/revoke").respond(200, json={"success": True, "is_async": True})

    result = await call_tool(mcp_client, "revoke_secret", {"secret_id": 9})

    assert sent_body(route) == {}
    assert tool_output(result) == {"secret_id": 9, "success": True, "reason": None, "is_async": True}


async def test_a_refused_revocation_says_why(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a secret GitGuardian cannot revoke
    WHEN revoke_secret is called
    THEN the result says it failed, with the API's reason
    """
    gg_api.post("/secrets/9/revoke").respond(200, json={"success": False, "reason": "No revoker for this detector."})

    result = await call_tool(mcp_client, "revoke_secret", {"secret_id": 9})

    output = tool_output(result)
    assert (output["success"], output["reason"]) == (False, "No revoker for this detector.")


async def test_an_unknown_outcome_says_not_to_request_again_blindly(
    mcp_client, gg_api, mock_token_scopes, no_retry_delay
):
    """
    GIVEN a revocation request that times out
    WHEN revoke_secret is called
    THEN it is sent once, and the error says it may or may not have been applied and how to check
    """
    route = gg_api.post("/secrets/9/revoke").mock(side_effect=httpx.ReadTimeout("timed out"))

    result = await call_tool(mcp_client, "revoke_secret", {"secret_id": 9})

    assert route.call_count == 1
    assert "may or may not have been applied" in tool_error_text(result)


async def test_it_needs_the_secrets_write_scope(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a token without secrets:write
    WHEN revoke_secret is called
    THEN it is refused naming the scope, and nothing is revoked
    """
    mock_token_scopes(scopes=["incidents:read", "incidents:write"])
    route = gg_api.post("/secrets/9/revoke").respond(200, json={"success": True})

    result = await call_tool(mcp_client, "revoke_secret", {"secret_id": 9})

    assert "secrets:write" in tool_error_text(result)
    assert not route.called
