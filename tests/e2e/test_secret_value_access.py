"""No tool reads a secret's value: GET /secrets/{id} is never called."""

import json

import httpx
import pytest
import respx

from tests.e2e.harness import GG_API_URL, call_tool, secret_value_reads

VALIDITY = {"id": 9, "validity": "valid", "validity_override": None, "last_checked_at": None, "analysis": None}

SECRET_TOOLS = [
    pytest.param("get_secret_validity", "get", "/secrets/9/validity", {}, httpx.Response(200, json=VALIDITY), id="get"),
    pytest.param(
        "request_secret_validity_check", "post", "/secrets/9/validity/check", {}, httpx.Response(202), id="check"
    ),
    pytest.param(
        "set_secret_validity_override",
        "post",
        "/secrets/9/validity",
        {"validity": "valid"},
        httpx.Response(200, json={**VALIDITY, "validity_override": "valid"}),
        id="set",
    ),
    pytest.param(
        "remove_secret_validity_override", "delete", "/secrets/9/validity", {}, httpx.Response(204), id="remove"
    ),
    pytest.param(
        "revoke_secret", "post", "/secrets/9/revoke", {}, httpx.Response(200, json={"success": True}), id="revoke"
    ),
]


@pytest.mark.parametrize(("tool", "method", "path", "extra", "response"), SECRET_TOOLS)
async def test_a_tool_that_takes_a_secret_id_never_reads_its_value(
    mcp_client, gg_api, mock_token_scopes, tool, method, path, extra, response
):
    """
    GIVEN an API that would answer GET /secrets/9 with the secret's value
    WHEN a tool that takes a secret_id is called
    THEN the value is never requested and is absent from the result
    """
    value_route = gg_api.get("/secrets/9").respond(200, json={"id": 9, "value": "the-clear-value"})
    getattr(gg_api, method)(path).mock(return_value=response)

    result = await call_tool(mcp_client, tool, {"secret_id": 9, **extra})

    assert not value_route.called
    assert "the-clear-value" not in json.dumps(result)


async def test_the_suite_guard_sees_a_read_of_a_secret_value_and_nothing_else():
    """
    GIVEN the check every e2e test runs on the mocked GitGuardian API when it ends
    WHEN the API receives a read of a secret's value among other calls on that secret
    THEN only the read of the value is reported
    """
    with respx.mock(base_url=GG_API_URL) as router:
        router.route().respond(200, json={})
        async with httpx.AsyncClient(base_url=GG_API_URL) as client:
            await client.get("/secrets/9")
            await client.get("/secrets/9/validity")
            await client.post("/secrets/9/validity")
            await client.delete("/secrets/9")
            await client.get("/incidents/secrets/9")

        assert [(r.method, r.url.path) for r in secret_value_reads(router)] == [("GET", "/v1/secrets/9")]
