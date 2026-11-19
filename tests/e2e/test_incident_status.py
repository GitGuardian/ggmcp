"""Resolve, ignore and reopen tools, one per change and per incident kind.

These tools write to customer workspaces, so the tests pin the endpoint and JSON body of
each tool, and that a missing or foreign argument blocks the API call.
"""

import pytest

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output

INTERNAL = "/incidents/secrets/42"
PUBLIC = "/public-incidents/secrets/42"


@pytest.mark.parametrize(
    ("tool", "arguments", "expected_path", "expected_body", "kind", "status"),
    [
        pytest.param(
            "resolve_internal_incident",
            {"secret_revoked": True},
            f"{INTERNAL}/resolve",
            {"secret_revoked": True},
            "internal",
            "RESOLVED",
            id="resolve_internal_incident",
        ),
        pytest.param(
            "ignore_internal_incident",
            {"ignore_reason": "low_risk"},
            f"{INTERNAL}/ignore",
            {"ignore_reason": "low_risk"},
            "internal",
            "IGNORED",
            id="ignore_internal_incident",
        ),
        pytest.param(
            "reopen_internal_incident",
            {},
            f"{INTERNAL}/reopen",
            None,
            "internal",
            "TRIGGERED",
            id="reopen_internal_incident",
        ),
        pytest.param(
            "resolve_public_incident",
            {"resolve_reason": "source_deleted"},
            f"{PUBLIC}/resolve",
            {"resolve_reason": "source_deleted"},
            "public",
            "RESOLVED",
            id="resolve_public_incident",
        ),
        pytest.param(
            "ignore_public_incident",
            {"ignore_reason": "ignore_actor"},
            f"{PUBLIC}/ignore",
            {"ignore_reason": "ignore_actor"},
            "public",
            "IGNORED",
            id="ignore_public_incident",
        ),
        pytest.param(
            "reopen_public_incident", {}, f"{PUBLIC}/reopen", None, "public", "TRIGGERED", id="reopen_public_incident"
        ),
    ],
)
async def test_each_tool_posts_to_its_endpoint(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, expected_path, expected_body, kind, status
):
    """
    GIVEN an incident and what the tool needs
    WHEN a resolve, ignore or reopen tool is called
    THEN its endpoint is POSTed with exactly the expected body, and the result names the incident, its kind,
         the change and the new status
    """
    incident = {"id": 42, "status": status}
    route = gg_api.post(expected_path).respond(200, json=incident)

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert route.called
    if expected_body is None:
        assert route.calls.last.request.content == b""
    else:
        assert sent_body(route) == expected_body
    assert tool_output(result) == {
        "incident_kind": kind,
        "incident_id": 42,
        "action": tool.split("_", 1)[0],
        "changed": True,
        "status": status,
        "incident": incident,
    }


@pytest.mark.parametrize(
    ("tool", "arguments", "field"),
    [
        pytest.param("resolve_internal_incident", {}, "secret_revoked", id="resolve-without-revocation-answer"),
        pytest.param("resolve_public_incident", {}, "resolve_reason", id="public-resolve-without-reason"),
        pytest.param("ignore_internal_incident", {}, "ignore_reason", id="ignore-without-reason"),
        pytest.param(
            "ignore_internal_incident",
            {"ignore_reason": "ignore_secret"},
            "ignore_reason",
            id="public-only-reason-on-internal",
        ),
        pytest.param(
            "resolve_internal_incident",
            {"secret_revoked": True, "resolve_reason": "revoked"},
            "resolve_reason",
            id="public-argument-on-internal",
        ),
        pytest.param(
            "resolve_public_incident",
            {"resolve_reason": "revoked", "secret_revoked": True},
            "secret_revoked",
            id="internal-argument-on-public",
        ),
        pytest.param(
            "reopen_internal_incident", {"ignore_reason": "low_risk"}, "ignore_reason", id="argument-reopen-lacks"
        ),
    ],
)
async def test_a_missing_or_foreign_argument_blocks_the_call(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, field
):
    """
    GIVEN a call without a field the tool requires, with a value it does not take, or with another tool's field
    WHEN the tool is called
    THEN the call fails naming that field, and the API is never called
    """
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 42})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 42})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert result["isError"] is True
    assert field in tool_error_text(result)
    assert not internal.called
    assert not public.called


@pytest.mark.parametrize(
    "incident_id",
    [
        pytest.param("1/../../members/5", id="path-traversal"),
        pytest.param("42?show_token=true", id="query-injection"),
        pytest.param("4٢", id="non-ascii-digit"),
        pytest.param("4_2", id="underscore"),
        pytest.param(True, id="boolean"),
        pytest.param(0, id="zero"),
    ],
)
async def test_an_incident_id_that_is_not_a_positive_number_never_reaches_the_api(
    mcp_client, gg_api, mock_token_scopes, incident_id
):
    """
    GIVEN an incident_id that is not a positive number
    WHEN reopen_internal_incident is called
    THEN the call fails validation and no incident endpoint is requested
    """
    result = await call_tool(mcp_client, "reopen_internal_incident", {"incident_id": incident_id})

    assert result["isError"] is True
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


async def test_a_numeric_string_incident_id_is_read_as_that_number(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN an incident_id sent as a string of digits, as some clients do
    WHEN reopen_internal_incident is called
    THEN the request goes to that incident's endpoint, and the result carries the ID as a number
    """
    route = gg_api.post(f"{INTERNAL}/reopen").respond(200, json={"id": 42, "status": "TRIGGERED"})

    result = await call_tool(mcp_client, "reopen_internal_incident", {"incident_id": "42"})

    assert route.called
    assert tool_output(result)["incident_id"] == 42


async def test_a_public_id_sent_to_an_internal_tool_gets_the_api_refusal(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a public incident ID sent to the internal tool, whose API does not know it
    WHEN reopen_internal_incident is called
    THEN the call fails, and the error says the two kinds of IDs are not interchangeable
    """
    gg_api.post(f"{INTERNAL}/reopen").respond(404, json={"detail": "Not found."})

    result = await call_tool(mcp_client, "reopen_internal_incident", {"incident_id": 42})

    assert result["isError"] is True
    assert "not interchangeable" in tool_error_text(result)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        pytest.param("resolve_internal_incident", {"secret_revoked": True}, id="resolve_internal_incident"),
        pytest.param("ignore_internal_incident", {"ignore_reason": "low_risk"}, id="ignore_internal_incident"),
        pytest.param("reopen_internal_incident", {}, id="reopen_internal_incident"),
        pytest.param("resolve_public_incident", {"resolve_reason": "revoked"}, id="resolve_public_incident"),
        pytest.param("ignore_public_incident", {"ignore_reason": "low_risk"}, id="ignore_public_incident"),
        pytest.param("reopen_public_incident", {}, id="reopen_public_incident"),
    ],
)
async def test_each_needs_the_incidents_write_scope(mcp_client, gg_api, mock_token_scopes, tool, arguments):
    """
    GIVEN a token with incidents:read but not incidents:write
    WHEN a resolve, ignore or reopen tool is called
    THEN it is refused for the missing scope, and the API is never called
    """
    mock_token_scopes(scopes=["incidents:read"])
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 42})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 42})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert "incidents:write" in tool_error_text(result)
    assert not internal.called
    assert not public.called
