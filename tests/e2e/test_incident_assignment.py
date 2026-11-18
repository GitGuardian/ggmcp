"""Assign and unassign tools, one per change and per incident kind.

These tools write to customer workspaces, so the tests pin the endpoint and JSON body of
each tool and way of naming the assignee, and that a wrong combination blocks the call.
"""

import logging

import pytest

from tests.e2e.harness import TEST_MEMBER_ID, call_tool, sent_body, tool_error_text, tool_output

INTERNAL = "/incidents/secrets/42"
PUBLIC = "/public-incidents/secrets/42"
ASSIGN_TOOLS = [
    pytest.param("assign_internal_incident", INTERNAL, "internal", id="internal"),
    pytest.param("assign_public_incident", PUBLIC, "public", id="public"),
]
UNASSIGN_TOOLS = [
    pytest.param("unassign_internal_incident", INTERNAL, "internal", id="internal"),
    pytest.param("unassign_public_incident", PUBLIC, "public", id="public"),
]


@pytest.mark.parametrize(("tool", "path", "kind"), ASSIGN_TOOLS)
@pytest.mark.parametrize(
    ("arguments", "expected_body"),
    [
        pytest.param({"assignee_member_id": 7}, {"member_id": 7}, id="by-member-id"),
        pytest.param({"assignee_email": "dev@example.com"}, {"email": "dev@example.com"}, id="by-email"),
        pytest.param({"mine": True}, {"member_id": TEST_MEMBER_ID}, id="to-me"),
    ],
)
async def test_assign_posts_only_the_assignee(
    mcp_client, gg_api, mock_token_scopes, tool, path, kind, arguments, expected_body
):
    """
    GIVEN one way of naming the assignee
    WHEN an assign tool is called
    THEN its endpoint is POSTed with only that assignee, and the result names the incident, its kind, the change
         and the member the API assigned
    """
    incident = {"id": 42, "status": "ASSIGNED", "assignee_id": 7}
    route = gg_api.post(f"{path}/assign").respond(200, json=incident)

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert sent_body(route) == expected_body
    assert tool_output(result) == {
        "incident_kind": kind,
        "incident_id": 42,
        "action": "assign",
        "assignee_id": 7,
        "incident": incident,
    }


@pytest.mark.parametrize(("tool", "path", "kind"), UNASSIGN_TOOLS)
async def test_unassign_posts_without_a_body(mcp_client, gg_api, mock_token_scopes, tool, path, kind):
    """
    GIVEN an assigned incident
    WHEN an unassign tool is called
    THEN its endpoint is POSTed with no body, and the result has no assignee
    """
    incident = {"id": 42, "status": "TRIGGERED", "assignee_id": None}
    route = gg_api.post(f"{path}/unassign").respond(200, json=incident)

    result = await call_tool(mcp_client, tool, {"incident_id": 42})

    assert route.calls.last.request.content == b""
    assert tool_output(result) == {
        "incident_kind": kind,
        "incident_id": 42,
        "action": "unassign",
        "assignee_id": None,
        "incident": incident,
    }


@pytest.mark.parametrize(
    ("tool", "arguments", "message"),
    [
        pytest.param("assign_internal_incident", {}, "exactly one of", id="no-assignee"),
        pytest.param(
            "assign_public_incident", {"mine": True, "assignee_member_id": 7}, "exactly one of", id="two-assignees"
        ),
        pytest.param("assign_internal_incident", {"assignee_member_id": True}, "must be a numeric ID", id="bool-id"),
        pytest.param("unassign_internal_incident", {"mine": True}, "mine", id="assignee-on-unassign"),
    ],
)
async def test_a_wrong_assignee_blocks_the_call(mcp_client, gg_api, mock_token_scopes, tool, arguments, message):
    """
    GIVEN no assignee, two of them, a member ID that is not a number, or an assignee on unassign
    WHEN the tool is called
    THEN the call fails naming the problem, and the API is never called
    """
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 42})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 42})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert result["isError"] is True
    assert message in tool_error_text(result)
    assert not internal.called
    assert not public.called


@pytest.mark.parametrize(
    "incident_id",
    [
        pytest.param("1/../../members/5", id="path-traversal"),
        pytest.param("42?show_token=true", id="query-injection"),
        pytest.param("abc", id="not-a-number"),
        pytest.param("4٢", id="non-ascii-digit"),
    ],
)
async def test_an_incident_id_that_is_not_a_number_never_reaches_the_api(
    mcp_client, gg_api, mock_token_scopes, incident_id
):
    """
    GIVEN an incident_id string that is not made of digits
    WHEN assign_internal_incident is called
    THEN the call fails validation and no incident endpoint is requested
    """
    result = await call_tool(mcp_client, "assign_internal_incident", {"incident_id": incident_id, "mine": True})

    assert "must be a numeric ID" in tool_error_text(result)
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


async def test_a_numeric_string_incident_id_is_read_as_that_number(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN an incident_id sent as a string of digits, as some clients do
    WHEN assign_internal_incident is called
    THEN the request goes to that incident's endpoint
    """
    route = gg_api.post(f"{INTERNAL}/assign").respond(200, json={"id": 42, "assignee_id": TEST_MEMBER_ID})

    result = await call_tool(mcp_client, "assign_internal_incident", {"incident_id": "42", "mine": True})

    assert route.called
    assert tool_output(result)["incident_id"] == 42


@pytest.mark.parametrize(("tool", "path", "kind"), ASSIGN_TOOLS)
async def test_an_email_no_member_has_gets_a_hint_that_does_not_repeat_it(
    mcp_client, gg_api, mock_token_scopes, caplog, tool, path, kind
):
    """
    GIVEN an email the API refuses with its bare "Invalid payload." 400
    WHEN an assign tool is called
    THEN the error says no member likely has that address and how to proceed, and neither it nor any log
         repeats it
    """
    gg_api.post(f"{path}/assign").respond(400, json={"detail": "Invalid payload."})

    with caplog.at_level(logging.DEBUG):
        result = await call_tool(mcp_client, tool, {"incident_id": 42, "assignee_email": "nobody@example.com"})

    error = tool_error_text(result)
    assert "Invalid payload" in error
    assert "no member of this workspace has that email address" in error
    assert "nobody@example.com" not in error
    assert [r.getMessage() for r in caplog.records if "nobody@example.com" in r.getMessage()] == []


async def test_a_member_id_refusal_gets_no_email_hint(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a member ID the API refuses with a 400
    WHEN assign_internal_incident is called
    THEN the error carries the API's reason only, with no hint about email addresses
    """
    gg_api.post(f"{INTERNAL}/assign").respond(400, json={"detail": "Invalid payload."})

    result = await call_tool(mcp_client, "assign_internal_incident", {"incident_id": 42, "assignee_member_id": 7})

    error = tool_error_text(result)
    assert "Invalid payload" in error
    assert "email" not in error


async def test_mine_with_a_token_tied_to_no_member_is_refused(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a token tied to no workspace member, such as a service account
    WHEN assign_public_incident is called with mine=True
    THEN it fails saying why, and the incident is not assigned
    """
    mock_token_scopes(scopes=["incidents:read", "incidents:write"], member_id=None)
    route = gg_api.post(f"{PUBLIC}/assign").respond(200, json={"id": 42})

    result = await call_tool(mcp_client, "assign_public_incident", {"incident_id": 42, "mine": True})

    assert "not tied to a workspace member" in tool_error_text(result)
    assert not route.called


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        pytest.param("assign_internal_incident", {"mine": True}, id="assign_internal_incident"),
        pytest.param("unassign_internal_incident", {}, id="unassign_internal_incident"),
        pytest.param("assign_public_incident", {"mine": True}, id="assign_public_incident"),
        pytest.param("unassign_public_incident", {}, id="unassign_public_incident"),
    ],
)
async def test_each_needs_the_incidents_write_scope(mcp_client, gg_api, mock_token_scopes, tool, arguments):
    """
    GIVEN a token with incidents:read but not incidents:write
    WHEN an assign or unassign tool is called
    THEN it is refused for the missing scope, and the API is never called
    """
    mock_token_scopes(scopes=["incidents:read"])
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 42})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 42})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, **arguments})

    assert "incidents:write" in tool_error_text(result)
    assert not internal.called
    assert not public.called
