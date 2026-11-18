"""Add and edit comment tools, one per change and per incident kind.

These tools write to customer workspaces, so the tests pin the endpoint and JSON body of
each tool, and that a missing or empty argument blocks the API call.
"""

import pytest

from tests.e2e.harness import call_tool, rpc, rpc_result, sent_body, tool_error_text, tool_output

INTERNAL = "/incidents/secrets/77"
PUBLIC = "/public-incidents/secrets/77"
KINDS = [
    pytest.param("internal", INTERNAL, id="internal"),
    pytest.param("public", PUBLIC, id="public"),
]


@pytest.mark.parametrize(("kind", "path"), KINDS)
async def test_add_posts_a_note_with_the_comment(mcp_client, gg_api, mock_token_scopes, kind, path):
    """
    GIVEN an incident of either kind
    WHEN its add-comment tool is called
    THEN a note is POSTed with the comment as its only field, and the result gives the comment and its ID
    """
    note = {"id": 9, "comment": "Rotating the key today"}
    route = gg_api.post(f"{path}/notes").respond(201, json=note)

    result = await call_tool(
        mcp_client, f"add_{kind}_incident_comment", {"incident_id": 77, "comment": "Rotating the key today"}
    )

    assert sent_body(route) == {"comment": "Rotating the key today"}
    assert tool_output(result) == {
        "incident_kind": kind,
        "incident_id": 77,
        "action": "add",
        "comment_id": 9,
        "comment": note,
    }


@pytest.mark.parametrize(("kind", "path"), KINDS)
async def test_edit_patches_the_note(mcp_client, gg_api, mock_token_scopes, kind, path):
    """
    GIVEN a comment ID on an incident of either kind
    WHEN its edit-comment tool is called
    THEN that note is PATCHed with the new comment
    """
    note = {"id": 9, "comment": "Key rotated"}
    route = gg_api.patch(f"{path}/notes/9").respond(200, json=note)

    result = await call_tool(
        mcp_client, f"edit_{kind}_incident_comment", {"incident_id": 77, "comment_id": 9, "comment": "Key rotated"}
    )

    assert sent_body(route) == {"comment": "Key rotated"}
    assert tool_output(result)["action"] == "edit"
    assert tool_output(result)["comment"] == note


async def test_the_id_add_returns_is_the_comment_id_edit_takes(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a comment added on an internal incident
    WHEN it is edited with the comment_id the add returned
    THEN the edit PATCHes that note, and the comment_id description says where the ID comes from
    """
    gg_api.post(f"{INTERNAL}/notes").respond(201, json={"id": 9, "comment": "Rotating the key"})
    edit = gg_api.patch(f"{INTERNAL}/notes/9").respond(200, json={"id": 9, "comment": "Key rotated"})

    added = tool_output(
        await call_tool(mcp_client, "add_internal_incident_comment", {"incident_id": 77, "comment": "Rotating the key"})
    )
    await call_tool(
        mcp_client,
        "edit_internal_incident_comment",
        {"incident_id": 77, "comment_id": added["comment_id"], "comment": "Key rotated"},
    )

    assert edit.called
    tools = rpc_result(await rpc(mcp_client, "tools/list", {}))["tools"]
    schema = next(tool["inputSchema"] for tool in tools if tool["name"] == "edit_internal_incident_comment")
    assert "the comment_id that adding the comment returned" in schema["properties"]["comment_id"]["description"]


@pytest.mark.parametrize(
    ("tool", "arguments", "field"),
    [
        pytest.param("add_internal_incident_comment", {}, "comment", id="add-without-comment"),
        pytest.param("add_public_incident_comment", {"comment": "   "}, "comment", id="blank-comment"),
        pytest.param("add_internal_incident_comment", {"comment": "x" * 10_001}, "comment", id="comment-too-long"),
        pytest.param("edit_public_incident_comment", {"comment": "x"}, "comment_id", id="edit-without-comment-id"),
        pytest.param("add_public_incident_comment", {"comment": "x", "comment_id": 9}, "comment_id", id="id-on-add"),
    ],
)
async def test_a_missing_or_foreign_argument_blocks_the_call(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, field
):
    """
    GIVEN a call without the comment or its ID, with an empty or too long comment, or with a field the tool lacks
    WHEN the tool is called
    THEN the call fails naming that field, and the API is never called
    """
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 9})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 9})

    result = await call_tool(mcp_client, tool, {"incident_id": 77, **arguments})

    assert result["isError"] is True
    assert field in tool_error_text(result)
    assert not internal.called
    assert not public.called


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        pytest.param("add_internal_incident_comment", {"comment": "x"}, id="add_internal_incident_comment"),
        pytest.param("edit_internal_incident_comment", {"comment": "x", "comment_id": 9}, id="edit_internal"),
        pytest.param("add_public_incident_comment", {"comment": "x"}, id="add_public_incident_comment"),
        pytest.param("edit_public_incident_comment", {"comment": "x", "comment_id": 9}, id="edit_public"),
    ],
)
async def test_each_needs_the_incidents_write_scope(mcp_client, gg_api, mock_token_scopes, tool, arguments):
    """
    GIVEN a token with incidents:read but not incidents:write
    WHEN a comment tool is called
    THEN it is refused for the missing scope, and the API is never called
    """
    mock_token_scopes(scopes=["incidents:read"])
    internal = gg_api.route(path__startswith=f"/v1{INTERNAL}/").respond(200, json={"id": 9})
    public = gg_api.route(path__startswith=f"/v1{PUBLIC}/").respond(200, json={"id": 9})

    result = await call_tool(mcp_client, tool, {"incident_id": 77, **arguments})

    assert "incidents:write" in tool_error_text(result)
    assert not internal.called
    assert not public.called
