"""Share and unshare a Public Monitoring incident through the remote MCP boundary."""

import logging

import httpx
import pytest

from tests.e2e.harness import TEST_PAT, call_tool, list_tool_names, sent_body, tool_error_text, tool_output

TOOL = "create_public_incident_share_link"
PATH = "/public-incidents/secrets/77/share"
TOKEN = "11111111-1111-4111-8111-111111111111"
SHARE = {
    "incident_id": 77,
    "share_url": f"https://dashboard.gitguardian.com/share/public-incidents#{TOKEN}",
    "expire_at": "2026-12-01T12:00:00Z",
    "feedback_collection": False,
    "auto_healing": False,
    "token": TOKEN,
    "revoked_at": None,
}


async def test_defaults_create_a_view_only_link(mcp_client, gg_api, mock_token_scopes, caplog):
    """
    GIVEN an unshared public incident and a token holding only incidents:share
    WHEN a link is requested with default options
    THEN the caller's token creates a view-only link with the workspace duration,
         and the URL is returned without logging the credential-bearing response
    """
    mock_token_scopes(["incidents:share"])
    route = gg_api.post(PATH).respond(200, json=SHARE)

    with caplog.at_level(logging.DEBUG, logger="gg_api_core.client"):
        result = await call_tool(mcp_client, TOOL, {"incident_id": 77})

    assert route.call_count == 1
    assert sent_body(route) == {"feedback_collection": False, "auto_healing": False, "lifespan": 0}
    assert route.calls.last.request.headers["Authorization"] == f"Token {TEST_PAT}"
    assert tool_output(result) == {key: value for key, value in SHARE.items() if key not in {"token", "revoked_at"}}
    assert TOKEN not in caplog.text
    assert SHARE["share_url"] not in caplog.text


@pytest.mark.parametrize(("feedback_collection", "auto_healing"), [(True, False), (False, True)])
async def test_explicit_permissions_and_lifespan_are_forwarded(
    mcp_client, gg_api, mock_token_scopes, feedback_collection, auto_healing
):
    """
    GIVEN explicit permissions and a duration
    WHEN a share link is requested
    THEN those options reach the public incident's share endpoint unchanged
    """
    options = {"feedback_collection": feedback_collection, "auto_healing": auto_healing, "lifespan": 24}
    response = {**SHARE, "feedback_collection": feedback_collection, "auto_healing": auto_healing}
    route = gg_api.post(PATH).respond(200, json=response)

    result = await call_tool(mcp_client, TOOL, {"incident_id": 77, **options})

    assert sent_body(route) == options
    output = tool_output(result)
    assert output["feedback_collection"] is feedback_collection
    assert output["auto_healing"] is auto_healing
    assert output["expire_at"] == response["expire_at"]


@pytest.mark.parametrize(("arguments", "header"), [({}, "false"), ({"privacy_mode": True}, "true")])
async def test_privacy_mode_is_off_unless_requested(mcp_client, gg_api, mock_token_scopes, arguments, header):
    """The share call runs without privacy mode by default, and the link is returned either way."""
    route = gg_api.post(PATH).respond(200, json=SHARE)

    result = await call_tool(mcp_client, TOOL, {"incident_id": 77, **arguments})

    assert route.calls.last.request.headers["X-Privacy-Mode"] == header
    assert tool_output(result)["share_url"] == SHARE["share_url"]


@pytest.mark.parametrize(
    ("arguments", "field"),
    [
        ({}, "incident_id"),
        ({"incident_id": 77, "lifespan": -1}, "lifespan"),
        ({"incident_id": 77, "auto_healing": "maybe"}, "auto_healing"),
        ({"incident_id": 77, "unknown": True}, "unknown"),
    ],
)
async def test_invalid_arguments_block_the_write(mcp_client, gg_api, mock_token_scopes, arguments, field):
    """Missing, invalid and unknown inputs fail before contacting the share endpoint."""
    route = gg_api.post(PATH).respond(200, json=SHARE)

    result = await call_tool(mcp_client, TOOL, arguments)

    assert field in tool_error_text(result)
    assert not route.called


async def test_missing_share_scope_hides_and_blocks_the_tool(mcp_client, gg_api, mock_token_scopes):
    """Incident read and write scopes alone grant no external sharing permission."""
    mock_token_scopes(["incidents:read", "incidents:write"])
    route = gg_api.post(PATH).respond(200, json=SHARE)

    assert TOOL not in await list_tool_names(mcp_client)
    result = await call_tool(mcp_client, TOOL, {"incident_id": 77})

    assert "incidents:share" in tool_error_text(result)
    assert not route.called


@pytest.mark.parametrize("status", [409, 429])
async def test_api_refusals_are_returned_without_retry(mcp_client, gg_api, mock_token_scopes, status):
    """An already-shared conflict and a rate limit remain errors, and the write is not sent again."""
    route = gg_api.post(PATH).respond(status, json={"detail": "Sharing refused"})

    result = await call_tool(mcp_client, TOOL, {"incident_id": 77})

    error = tool_error_text(result)
    assert str(status) in error
    assert "may or may not have been applied" not in error
    assert route.call_count == 1


async def test_an_uncertain_write_is_sent_once_with_dashboard_check_advice(mcp_client, gg_api, mock_token_scopes):
    """An unknown outcome asks the caller to check sharing settings before trying again."""
    route = gg_api.post(PATH).mock(side_effect=httpx.ReadTimeout("connection interrupted"))

    result = await call_tool(mcp_client, TOOL, {"incident_id": 77})

    error = tool_error_text(result)
    assert "may or may not have been applied" in error
    assert "sharing settings in the GitGuardian dashboard" in error
    assert route.call_count == 1


async def test_share_response_redirects_are_refused(mcp_client, gg_api, mock_token_scopes):
    """A credential-bearing sharing call follows no redirect."""
    route = gg_api.post(PATH).respond(307, headers={"Location": "/v1/share-destination"})
    destination = gg_api.post("/share-destination").respond(200, json=SHARE)

    result = await call_tool(mcp_client, TOOL, {"incident_id": 77})

    assert "307" in tool_error_text(result)
    assert route.call_count == 1
    assert not destination.called


REVOKE_TOOL = "revoke_public_incident_share_link"
REVOKE_PATH = "/public-incidents/secrets/77/unshare"


async def test_revoking_the_link_unshares_the_incident(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a shared public incident and a token holding only incidents:share
    WHEN its link is revoked
    THEN the caller's token calls the unshare endpoint once and the result reports a change
    """
    mock_token_scopes(["incidents:share"])
    route = gg_api.post(REVOKE_PATH).respond(204)

    result = await call_tool(mcp_client, REVOKE_TOOL, {"incident_id": 77})

    assert route.call_count == 1
    assert route.calls.last.request.headers["Authorization"] == f"Token {TEST_PAT}"
    assert tool_output(result) == {"incident_id": 77, "changed": True}


async def test_revoking_a_missing_link_reports_no_change(mcp_client, gg_api, mock_token_scopes):
    """An incident with no active link answers 409, which is the requested state."""
    route = gg_api.post(REVOKE_PATH).respond(409, json={"detail": "Incident is not shared"})

    result = await call_tool(mcp_client, REVOKE_TOOL, {"incident_id": 77})

    assert tool_output(result) == {"incident_id": 77, "changed": False}
    assert route.call_count == 1


async def test_missing_share_scope_hides_and_blocks_the_revocation(mcp_client, gg_api, mock_token_scopes):
    """Incident read and write scopes alone cannot end external sharing."""
    mock_token_scopes(["incidents:read", "incidents:write"])
    route = gg_api.post(REVOKE_PATH).respond(204)

    assert REVOKE_TOOL not in await list_tool_names(mcp_client)
    result = await call_tool(mcp_client, REVOKE_TOOL, {"incident_id": 77})

    assert "incidents:share" in tool_error_text(result)
    assert not route.called


async def test_a_missing_incident_is_an_error_not_an_absent_link(mcp_client, gg_api, mock_token_scopes):
    """Only a 409 means there was no link; a 404 remains an error."""
    route = gg_api.post(REVOKE_PATH).respond(404, json={"detail": "Not found"})

    result = await call_tool(mcp_client, REVOKE_TOOL, {"incident_id": 77})

    assert "404" in tool_error_text(result)
    assert route.call_count == 1


async def test_an_uncertain_revocation_is_sent_once_with_dashboard_check_advice(mcp_client, gg_api, mock_token_scopes):
    """An unknown outcome asks the caller to check sharing settings before trying again."""
    route = gg_api.post(REVOKE_PATH).respond(503, json={"detail": "Unavailable"})

    result = await call_tool(mcp_client, REVOKE_TOOL, {"incident_id": 77})

    error = tool_error_text(result)
    assert "may or may not have been applied" in error
    assert "sharing settings in the GitGuardian dashboard" in error
    assert route.call_count == 1
