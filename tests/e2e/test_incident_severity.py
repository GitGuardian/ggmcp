"""set_internal_incident_severity and set_public_incident_severity."""

import pytest

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output

KINDS = [
    pytest.param(
        "set_internal_incident_severity", "/incidents/secrets/42", "patch", "/incidents/secrets/42", id="internal"
    ),
    pytest.param(
        "set_public_incident_severity",
        "/public-incidents/secrets/42",
        "post",
        "/public-incidents/secrets/42/set_severity",
        id="public",
    ),
]


@pytest.mark.parametrize(("tool", "read_path", "method", "write_path"), KINDS)
async def test_a_new_severity_is_written(mcp_client, gg_api, mock_token_scopes, tool, read_path, method, write_path):
    """
    GIVEN an incident of medium severity
    WHEN its severity is set to high
    THEN that kind's endpoint receives only the severity, and the result says it changed
    """
    gg_api.get(read_path).respond(200, json={"id": 42, "severity": "medium"})
    write = getattr(gg_api, method)(write_path).respond(200, json={"id": 42, "severity": "high"})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, "severity": "high"})

    assert sent_body(write) == {"severity": "high"}
    output = tool_output(result)
    assert (output["changed"], output["severity"]) == (True, "high")


@pytest.mark.parametrize(("tool", "read_path", "method", "write_path"), KINDS)
async def test_the_same_severity_writes_nothing(
    mcp_client, gg_api, mock_token_scopes, tool, read_path, method, write_path
):
    """
    GIVEN an incident of high severity
    WHEN its severity is set to high
    THEN nothing is written, and the result says nothing changed
    """
    gg_api.get(read_path).respond(200, json={"id": 42, "severity": "high"})
    write = getattr(gg_api, method)(write_path).respond(200, json={"id": 42, "severity": "high"})

    result = await call_tool(mcp_client, tool, {"incident_id": 42, "severity": "high"})

    assert not write.called
    assert tool_output(result)["changed"] is False


async def test_a_public_incident_takes_no_unknown_severity(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN the public severity endpoint, which has no unknown severity
    WHEN set_public_incident_severity is called with unknown
    THEN the call is refused naming severity
    """
    result = await call_tool(mcp_client, "set_public_incident_severity", {"incident_id": 42, "severity": "unknown"})

    assert "severity" in tool_error_text(result)
