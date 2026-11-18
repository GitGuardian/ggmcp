"""Tools take their arguments at the top level (SI-3963).

Each tool's arguments are the fields of one pydantic model. The model's fields
are the tool's top-level arguments, and the model still validates them.
"""

import json

import httpx

from tests.e2e.harness import call_tool, rpc, rpc_result, sent_params, tool_error_text, tool_output


async def _tool_schemas(mcp_client) -> dict[str, dict]:
    tools = rpc_result(await rpc(mcp_client, "tools/list", {}))["tools"]
    return {tool["name"]: tool["inputSchema"] for tool in tools}


class TestTopLevelArguments:
    async def test_no_tool_wraps_its_arguments_in_a_params_object(self, mcp_client, mock_token_scopes):
        """
        GIVEN the full tool catalog
        WHEN the tools are listed
        THEN no input schema has a params property, and unknown arguments are not allowed
        """
        schemas = await _tool_schemas(mcp_client)

        assert schemas
        assert [name for name, schema in schemas.items() if "params" in schema.get("properties", {})] == []
        assert all(schema.get("additionalProperties") is False for schema in schemas.values())

    async def test_required_fields_are_required_top_level_arguments(self, mcp_client, mock_token_scopes):
        """
        GIVEN tools whose model has required fields
        WHEN the tools are listed
        THEN those fields are the schema's required top-level arguments
        """
        schemas = await _tool_schemas(mcp_client)

        assert schemas["get_incident"]["required"] == ["incident_id"]
        assert set(schemas["get_incident"]["properties"]) == {"incident_id", "with_occurrences", "with_history"}
        assert schemas["resolve_internal_incident"]["required"] == ["incident_id", "secret_revoked"]
        assert schemas["scan_secrets"]["required"] == ["documents"]
        assert "required" not in schemas["list_incidents"]

    async def test_a_flat_call_reaches_the_api(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN get_incident called with incident_id at the top level
        WHEN it runs
        THEN the incident is fetched
        """
        route = gg_api.get("/incidents/secrets/77").respond(200, json={"id": 77})

        result = await call_tool(mcp_client, "get_incident", {"incident_id": 77})

        assert route.called
        assert tool_output(result) == {"incident": {"id": 77}}

    async def test_the_model_still_coerces_a_single_value_into_a_list(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN list_public_incidents called with one status instead of a list
        WHEN it runs
        THEN the model's before-validator accepts it, as it did inside params
        """
        route = gg_api.get("/public-incidents/secrets").respond(200, json=[])

        await call_tool(mcp_client, "list_public_incidents", {"status": "IGNORED"})

        assert sent_params(route)["status"] == "IGNORED"

    async def test_the_model_validators_still_run(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN resolve_internal_incident called without saying whether the secret was revoked
        WHEN it runs
        THEN the model's validator blocks it before any API call
        """
        resolve = gg_api.post("/incidents/secrets/77/resolve").respond(200, json={"id": 77})

        result = await call_tool(mcp_client, "resolve_internal_incident", {"incident_id": 77})

        assert "secret_revoked" in tool_error_text(result)
        assert not resolve.called

    async def test_a_call_in_the_old_params_shape_is_refused_with_a_hint(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a client that still sends its arguments inside a params object
        WHEN list_incidents, whose arguments are all optional, is called that way
        THEN it is refused with a hint instead of running with default filters
        """
        route = gg_api.get("/incidents-for-mcp").mock(return_value=httpx.Response(200, json={"results": []}))

        result = await call_tool(mcp_client, "list_incidents", {"params": {"status": ["RESOLVED"]}})

        error = tool_error_text(result)
        assert "params" in error
        assert "top level" in error
        assert not route.called

    async def test_a_missing_argument_is_named_without_internal_details(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN get_incident called without its required incident_id
        WHEN it runs
        THEN the error names the missing argument, not the internal model, and echoes no input
        """
        error = tool_error_text(await call_tool(mcp_client, "get_incident", {"with_occurrences": 0}))

        assert "Invalid arguments for tool 'get_incident': incident_id: Field required" in error
        assert "GetIncidentParams" not in error
        assert "input_value" not in error

    async def test_validity_filters_only_offer_values_their_endpoint_accepts(self, mcp_client, mock_token_scopes):
        """
        GIVEN the occurrence and public incident endpoints, which reject not_checked and accept unknown,
        and the incident endpoint, which does the opposite
        WHEN the tools are listed
        THEN each tool's validity filter offers only the values its endpoint accepts
        """
        schemas = await _tool_schemas(mcp_client)

        for tool in ("list_repo_occurrences", "list_public_incidents"):
            offered = json.dumps(schemas[tool])
            assert '"not_checked"' not in offered, tool
            assert '"unknown"' in offered, tool
        assert "not_checked" in schemas["list_incidents"]["properties"]["validity"]["description"]
