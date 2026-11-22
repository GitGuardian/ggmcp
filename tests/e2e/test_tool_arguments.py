"""Tools take their arguments at the top level.

Each tool's arguments are the fields of one pydantic model. The model's fields
are the tool's top-level arguments, and the model still validates them.
"""

import json

import httpx
import jsonschema
import pytest

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

        assert schemas["get_internal_incident"]["required"] == ["incident_id"]
        assert set(schemas["get_internal_incident"]["properties"]) == {
            "incident_id",
            "with_occurrences",
            "with_history",
        }
        assert schemas["resolve_internal_incident"]["required"] == ["incident_id", "secret_revoked"]
        assert schemas["scan_secrets"]["required"] == ["documents"]
        assert "required" not in schemas["list_internal_incidents"]

    async def test_a_flat_call_reaches_the_api(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN get_internal_incident called with incident_id at the top level
        WHEN it runs
        THEN the incident is fetched
        """
        route = gg_api.get("/incidents/secrets/77").respond(200, json={"id": 77})

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

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
        WHEN list_internal_incidents, whose arguments are all optional, is called that way
        THEN it is refused with a hint instead of running with default filters
        """
        route = gg_api.get("/incidents-for-mcp").mock(return_value=httpx.Response(200, json={"results": []}))

        result = await call_tool(mcp_client, "list_internal_incidents", {"params": {"status": ["RESOLVED"]}})

        error = tool_error_text(result)
        assert "params" in error
        assert "top level" in error
        assert not route.called

    async def test_a_missing_argument_is_named_without_internal_details(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN get_internal_incident called without its required incident_id
        WHEN it runs
        THEN the error names the missing argument, not the internal model, and echoes no input
        """
        error = tool_error_text(await call_tool(mcp_client, "get_internal_incident", {"with_occurrences": 0}))

        assert "Invalid arguments for tool 'get_internal_incident': incident_id: Field required" in error
        assert "GetIncidentParams" not in error
        assert "input_value" not in error

    async def test_validity_filters_offer_the_same_values_everywhere(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the occurrence and public incident endpoints, which take unknown, and the incident endpoint,
        which calls the same validity not_checked
        WHEN the tools are listed, and list_internal_incidents is called with unknown
        THEN every tool offers unknown and none offers not_checked, and the incident endpoint receives not_checked
        """
        schemas = await _tool_schemas(mcp_client)
        route = gg_api.get("/incidents-for-mcp").respond(200, json={"results": [], "next": None})

        await call_tool(mcp_client, "list_internal_incidents", {"validity": ["unknown"]})

        for tool in (
            "list_internal_incidents",
            "count_internal_incidents",
            "list_internal_occurrences",
            "list_public_incidents",
        ):
            offered = json.dumps(schemas[tool]["properties"]["validity"])
            assert '"not_checked"' not in offered, tool
            assert '"unknown"' in offered, tool
        assert sent_params(route)["validity__in"] == "not_checked"


class TestPerPageAlias:
    """per_page is advertised; page_size, its name in gg-mcp 0.8, is still accepted."""

    async def test_page_size_is_accepted_but_not_advertised(self, mcp_client, mock_token_scopes):
        """
        GIVEN every tool that takes per_page
        WHEN the tools are listed
        THEN page_size is not one of their properties, yet a call sending page_size validates
        against the advertised schema, and one sending an unknown argument still does not
        """
        schemas = await _tool_schemas(mcp_client)
        paged = {name: schema for name, schema in schemas.items() if "per_page" in schema["properties"]}

        assert paged
        for name, schema in paged.items():
            assert "page_size" not in schema["properties"], name
            # Only the page size is under test, not the tool's required arguments.
            schema = {key: value for key, value in schema.items() if key != "required"}
            jsonschema.validate({"page_size": 5}, schema)
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"page_size": 500}, schema)
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"pagesize": 5}, schema)

    async def test_a_call_with_page_size_runs_and_resumes_with_per_page(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN list_members called with page_size, as written against gg-mcp 0.8
        WHEN it runs
        THEN the API gets that page size as per_page, and next_arguments use per_page
        """
        route = gg_api.get("/members").respond(
            200,
            json=[{"id": 7}],
            headers={"Link": '<https://api.gitguardian.com/v1/members?cursor=cD0x>; rel="next"'},
        )

        output = tool_output(await call_tool(mcp_client, "list_members", {"page_size": 1}))

        assert sent_params(route)["per_page"] == "1"
        assert output["per_page"] == 1
        assert output["next_arguments"] == {"per_page": 1, "cursor": "cD0x"}

    async def test_page_size_is_still_checked_against_its_bounds(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN list_members called with a page_size above 100
        WHEN it runs
        THEN the call is refused before any API call
        """
        route = gg_api.get("/members").respond(200, json=[])

        result = await call_tool(mcp_client, "list_members", {"page_size": 500})

        assert "page_size" in tool_error_text(result)
        assert not route.called
