"""get_secret_validity, request_secret_validity_check, set_secret_validity_override and
remove_secret_validity_override."""

import httpx
import pytest

from tests.e2e.harness import call_tool, rpc, rpc_result, sent_body, tool_error_text, tool_output

VALIDITY = {
    "id": 9,
    "validity": "valid",
    "validity_override": None,
    "last_checked_at": "2026-10-20T13:00:00Z",
    "analysis": {
        "status": "analyzed",
        "scopes": [{"name": "read:org"}, {"name": "repo"}],
        "metadata": {"user": {"login": "octocat"}},
        "last_analyzed_at": "2026-10-20T13:00:05Z",
    },
}
OVERRIDDEN = {**VALIDITY, "validity": "invalid", "validity_override": "invalid"}

TOOLS = [
    pytest.param("get_secret_validity", "get", "/secrets/9/validity", {}, id="get"),
    pytest.param("request_secret_validity_check", "post", "/secrets/9/validity/check", {}, id="check"),
    pytest.param("set_secret_validity_override", "post", "/secrets/9/validity", {"validity": "invalid"}, id="set"),
    pytest.param("remove_secret_validity_override", "delete", "/secrets/9/validity", {}, id="remove"),
]
WRITES = TOOLS[1:]
SUCCESS = {
    "get_secret_validity": httpx.Response(200, json=VALIDITY),
    "request_secret_validity_check": httpx.Response(202),
    "set_secret_validity_override": httpx.Response(200, json=OVERRIDDEN),
    "remove_secret_validity_override": httpx.Response(204),
}


async def _tools(mcp_client) -> dict[str, dict]:
    """The tools the client is shown, by name."""
    tools = rpc_result(await rpc(mcp_client, "tools/list"))["tools"]
    return {tool["name"]: tool for tool in tools}


class TestCatalog:
    async def test_each_tool_takes_a_secret_id_and_only_the_override_takes_a_validity(
        self, mcp_client, mock_token_scopes
    ):
        """
        GIVEN a token holding every scope
        WHEN the tools are listed
        THEN the four tools require a positive integer secret_id, and only set_secret_validity_override takes
             a validity, limited to the three values the API accepts as an override
        """
        tools = await _tools(mcp_client)

        for name in ("get_secret_validity", "request_secret_validity_check", "remove_secret_validity_override"):
            schema = tools[name]["inputSchema"]
            assert (set(schema["properties"]), schema["required"]) == ({"secret_id"}, ["secret_id"]), name
            assert schema["properties"]["secret_id"]["minimum"] == 1, name
            assert schema["additionalProperties"] is False, name
        schema = tools["set_secret_validity_override"]["inputSchema"]
        assert set(schema["required"]) == {"secret_id", "validity"}
        assert schema["properties"]["validity"]["enum"] == ["valid", "invalid", "failed_to_check"]

    async def test_the_outputs_state_what_each_call_establishes(self, mcp_client, mock_token_scopes):
        """
        GIVEN a token holding every scope
        WHEN the tools are listed
        THEN reading and overriding return the validity fields, while the check request and the removal return
             only an acknowledgement and no validity
        """
        tools = await _tools(mcp_client)

        validity_fields = {"secret_id", "validity", "validity_override", "last_checked_at", "analysis"}
        assert set(tools["get_secret_validity"]["outputSchema"]["properties"]) == validity_fields
        assert set(tools["set_secret_validity_override"]["outputSchema"]["properties"]) == validity_fields
        assert set(tools["request_secret_validity_check"]["outputSchema"]["properties"]) == {"secret_id", "accepted"}
        assert set(tools["remove_secret_validity_override"]["outputSchema"]["properties"]) == {
            "secret_id",
            "override_removed",
        }

    async def test_the_descriptions_say_what_the_user_decides_and_what_a_call_does_not_prove(
        self, mcp_client, mock_token_scopes
    ):
        """
        GIVEN a token holding every scope
        WHEN the tools are listed
        THEN the override says it pauses periodic checks, what it can do to the secret's incidents and that
             its value comes from the user, and the check request says an acknowledgement is not a check
        """
        tools = await _tools(mcp_client)

        override = tools["set_secret_validity_override"]["description"]
        assert "stops its periodic validity checks" in override
        assert "must come from the user" in override
        assert "invalid can resolve or ignore them, valid can reopen them" in override
        removal = tools["remove_secret_validity_override"]["description"]
        assert "confirm with the user" in removal
        assert "can resolve, ignore or reopen the secret's incidents" in removal
        check = tools["request_secret_validity_check"]["description"]
        assert "accepted only means the API acknowledged the request" in check
        assert "do not report the secret as checked" in check
        assert "can resolve, ignore or reopen the secret's incidents" in check
        assert "Setting an override also moves last_checked_at" in tools["get_secret_validity"]["description"]

    @pytest.mark.parametrize(
        ("scopes", "visible"),
        [
            pytest.param(["secrets:read"], {"get_secret_validity"}, id="read"),
            pytest.param(
                ["secrets:write"],
                {"request_secret_validity_check", "set_secret_validity_override", "remove_secret_validity_override"},
                id="write",
            ),
            pytest.param(["incidents:read", "incidents:write"], set(), id="neither"),
        ],
    )
    async def test_each_tool_shows_only_with_its_scope(self, mcp_client, mock_token_scopes, scopes, visible):
        """
        GIVEN a token with secrets:read, with secrets:write, or with neither
        WHEN the tools are listed
        THEN the read tool shows only with secrets:read and the three writes only with secrets:write
        """
        mock_token_scopes(scopes=scopes)

        names = set(await _tools(mcp_client))

        validity_tools = {
            "get_secret_validity",
            "request_secret_validity_check",
            "set_secret_validity_override",
            "remove_secret_validity_override",
        }
        assert names & validity_tools == visible


class TestArguments:
    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_a_secret_id_is_required(self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra):
        """
        GIVEN a call without a secret_id
        WHEN the tool runs
        THEN it is refused naming secret_id, and the API is not called
        """
        route = getattr(gg_api, method)(path).mock(return_value=SUCCESS[tool])

        error = tool_error_text(await call_tool(mcp_client, tool, extra))

        assert "secret_id: Field required" in error
        assert not route.called

    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    @pytest.mark.parametrize("secret_id", ["9/../../members", "4_2", "abc", 0, -3, True, 1.5])
    async def test_a_secret_id_that_is_not_a_positive_integer_is_refused(
        self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra, secret_id
    ):
        """
        GIVEN a secret_id that is not a positive integer, such as text that would change the URL path
        WHEN the tool runs
        THEN it is refused naming secret_id, and no request reaches the API
        """
        any_request = gg_api.route(path__regex=r"^/v1/(?!api_tokens/self)").mock(return_value=SUCCESS[tool])

        error = tool_error_text(await call_tool(mcp_client, tool, {"secret_id": secret_id, **extra}))

        assert "secret_id" in error
        assert not any_request.called

    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_a_secret_id_given_as_digits_is_read_as_that_number(
        self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra
    ):
        """
        GIVEN a secret_id sent as a string of digits
        WHEN the tool runs
        THEN the request goes to that secret's endpoint
        """
        route = getattr(gg_api, method)(path).mock(return_value=SUCCESS[tool])

        result = await call_tool(mcp_client, tool, {"secret_id": "9", **extra})

        assert route.call_count == 1
        assert tool_output(result)["secret_id"] == 9

    @pytest.mark.parametrize("validity", ["valid", "invalid", "failed_to_check"])
    async def test_an_override_takes_the_three_values_the_api_accepts(
        self, mcp_client, gg_api, mock_token_scopes, validity
    ):
        """
        GIVEN one of the validities the API accepts as an override
        WHEN set_secret_validity_override is called with it
        THEN the API receives exactly that validity
        """
        route = gg_api.post("/secrets/9/validity").respond(
            200, json={**VALIDITY, "validity": validity, "validity_override": validity}
        )

        result = await call_tool(mcp_client, "set_secret_validity_override", {"secret_id": 9, "validity": validity})

        assert sent_body(route) == {"validity": validity}
        assert tool_output(result)["validity_override"] == validity

    @pytest.mark.parametrize(
        "arguments",
        [
            pytest.param({"secret_id": 9}, id="missing"),
            pytest.param({"secret_id": 9, "validity": "no_checker"}, id="no_checker"),
            pytest.param({"secret_id": 9, "validity": "unknown"}, id="unknown"),
            pytest.param({"secret_id": 9, "validity": "Valid"}, id="wrong-case"),
            pytest.param({"secret_id": 9, "validity": None}, id="null"),
            pytest.param({"secret_id": 9, "validity": True}, id="boolean"),
        ],
    )
    async def test_an_override_without_one_of_those_values_is_refused(
        self, mcp_client, gg_api, mock_token_scopes, arguments
    ):
        """
        GIVEN no validity, or one the API does not accept as an override
        WHEN set_secret_validity_override is called
        THEN it is refused naming validity, and nothing is written
        """
        route = gg_api.post("/secrets/9/validity").respond(200, json=OVERRIDDEN)

        error = tool_error_text(await call_tool(mcp_client, "set_secret_validity_override", arguments))

        assert "validity" in error
        assert not route.called

    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_an_unknown_argument_is_refused(
        self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra
    ):
        """
        GIVEN an argument the tool does not take, such as a validity on a tool that sets none
        WHEN the tool runs
        THEN it is refused, and the API is not called
        """
        route = getattr(gg_api, method)(path).mock(return_value=SUCCESS[tool])

        result = await call_tool(mcp_client, tool, {"secret_id": 9, **extra, "force": True})

        assert "force" in tool_error_text(result)
        assert not route.called


class TestGetSecretValidity:
    async def test_the_validity_override_analysis_and_check_date_are_returned(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a secret with a validity, no override and a stored analysis
        WHEN get_secret_validity is called
        THEN one GET with no query reads it, and the documented fields are returned with scopes by name
        """
        route = gg_api.get("/secrets/9/validity").respond(200, json=VALIDITY)

        result = await call_tool(mcp_client, "get_secret_validity", {"secret_id": 9})

        request = route.calls.last.request
        assert (request.method, request.url.path, request.url.query) == ("GET", "/v1/secrets/9/validity", b"")
        assert tool_output(result) == {
            "secret_id": 9,
            "validity": "valid",
            "validity_override": None,
            "last_checked_at": "2026-10-20T13:00:00Z",
            "analysis": {
                "status": "analyzed",
                "scopes": ["read:org", "repo"],
                "metadata": {"user": {"login": "octocat"}},
                "last_analyzed_at": "2026-10-20T13:00:05Z",
            },
        }

    async def test_a_secret_never_checked_or_analyzed_has_null_dates(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a secret GitGuardian never checked or analyzed
        WHEN get_secret_validity is called
        THEN the dates are null, and the analysis has no scopes and no metadata
        """
        gg_api.get("/secrets/9/validity").respond(
            200,
            json={
                "id": 9,
                "validity": "no_checker",
                "validity_override": None,
                "last_checked_at": None,
                "analysis": {"status": "no_analyzer", "scopes": [], "metadata": {}, "last_analyzed_at": None},
            },
        )

        output = tool_output(await call_tool(mcp_client, "get_secret_validity", {"secret_id": 9}))

        assert (output["validity"], output["last_checked_at"]) == ("no_checker", None)
        assert output["analysis"] == {
            "status": "no_analyzer",
            "scopes": [],
            "metadata": {},
            "last_analyzed_at": None,
        }

    async def test_an_override_shows_in_both_validity_fields(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a secret with an override
        WHEN get_secret_validity is called
        THEN the override is returned, next to the validity that reflects it
        """
        gg_api.get("/secrets/9/validity").respond(200, json=OVERRIDDEN)

        output = tool_output(await call_tool(mcp_client, "get_secret_validity", {"secret_id": 9}))

        assert (output["validity"], output["validity_override"]) == ("invalid", "invalid")


class TestRequestSecretValidityCheck:
    async def test_a_202_is_reported_as_an_acknowledgement_only(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answering a check request with 202 and no body
        WHEN request_secret_validity_check is called
        THEN one POST with no body is sent, the validity is not read, and the result carries only the
             acknowledgement: no validity and no claim that a check ran
        """
        route = gg_api.post("/secrets/9/validity/check").respond(202)
        read = gg_api.get("/secrets/9/validity").respond(200, json=VALIDITY)

        result = await call_tool(mcp_client, "request_secret_validity_check", {"secret_id": 9})

        request = route.calls.last.request
        assert (request.method, request.url.path, request.read()) == ("POST", "/v1/secrets/9/validity/check", b"")
        assert route.call_count == 1
        assert not read.called
        assert tool_output(result) == {"secret_id": 9, "accepted": True}

    async def test_a_workspace_without_validity_checks_is_refused_with_the_reason(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a workspace where validity checks are turned off, for which the API answers 403
        WHEN request_secret_validity_check is called
        THEN the error carries the API's refusal and says retrying will not help
        """
        gg_api.post("/secrets/9/validity/check").respond(403, json={"detail": "Forbidden."})

        error = tool_error_text(await call_tool(mcp_client, "request_secret_validity_check", {"secret_id": 9}))

        assert "GitGuardian API returned 403 Forbidden: Forbidden." in error
        assert "validity checks are not enabled for this workspace" in error
        assert "may or may not" not in error


class TestSetSecretValidityOverride:
    async def test_the_override_is_written_and_the_validity_returned(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a secret GitGuardian found valid
        WHEN set_secret_validity_override is called with invalid
        THEN one POST carries only that validity, and the secret's validity as the API returned it is the result
        """
        route = gg_api.post("/secrets/9/validity").respond(200, json=OVERRIDDEN)

        result = await call_tool(mcp_client, "set_secret_validity_override", {"secret_id": 9, "validity": "invalid"})

        request = route.calls.last.request
        assert (request.method, request.url.path) == ("POST", "/v1/secrets/9/validity")
        assert sent_body(route) == {"validity": "invalid"}
        output = tool_output(result)
        assert (output["validity"], output["validity_override"]) == ("invalid", "invalid")
        assert output["last_checked_at"] == "2026-10-20T13:00:00Z"

    async def test_it_writes_nothing_else(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an override that is accepted
        WHEN set_secret_validity_override is called
        THEN the override is the only request made for the secret: no check, no incident change
        """
        gg_api.post("/secrets/9/validity").respond(200, json=OVERRIDDEN)

        await call_tool(mcp_client, "set_secret_validity_override", {"secret_id": 9, "validity": "invalid"})

        requests = [(call.request.method, call.request.url.path) for call in gg_api.calls]
        assert [request for request in requests if request[1] != "/v1/api_tokens/self"] == [
            ("POST", "/v1/secrets/9/validity")
        ]

    async def test_an_answer_without_the_validity_does_not_confirm_the_override(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the API answering the override with an empty body
        WHEN set_secret_validity_override is called
        THEN the result is an error saying the override is not confirmed and how to check, not a validity
        """
        gg_api.post("/secrets/9/validity").respond(200)

        result = await call_tool(mcp_client, "set_secret_validity_override", {"secret_id": 9, "validity": "invalid"})

        error = tool_error_text(result)
        assert "the override is not confirmed" in error
        assert "get_secret_validity" in error

    async def test_an_invalid_data_refusal_carries_the_apis_reason(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API refusing the override with a 400
        WHEN set_secret_validity_override is called
        THEN the error carries the API's reason, as a refusal and not as an unknown outcome
        """
        gg_api.post("/secrets/9/validity").respond(400, json={"detail": "Invalid data."})

        result = await call_tool(mcp_client, "set_secret_validity_override", {"secret_id": 9, "validity": "invalid"})

        error = tool_error_text(result)
        assert "GitGuardian API returned 400 Bad Request: Invalid data." in error
        assert "may or may not" not in error


class TestRemoveSecretValidityOverride:
    async def test_a_204_with_no_body_is_a_removal(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answering the removal with 204 and no body
        WHEN remove_secret_validity_override is called
        THEN one DELETE with no body is sent, the validity is not read, and the result says the override was
             removed without claiming a validity
        """
        route = gg_api.delete("/secrets/9/validity").respond(204)
        read = gg_api.get("/secrets/9/validity").respond(200, json=VALIDITY)

        result = await call_tool(mcp_client, "remove_secret_validity_override", {"secret_id": 9})

        request = route.calls.last.request
        assert (request.method, request.url.path, request.read()) == ("DELETE", "/v1/secrets/9/validity", b"")
        assert route.call_count == 1
        assert not read.called
        assert tool_output(result) == {"secret_id": 9, "override_removed": True}


class TestRefusals:
    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_a_secret_the_token_cannot_see_says_which_id_to_pass(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, tool, method, path, extra
    ):
        """
        GIVEN the API answering 404, as it does for a secret with no incident the token can see
        WHEN the tool is called
        THEN it is asked once, and the error says to pass an incident's secret_id rather than its incident ID
        """
        route = getattr(gg_api, method)(path).respond(404, json={"detail": "Resource not found."})

        error = tool_error_text(await call_tool(mcp_client, tool, {"secret_id": 9, **extra}))

        assert route.call_count == 1
        assert "GitGuardian API returned 404 Not Found: Resource not found." in error
        assert "pass an incident's secret_id, not its incident ID" in error

    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_a_forbidden_call_carries_the_apis_refusal(
        self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra
    ):
        """
        GIVEN the API refusing the call with a 403
        WHEN the tool is called
        THEN it is asked once and the refusal is returned as an error
        """
        route = getattr(gg_api, method)(path).respond(403, json={"detail": "Forbidden."})

        error = tool_error_text(await call_tool(mcp_client, tool, {"secret_id": 9, **extra}))

        assert route.call_count == 1
        assert "GitGuardian API returned 403 Forbidden: Forbidden." in error

    @pytest.mark.parametrize(("tool", "method", "path", "extra"), TOOLS)
    async def test_a_token_without_the_scope_is_refused_before_the_api(
        self, mcp_client, gg_api, mock_token_scopes, tool, method, path, extra
    ):
        """
        GIVEN a token with neither secrets:read nor secrets:write
        WHEN the tool is called
        THEN it is refused naming the scope it needs, and the API is not called
        """
        mock_token_scopes(scopes=["incidents:read", "incidents:write"])
        route = getattr(gg_api, method)(path).mock(return_value=SUCCESS[tool])

        error = tool_error_text(await call_tool(mcp_client, tool, {"secret_id": 9, **extra}))

        assert ("secrets:read" if tool == "get_secret_validity" else "secrets:write") in error
        assert not route.called

    async def test_reading_needs_secrets_read_even_with_secrets_write(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token with secrets:write but not secrets:read
        WHEN get_secret_validity is called
        THEN it is refused naming secrets:read, and the API is not called
        """
        mock_token_scopes(scopes=["secrets:write"])
        route = gg_api.get("/secrets/9/validity").respond(200, json=VALIDITY)

        error = tool_error_text(await call_tool(mcp_client, "get_secret_validity", {"secret_id": 9}))

        assert "secrets:read" in error
        assert not route.called


class TestUncertainWrites:
    @pytest.mark.parametrize(("tool", "method", "path", "extra"), WRITES)
    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(httpx.ReadTimeout("timed out"), id="timeout"),
            pytest.param(httpx.ConnectError("connection lost"), id="connection"),
            pytest.param(httpx.Response(500), id="500"),
            pytest.param(httpx.Response(502), id="502"),
            pytest.param(httpx.Response(503, json={"detail": "API under scheduled maintenance."}), id="503"),
        ],
    )
    async def test_a_write_with_an_unknown_outcome_is_sent_once_and_says_how_to_check(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, tool, method, path, extra, failure
    ):
        """
        GIVEN a write that times out, loses its connection or gets a server error
        WHEN the tool is called
        THEN it is sent once, never retried, and the error says the outcome is unknown and to read the
             validity back before trying again
        """
        route = getattr(gg_api, method)(path)
        if isinstance(failure, httpx.Response):
            route.mock(return_value=failure)
        else:
            route.mock(side_effect=failure)

        error = tool_error_text(await call_tool(mcp_client, tool, {"secret_id": 9, **extra}))

        assert route.call_count == 1
        assert "may or may not have been applied" in error
        assert "get_secret_validity" in error
        assert "before trying again" in error

    async def test_a_read_that_fails_claims_no_unknown_write(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the validity read answering 500 every time
        WHEN get_secret_validity is called
        THEN the error is the server's failure, without the unknown-outcome wording of a write
        """
        gg_api.get("/secrets/9/validity").respond(500)

        error = tool_error_text(await call_tool(mcp_client, "get_secret_validity", {"secret_id": 9}))

        assert "GitGuardian API returned 500" in error
        assert "may or may not" not in error
