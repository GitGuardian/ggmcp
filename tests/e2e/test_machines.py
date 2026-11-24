"""Endpoint inventory reads: list_machines and get_machine."""

import pytest

from tests.e2e.harness import call_tool, list_tool_names, sent_params, tool_error_text, tool_output

MACHINE = {
    "id": 12,
    "name": "ada-laptop",
    "machine_id": "4C4C4544-0042",
    "last_seen_at": "2026-11-19T08:00:00Z",
    "partitions": [
        {
            "id": 31,
            "partition_id": "system",
            "partition_kind": "system",
            "username": "",
            "display_name": "",
            "home_path": "",
            "is_privileged_account": None,
            "last_seen_at": "2026-11-19T08:00:00Z",
            "registered_at": None,
        },
        {
            "id": 32,
            "partition_id": "user:0a1b",
            "partition_kind": "user",
            "username": "ada",
            "display_name": "Ada Lovelace",
            "home_path": "/Users/ada",
            "is_privileged_account": True,
            "last_seen_at": "2026-11-19T08:00:00Z",
            "registered_at": "2026-10-01T09:00:00Z",
        },
    ],
}


class TestListMachines:
    async def test_machines_are_searched_with_the_pagination_contract(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN machines across two pages
        WHEN list_machines searches by text and usernames with an ordering and a page size
        THEN the filters reach /endpoints/machines under the API's names, usernames comma-separated, and
             next_arguments resume with the same filters
        """
        route = gg_api.get("/endpoints/machines").respond(
            200,
            json=[MACHINE],
            headers={"Link": '<https://api.gitguardian.com/v1/endpoints/machines?cursor=cD0x>; rel="next"'},
        )

        result = await call_tool(
            mcp_client,
            "list_machines",
            {"search": "laptop", "usernames": ["ada", "grace"], "ordering": "-id", "page_size": 1},
        )

        assert sent_params(route) == {
            "search": "laptop",
            "username__in": "ada,grace",
            "ordering": "-id",
            "per_page": "1",
        }
        output = tool_output(result)
        assert output["machines"] == [MACHINE]
        assert (output["has_more"], output["stop_reason"]) == (True, "page")
        assert output["next_arguments"] == {
            "search": "laptop",
            "usernames": ["ada", "grace"],
            "ordering": "-id",
            "page_size": 1,
            "cursor": "cD0x",
        }

    async def test_no_argument_lists_the_first_page_by_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a workspace with one machine
        WHEN list_machines is called without arguments
        THEN one page of 20 is asked for, sorted by id, and the result says there is no more
        """
        route = gg_api.get("/endpoints/machines").respond(200, json=[MACHINE])

        output = tool_output(await call_tool(mcp_client, "list_machines"))

        assert sent_params(route) == {"ordering": "id", "per_page": "20"}
        assert (output["has_more"], output["stop_reason"], output["next_arguments"]) == (False, "end", None)

    @pytest.mark.parametrize(
        "arguments",
        [
            pytest.param({"ordering": "name"}, id="ordering"),
            pytest.param({"page_size": 0}, id="page-size-low"),
            pytest.param({"page_size": 101}, id="page-size-high"),
            pytest.param({"username": "ada"}, id="unknown-argument"),
        ],
    )
    async def test_an_argument_the_api_does_not_take_is_refused(self, mcp_client, gg_api, mock_token_scopes, arguments):
        """
        GIVEN an ordering, a page size or an argument the endpoint does not take
        WHEN list_machines is called with it
        THEN the call is refused naming the argument, and the API is never asked
        """
        route = gg_api.get("/endpoints/machines").respond(200, json=[])

        error = tool_error_text(await call_tool(mcp_client, "list_machines", arguments))

        assert next(iter(arguments)) in error
        assert not route.called

    async def test_a_token_below_manager_is_told_why(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answering 403, as it does for a token below the Manager access level
        WHEN list_machines is called
        THEN the error carries the refusal and says which access level the inventory needs
        """
        gg_api.get("/endpoints/machines").respond(403, json={"detail": "Permission denied."})

        error = tool_error_text(await call_tool(mcp_client, "list_machines"))

        assert "GitGuardian API returned 403 Forbidden: Permission denied." in error
        assert "Manager access level or above, or a service account token" in error


class TestGetMachine:
    async def test_one_machine_is_read_by_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a machine id from list_machines
        WHEN get_machine is called
        THEN that machine is read and returned with its partitions
        """
        route = gg_api.get("/endpoints/machines/12").respond(200, json=MACHINE)

        result = await call_tool(mcp_client, "get_machine", {"machine_id": 12})

        assert route.calls.last.request.url.path == "/v1/endpoints/machines/12"
        assert tool_output(result) == {"machine": MACHINE}

    @pytest.mark.parametrize("machine_id", ["4C4C4544-0042", "12/../../members", 0, True])
    async def test_a_machine_id_that_is_not_a_positive_integer_is_refused(
        self, mcp_client, gg_api, mock_token_scopes, machine_id
    ):
        """
        GIVEN the machine_id text of a machine, or another value that is not a positive integer
        WHEN get_machine is called with it
        THEN it is refused naming machine_id, and no request reaches the API
        """
        any_request = gg_api.route(path__regex=r"^/v1/(?!api_tokens/self)").respond(200, json=MACHINE)

        error = tool_error_text(await call_tool(mcp_client, "get_machine", {"machine_id": machine_id}))

        assert "machine_id" in error
        assert not any_request.called

    async def test_an_unknown_machine_says_which_id_to_pass(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answering 404 for a machine id
        WHEN get_machine is called
        THEN the error says to pass the id from list_machines, not the machine_id text
        """
        gg_api.get("/endpoints/machines/12").respond(404, json={"detail": "Machine not found."})

        error = tool_error_text(await call_tool(mcp_client, "get_machine", {"machine_id": 12}))

        assert "GitGuardian API returned 404 Not Found: Machine not found." in error
        assert "pass a machine's id from list_machines, not its machine_id" in error


class TestScope:
    @pytest.mark.parametrize(
        ("scopes", "visible"),
        [
            pytest.param(["endpoints:read"], {"list_machines", "get_machine"}, id="with"),
            pytest.param(["incidents:read", "sources:read", "members:read"], set(), id="without"),
        ],
    )
    async def test_the_machine_tools_show_only_with_endpoints_read(
        self, mcp_client, mock_token_scopes, scopes, visible
    ):
        """
        GIVEN a token with or without endpoints:read
        WHEN the tools are listed
        THEN the machine tools show only with it
        """
        mock_token_scopes(scopes=scopes)

        names = await list_tool_names(mcp_client)

        assert names & {"list_machines", "get_machine"} == visible

    async def test_a_token_without_the_scope_is_refused_before_the_api(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a token without endpoints:read
        WHEN list_machines is called
        THEN it is refused naming the scope, and the API is not called
        """
        mock_token_scopes(scopes=["incidents:read"])
        route = gg_api.get("/endpoints/machines").respond(200, json=[])

        error = tool_error_text(await call_tool(mcp_client, "list_machines"))

        assert "endpoints:read" in error
        assert not route.called
