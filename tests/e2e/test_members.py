"""Member and team reads: list_members, get_member, and who can see an internal incident."""

import pytest

from tests.e2e.harness import TEST_MEMBER_ID, call_tool, sent_params, tool_error_text, tool_output

MEMBER = {"id": 7, "name": "Ada", "email": "ada@example.com", "access_level": "member", "active": True}


class TestListMembers:
    async def test_members_are_searched_with_the_pagination_contract(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN members across two pages
        WHEN list_members searches by name with a role and a page size
        THEN the filters reach /members under the API's names, and next_arguments resume with them
        """
        route = gg_api.get("/members").respond(
            200,
            json=[MEMBER],
            headers={"Link": '<https://api.gitguardian.com/v1/members?cursor=cD0x>; rel="next"'},
        )

        result = await call_tool(
            mcp_client,
            "list_members",
            {"search": "ada", "access_level": "member", "active": True, "per_page": 1},
        )

        assert sent_params(route) == {"search": "ada", "access_level": "member", "active": "true", "per_page": "1"}
        output = tool_output(result)
        assert output["members"] == [MEMBER]
        assert output["next_arguments"]["cursor"] == "cD0x"

    async def test_an_unknown_role_is_refused(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a role that is not a workspace access level
        WHEN list_members is called with it
        THEN the call is refused naming access_level, and the API is never asked
        """
        route = gg_api.get("/members").respond(200, json=[])

        result = await call_tool(mcp_client, "list_members", {"access_level": "admin"})

        assert "access_level" in tool_error_text(result)
        assert not route.called


class TestGetMember:
    async def test_one_member_is_read_by_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a member ID, such as an incident's assignee_id
        WHEN get_member is called
        THEN that member is read and returned
        """
        gg_api.get("/members/7").respond(200, json=MEMBER)

        result = await call_tool(mcp_client, "get_member", {"member_id": 7})

        assert tool_output(result) == {"member": MEMBER}


class TestIncidentAccess:
    @pytest.mark.parametrize(
        ("tool", "endpoint", "items_key"),
        [
            pytest.param("list_internal_incident_members", "/incidents/secrets/42/members", "members", id="members"),
            pytest.param("list_internal_incident_teams", "/incidents/secrets/42/teams", "teams", id="teams"),
        ],
    )
    async def test_who_can_see_an_incident_is_listed(
        self, mcp_client, gg_api, mock_token_scopes, tool, endpoint, items_key
    ):
        """
        GIVEN an internal incident
        WHEN the members or the teams that can see it are listed
        THEN that incident's endpoint answers, under the pagination contract
        """
        entry = {"id": TEST_MEMBER_ID, "incident_permission": "can_edit"}
        gg_api.get(endpoint).respond(200, json=[entry])

        result = await call_tool(mcp_client, tool, {"incident_id": 42})

        output = tool_output(result)
        assert output[items_key] == [entry]
        assert output["stop_reason"] == "end"

    @pytest.mark.parametrize(
        ("tool", "arguments", "scope"),
        [
            pytest.param("list_members", {}, "members:read", id="list_members"),
            pytest.param("get_member", {"member_id": 7}, "members:read", id="get_member"),
            pytest.param("list_internal_incident_members", {"incident_id": 42}, "members:read", id="incident-members"),
            pytest.param("list_internal_incident_teams", {"incident_id": 42}, "teams:read", id="incident-teams"),
        ],
    )
    async def test_each_needs_its_scope(self, mcp_client, gg_api, mock_token_scopes, tool, arguments, scope):
        """
        GIVEN a token with incidents:read only
        WHEN a member or team tool is called
        THEN it is refused naming the scope it needs
        """
        mock_token_scopes(scopes=["incidents:read"])

        result = await call_tool(mcp_client, tool, arguments)

        assert scope in tool_error_text(result)
