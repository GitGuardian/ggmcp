"""Mutating incident tools: status changes, severity edits and assignment.

These tools write to customer workspaces, so the tests pin the exact endpoint
and JSON body for every action, and that guard rails (required reasons) block
the HTTP call entirely.
"""

import pytest

from tests.e2e.harness import call_tool, sent_body, tool_error_text, tool_output


class TestManagePrivateIncident:
    @pytest.mark.parametrize(
        ("arguments", "expected_path", "expected_body"),
        [
            pytest.param(
                {"incident_id": 42, "action": "resolve", "secret_revoked": True},
                "/incidents/secrets/42/resolve",
                {"secret_revoked": True},
                id="resolve-sends-secret-revoked",
            ),
            pytest.param(
                {"incident_id": 42, "action": "ignore", "ignore_reason": "low_risk"},
                "/incidents/secrets/42/ignore",
                {"ignore_reason": "low_risk"},
                id="ignore-sends-ignore-reason",
            ),
            pytest.param(
                {"incident_id": 42, "action": "reopen"},
                "/incidents/secrets/42/reopen",
                None,
                id="reopen-sends-no-body",
            ),
            pytest.param(
                {"incident_id": 42, "action": "unassign"},
                "/incidents/secrets/42/unassign",
                None,
                id="unassign-sends-no-body",
            ),
        ],
    )
    async def test_each_action_hits_its_endpoint_with_the_exact_body(
        self, mcp_client, gg_api, mock_token_scopes, arguments, expected_path, expected_body
    ):
        """
        GIVEN a private incident action
        WHEN manage_private_incident is called
        THEN the matching status endpoint receives a POST with exactly the
             documented body and the API response is returned verbatim
        """
        route = gg_api.post(expected_path).respond(200, json={"id": 42, "status": "UPDATED"})

        result = await call_tool(mcp_client, "manage_private_incident", {"params": arguments})

        assert route.called
        assert sent_body(route) == expected_body
        assert tool_output(result) == {"id": 42, "status": "UPDATED"}

    async def test_resolving_without_the_revocation_answer_is_blocked_locally(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN action=resolve without secret_revoked
        WHEN manage_private_incident is called
        THEN the tool refuses with guidance and no API call happens
        """
        route = gg_api.post("/incidents/secrets/42/resolve").respond(200, json={})

        result = await call_tool(
            mcp_client, "manage_private_incident", {"params": {"incident_id": 42, "action": "resolve"}}
        )

        assert "'secret_revoked' parameter is required" in tool_error_text(result)
        assert not route.called

    async def test_ignoring_without_a_reason_is_blocked_locally(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=ignore without ignore_reason
        WHEN manage_private_incident is called
        THEN the tool refuses with guidance and no API call happens
        """
        route = gg_api.post("/incidents/secrets/42/ignore").respond(200, json={})

        result = await call_tool(
            mcp_client, "manage_private_incident", {"params": {"incident_id": 42, "action": "ignore"}}
        )

        assert "'ignore_reason' parameter is required" in tool_error_text(result)
        assert not route.called


class TestUpdateIncidentSeverity:
    async def test_severity_is_patched_on_the_incident(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a severity change
        WHEN update_incident_severity is called
        THEN the incident is PATCHed with exactly the severity field
        """
        route = gg_api.patch("/incidents/secrets/42").respond(200, json={"id": 42, "severity": "high"})

        result = await call_tool(
            mcp_client, "update_incident_severity", {"params": {"incident_id": 42, "severity": "high"}}
        )

        assert sent_body(route) == {"severity": "high"}
        assert tool_output(result) == {"id": 42, "severity": "high"}


class TestManageIncidentCustomTags:
    async def test_add_merges_into_existing_tags(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an incident that already carries tags and an additive tag request
        WHEN manage_incident_custom_tags is called
        THEN the incident is read first, then PATCHed with the merged union set
             (existing tags preserved, new tag appended)
        """
        gg_api.get("/incidents/secrets/42").respond(
            200,
            json={
                "id": 42,
                "custom_tags": [
                    {"key": "team", "value": "red"},
                    {"key": "env", "value": "prod"},
                ],
            },
        )
        patch_route = gg_api.patch("/incidents/secrets/42").respond(
            200, json={"id": 42}
        )

        result = await call_tool(
            mcp_client,
            "manage_incident_custom_tags",
            {"params": {"incident_id": 42, "custom_tags": ["status:reviewed"]}},
        )

        assert sent_body(patch_route) == {
            "custom_tags": [
                {"key": "team", "value": "red"},
                {"key": "env", "value": "prod"},
                {"key": "status", "value": "reviewed"},
            ]
        }
        assert tool_output(result) == {"id": 42}

    async def test_add_does_not_duplicate_an_existing_tag(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an incident already carrying env:prod
        WHEN adding env:prod again
        THEN the PATCH payload contains it exactly once
        """
        gg_api.get("/incidents/secrets/42").respond(
            200,
            json={"id": 42, "custom_tags": [{"key": "env", "value": "prod"}]},
        )
        patch_route = gg_api.patch("/incidents/secrets/42").respond(
            200, json={"id": 42}
        )

        await call_tool(
            mcp_client,
            "manage_incident_custom_tags",
            {
                "params": {
                    "incident_id": 42,
                    "custom_tags": ["env:prod", "env:prod"],
                }
            },
        )

        assert sent_body(patch_route) == {"custom_tags": [{"key": "env", "value": "prod"}]}

    async def test_remove_unlinks_only_the_requested_tags(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an incident carrying multiple tags
        WHEN removing a subset
        THEN the PATCH payload keeps the remaining tags and drops the requested one
        """
        gg_api.get("/incidents/secrets/42").respond(
            200,
            json={
                "id": 42,
                "custom_tags": [
                    {"key": "team", "value": "red"},
                    {"key": "env", "value": "prod"},
                ],
            },
        )
        patch_route = gg_api.patch("/incidents/secrets/42").respond(
            200, json={"id": 42}
        )

        await call_tool(
            mcp_client,
            "manage_incident_custom_tags",
            {
                "params": {
                    "incident_id": 42,
                    "action": "remove",
                    "custom_tags": ["env:prod"],
                }
            },
        )

        assert sent_body(patch_route) == {"custom_tags": [{"key": "team", "value": "red"}]}

    async def test_set_replaces_the_whole_set(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an incident carrying existing tags
        WHEN setting a new set
        THEN the PATCH payload is exactly the requested tags
        """
        gg_api.get("/incidents/secrets/42").respond(
            200,
            json={
                "id": 42,
                "custom_tags": [
                    {"key": "team", "value": "red"},
                    {"key": "env", "value": "prod"},
                ],
            },
        )
        patch_route = gg_api.patch("/incidents/secrets/42").respond(
            200, json={"id": 42}
        )

        await call_tool(
            mcp_client,
            "manage_incident_custom_tags",
            {
                "params": {
                    "incident_id": 42,
                    "action": "set",
                    "custom_tags": ["status:reviewed"],
                }
            },
        )

        assert sent_body(patch_route) == {"custom_tags": [{"key": "status", "value": "reviewed"}]}


class TestAssignIncident:
    async def test_mine_assigns_to_the_callers_member_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True
        WHEN assign_incident is called
        THEN the caller is resolved via /api_tokens/self and the assign body
             carries the stringified member id with a null email
        """
        route = gg_api.post("/incidents/secrets/42/assign").respond(200, json={"id": 42, "assignee_id": 4242})

        result = await call_tool(mcp_client, "assign_incident", {"params": {"incident_id": 42, "mine": True}})

        assert sent_body(route) == {"member_id": "4242", "email": None}
        output = tool_output(result)
        assert output["assignee_id"] == 4242
        assert output["success"] is True

    async def test_assignment_by_email_sends_a_null_member_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an assignee email
        WHEN assign_incident is called
        THEN the body carries the email and a null member_id
        """
        route = gg_api.post("/incidents/secrets/42/assign").respond(200, json={"id": 42})

        await call_tool(mcp_client, "assign_incident", {"params": {"incident_id": 42, "email": "dev@corp.test"}})

        assert sent_body(route) == {"member_id": None, "email": "dev@corp.test"}


class TestUpdatePublicIncidentStatus:
    async def test_resolving_a_public_incident_requires_and_sends_the_reason(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a public incident resolution with a reason
        WHEN update_public_incident_status is called
        THEN the public-incidents endpoint receives the resolve_reason body
        """
        route = gg_api.post("/public-incidents/secrets/7/resolve").respond(200, json={"id": 7, "status": "RESOLVED"})

        result = await call_tool(
            mcp_client,
            "update_public_incident_status",
            {"params": {"incident_id": 7, "action": "resolve", "resolve_reason": "revoked"}},
        )

        assert sent_body(route) == {"resolve_reason": "revoked"}
        assert tool_output(result) == {"id": 7, "status": "RESOLVED"}

    async def test_resolving_without_a_reason_is_blocked_locally(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN action=resolve without resolve_reason
        WHEN update_public_incident_status is called
        THEN the tool refuses with guidance and no API call happens
        """
        route = gg_api.post("/public-incidents/secrets/7/resolve").respond(200, json={})

        result = await call_tool(
            mcp_client, "update_public_incident_status", {"params": {"incident_id": 7, "action": "resolve"}}
        )

        assert "'resolve_reason' parameter is required" in tool_error_text(result)
        assert not route.called
