"""Incident URLs are resolved through the same authenticated API as ID-based tools."""

from http import HTTPStatus

import pytest

from tests.e2e.harness import (
    TEST_PAT,
    call_tool,
    rpc,
    rpc_result,
    sent_params,
    token_info,
    tool_error_text,
    tool_output,
)


@pytest.mark.parametrize(
    "url, endpoint, resource_type, workspace_id",
    [
        (
            "https://dashboard.gitguardian.com/workspace/1/incidents/77",
            "/incidents/secrets/77",
            "internal_incident",
            1,
        ),
        (
            "https://dashboard.gitguardian.com/workspace/1/public-incidents/77/",
            "/public-incidents/secrets/77",
            "public_incident",
            1,
        ),
        (
            "https://api.gitguardian.com/v1/incidents/secrets/77",
            "/incidents/secrets/77",
            "internal_incident",
            None,
        ),
        (
            "https://api.gitguardian.com/v1/public-incidents/secrets/77/",
            "/public-incidents/secrets/77",
            "public_incident",
            None,
        ),
        (
            "https://DASHBOARD.gitguardian.com:443/workspace/1/incidents/77",
            "/incidents/secrets/77",
            "internal_incident",
            1,
        ),
    ],
)
async def test_url_selects_the_matching_incident_endpoint(
    mcp_client, gg_api, mock_token_scopes, url, endpoint, resource_type, workspace_id
):
    """
    GIVEN dashboard and API URLs for internal and public incidents with the same numeric ID
    WHEN the URL entry point is called
    THEN only the matching read endpoint receives the caller's token and the IDs and details are returned
    """
    incident = {"id": 77, "status": "TRIGGERED", "secret": {"detector": {"name": "aws_iam"}}}
    route = gg_api.get(endpoint).respond(200, json=incident)

    result = await call_tool(mcp_client, "get_gitguardian_resource", {"url": url})

    assert tool_output(result) == {
        "resource_type": resource_type,
        "incident_id": 77,
        "workspace_id": workspace_id,
        "url": url,
        "incident": incident,
    }
    assert route.call_count == 1
    assert sent_params(route) == {}
    assert route.calls.last.request.headers["authorization"] == f"Token {TEST_PAT}"


async def test_url_parameters_and_fragment_are_neither_forwarded_nor_returned(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN an internal incident link with query parameters and a fragment
    WHEN the caller explicitly requests zero occurrences
    THEN only that occurrence limit reaches the API and the returned URL drops query and fragment
    """
    route = gg_api.get("/incidents/secrets/77").respond(200, json={"id": 77})
    url = "https://dashboard.gitguardian.com/workspace/1/incidents/77"

    result = await call_tool(
        mcp_client,
        "get_gitguardian_resource",
        {"url": url + "?with_occurrences=99&search=sensitive-marker#occurrence-123", "with_occurrences": 0},
    )

    assert sent_params(route) == {"with_occurrences": "0"}
    assert tool_output(result)["url"] == url
    assert "sensitive-marker" not in str(result)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/workspace/1/incidents/77",
        "https://dashboard.gitguardian.com.evil.example/workspace/1/incidents/77",
        "https://dashboard.eu1.gitguardian.com/workspace/1/incidents/77",
        "https://dashboard.gitguardian.com:444/workspace/1/incidents/77",
        "http://dashboard.gitguardian.com/workspace/1/incidents/77",
        "https://user:password@dashboard.gitguardian.com/workspace/1/incidents/77",
        "https://dashboard.gitguardian.com@evil.example/workspace/1/incidents/77",
        "https://dashboard.gitguardian.com:invalid/workspace/1/incidents/77",
        "https://[invalid/workspace/1/incidents/77",
        "//dashboard.gitguardian.com/workspace/1/incidents/77",
        "/workspace/1/incidents/77",
        "file:///workspace/1/incidents/77",
        "https://dashboard.gitguardian.com/workspace/1/incidents/77\n",
        "https://dashboard.gitguardian.com/workspace/1/incidents/7\t7",
        "https://dashboard.gitguardian.com\\@evil.example/workspace/1/incidents/77",
        "https://dashboard.gitguardian.com/workspace/1/incidents",
        "https://dashboard.gitguardian.com/workspace/1/incidents/secrets",
        "https://dashboard.gitguardian.com/workspace/1/incidents/77/resolve",
        "https://dashboard.gitguardian.com/workspace/1/incidents/77/../78",
        "https://dashboard.gitguardian.com/workspace/1/incidents/%37%37",
        "https://dashboard.gitguardian.com/workspace/1/incidents/-77",
        "https://dashboard.gitguardian.com/workspace/1/incidents/７７",
        "https://dashboard.gitguardian.com/workspace/1/public-incidents/keywords",
        "https://dashboard.gitguardian.com/workspace/1/sources/77",
        "https://dashboard.gitguardian.com/v1/incidents/secrets/77",
        "https://api.gitguardian.com/workspace/1/incidents/77",
        "https://api.gitguardian.com/v1/incidents/secrets/77/notes",
        "https://dashboard.gitguardian.com/share/incidents/share-token-marker",
        "https://dashboard.gitguardian.com/share/public-incidents/share-token-marker",
    ],
)
async def test_invalid_or_unsupported_urls_never_reach_an_incident_endpoint(mcp_client, gg_api, mock_token_scopes, url):
    """
    GIVEN an unsupported, malformed, credential-bearing or different-instance link
    WHEN the URL entry point is called
    THEN a tool error is returned with no incident request or input URL echoed in the error
    """
    result = await call_tool(mcp_client, "get_gitguardian_resource", {"url": url})

    error = tool_error_text(result)
    assert "GitGuardian" in error or "instance" in error
    assert url not in error
    assert "share-token-marker" not in error
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


async def test_wrong_workspace_is_refused_before_fetching(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a URL from a workspace different from the caller's token
    WHEN it is resolved
    THEN the caller is asked to authenticate for that workspace and no incident is fetched
    """
    result = await call_tool(
        mcp_client,
        "get_gitguardian_resource",
        {"url": "https://dashboard.gitguardian.com/workspace/2/incidents/77"},
    )

    error = tool_error_text(result)
    assert "workspace 2" in error
    assert "workspace 1" in error
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


@pytest.mark.parametrize("category", ["incidents", "public-incidents"])
async def test_api_refusal_keeps_the_selected_category(mcp_client, gg_api, mock_token_scopes, category):
    """
    GIVEN the selected incident endpoint refuses access
    WHEN the URL is resolved
    THEN its API error reaches the caller without trying the other incident category
    """
    route = gg_api.get(f"/{category}/secrets/77").respond(404, json={"detail": "Not found."})

    result = await call_tool(
        mcp_client,
        "get_gitguardian_resource",
        {"url": f"https://dashboard.gitguardian.com/workspace/1/{category}/77"},
    )

    assert "404" in tool_error_text(result)
    assert route.call_count == 1
    assert len(gg_api.calls) == 2


async def test_rejected_token_requests_reauthentication(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a token rejected by the incident API
    WHEN an incident URL is resolved
    THEN the HTTP response preserves the authentication challenge
    """
    gg_api.get("/incidents/secrets/77").respond(401, json={"detail": "Invalid API key."})

    response = await rpc(
        mcp_client,
        "tools/call",
        {
            "name": "get_gitguardian_resource",
            "arguments": {"url": "https://api.gitguardian.com/v1/incidents/secrets/77"},
        },
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "www-authenticate" in response.headers


async def test_incident_read_scope_is_required_for_listing_and_calling(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a token with only scan permission
    WHEN tools are listed and the URL entry point is called directly
    THEN it is hidden and the direct call is refused before any incident request
    """
    mock_token_scopes(["scan"])
    tools = rpc_result(await rpc(mcp_client, "tools/list", {}))["tools"]
    assert "get_gitguardian_resource" not in {tool["name"] for tool in tools}

    result = await call_tool(
        mcp_client,
        "get_gitguardian_resource",
        {"url": "https://dashboard.gitguardian.com/workspace/1/incidents/77"},
    )

    assert "incidents:read" in tool_error_text(result)
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


@pytest.mark.parametrize(
    "dashboard, api, path",
    [
        ("https://dashboard.eu1.gitguardian.com", "https://api.eu1.gitguardian.com/v1", "/workspace/1/incidents/77"),
        ("https://gg.example.test", "https://gg.example.test/exposed/v1", "/workspace/1/incidents/77"),
        ("https://gg.example.test", "https://gg.example.test/exposed/v1", "/exposed/v1/incidents/secrets/77"),
        ("http://localhost:3000", "http://localhost:3000/exposed/v1", "/workspace/1/incidents/77"),
    ],
)
async def test_configured_regional_and_self_hosted_instances(mcp_client, gg_api, monkeypatch, dashboard, api, path):
    """
    GIVEN a server configured for EU SaaS, self-hosting or local development
    WHEN a matching dashboard or API incident URL is resolved
    THEN authentication and incident reads stay on that configured API
    """
    monkeypatch.setenv("GITGUARDIAN_URL", dashboard)
    gg_api.get(api + "/api_tokens/self").respond(200, json=token_info())
    route = gg_api.get(api + "/incidents/secrets/77").respond(200, json={"id": 77})

    result = await call_tool(mcp_client, "get_gitguardian_resource", {"url": dashboard + path})

    assert tool_output(result)["incident"] == {"id": 77}
    assert route.call_count == 1
    assert str(route.calls.last.request.url) == api + "/incidents/secrets/77"


INTERNAL_77 = {"id": 77, "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/incidents/77"}
PUBLIC_77 = {"id": 77, "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/public-incidents/77"}


@pytest.mark.parametrize("arguments", [{"incident_id": 77}, {"url": " 77 "}], ids=["incident_id", "id-in-url"])
@pytest.mark.parametrize(
    "internal, public, resource_type, incident",
    [
        ((200, INTERNAL_77), (404, {"detail": "Not found."}), "internal_incident", INTERNAL_77),
        ((404, {"detail": "Not found."}), (200, PUBLIC_77), "public_incident", PUBLIC_77),
        ((200, INTERNAL_77), (403, {"detail": "Forbidden."}), "internal_incident", INTERNAL_77),
    ],
    ids=["internal-only", "public-only", "internal-without-public-monitoring"],
)
async def test_a_bare_id_returns_the_one_kind_that_exists(
    mcp_client, gg_api, mock_token_scopes, arguments, internal, public, resource_type, incident
):
    """
    GIVEN an incident ID that exists as exactly one kind of incident
    WHEN it is passed as incident_id, or as a bare number where a link was expected
    THEN both kinds are looked up once and the one that exists is returned with its dashboard link
    """
    internal_route = gg_api.get("/incidents/secrets/77").respond(internal[0], json=internal[1])
    public_route = gg_api.get("/public-incidents/secrets/77").respond(public[0], json=public[1])

    result = await call_tool(mcp_client, "get_gitguardian_resource", arguments)

    assert tool_output(result) == {
        "resource_type": resource_type,
        "incident_id": 77,
        "workspace_id": None,
        "url": incident["gitguardian_url"],
        "incident": incident,
    }
    assert internal_route.call_count == 1
    assert public_route.call_count == 1


async def test_a_bare_id_that_exists_as_both_kinds_is_reported_as_ambiguous(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN an ID that exists both as an internal and as a public incident
    WHEN it is passed without a link
    THEN neither is returned, and the error says they are different incidents and how to pick one
    """
    gg_api.get("/incidents/secrets/77").respond(200, json=INTERNAL_77)
    gg_api.get("/public-incidents/secrets/77").respond(200, json=PUBLIC_77)

    result = await call_tool(mcp_client, "get_gitguardian_resource", {"incident_id": 77})

    error = tool_error_text(result)
    assert "both as an internal incident and as a public incident" in error
    assert "get_incident" in error and "get_public_incident" in error


@pytest.mark.parametrize(
    "public_status, expected",
    [(404, "nor a public incident"), (403, "Public Monitoring is likely not enabled")],
)
async def test_a_bare_id_found_nowhere_says_what_was_checked(
    mcp_client, gg_api, mock_token_scopes, public_status, expected
):
    """
    GIVEN an ID that matches no incident this token can see
    WHEN it is passed without a link
    THEN one error covers both kinds, says whether public incidents could be checked, and that retrying will not help
    """
    gg_api.get("/incidents/secrets/77").respond(404, json={"detail": "Not found."})
    gg_api.get("/public-incidents/secrets/77").respond(public_status, json={"detail": "Nope."})

    result = await call_tool(mcp_client, "get_gitguardian_resource", {"incident_id": 77})

    error = tool_error_text(result)
    assert "No incident 77 is visible to this token" in error
    assert expected in error
    assert "Retrying will not help" in error


async def test_a_failed_lookup_never_hides_a_second_match(mcp_client, gg_api, mock_token_scopes, no_retry_delay):
    """
    GIVEN an ID whose internal lookup fails with a 500 while a public incident matches
    WHEN it is passed without a link
    THEN the failure is reported instead of the public incident, since the ID may also be internal
    """
    gg_api.get("/incidents/secrets/77").respond(500, json={"detail": "Boom."})
    gg_api.get("/public-incidents/secrets/77").respond(200, json=PUBLIC_77)

    result = await call_tool(mcp_client, "get_gitguardian_resource", {"incident_id": 77})

    assert "500" in tool_error_text(result)


@pytest.mark.parametrize("rejected", ["/incidents/secrets/77", "/public-incidents/secrets/77"])
async def test_a_bare_id_with_a_rejected_token_requests_reauthentication(
    mcp_client, gg_api, mock_token_scopes, rejected
):
    """
    GIVEN a token one of the two incident lookups rejects with 401
    WHEN a bare ID is resolved
    THEN the HTTP response carries the 401 challenge
    """
    for path in ("/incidents/secrets/77", "/public-incidents/secrets/77"):
        status = HTTPStatus.UNAUTHORIZED if path == rejected else HTTPStatus.NOT_FOUND
        gg_api.get(path).respond(status, json={"detail": "Nope."})

    response = await rpc(
        mcp_client, "tools/call", {"name": "get_gitguardian_resource", "arguments": {"incident_id": 77}}
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "www-authenticate" in response.headers


@pytest.mark.parametrize(
    "arguments",
    [{}, {"url": "https://dashboard.gitguardian.com/workspace/1/incidents/77", "incident_id": 77}],
    ids=["neither", "both"],
)
async def test_exactly_one_of_link_or_id_is_accepted(mcp_client, gg_api, mock_token_scopes, arguments):
    """
    GIVEN no link and no ID, or both at once
    WHEN the tool is called
    THEN it is refused before any incident lookup
    """
    result = await call_tool(mcp_client, "get_gitguardian_resource", arguments)

    error = tool_error_text(result)
    assert "Provide exactly one of url or incident_id." in error
    assert "Value error" not in error
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


@pytest.mark.parametrize(
    "path, pointer",
    [
        ("/workspace/1/incidents?status=TRIGGERED&severity=high", "list_incidents"),
        ("/workspace/1/incidents/", "list_incidents"),
        ("/workspace/1/public-incidents", "list_public_incidents"),
        ("/workspace/1/honeytokens", "generate_honeytoken"),
        ("/workspace/1/honeytokens/dcfa8ef5-d3eb-46a8-9d57-3c7d66e7d053", "generate_honeytoken"),
    ],
)
async def test_a_list_or_honeytoken_page_points_to_the_right_tool(mcp_client, gg_api, mock_token_scopes, path, pointer):
    """
    GIVEN a dashboard link to an incidents list, a public incidents list, or a honeytoken page
    WHEN it is passed as a link
    THEN the error names the tool that covers that page, and no incident is looked up
    """
    result = await call_tool(
        mcp_client, "get_gitguardian_resource", {"url": "https://dashboard.gitguardian.com" + path}
    )

    assert pointer in tool_error_text(result)
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)


async def test_digits_from_other_scripts_are_not_taken_as_an_id(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN a value made of non-ASCII digits, which Python's int() would accept
    WHEN it is passed where a link was expected
    THEN it is refused as an invalid link instead of being looked up as an ID
    """
    result = await call_tool(mcp_client, "get_gitguardian_resource", {"url": "７７"})

    assert "valid absolute GitGuardian HTTP(S) URL" in tool_error_text(result)
    assert all(call.request.url.path == "/v1/api_tokens/self" for call in gg_api.calls)
