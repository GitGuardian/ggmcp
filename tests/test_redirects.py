"""Redirects are followed only while they stay on the request's origin (SI-4058)."""

import httpx
import pytest

from gg_api_core.redirects import CrossOriginRedirectError, request_following_same_origin

API = "https://api.gitguardian.com"


def _client(routes: dict[str, httpx.Response], seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return routes[f"{request.method} {request.url.copy_with(query=None)}"]

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def test_a_same_origin_redirect_is_followed_with_its_credentials():
    """
    GIVEN an API that answers 301 to another path on the same origin
    WHEN a GET is sent through the helper
    THEN the redirect is followed and the Authorization header is still sent
    """
    seen: list[httpx.Request] = []
    routes = {
        f"GET {API}/v1/sources": httpx.Response(301, headers={"Location": f"{API}/v1/sources/"}),
        f"GET {API}/v1/sources/": httpx.Response(200, json=[{"id": 1}]),
    }
    async with _client(routes, seen) as client:
        response = await request_following_same_origin(
            client, "GET", f"{API}/v1/sources", headers={"Authorization": "Token pat"}
        )

    assert response.json() == [{"id": 1}]
    assert [r.url.path for r in seen] == ["/v1/sources", "/v1/sources/"]
    assert seen[-1].headers["Authorization"] == "Token pat"


async def test_a_cross_origin_redirect_never_receives_the_request_body():
    """
    GIVEN an API that answers a scan POST with a 307 to another host
    WHEN the POST is sent through the helper
    THEN it fails naming the other origin, and the other host is never contacted
    """
    seen: list[httpx.Request] = []
    routes = {f"POST {API}/v1/multiscan": httpx.Response(307, headers={"Location": "https://collector.example/x"})}
    async with _client(routes, seen) as client:
        with pytest.raises(CrossOriginRedirectError, match="collector.example"):
            await request_following_same_origin(client, "POST", f"{API}/v1/multiscan", json=[{"document": "x"}])

    assert [r.url.host for r in seen] == ["api.gitguardian.com"]


async def test_an_http_to_https_upgrade_of_the_same_host_is_followed():
    """
    GIVEN a GitGuardian URL configured with http://
    WHEN the API redirects to the https:// URL of the same host
    THEN the upgrade is followed
    """
    seen: list[httpx.Request] = []
    routes = {
        "GET http://api.gitguardian.com/v1/health": httpx.Response(
            301, headers={"Location": "https://api.gitguardian.com/v1/health"}
        ),
        f"GET {API}/v1/health": httpx.Response(200, json={"ok": True}),
    }
    async with _client(routes, seen) as client:
        response = await request_following_same_origin(client, "GET", "http://api.gitguardian.com/v1/health")

    assert response.status_code == 200


@pytest.mark.parametrize(
    "location",
    [
        "https://api.gitguardian.com.evil.example/v1/x",
        "https://api.gitguardian.com:8443/v1/x",
        "http://api.gitguardian.com/v1/x",
    ],
    ids=["other-host", "other-port", "https-downgrade"],
)
async def test_any_other_origin_change_is_refused(location: str):
    """
    GIVEN a redirect that changes host, port, or downgrades the scheme
    WHEN it is sent through the helper
    THEN it is refused
    """
    seen: list[httpx.Request] = []
    routes = {f"GET {API}/v1/x": httpx.Response(302, headers={"Location": location})}
    async with _client(routes, seen) as client:
        with pytest.raises(CrossOriginRedirectError):
            await request_following_same_origin(client, "GET", f"{API}/v1/x")

    assert len(seen) == 1


async def test_with_no_redirect_budget_the_redirect_response_is_returned_as_is():
    """
    GIVEN max_redirects=0, used for requests that ask for unmasked values
    WHEN the API answers a redirect
    THEN the redirect response itself is returned and nothing else is sent
    """
    seen: list[httpx.Request] = []
    routes = {f"GET {API}/v1/honeytokens": httpx.Response(301, headers={"Location": f"{API}/v1/honeytokens/"})}
    async with _client(routes, seen) as client:
        response = await request_following_same_origin(client, "GET", f"{API}/v1/honeytokens", max_redirects=0)

    assert response.status_code == 301
    assert len(seen) == 1


async def test_a_redirect_loop_stops_after_the_budget():
    """
    GIVEN an API that keeps redirecting to itself
    WHEN a GET is sent through the helper
    THEN it stops with TooManyRedirects after the budget
    """
    seen: list[httpx.Request] = []
    routes = {f"GET {API}/v1/loop": httpx.Response(302, headers={"Location": f"{API}/v1/loop"})}
    async with _client(routes, seen) as client:
        with pytest.raises(httpx.TooManyRedirects):
            await request_following_same_origin(client, "GET", f"{API}/v1/loop", max_redirects=3)

    assert len(seen) == 4
