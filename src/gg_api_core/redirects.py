"""Redirect handling for requests that carry a GitGuardian credential or payload.

httpx drops ``Authorization`` when a redirect leaves the origin, but forwards
every other header, and on 307/308 it sends the request body again to the new
location. A scan payload or an OAuth code exchange must never be replayed to a
host the caller did not configure, so redirects are followed only while they
stay on the request's origin.
"""

from typing import Any

import httpx

MAX_REDIRECTS = 5

_DEFAULT_PORTS = {"http": 80, "https": 443}


class CrossOriginRedirectError(Exception):
    """The GitGuardian API answered with a redirect to another origin, which was not followed."""


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    return url.scheme, url.host, url.port or _DEFAULT_PORTS.get(url.scheme)


def _stays_on_origin(source: httpx.URL, target: httpx.URL) -> bool:
    """Same scheme, host and port, or the http-to-https upgrade of the same host on default ports."""
    if _origin(source) == _origin(target):
        return True
    return (
        source.scheme == "http"
        and target.scheme == "https"
        and source.host == target.host
        and source.port in (None, 80)
        and target.port in (None, 443)
    )


async def request_following_same_origin(
    client: httpx.AsyncClient, method: str, url: str, *, max_redirects: int = MAX_REDIRECTS, **kwargs: Any
) -> httpx.Response:
    """Send a request, following at most ``max_redirects`` redirects that stay on its origin.

    The client must not follow redirects itself. With ``max_redirects=0`` the
    first response is returned as is, redirect or not.

    Raises:
        CrossOriginRedirectError: a redirect points to another origin.
        httpx.TooManyRedirects: more than ``max_redirects`` same-origin redirects.
    """
    response = await client.request(method, url, **kwargs)
    if max_redirects == 0:
        return response
    origin_url = httpx.URL(url)
    for _ in range(max_redirects):
        next_request = response.next_request
        if next_request is None:
            return response
        if not _stays_on_origin(origin_url, next_request.url):
            await response.aclose()
            target = f"{next_request.url.scheme}://{next_request.url.host}"
            raise CrossOriginRedirectError(
                f"The GitGuardian API redirected {method} {origin_url.path} to another origin "
                f"({target}). The redirect was not followed, so no request data left the configured API."
            )
        await response.aclose()
        response = await client.send(next_request)
    if response.next_request is not None:
        raise httpx.TooManyRedirects(f"Exceeded {max_redirects} redirects", request=response.request)
    return response
