"""Probe host reachability: DNS → TCP → optional HTTP GET → WAF heuristics."""

import asyncio
import logging
import socket

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 3.0
TCP_TIMEOUT = 3.0
HTTP_TIMEOUT = 5.0

# Headers that signal a known WAF / edge provider.
_WAF_HEADER_SIGNALS = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-amz-cf-id": "cloudfront",
    "x-amz-cf-pop": "cloudfront",
    "x-akamai-transformed": "akamai",
    "x-sucuri-id": "sucuri",
    "x-fastly-request-id": "fastly",
}
_WAF_SERVER_SUBSTRINGS = ("cloudflare", "cloudfront", "akamai", "sucuri", "imperva", "fastly")


class CheckHostReachabilityParams(BaseModel):
    """Parameters for ``check_host_reachability``."""

    host: str = Field(description="Hostname or IP to probe.")
    port: int = Field(default=443, ge=1, le=65535, description="TCP port to test.")
    try_http: bool = Field(default=True, description="If True, also attempt an HTTPS GET on the host.")


class CheckHostReachabilityResult(BaseModel):
    """Result of a reachability probe."""

    host: str
    port: int
    dns_ok: bool = False
    tcp_ok: bool = False
    http_status: int | None = None
    tls_ok: bool = False
    waf_detected: bool = False
    waf_vendor: str | None = None
    error: str | None = None


def _dns_resolve(host: str) -> str | None:
    """Return the first resolved IP for ``host`` or None."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        infos = socket.getaddrinfo(host, None)
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


async def _tcp_check(host: str, port: int) -> bool:
    """Open a TCP connection to ``host:port`` with a hard timeout."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        _ = reader  # silence linters
        return True
    except (asyncio.TimeoutError, OSError):
        return False


def _detect_waf(headers: dict[str, str]) -> tuple[bool, str | None]:
    """Return (detected, vendor) based on response headers."""
    lower = {k.lower(): v for k, v in headers.items()}
    for header, vendor in _WAF_HEADER_SIGNALS.items():
        if header in lower:
            return True, vendor
    server = lower.get("server", "").lower()
    for needle in _WAF_SERVER_SUBSTRINGS:
        if needle in server:
            return True, needle
    return False, None


async def check_host_reachability(params: CheckHostReachabilityParams) -> CheckHostReachabilityResult:
    """Probe whether a host is reachable and detect a fronting WAF.

    Sequentially: DNS → TCP connect (3 s) → optional HTTPS GET (5 s). Detects
    Cloudflare / CloudFront / Akamai / Fastly / Sucuri / Imperva via response
    headers. Useful when assessing whether a leaked endpoint is live
    production infrastructure.

    Args:
        params: ``CheckHostReachabilityParams``.

    Returns:
        ``CheckHostReachabilityResult`` with per-stage booleans.
    """
    result = CheckHostReachabilityResult(host=params.host, port=params.port)

    logger.debug(f"check_host_reachability host={params.host} port={params.port}")

    resolved = await asyncio.to_thread(_dns_resolve, params.host)
    result.dns_ok = resolved is not None
    if not result.dns_ok:
        result.error = "dns_failed"
        return result

    result.tcp_ok = await _tcp_check(params.host, params.port)
    if not result.tcp_ok:
        result.error = "tcp_failed"
        return result

    if not params.try_http:
        return result

    scheme = "https" if params.port == 443 else "http"
    url = f"{scheme}://{params.host}:{params.port}/"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False, verify=True) as client:
            response = await client.get(url)
        result.http_status = response.status_code
        result.tls_ok = scheme == "https"
        waf, vendor = _detect_waf(dict(response.headers))
        result.waf_detected = waf
        result.waf_vendor = vendor
    except httpx.TimeoutException:
        result.error = "http_timeout"
    except httpx.HTTPError as exc:
        result.error = f"http_error:{exc.__class__.__name__}"

    return result
