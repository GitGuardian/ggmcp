"""Reverse DNS lookup — IP → hostname."""

import asyncio
import logging
import socket

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

REVERSE_DNS_TIMEOUT = 5.0


class ReverseDnsLookupParams(BaseModel):
    """Parameters for ``reverse_dns_lookup``."""

    ip_address: str = Field(description="IPv4 or IPv6 address to reverse-resolve.")


class ReverseDnsLookupResult(BaseModel):
    """Result of a reverse DNS lookup."""

    ip_address: str = Field(description="The IP that was queried.")
    hostname: str | None = Field(default=None, description="Reverse-resolved hostname, if any.")
    aliases: list[str] = Field(default_factory=list, description="Additional aliases returned by the resolver.")
    error: str | None = Field(default=None, description="Error string if the lookup failed.")


def _reverse_one(ip_address: str) -> tuple[str | None, list[str], str | None]:
    """Run ``socket.gethostbyaddr`` with a default timeout. Synchronous; runs in a thread."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(REVERSE_DNS_TIMEOUT)
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        return hostname, list(aliases), None
    except socket.herror as exc:
        return None, [], f"herror:{exc}"
    except socket.gaierror as exc:
        return None, [], f"gaierror:{exc}"
    except OSError as exc:
        return None, [], f"oserror:{exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, [], f"error:{exc.__class__.__name__}"
    finally:
        socket.setdefaulttimeout(previous)


async def reverse_dns_lookup(params: ReverseDnsLookupParams) -> ReverseDnsLookupResult:
    """Reverse-resolve an IP address to a hostname.

    Useful when a leaked secret embeds an IP literal: a PTR record can hint
    at the owning organization (e.g. ``ec2-...amazonaws.com``).

    Args:
        params: ``ReverseDnsLookupParams`` with the IP to query.

    Returns:
        ``ReverseDnsLookupResult`` with hostname/aliases or an ``error``.
    """
    logger.debug(f"reverse_dns_lookup ip={params.ip_address}")

    try:
        hostname, aliases, error = await asyncio.wait_for(
            asyncio.to_thread(_reverse_one, params.ip_address),
            timeout=REVERSE_DNS_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        return ReverseDnsLookupResult(ip_address=params.ip_address, error="timeout")

    return ReverseDnsLookupResult(
        ip_address=params.ip_address,
        hostname=hostname,
        aliases=aliases,
        error=error,
    )
