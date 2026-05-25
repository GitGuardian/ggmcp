"""DNS lookup tool — resolve A/AAAA/CNAME/MX/TXT/NS records for a hostname."""

import asyncio
import logging
from typing import Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

RecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# Hard timeout per individual DNS query (seconds).
DNS_QUERY_TIMEOUT = 5.0
DNS_TOTAL_TIMEOUT = 15.0


class DnsLookupParams(BaseModel):
    """Parameters for the ``dns_lookup`` tool."""

    hostname: str = Field(description="Hostname to resolve (e.g. 'api.acme.com').")
    record_types: list[RecordType] = Field(
        default=["A", "CNAME"],
        description=("DNS record types to query. Defaults to ['A', 'CNAME']. Allowed: A, AAAA, CNAME, MX, TXT, NS."),
    )


class DnsLookupResult(BaseModel):
    """Result of a DNS lookup."""

    hostname: str = Field(description="The hostname that was queried.")
    records: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of record type to list of resolved values.",
    )
    error: str | None = Field(
        default=None,
        description="Error string if the lookup failed entirely (e.g. NXDOMAIN, timeout).",
    )


def _resolve_one(hostname: str, record_type: str) -> tuple[str, list[str] | str]:
    """Resolve a single record type. Runs in a thread so the tool stays async-friendly."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_QUERY_TIMEOUT
    resolver.timeout = DNS_QUERY_TIMEOUT

    try:
        answer = resolver.resolve(hostname, record_type)
        values = [rdata.to_text() for rdata in answer]
        return record_type, values
    except dns.resolver.NXDOMAIN:
        return record_type, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return record_type, []
    except dns.resolver.NoNameservers:
        return record_type, "no_nameservers"
    except dns.exception.Timeout:
        return record_type, "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return record_type, f"error:{exc.__class__.__name__}"


async def dns_lookup(params: DnsLookupParams) -> DnsLookupResult:
    """Resolve DNS records for a hostname.

    Use this to map a domain found in a leaked secret (host, URL) to an IP,
    CNAME, or mail server, which can then be RDAP-looked-up to identify the
    owning organization.

    Args:
        params: ``DnsLookupParams`` with hostname and record types.

    Returns:
        ``DnsLookupResult`` with a ``records`` map (one entry per requested
        record type) and an optional ``error`` if every query failed.
    """
    logger.debug(f"dns_lookup hostname={params.hostname} types={params.record_types}")

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    async def _run(rt: str) -> tuple[str, list[str] | str]:
        return await asyncio.to_thread(_resolve_one, params.hostname, rt)

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*[_run(rt) for rt in params.record_types]),
            timeout=DNS_TOTAL_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return DnsLookupResult(hostname=params.hostname, error="timeout")

    for record_type, value in results:
        if isinstance(value, list):
            records[record_type] = value
        else:
            errors[record_type] = value

    # If every record type failed with the same hard error (NXDOMAIN, timeout),
    # surface it at the top level.
    if not records and errors:
        unique = set(errors.values())
        if len(unique) == 1:
            return DnsLookupResult(hostname=params.hostname, error=next(iter(unique)))

    return DnsLookupResult(
        hostname=params.hostname,
        records=records,
        error=None if records else "; ".join(f"{k}={v}" for k, v in errors.items()) or None,
    )
