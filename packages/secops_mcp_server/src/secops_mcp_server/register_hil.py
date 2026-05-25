"""Register the HIL network + GitHub primitive tools on the SecOps server.

The HIL prompts and validity-check / patch-reader tools are wired separately;
see ``gg_api_core.prompts.register_prompts`` and the deferred stubs under
``gg_api_core.tools.{check_secret_validity,list_secret_checkers,get_public_occurrence_patch}``.
"""

from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.tools.github.get_github_repo_metadata import get_github_repo_metadata
from gg_api_core.tools.github.list_github_repo_contributors import list_github_repo_contributors
from gg_api_core.tools.github.search_github_code import search_github_code
from gg_api_core.tools.github.search_github_issues import search_github_issues
from gg_api_core.tools.network.check_host_reachability import check_host_reachability
from gg_api_core.tools.network.check_ssl_certificate import check_ssl_certificate
from gg_api_core.tools.network.dns_lookup import dns_lookup
from gg_api_core.tools.network.rdap_domain_lookup import rdap_domain_lookup
from gg_api_core.tools.network.rdap_ip_lookup import rdap_ip_lookup
from gg_api_core.tools.network.reverse_dns_lookup import reverse_dns_lookup


def register_hil_tools(mcp: AbstractGitGuardianFastMCP) -> None:
    """Register the network and GitHub primitives used by HIL playbooks."""

    # ----- Network primitives (no GG auth required) -----

    mcp.tool(
        dns_lookup,
        description=(
            "Resolve DNS records (A, AAAA, CNAME, MX, TXT, NS) for a hostname. "
            "First step when mapping a leaked URL/host back to an owning org — "
            "feed the resolved IP into rdap_ip_lookup, or follow the CNAME."
        ),
        required_scopes=[],
    )

    mcp.tool(
        reverse_dns_lookup,
        description=(
            "Reverse-resolve an IP to a hostname (PTR record). Useful when a "
            "leak embeds an IP literal — PTR records often hint at the hosting "
            "provider (ec2-...amazonaws.com)."
        ),
        required_scopes=[],
    )

    mcp.tool(
        rdap_domain_lookup,
        description=(
            "Look up the registrant organization of a domain via RDAP (modern "
            "WHOIS). Primary signal for tying a leaked URL/host back to a "
            "company. Returns registrant_organization, registrar, country, NS."
        ),
        required_scopes=[],
    )

    mcp.tool(
        rdap_ip_lookup,
        description=(
            "Look up the network/organization owning an IP address via RDAP. "
            "Run after dns_lookup; the owner field tells you whether the host "
            "is on AWS, GCP, the company's own ASN, etc."
        ),
        required_scopes=[],
    )

    mcp.tool(
        check_host_reachability,
        description=(
            "Probe whether a host is reachable (DNS → TCP → optional HTTPS GET) "
            "and detect a fronting WAF (Cloudflare/CloudFront/Akamai/Fastly). "
            "Useful when assessing whether a leaked endpoint is live prod infra."
        ),
        required_scopes=[],
    )

    mcp.tool(
        check_ssl_certificate,
        description=(
            "Fetch the TLS certificate for a hostname and extract Subject "
            "Organization, CN, SANs and issuer. Subject O is a near-conclusive "
            "ownership signal when it matches a candidate company."
        ),
        required_scopes=[],
    )

    # ----- GitHub primitives (optional GITHUB_TOKEN, no GG scope) -----

    mcp.tool(
        search_github_issues,
        description=(
            "Search GitHub issues, optionally scoped to a repo. Use to check "
            "whether a leaked secret was already reported, or to find context "
            "tying a repo to a company."
        ),
        required_scopes=[],
    )

    mcp.tool(
        search_github_code,
        description=(
            "Search GitHub code, optionally scoped to a repo. Requires "
            "GITHUB_TOKEN. Use to find additional occurrences of a leaked "
            "value, or files (README, CODEOWNERS) tying a repo to a company."
        ),
        required_scopes=[],
    )

    mcp.tool(
        get_github_repo_metadata,
        description=(
            "Fetch GitHub repo + owner metadata (description, homepage, owner "
            "type/company, stars, topics, default branch). Owner.company and "
            "description are direct ownership signals."
        ),
        required_scopes=[],
    )

    mcp.tool(
        list_github_repo_contributors,
        description=(
            "List top contributors of a GitHub repo with their public profile "
            "data (company, email, name). Strong signal for tying a repo to a "
            "specific organization. Pass limit=0 to skip per-user enrichment."
        ),
        required_scopes=[],
    )
