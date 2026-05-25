"""Prompt: qualify whether a public leak is a High Impact Leak (HIL)."""

from textwrap import dedent

DEEP_ANALYSIS_OUTPUT_SCHEMA = dedent(
    """
    {
      "verdict": "confirmed | rejected | inconclusive",
      "company_name": "string | null — the company the leak is attributed to (if confirmed)",
      "relationship_type": "owned | uses | unknown — does the company OWN the leaked asset, or merely USE it?",
      "evidence_chain": [
        {
          "tool_used": "string — name of the tool called",
          "finding": "string — what the tool returned (no secret values)",
          "supports_company": "boolean — does this support the candidate company?",
          "reasoning": "string — why this matters"
        }
      ],
      "rejection_reason": "string | null — only set when verdict=rejected",
      "agrees_with_triage": "boolean | null — only set when triage_summary was provided",
      "triage_disagreement_reason": "string | null — only set when agrees_with_triage=false"
    }
    """
).strip()


def render_qualify_high_impact_leak(
    incident_id: str,
    triage_summary: str | None = None,
    target_company: str | None = None,
) -> str:
    """Render the qualification prompt as plain text."""
    triage_block = (
        dedent(
            f"""
            # Prior triage (treat as a hypothesis, not ground truth)
            {triage_summary}
            """
        ).strip()
        if triage_summary
        else "# Prior triage\nNone provided. Treat this as a cold investigation."
    )

    target_block = (
        f"# Target company\nThe caller suspects: **{target_company}**. Confirm or refute."
        if target_company
        else "# Target company\nNone supplied. Identify the most likely owning company from the evidence."
    )

    return dedent(
        f"""
        # Role
        You are qualifying whether a leaked secret is a **High Impact Leak (HIL)** for
        a specific company. HIL means: the secret meaningfully impacts a real, named
        organization (it grants access to *their* infrastructure or data), not a
        random hobby project. Be conservative: false positives are expensive.

        # Incident
        Incident id: ``{incident_id}``

        {target_block}

        {triage_block}

        # Inputs to gather (mandatory)
        1. ``get_public_incident({{"incident_id": {incident_id}}})``
        2. ``list_public_occurrences({{"incident_id": {incident_id}}})``

        Extract candidate hostnames, domains and IPs from URLs in the occurrence
        metadata and from detector-specific fields (``rotation_url``, ``api_url``,
        etc.).

        # Tool playbook (cheap → expensive)

        Run these in order, **stopping as soon as evidence is sufficient**:

        1. **DNS / ownership chain (cheap)**
           For each candidate hostname:
           * ``dns_lookup({{"hostname": "<host>"}})`` — resolve A/CNAME.
           * If resolvable: ``check_ssl_certificate({{"hostname": "<host>"}})``
             — Subject Organization on the cert is the strongest single signal.
           * In parallel: ``rdap_domain_lookup({{"domain": "<host's apex domain>"}})``
             — registrant_organization is the second strongest.
           * If the candidate is an IP literal:
             ``rdap_ip_lookup({{"ip_address": "<ip>"}})``.
           * Optional: ``check_host_reachability({{"host": "<host>"}})`` to
             distinguish live production from parked / sinkholed hosts.

        2. **Repo metadata (still cheap)**
           For the source repository of the leak:
           * ``get_github_repo_metadata({{"repo": "owner/name"}})``
           * ``list_github_repo_contributors({{"repo": "owner/name", "limit": 5}})``
           The owner's ``company`` field and contributor companies are direct signals.

        3. **Code search (more expensive)**
           If the above is inconclusive:
           * ``search_github_code({{"query": "<candidate company name>", "repo": "<repo>"}})``
           * ``search_github_issues({{"query": "<candidate company name>", "repo": "<repo>"}})``

        4. **Validity check (most expensive — gated)**
           ``check_secret_validity`` *would* be the conclusive signal, but it hits
           the third-party provider's API. Only invoke it when:
           * Steps 1-3 give a single coherent candidate company, AND
           * The user has explicitly consented to a third-party API call.
           This tool may be **unavailable** in this MCP. If you can't find it in
           your tool list, skip step 4 and report ``relationship_type=unknown``
           if other signals don't disambiguate ``owned`` vs ``uses``.

        # Stop rule
        Stop as soon as you have a confident verdict OR after **8 tool calls total**.
        Whichever comes first. Prefer stopping early with ``verdict=inconclusive`` over
        burning the budget on weak signals.

        # Decision rules
        * ``verdict=confirmed`` requires at least **two independent supporting
          signals** (e.g. cert O matches AND RDAP registrant matches; or repo owner
          company matches AND code search confirms).
        * ``relationship_type=owned`` means the leaked credential belongs to the
          company's own infra (their AWS, their API). ``uses`` means a credential
          for a third-party SaaS that the company has an account on (e.g. a Stripe
          key issued to the company). Default to ``unknown`` when unclear.
        * If triage was provided and you disagree, set ``agrees_with_triage=false``
          and explain in ``triage_disagreement_reason``. Do not silently overwrite
          triage's company assignment without justification.
        * Never include secret values, partial keys, or tokens in
          ``evidence_chain[].finding``. Refer to them as "the credential" or by
          detector name.

        # Output
        Return **only** a single JSON object matching the schema below, no prose
        outside it.

        ```json
        {DEEP_ANALYSIS_OUTPUT_SCHEMA}
        ```
        """
    ).strip()
