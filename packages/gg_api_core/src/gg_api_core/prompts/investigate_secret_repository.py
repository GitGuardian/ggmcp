"""Prompt: investigate a GitHub repo for ownership / impact evidence."""

from textwrap import dedent

READER_TASK_RESULT_SCHEMA = dedent(
    """
    {
      "evidence_items": [
        {
          "source": "string — tool name + scope (e.g. 'get_github_repo_metadata(owner/name)')",
          "finding": "string — what the tool returned",
          "relevance": "string — why this is relevant to the task",
          "confidence": "low | medium | high"
        }
      ],
      "conclusion": "string — 1-3 sentence answer to the task",
      "files_examined": ["string — file paths or repo references inspected"]
    }
    """
).strip()


def render_investigate_secret_repository(
    repo: str,
    task: str,
    incident_id: str | None = None,
) -> str:
    """Render the reader / investigator prompt."""
    incident_block = (
        f"# Incident cross-reference\nIncident id: ``{incident_id}`` — cross-check findings against\n"
        f"the occurrences of this incident when relevant.\n"
        if incident_id
        else "# Incident cross-reference\nNone provided. Investigate the repo in isolation.\n"
    )

    return dedent(
        f"""
        # Role
        You are investigating a GitHub repository to gather evidence about ownership
        or impact of a leaked secret. You are a **reader**, not a decider: collect
        evidence, summarize, and stop. Do not produce verdicts — that is the
        caller's job.

        # Repository
        ``{repo}``

        # Task
        {task}

        {incident_block}

        # Tool playbook
        Run these in order, stopping as soon as the task is answered:

        1. ``get_github_repo_metadata({{"repo": "{repo}"}})`` — description,
           homepage, owner.company, topics. Cheap, always start here.
        2. ``list_github_repo_contributors({{"repo": "{repo}", "limit": 5}})`` —
           collect contributor companies/emails. Limits per-user lookups.
        3. ``search_github_code({{"query": "<task keywords>", "repo": "{repo}"}})``
           — look for code paths matching the task (CODEOWNERS, README, package
           manifests, deployment configs). Requires ``GITHUB_TOKEN``; surface
           ``error=no_github_token`` if missing instead of guessing.
        4. ``search_github_issues({{"query": "<task keywords>", "repo": "{repo}"}})``
           — look for prior reports or context.

        # Stop rule
        Stop after **6 tool calls total** and submit ``ReaderTaskResult`` even if
        uncertain. This mirrors the ``_StepBudgetMiddleware`` in the upstream
        agent. Do not loop.

        # Decision rules
        * Each ``evidence_items[]`` entry must cite the exact tool call that
          produced it (e.g. ``get_github_repo_metadata(GitGuardian/ggmcp)``).
        * Mark ``confidence=high`` only when the finding is unambiguous (e.g.
          owner.company is set to a known company name). Default to ``medium``;
          use ``low`` for indirect inferences.
        * Never include secret values, partial keys or tokens in ``finding``.

        # Output
        Return **only** a single JSON object matching the schema below.

        ```json
        {READER_TASK_RESULT_SCHEMA}
        ```
        """
    ).strip()
