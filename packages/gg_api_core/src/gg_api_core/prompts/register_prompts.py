"""Register the HIL prompts on a GitGuardian MCP server."""

from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
from gg_api_core.prompts.investigate_secret_repository import render_investigate_secret_repository
from gg_api_core.prompts.qualify_high_impact_leak import render_qualify_high_impact_leak
from gg_api_core.prompts.triage_public_secret_leak import render_triage_public_secret_leak


def register_hil_prompts(mcp: AbstractGitGuardianFastMCP) -> None:
    """Register the three HIL prompts on ``mcp``.

    Prompts intentionally return plain text. FastMCP serializes a single
    string return as a user message — clients can paste it into their own
    model's context or wire it through ``getPrompt``.
    """

    @mcp.prompt(
        name="triage_public_secret_leak",
        description=(
            "Triage a single public secret leak in one pass. Returns the HIL "
            "SecretTriageOutput schema and the minimal tool playbook a client "
            "should follow."
        ),
    )
    def triage_public_secret_leak(incident_id: str, target_company: str | None = None) -> str:
        return render_triage_public_secret_leak(incident_id=incident_id, target_company=target_company)

    @mcp.prompt(
        name="qualify_high_impact_leak",
        description=(
            "Multi-step HIL qualification playbook (DNS → SSL → RDAP → repo → "
            "validity). Embeds the DeepIncidentAnalysisOutput schema and an "
            "8-call budget."
        ),
    )
    def qualify_high_impact_leak(
        incident_id: str,
        triage_summary: str | None = None,
        target_company: str | None = None,
    ) -> str:
        return render_qualify_high_impact_leak(
            incident_id=incident_id,
            triage_summary=triage_summary,
            target_company=target_company,
        )

    @mcp.prompt(
        name="investigate_secret_repository",
        description=(
            "Reader playbook for a single GitHub repo: gather ownership / "
            "impact evidence under a 6-call budget. Returns the ReaderTaskResult "
            "schema."
        ),
    )
    def investigate_secret_repository(
        repo: str,
        task: str,
        incident_id: str | None = None,
    ) -> str:
        return render_investigate_secret_repository(repo=repo, task=task, incident_id=incident_id)
