"""Smoke tests for the HIL prompt renderers.

We don't snapshot the entire prompt body to disk because the prompts are
intentionally hand-written prose that may evolve; instead we assert the
load-bearing sections are present (schema block, stop rule, expected tool
names) so accidental refactors break the test.
"""

import pytest
from gg_api_core.prompts.investigate_secret_repository import render_investigate_secret_repository
from gg_api_core.prompts.qualify_high_impact_leak import render_qualify_high_impact_leak
from gg_api_core.prompts.triage_public_secret_leak import render_triage_public_secret_leak


def test_triage_open_mode_mentions_required_tools():
    text = render_triage_public_secret_leak(incident_id="12345")
    assert "get_public_incident" in text
    assert "list_public_occurrences" in text
    assert "company_confidence" in text
    assert "risk_severity" in text
    assert "Stop rule" in text
    assert "12345" in text
    # Targeted-only language should NOT appear in open mode.
    assert "targeted" not in text.lower() or "Mode: open" in text


def test_triage_targeted_mode_carries_company():
    text = render_triage_public_secret_leak(incident_id="42", target_company="Acme Corp")
    assert "Acme Corp" in text
    assert "Mode: targeted" in text


def test_qualify_mentions_full_playbook_and_schema():
    text = render_qualify_high_impact_leak(incident_id="42", target_company="Acme")
    for tool in (
        "dns_lookup",
        "check_ssl_certificate",
        "rdap_domain_lookup",
        "rdap_ip_lookup",
        "get_github_repo_metadata",
        "list_github_repo_contributors",
        "check_secret_validity",
    ):
        assert tool in text, f"qualify prompt should mention {tool}"
    assert "verdict" in text
    assert "evidence_chain" in text
    assert "8 tool calls" in text


def test_qualify_with_triage_summary_included():
    text = render_qualify_high_impact_leak(
        incident_id="42",
        triage_summary="Triage said this is a leaked Acme prod AWS key, severity=high.",
    )
    assert "Triage said this is a leaked Acme prod AWS key" in text
    assert "agrees_with_triage" in text


def test_investigate_repository_mentions_step_budget():
    text = render_investigate_secret_repository(
        repo="acme/repo",
        task="Determine whether this repo is owned by Acme Corp.",
    )
    assert "acme/repo" in text
    assert "6 tool calls" in text
    assert "evidence_items" in text
    assert "get_github_repo_metadata" in text


@pytest.mark.parametrize(
    "renderer,kwargs",
    [
        (render_triage_public_secret_leak, {"incident_id": "1"}),
        (render_qualify_high_impact_leak, {"incident_id": "1"}),
        (
            render_investigate_secret_repository,
            {"repo": "acme/repo", "task": "ownership"},
        ),
    ],
)
def test_no_emojis_in_prompts(renderer, kwargs):
    """Prompts must stay emoji-free per repo convention."""
    text = renderer(**kwargs)
    # Quick heuristic: BMP-only characters except the standard typography.
    for ch in text:
        assert ord(ch) < 0x2700 or ch in "—…", f"emoji-like char in prompt: {ch!r}"
