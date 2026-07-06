import logging
from pathlib import Path
from typing import Any

from jinja2 import Template
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import TagNames
from gg_api_core.utils import get_client

from .list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesParams,
    list_repo_occurrences,
)

logger = logging.getLogger(__name__)

REMEDIATION_PROMPT_PATH = Path(__file__).parent / "remediation_prompt.md"

DEFAULT_MAX_INCIDENTS = 20
DEFAULT_MAX_OCCURRENCES_PER_INCIDENT = 10
# get_incident caps embedded occurrences at 100 (API limit)
DRILLDOWN_MAX_OCCURRENCES = 100


class ListRepoOccurrencesParamsForTargets(ListRepoOccurrencesParams):
    # Overriding the tags one to add a default filter : for remediation, we're more interested in occurrences that
    # are in the branch the developer is currently on. And occurrences on DEFAULT_BRANCH are a heuristic for that
    tags: list[str] = Field(
        default=[TagNames.DEFAULT_BRANCH.value],
        description="List of tags to filter incidents by. Default to DEFAULT_BRANCH to avoid requiring a git checkout for the fix",
    )
    # Recent-first so that, once grouped, incidents surface by their most recent occurrence
    ordering: str = Field(
        default="-date",
        description="Sort field for the underlying occurrences query. Defaults to '-date' (most recent first).",
    )


class ListRemediationTargetsParams(BaseModel):
    """Parameters for listing secret incidents that are candidates for fixing."""

    source_id: str | int | None = Field(
        default=None,
        description="The source ID of the repository. Pass the current repository source ID if not provided.",
    )
    incident_id: int | None = Field(
        default=None,
        description="If provided, drill into a single incident and return its COMPLETE set of occurrences "
        "(everywhere that secret leaks), instead of a repo-wide overview. Use this to fully remediate one incident.",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )
    max_incidents: int = Field(
        default=DEFAULT_MAX_INCIDENTS,
        ge=1,
        description="Overview only: maximum number of incidents to return (most recent first).",
    )
    max_occurrences_per_incident: int = Field(
        default=DEFAULT_MAX_OCCURRENCES_PER_INCIDENT,
        ge=1,
        description="Overview only: maximum occurrences to include per incident. The full count is always reported "
        "as 'total_occurrence_count'; use incident_id to fetch every occurrence of one incident.",
    )
    get_all: bool = Field(
        default=True,
        description="Whether to fetch all pages of occurrences (overview only)",
    )

    # sub tools
    list_repo_occurrences_params: ListRepoOccurrencesParamsForTargets | None = Field(
        default=None,
        description="Parameters for the underlying repository occurrences query (overview only)",
    )

    @model_validator(mode="after")
    def populate_list_repo_occurrences_params(self) -> "ListRemediationTargetsParams":
        """Populate list_repo_occurrences_params with repository info from parent if not provided."""
        if self.list_repo_occurrences_params is None:
            # Create with parent's source info
            self.list_repo_occurrences_params = ListRepoOccurrencesParamsForTargets(
                source_id=self.source_id,
            )
        return self


class RemediationTarget(BaseModel):
    """A single incident and the occurrences to fix for it."""

    incident_id: int | str | None = Field(default=None, description="The incident this target belongs to")
    detector: str | None = Field(default=None, description="Detector name for the leaked secret")
    severity: str | None = Field(default=None, description="Incident severity")
    status: str | None = Field(default=None, description="Incident status")
    incident_url: str | None = Field(default=None, description="Link to the incident in GitGuardian")
    total_occurrence_count: int | None = Field(
        default=None,
        description="Total occurrences the incident has according to GitGuardian (may exceed the ones listed here)",
    )
    occurrence_count_in_view: int = Field(
        default=0, description="Number of occurrences gathered for this incident by this query"
    )
    occurrences_truncated: bool = Field(
        default=False,
        description="True if occurrences were capped. Pass incident_id to fetch the complete set.",
    )
    occurrences: list[dict[str, Any]] = Field(
        default_factory=list, description="Occurrence objects with exact match locations"
    )


class ListRemediationTargetsResult(BaseModel):
    """Result from listing remediation targets."""

    guidance: str = Field(
        default="",
        description="Fallback remediation guidance. Defer to a remediation skill/workflow when one is available.",
    )
    incidents: list[RemediationTarget] = Field(
        default_factory=list, description="Incidents to remediate, most recent first"
    )
    incident_count: int = Field(default=0, description="Number of incidents returned")
    total_incident_count: int = Field(
        default=0, description="Total distinct incidents found before the max_incidents cap"
    )
    truncated: bool = Field(
        default=False,
        description="True if incidents were capped or the underlying occurrences query was truncated",
    )

    sub_tools_results: dict[str, Any] = Field(default_factory=dict, description="Results from sub tools")


class ListRemediationTargetsError(BaseModel):
    """Error result from listing remediation targets."""

    error: str = Field(description="Error message")
    sub_tools_results: dict[str, Any] = Field(default_factory=dict, description="Results from sub tools")


def _detector_name(entity: dict[str, Any]) -> str | None:
    """Extract a human-readable detector name from an incident/occurrence's `detector` field."""
    detector = entity.get("detector")
    if isinstance(detector, dict):
        return detector.get("display_name") or detector.get("name")
    return detector


def _render_guidance() -> str:
    template_content = REMEDIATION_PROMPT_PATH.read_text()
    return Template(template_content).render()


def _group_by_incident(
    occurrences: list[dict[str, Any]],
    max_incidents: int,
    max_occurrences_per_incident: int,
) -> tuple[list[RemediationTarget], int]:
    """Group a flat occurrence list into per-incident remediation targets.

    Occurrences are assumed to arrive most-recent-first, so the first occurrence seen for an
    incident fixes both its metadata and its position in the returned list.

    Returns the (capped) targets and the total number of distinct incidents seen.
    """
    order: list[int | str] = []
    grouped: dict[int | str, list[dict[str, Any]]] = {}
    metadata: dict[int | str, dict[str, Any]] = {}

    for occ in occurrences:
        incident = occ.get("incident") or {}
        incident_id = incident.get("id") if isinstance(incident, dict) else None
        if incident_id is None:
            incident_id = occ.get("incident_id")
        if incident_id is None:
            continue
        if incident_id not in grouped:
            order.append(incident_id)
            grouped[incident_id] = []
            metadata[incident_id] = incident if isinstance(incident, dict) else {}
        grouped[incident_id].append(occ)

    targets: list[RemediationTarget] = []
    for incident_id in order[:max_incidents]:
        incident = metadata[incident_id]
        all_occ = grouped[incident_id]
        targets.append(
            RemediationTarget(
                incident_id=incident_id,
                detector=_detector_name(incident),
                severity=incident.get("severity"),
                status=incident.get("status"),
                incident_url=incident.get("gitguardian_url"),
                total_occurrence_count=incident.get("occurrences_count"),
                occurrence_count_in_view=len(all_occ),
                occurrences_truncated=len(all_occ) > max_occurrences_per_incident,
                occurrences=all_occ[:max_occurrences_per_incident],
            )
        )

    return targets, len(order)


async def _drilldown(incident_id: int) -> ListRemediationTargetsResult | ListRemediationTargetsError:
    """Return the complete occurrence set for a single incident."""
    client = await get_client()
    try:
        incident = await client.get_incident(incident_id=incident_id, with_occurrences=DRILLDOWN_MAX_OCCURRENCES)
    except Exception as e:
        logger.exception(f"Error fetching incident {incident_id}: {str(e)}")
        return ListRemediationTargetsError(error=f"Failed to fetch incident {incident_id}: {str(e)}")

    occurrences = incident.get("occurrences") or []
    total = incident.get("occurrences_count", len(occurrences))
    target = RemediationTarget(
        incident_id=incident_id,
        detector=_detector_name(incident),
        severity=incident.get("severity"),
        status=incident.get("status"),
        incident_url=incident.get("gitguardian_url"),
        total_occurrence_count=total,
        occurrence_count_in_view=len(occurrences),
        occurrences_truncated=isinstance(total, int) and total > len(occurrences),
        occurrences=occurrences,
    )
    return ListRemediationTargetsResult(
        guidance=_render_guidance() if occurrences else "This incident has no occurrences.",
        incidents=[target],
        incident_count=1,
        total_incident_count=1,
        truncated=target.occurrences_truncated,
    )


async def list_remediation_targets(
    params: ListRemediationTargetsParams,
) -> ListRemediationTargetsResult | ListRemediationTargetsError:
    """
    List secret incidents on the current branch that are candidates for fixing, grouped by incident.

    Without ``incident_id`` this returns a repo overview: the incidents (most recent first, capped by
    ``max_incidents``) with a representative sample of their occurrences (capped by
    ``max_occurrences_per_incident``); ``total_occurrence_count`` reports the true size and
    ``occurrences_truncated`` flags when there are more. With ``incident_id`` it drills into a single
    incident and returns its COMPLETE occurrence set so you can fully remediate it.

    This tool returns occurrence data (file paths, line numbers, character indices) — it does NOT
    rotate credentials or modify any files. Locate the secrets with this tool, then follow your
    remediation skill/workflow for how to fix them (rotate first). The ``guidance`` field is only a
    minimal rotation-first fallback for when no such skill is present.

    Args:
        params: ListRemediationTargetsParams model containing configuration

    Returns:
        ListRemediationTargetsResult or ListRemediationTargetsError
    """
    if params.incident_id is not None:
        logger.debug(f"Using list_remediation_targets drill-down for incident_id: {params.incident_id}")
        return await _drilldown(params.incident_id)

    logger.debug(f"Using list_remediation_targets overview for source_id: {params.source_id}")

    try:
        if params.list_repo_occurrences_params is None:
            return ListRemediationTargetsError(error="list_repo_occurrences_params is required", sub_tools_results={})

        occurrences_params = params.list_repo_occurrences_params.model_copy(
            update={
                "source_id": params.source_id or params.list_repo_occurrences_params.source_id,
                "get_all": params.get_all,
            }
        )

        occurrences_result = await list_repo_occurrences(occurrences_params)
        if isinstance(occurrences_result, ListRepoOccurrencesError):
            return ListRemediationTargetsError(
                error=occurrences_result.error,
                sub_tools_results={"list_repo_occurrences": occurrences_result},
            )

        occurrences = occurrences_result.occurrences
        if params.mine:
            occurrences = await filter_mine(occurrences)

        incidents, total_incident_count = _group_by_incident(
            occurrences,
            max_incidents=params.max_incidents,
            max_occurrences_per_incident=params.max_occurrences_per_incident,
        )

        if not incidents:
            guidance = (
                "No secret incidents found for this repository that match the criteria. "
                "Adjust 'list_repo_occurrences_params' to modify filtering."
            )
        else:
            guidance = _render_guidance()

        return ListRemediationTargetsResult(
            guidance=guidance,
            incidents=incidents,
            incident_count=len(incidents),
            total_incident_count=total_incident_count,
            truncated=total_incident_count > len(incidents) or occurrences_result.has_more,
            sub_tools_results={"list_repo_occurrences": occurrences_result},
        )

    except Exception as e:
        logger.exception(f"Error listing remediation targets: {str(e)}")
        return ListRemediationTargetsError(error=f"Failed to list remediation targets: {str(e)}")


async def filter_mine(occurrences):
    """Filter occurrences create by the current user"""
    client = await get_client()
    try:
        token_info = await client.get_current_token_info()
        current_user_id = token_info.get("member_id") if token_info else None

        if current_user_id:
            occurrences = [occ for occ in occurrences if occ.get("incident", {}).get("assignee_id") == current_user_id]
            logger.debug(f"Filtered to {len(occurrences)} occurrences for user {current_user_id}")
    except Exception as e:
        logger.warning(f"Could not filter by assignee: {str(e)}")
    return occurrences
