from pydantic import Field

from gg_api_core.client import TagNames

from .list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesParams,
    ListRepoOccurrencesResult,
    list_repo_occurrences,
)


class ListRemediationTargetsParams(ListRepoOccurrencesParams):
    """Occurrence filters defaulting to recent findings on the repository's default branch."""

    tags: list[str] | None = Field(
        default=[TagNames.DEFAULT_BRANCH.value],
        description="Filter occurrence tags. Defaults to DEFAULT_BRANCH, the repository's remote default branch; "
        "this does not identify your checked-out branch. Pass [] to remove the tag filter.",
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort occurrences by date, most recent first by default.",
    )


async def list_remediation_targets(
    params: ListRemediationTargetsParams = ListRemediationTargetsParams(),
) -> ListRepoOccurrencesResult | ListRepoOccurrencesError:
    """List candidate secret occurrences with locations and pagination metadata.

    Pass source_id to scope the query to a repository. Defaults select its remote
    default branch and exclude known noise using list_repo_occurrences filters.
    The response is one page by default; while has_more is true, pass cursor back
    with the same filters. occurrences_count counts only the returned occurrences.
    get_all aggregates pages up to the server's byte limit and may still need a cursor.

    Use incident_id to filter one incident. To enumerate all of its known locations,
    use list_repo_occurrences with tags, exclude_tags, status, severity, and validity
    set to [], and omit source_id unless repository scoping is intended. Get incident
    metadata separately with get_incident.

    This read tool returns data only. Follow the triage-incidents skill and retrieve
    the workspace's instructions with get_remediation_workflow to plan remediation.

    Args:
        params: Repository or incident filters and cursor pagination options.

    Returns:
        Occurrence data, applied filters, and continuation metadata, or an error.
    """
    return await list_repo_occurrences(params)
