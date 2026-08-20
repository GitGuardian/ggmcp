import logging
from typing import Annotated, Any

from pydantic import BaseModel, Field

from gg_api_core.incident_filters import (
    IncidentFilterParams,
    build_api_params,
    build_filter_info,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class CountIncidentsParams(IncidentFilterParams):
    """Parameters for counting incidents using the MCP-optimized count endpoint.

    Accepts the same filters as list_incidents but returns only a count.
    """


class CountIncidentsResult(BaseModel):
    """Result from counting incidents."""

    count: int = Field(description="Total number of matching incidents")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


class CountIncidentsError(BaseModel):
    """Error result from counting incidents."""

    error: str = Field(description="Error message")


async def count_incidents(
    search: Annotated[str | None, Field(default=None, description='Search term to filter incidents by name or content')] = None,
    status: Annotated[list[str] | str | None, Field(default=['TRIGGERED', 'ASSIGNED', 'RESOLVED'], description='Filter by status. Values: TRIGGERED (unassigned active), ASSIGNED (assigned active), RESOLVED, IGNORED. Default excludes IGNORED.')] = ['TRIGGERED', 'ASSIGNED', 'RESOLVED'],
    mine: Annotated[bool, Field(default=False, description='If True, count only incidents assigned to the current user. Overrides assignee_id.')] = False,
    assignee_id: Annotated[int | None, Field(default=None, description="Filter by assignee member ID. Use 0 for unassigned incidents. Cannot be used with 'mine'.")] = None,
    severity: Annotated[list[str | int] | str | int | None, Field(default=[10, 20, 30, 100], description='Filter by severity levels. Values: critical (10), high (20), medium (30), low (40), info (50), unknown (100). Default excludes LOW and INFO.')] = [10, 20, 30, 100],
    score_min: Annotated[int | None, Field(default=None, ge=0, le=100, description='Filter incidents with a score greater than or equal to this value (0-100).')] = None,
    score_max: Annotated[int | None, Field(default=None, ge=0, le=100, description='Filter incidents with a score less than or equal to this value (0-100).')] = None,
    validity: Annotated[list[str] | str | None, Field(default=['valid', 'failed_to_check', 'no_checker', 'not_checked'], description='Filter by validity status. Values: valid, invalid, failed_to_check, no_checker, not_checked. Default excludes INVALID.')] = ['valid', 'failed_to_check', 'no_checker', 'not_checked'],
    detector_group_name: Annotated[list[str] | str | None, Field(default=None, description="Filter by detector group name (e.g., 'AWS Keys', 'GitHub Tokens')")] = None,
    detector_type: Annotated[list[str] | str | None, Field(default=None, description='Filter by detector type/nature')] = None,
    detector_category: Annotated[list[str] | str | None, Field(default=None, description='Filter by detector category')] = None,
    issue_name: Annotated[list[str] | str | None, Field(default=None, description='Filter by issue/incident name')] = None,
    secret_category: Annotated[list[str] | str | None, Field(default=None, description='Filter by secret category')] = None,
    secret_family: Annotated[list[str] | str | None, Field(default=None, description='Filter by secret family')] = None,
    secret_provider: Annotated[list[str] | str | None, Field(default=None, description="Filter by secret provider (e.g., 'aws', 'github', 'google')")] = None,
    source_ids: Annotated[list[int] | int | None, Field(default=None, description='Filter by source ID(s). Can be obtained using list_source or find_current_source_id tools.')] = None,
    source_type: Annotated[list[str] | str | None, Field(default=None, description="Filter by source type (e.g., 'github', 'gitlab', 'bitbucket')")] = None,
    source_criticality: Annotated[list[str] | str | None, Field(default=None, description='Filter by source criticality. Values: critical, high, medium, low, unknown')] = None,
    occurrence_count_min: Annotated[int | None, Field(default=None, description='Filter incidents with at least this many occurrences')] = None,
    presence: Annotated[list[str] | str | None, Field(default=None, description='Filter by occurrence presence status. Values: present, removed')] = None,
    opened_for_days: Annotated[int | None, Field(default=None, description='Filter incidents that have been open for at least this many days')] = None,
    tags: Annotated[list[str] | str | None, Field(default=None, description="Filter by tag names (e.g., 'REGRESSION', 'PUBLICLY_EXPOSED', 'TEST_FILE')")] = None,
    exclude_tags: Annotated[list[str] | str | None, Field(default=['TEST_FILE', 'FALSE_POSITIVE', 'CHECK_RUN_SKIP_FALSE_POSITIVE', 'CHECK_RUN_SKIP_LOW_RISK', 'CHECK_RUN_SKIP_TEST_CRED'], description='Exclude incidents with these tag names. Default excludes TEST_FILE, FALSE_POSITIVE, and CHECK_RUN_SKIP_* tags.')] = ['TEST_FILE', 'FALSE_POSITIVE', 'CHECK_RUN_SKIP_FALSE_POSITIVE', 'CHECK_RUN_SKIP_LOW_RISK', 'CHECK_RUN_SKIP_TEST_CRED'],
    public_exposure: Annotated[list[str] | str | None, Field(default=None, description='Filter by public exposure. Values: source_publicly_visible, public_incident_linked, leaked_outside_perimeter')] = None,
    integration: Annotated[list[str] | str | None, Field(default=None, description="Filter by integration type (e.g., 'github', 'gitlab', 'slack')")] = None,
    issue_tracker: Annotated[list[str] | str | None, Field(default=None, description='Filter by issue tracker type. Values: jira_cloud_notifier, jira_data_center_notifier, servicenow')] = None,
    has_related_issues: Annotated[bool | None, Field(default=None, description='Filter to incidents with (True) or without (False) related issues')] = None,
    location: Annotated[bool | None, Field(default=None, description='Filter to incidents with (True) or without (False) location information')] = None,
    feedback: Annotated[bool | None, Field(default=None, description='Filter to incidents with (True) or without (False) feedback')] = None,
    publicly_shared: Annotated[bool | None, Field(default=None, description="Filter to incidents that are (True) or aren't (False) publicly shared")] = None,
    secret_manager_type: Annotated[list[str] | str | None, Field(default=None, description='Filter by vault type. Values: hashicorpvault, awssecretsmanager, azurekeyvault, gcpsecretmanager, cyberarksaas, cyberarkselfhosted, akeyless, delineasecretserver')] = None,
    secret_manager_instance: Annotated[list[int] | int | None, Field(default=None, description='Filter by vault instance ID(s)')] = None,
    nhi_env: Annotated[list[str] | str | None, Field(default=None, description='Filter by NHI environment name(s)')] = None,
    nhi_policy: Annotated[list[str] | str | None, Field(default=None, description='Filter by NHI policy breach name(s)')] = None,
    teams: Annotated[list[int] | int | None, Field(default=None, description='Filter by team ID(s)')] = None,
    similar_to: Annotated[int | None, Field(default=None, description='Filter incidents similar to the given incident ID')] = None,
    date_before: Annotated[str | None, Field(default=None, description='Filter incidents detected before this date (YYYY-MM-DD format)')] = None,
    date_after: Annotated[str | None, Field(default=None, description='Filter incidents detected after this date (YYYY-MM-DD format)')] = None,
    secret_scope: Annotated[list[str] | str | None, Field(default=None, description='Filter by secret scope name(s)')] = None,
    analyzer_status: Annotated[list[str] | str | None, Field(default=None, description='Filter by analyzer status. Values: no_checker, not_checked, checked, invalid, failed_to_check')] = None,
    custom_tags: Annotated[list[int] | int | None, Field(default=None, description='Filter by custom tag ID(s)')] = None,
) -> CountIncidentsResult | CountIncidentsError:
    """
        Count secret incidents matching the given filters.

        Returns the total number of matching incidents without fetching the full list.
        This is useful to get an overview of incident volume, check filter results
        before paginating, or build dashboards.

        Accepts the same filters as list_incidents (status, severity, detector type,
        source, tags, etc.) but returns only the count.

        Args:
            params: CountIncidentsParams model containing all filtering options.

        Returns:
            CountIncidentsResult: Pydantic model containing:
                - count: Total number of matching incidents
                - applied_filters: Dictionary of filters that were applied

            CountIncidentsError: Pydantic model with error message if the operation fails

    """
    params = CountIncidentsParams(
        search=search,
        status=status,
        mine=mine,
        assignee_id=assignee_id,
        severity=severity,
        score_min=score_min,
        score_max=score_max,
        validity=validity,
        detector_group_name=detector_group_name,
        detector_type=detector_type,
        detector_category=detector_category,
        issue_name=issue_name,
        secret_category=secret_category,
        secret_family=secret_family,
        secret_provider=secret_provider,
        source_ids=source_ids,
        source_type=source_type,
        source_criticality=source_criticality,
        occurrence_count_min=occurrence_count_min,
        presence=presence,
        opened_for_days=opened_for_days,
        tags=tags,
        exclude_tags=exclude_tags,
        public_exposure=public_exposure,
        integration=integration,
        issue_tracker=issue_tracker,
        has_related_issues=has_related_issues,
        location=location,
        feedback=feedback,
        publicly_shared=publicly_shared,
        secret_manager_type=secret_manager_type,
        secret_manager_instance=secret_manager_instance,
        nhi_env=nhi_env,
        nhi_policy=nhi_policy,
        teams=teams,
        similar_to=similar_to,
        date_before=date_before,
        date_after=date_after,
        secret_scope=secret_scope,
        analyzer_status=analyzer_status,
        custom_tags=custom_tags,
    )

    client = await get_client()

    try:
        api_params: dict[str, Any] = {}

        # Handle 'mine' parameter
        if params.mine:
            member = await client.get_current_member()
            current_user_id = member["id"]
            if params.assignee_id is not None and params.assignee_id != current_user_id:
                return CountIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                    f"but assignee_id={params.assignee_id} was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_id', not both."
                )
            api_params["assignee_id"] = current_user_id
        elif params.assignee_id is not None:
            api_params["assignee_id"] = params.assignee_id

        api_params.update(build_api_params(params))

        response = await client.count_incidents_for_mcp(**api_params)

        return CountIncidentsResult(
            count=response["count"],
            applied_filters=build_filter_info(params),
        )

    except Exception as e:
        logger.exception(f"Error counting incidents: {str(e)}")
        return CountIncidentsError(error=f"Failed to count incidents: {str(e)}")
