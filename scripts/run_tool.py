from gg_api_core.tools.assign_incident import assign_incident, AssignIncidentParams
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.list_honey_tokens import ListHoneytokensParams, list_honeytokens
from gg_api_core.tools.list_incidents import ListIncidentsParams, list_incidents
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams
import asyncio

from gg_api_core.tools.list_users import list_users, ListUsersParams
from gg_api_core.tools.remediate_secret_incidents import RemediateSecretIncidentsParams, remediate_secret_incidents, \
    ListRepoOccurrencesParamsForRemediate
from gg_api_core.tools.revoke_secret import revoke_secret, RevokeSecretParams
from gg_api_core.tools.scan_secret import scan_secrets, ScanSecretsParams


async def run_fetch_repo_occurrences():
    result = await list_repo_occurrences(
        ListRepoOccurrencesParams(source_id="9036019", get_all=False, status=None,
                                  severity=["critical", "high", "medium", "low", "info", "unknown"])
    )
    print(result)


async def run_remediate_secret_incidents():
    result = await remediate_secret_incidents(
        RemediateSecretIncidentsParams(source_id="9036019")
    )
    print(result)


async def run_find_current_source_id():
    result = await find_current_source_id()
    print(result)


async def main():
    print(await run_find_current_source_id())

    # Remediate
    print(await remediate_secret_incidents(
        RemediateSecretIncidentsParams(
            list_repo_occurrences_params=ListRepoOccurrencesParamsForRemediate(source_id="9036019")))
          )

    # Occurrences
    print(await list_repo_occurrences(
        ListRepoOccurrencesParams(source_id="9036019", get_all=False, status=None,
                                  severity=["critical", "high", "medium", "low", "info", "unknown"], tags=["TEST_FILE"])
    ))

    # Incidents
    print(await list_incidents(
        ListIncidentsParams(source_id="9036019", get_all=False, status=None,
                                severity=["critical", "high", "medium", "low", "info", "unknown"], tags=["TEST_FILE"])))

    print(await list_incidents(ListIncidentsParams(source_id="9036019")))

    # Honey Tokens
    print(await list_honeytokens(ListHoneytokensParams()))

    # Scan
    print(await scan_secrets(
        ScanSecretsParams(documents=[{'document': 'file content', 'filename': 'optional_filename.txt'}, ])))

    # List users
    print(await list_users(ListUsersParams(search="Pierre")))

    # Revoke secret (example with a placeholder ID - replace with actual secret ID)
    print(await revoke_secret(RevokeSecretParams(secret_id="12345")))

    # Assign incident (example with placeholder IDs - replace with actual incident and member IDs)
    # Assign to specific member by ID:
    # print(await assign_incident(AssignIncidentParams(incident_id="67890", assignee_member_id="123")))
    # Or assign to member by email:
    # print(await assign_incident(AssignIncidentParams(incident_id="67890", email="user@example.com")))
    # Or assign to current user:
    # print(await assign_incident(AssignIncidentParams(incident_id="67890", mine=True)))


async def main():
    print(await list_incidents(params=ListIncidentsParams()))

async def init_secops_server():
    from secops_mcp_server.server import mcp
    print(await mcp.call_tool("list_users", {"params": {}}))


if __name__ == "__main__":
    asyncio.run(main())
    # asyncio.run(init_secops_server())
