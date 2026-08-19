import asyncio

from ggmcp.tools.find_current_source_id import find_current_source_id
from ggmcp.tools.list_honeytokens import ListHoneytokensParams, list_honeytokens
from ggmcp.tools.list_incidents import ListIncidentsParams, list_incidents
from ggmcp.tools.list_repo_occurrences import ListRepoOccurrencesParams, list_repo_occurrences
from ggmcp.tools.list_users import ListUsersParams, list_users
from ggmcp.tools.remediate_secret_incidents import (
    ListRepoOccurrencesParamsForRemediate,
    RemediateSecretIncidentsParams,
    remediate_secret_incidents,
)
from ggmcp.tools.revoke_secret import RevokeSecretParams, revoke_secret
from ggmcp.tools.scan_secret import ScanSecretsParams, scan_secrets


async def run_find_current_source_id():
    result = await find_current_source_id()
    print(result)


async def main():
    print(await run_find_current_source_id())

    # Remediate
    print(
        await remediate_secret_incidents(
            RemediateSecretIncidentsParams(
                list_repo_occurrences_params=ListRepoOccurrencesParamsForRemediate(source_id="9036019")
            )
        )
    )

    # Occurrences
    print(
        await list_repo_occurrences(
            ListRepoOccurrencesParams(
                source_id="9036019",
                get_all=False,
                status=None,
                severity=["critical", "high", "medium", "low", "info", "unknown"],
                tags=["TEST_FILE"],
            )
        )
    )

    # Incidents
    print(
        await list_incidents(
            ListIncidentsParams(
                source_ids=[9036019],
                severity=["critical", "high", "medium", "low", "info", "unknown"],
                tags=["TEST_FILE"],
            )
        )
    )

    print(await list_incidents(ListIncidentsParams(source_ids=[9036019])))

    # Honey Tokens
    print(await list_honeytokens(ListHoneytokensParams()))

    # Scan
    print(
        await scan_secrets(
            ScanSecretsParams(
                documents=[
                    {"document": "file content", "filename": "optional_filename.txt"},
                ]
            )
        )
    )

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


if __name__ == "__main__":
    asyncio.run(main())
