from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.list_honey_tokens import ListHoneytokensParams, list_honeytokens
from gg_api_core.tools.list_repo_incidents import ListRepoIncidentsParams, list_repo_incidents
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams
import asyncio

from gg_api_core.tools.remediate_secret_incidents import RemediateSecretIncidentsParams, remediate_secret_incidents, \
    ListRepoOccurrencesParamsForRemediate
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
    print(await list_repo_incidents(
        ListRepoIncidentsParams(source_id="9036019", get_all=False, status=None,
                                severity=["critical", "high", "medium", "low", "info", "unknown"], tags=["TEST_FILE"])))

    print(await list_repo_incidents(ListRepoIncidentsParams(source_id="9036019")))

    # Honey Tokens
    print(await list_honeytokens(ListHoneytokensParams()))

    # Scan
    print(await scan_secrets(
        ScanSecretsParams(documents=[{'document': 'file content', 'filename': 'optional_filename.txt'}, ])))


if __name__ == "__main__":
    asyncio.run(main())
