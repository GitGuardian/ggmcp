from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams
import asyncio

from gg_api_core.tools.remediate_secret_incidents import RemediateSecretIncidentsParams, remediate_secret_incidents


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


if __name__ == "__main__":
    asyncio.run(run_find_current_source_id())
