from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams
import asyncio

async def main():
    result = await list_repo_occurrences(
        ListRepoOccurrencesParams(source_id="9036019")
    )
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
