import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.utils import get_client, parse_repo_url

logger = logging.getLogger(__name__)

GIT_REMOTE_SUGGESTION = (
    "This MCP server cannot access your local filesystem or git repository. "
    "To find the source_id for the current repository, run "
    "`git config --get remote.origin.url` in the repository directory yourself "
    "(e.g. with a shell/Bash tool), then call this tool again passing the output as the "
    "`remote_url` argument."
)


class SourceCandidate(BaseModel):
    """A candidate source that might match the repository."""

    id: str | int = Field(description="Source ID")
    url: str | None = Field(default=None, description="Repository URL")
    name: str | None = Field(default=None, description="Repository name")
    monitored: bool | None = Field(default=None, description="Whether source is monitored")
    deleted_at: str | None = Field(default=None, description="Deletion timestamp if deleted")


class FindCurrentSourceIdResult(BaseModel):
    """Successful result from finding source ID."""

    repository_name: str = Field(description="Detected repository name")
    source_id: str | int | None = Field(default=None, description="GitGuardian source ID (if exact match)")
    source: dict[str, Any] | None = Field(default=None, description="Full source information (if exact match)")
    message: str | None = Field(default=None, description="Status or informational message")
    suggestion: str | None = Field(default=None, description="Suggestions for next steps")
    candidates: list[SourceCandidate] | None = Field(
        default=None, description="List of candidate sources (if no exact match)"
    )


class FindCurrentSourceIdSuggestion(BaseModel):
    """Returned when no ``remote_url`` is provided.

    The server has no access to the user's filesystem or ``git`` binary (regardless
    of transport), so it asks the calling agent to run git locally and call the tool
    again with the resulting ``remote_url``.
    """

    suggestion: str = Field(description="Instructions for the agent to obtain the repository remote URL")
    message: str = Field(description="User-friendly explanation of why detection could not run server-side")


class FindCurrentSourceIdError(BaseModel):
    """Error result from finding source ID."""

    error: str = Field(description="Error message")
    repository_name: str | None = Field(default=None, description="Repository name if detected")
    details: str | None = Field(default=None, description="Additional error details")
    message: str | None = Field(default=None, description="User-friendly message")
    suggestion: str | None = Field(default=None, description="Suggestions for resolving the error")


async def find_current_source_id(
    remote_url: str | None = None,
) -> FindCurrentSourceIdResult | FindCurrentSourceIdError | FindCurrentSourceIdSuggestion:
    """
    Find the GitGuardian source_id for a repository.

    This tool:
    1. Determines the repository name from the git remote URL
    2. Searches GitGuardian for matching sources
    3. Returns the source_id if an exact match is found
    4. If no exact match, returns all search results for the model to choose from

    The repository is resolved solely from ``remote_url``; the tool never accesses the local
    filesystem or shells out to git, so its behavior is identical across transports (hosted HTTP
    and stdio). The calling agent is responsible for resolving the remote URL locally:
    - If ``remote_url`` is passed, it is parsed to derive the repository name.
    - Otherwise the tool returns a suggestion asking the agent to run
      ``git config --get remote.origin.url`` and call again with the result.

    Args:
        remote_url: The repository's git remote URL (e.g. the output of
                    ``git config --get remote.origin.url``). Required for the tool to detect
                    the repository.

    Returns:
        FindCurrentSourceIdResult: Pydantic model containing:
            - repository_name: The detected repository name
            - source_id: The GitGuardian source ID (if exact match found)
            - source: Full source information from GitGuardian (if exact match found)
            - message: Status or informational message
            - suggestion: Suggestions for next steps
            - candidates: List of SourceCandidate objects (if no exact match but potential matches found)

        FindCurrentSourceIdSuggestion: Pydantic model returned when the server cannot detect the
            repository itself and needs the agent to run git locally:
            - suggestion: Instructions to obtain the remote URL and call again
            - message: Explanation of why detection could not run server-side

        FindCurrentSourceIdError: Pydantic model containing:
            - error: Error message
            - repository_name: Repository name if detected
            - details: Additional error details
            - message: User-friendly message
            - suggestion: Suggestions for resolving the error
    """
    client = await get_client()
    logger.debug(f"Finding source_id for repository from remote URL: {remote_url}")

    try:
        if remote_url is not None:
            # The agent resolved the remote URL locally (e.g. ran git). Use it directly.
            parsed_url = parse_repo_url(remote_url)
            repository_name = parsed_url.split("/")[-1] if parsed_url else None
            logger.debug(f"Using provided remote URL: {remote_url}, parsed repository name: {repository_name}")
        else:
            # No remote_url: the server has no access to the user's filesystem or git binary,
            # so ask the agent to resolve the remote URL locally and call again.
            logger.info("No remote_url provided; returning suggestion to run git locally")
            return FindCurrentSourceIdSuggestion(
                suggestion=GIT_REMOTE_SUGGESTION,
                message="The repository could not be detected server-side.",
            )

        if not repository_name:
            return FindCurrentSourceIdError(
                error="Could not determine repository name",
                message=f"The provided remote_url '{remote_url}' could not be parsed into a repository name.",
                suggestion="Provide a valid git remote URL (e.g. the output of `git config --get remote.origin.url`).",
            )

        logger.info(f"Detected repository name: {repository_name}")

        # Search for the source in GitGuardian with robust non-exact matching
        source_result: dict[str, Any] | list[dict[str, Any]] | None = await client.get_source_by_name(
            repository_name, return_all_on_no_match=True
        )

        # Handle exact match (single dict result)
        if isinstance(source_result, dict):
            source_id: str | int | None = source_result.get("id")
            logger.info(f"Found exact match with source_id: {source_id}")

            message = f"Successfully found exact match for GitGuardian source: {repository_name}"

            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                source_id=source_id if source_id is not None else "",
                source=source_result,
                message=message,
            )

        # Handle multiple candidates (list result)
        elif isinstance(source_result, list) and len(source_result) > 0:
            logger.info(f"Found {len(source_result)} candidate sources for repository: {repository_name}")

            message = f"No exact match found for '{repository_name}', but found {len(source_result)} potential matches."

            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                message=message,
                suggestion="Review the candidates below and determine which source best matches the current repository based on the name and URL.",
                candidates=[
                    SourceCandidate(
                        id=source.get("id", -1),
                        url=source.get("url"),
                        name=source.get("full_name") or source.get("name"),
                        monitored=source.get("monitored"),
                        deleted_at=source.get("deleted_at"),
                    )
                    for source in source_result
                ],
            )

        # No matches found at all
        else:
            # Try searching with just the repo name (without org) as fallback
            if "/" in repository_name:
                repo_only = repository_name.split("/")[-1]
                logger.debug(f"Trying fallback search with repo name only: {repo_only}")
                fallback_result = await client.get_source_by_name(repo_only, return_all_on_no_match=True)

                # Handle fallback results
                if isinstance(fallback_result, dict):
                    fallback_source_id: str | int | None = fallback_result.get("id")
                    logger.info(f"Found match using repo name only, source_id: {fallback_source_id}")

                    message = f"Found match using repository name '{repo_only}' (without organization prefix)"

                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        source_id=fallback_source_id if fallback_source_id is not None else "",
                        source=fallback_result,
                        message=message,
                    )
                elif isinstance(fallback_result, list) and len(fallback_result) > 0:
                    logger.info(f"Found {len(fallback_result)} candidates using repo name only")

                    message = f"No exact match for '{repository_name}', but found {len(fallback_result)} potential matches using repo name '{repo_only}'."

                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        message=message,
                        suggestion="Review the candidates below and determine which source best matches the current repository.",
                        candidates=[
                            SourceCandidate(
                                id=source.get("id", -1),
                                url=source.get("url"),
                                name=source.get("full_name") or source.get("name"),
                                monitored=source.get("monitored"),
                                deleted_at=source.get("deleted_at"),
                            )
                            for source in fallback_result
                            if source.get("id") is not None
                        ],
                    )

            # Absolutely no matches found
            logger.warning(f"No sources found for repository: {repository_name}")

            message = "The repository may not be connected to GitGuardian, or you may not have access to it."

            return FindCurrentSourceIdError(
                repository_name=repository_name,
                error=f"Repository '{repository_name}' not found in GitGuardian",
                message=message,
                suggestion="Check that the repository is properly connected to GitGuardian and that your account has access to it.",
            )

    except Exception as e:
        logger.exception(f"Error finding source_id: {str(e)}")
        return FindCurrentSourceIdError(error=f"Failed to find source_id: {str(e)}")
