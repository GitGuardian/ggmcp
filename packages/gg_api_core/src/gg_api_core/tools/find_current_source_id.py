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


def _repository_name_from(remote_url: str) -> str | None:
    """Extract the bare repository name (no org prefix) from a git remote URL.

    ``parse_repo_url`` returns ``org/repo`` (or ``org/proj/repo`` for Azure DevOps);
    the GitGuardian source lookup matches on the bare repository name, so only the
    final path segment is kept.
    """
    parsed = parse_repo_url(remote_url)
    return parsed.split("/")[-1] if parsed else None


def _exact_match(
    repository_name: str, source: dict[str, Any]
) -> FindCurrentSourceIdResult:
    """Build a result for an exact source match."""
    return FindCurrentSourceIdResult(
        repository_name=repository_name,
        source_id=source.get("id"),
        source=source,
        message=f"Successfully found exact match for GitGuardian source: {repository_name}",
    )


def _multiple_candidates(
    repository_name: str, sources: list[dict[str, Any]]
) -> FindCurrentSourceIdResult:
    """Build a result listing candidate sources for the agent to pick from."""
    return FindCurrentSourceIdResult(
        repository_name=repository_name,
        message=f"No exact match found for '{repository_name}', but found {len(sources)} potential matches.",
        suggestion=(
            "Review the candidates below and determine which source best matches "
            "the current repository based on the name and URL."
        ),
        candidates=[
            SourceCandidate(
                id=source.get("id", -1),
                url=source.get("url"),
                name=source.get("full_name") or source.get("name"),
                monitored=source.get("monitored"),
                deleted_at=source.get("deleted_at"),
            )
            for source in sources
        ],
    )


def _no_match(repository_name: str) -> FindCurrentSourceIdError:
    """Build the error returned when the repository is not among the sources."""
    return FindCurrentSourceIdError(
        repository_name=repository_name,
        error=f"Repository '{repository_name}' not found in GitGuardian",
        message="The repository may not be connected to GitGuardian, or you may not have access to it.",
        suggestion="Check that the repository is properly connected to GitGuardian and that your account has access to it.",
    )


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
    if remote_url is None:
        logger.info("No remote_url provided; returning suggestion to run git locally")
        return FindCurrentSourceIdSuggestion(
            suggestion=GIT_REMOTE_SUGGESTION,
            message="The repository could not be detected server-side.",
        )

    repository_name = _repository_name_from(remote_url)
    if repository_name is None:
        return FindCurrentSourceIdError(
            error="Could not determine repository name",
            message=f"The provided remote_url '{remote_url}' could not be parsed into a repository name.",
            suggestion="Provide a valid git remote URL (e.g. the output of `git config --get remote.origin.url`).",
        )

    logger.info(f"Detected repository name: {repository_name}")

    try:
        client = await get_client()
        source_result: dict[str, Any] | list[dict[str, Any]] | None = await client.get_source_by_name(
            repository_name, return_all_on_no_match=True
        )

        if isinstance(source_result, dict):
            return _exact_match(repository_name, source_result)

        if isinstance(source_result, list) and source_result:
            return _multiple_candidates(repository_name, source_result)

        return _no_match(repository_name)
    except Exception as e:
        logger.exception(f"Error finding source_id: {str(e)}")
        return FindCurrentSourceIdError(error=f"Failed to find source_id: {str(e)}")
