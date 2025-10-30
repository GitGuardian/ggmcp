from typing import Any
import logging
import subprocess
from pydantic import BaseModel, Field
from gg_api_core.utils import get_client, parse_repo_url

logger = logging.getLogger(__name__)


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
    candidates: list[SourceCandidate] | None = Field(default=None,
                                                     description="List of candidate sources (if no exact match)")


class FindCurrentSourceIdError(BaseModel):
    """Error result from finding source ID."""
    error: str = Field(description="Error message")
    repository_name: str | None = Field(default=None, description="Repository name if detected")
    details: str | None = Field(default=None, description="Additional error details")
    message: str | None = Field(default=None, description="User-friendly message")
    suggestion: str | None = Field(default=None, description="Suggestions for resolving the error")


async def find_current_source_id() -> FindCurrentSourceIdResult | FindCurrentSourceIdError:
    """
    Find the GitGuardian source_id for the current repository.

    This tool:
    1. Gets the current repository information from git
    2. Extracts the repository name from the remote URL
    3. Searches GitGuardian for matching sources
    4. Returns the source_id if an exact match is found
    5. If no exact match, returns all search results for the model to choose from

    Returns:
        FindCurrentSourceIdResult: Pydantic model containing:
            - repository_name: The detected repository name
            - source_id: The GitGuardian source ID (if exact match found)
            - source: Full source information from GitGuardian (if exact match found)
            - message: Status or informational message
            - suggestion: Suggestions for next steps
            - candidates: List of SourceCandidate objects (if no exact match but potential matches found)

        FindCurrentSourceIdError: Pydantic model containing:
            - error: Error message
            - repository_name: Repository name if detected
            - details: Additional error details
            - message: User-friendly message
            - suggestion: Suggestions for resolving the error
    """
    client = get_client()
    logger.debug("Finding source_id for current repository")

    try:
        # Get current repository remote URL
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            remote_url = result.stdout.strip()
            logger.debug(f"Found remote URL: {remote_url}")
        except subprocess.CalledProcessError as e:
            return FindCurrentSourceIdError(
                error="Not a git repository or no remote 'origin' configured",
                details=str(e),
            )
        except subprocess.TimeoutExpired:
            return FindCurrentSourceIdError(error="Git command timed out")

        # Parse repository name from remote URL
        repository_name = parse_repo_url(remote_url).split("/")[-1]

        if not repository_name:
            return FindCurrentSourceIdError(
                error=f"Could not parse repository URL: {remote_url}",
                details="The URL format is not recognized. Supported platforms: GitHub, GitLab (Cloud & Self-hosted), Bitbucket (Cloud & Data Center), Azure DevOps",
            )

        logger.info(f"Detected repository name: {repository_name}")

        # Search for the source in GitGuardian with robust non-exact matching
        result = await client.get_source_by_name(repository_name, return_all_on_no_match=True)

        # Handle exact match (single dict result)
        if isinstance(result, dict):
            source_id = result.get("id")
            logger.info(f"Found exact match with source_id: {source_id}")
            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                source_id=source_id,
                source=result,
                message=f"Successfully found exact match for GitGuardian source: {repository_name}",
            )

        # Handle multiple candidates (list result)
        elif isinstance(result, list) and len(result) > 0:
            logger.info(f"Found {len(result)} candidate sources for repository: {repository_name}")
            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                message=f"No exact match found for '{repository_name}', but found {len(result)} potential matches.",
                suggestion="Review the candidates below and determine which source best matches the current repository based on the name and URL.",
                candidates=[
                    SourceCandidate(
                        id=source.get("id"),
                        url=source.get("url"),
                        name=source.get("full_name") or source.get("name"),
                        monitored=source.get("monitored"),
                        deleted_at=source.get("deleted_at"),
                    )
                    for source in result
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
                    source_id = fallback_result.get("id")
                    logger.info(f"Found match using repo name only, source_id: {source_id}")
                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        source_id=source_id,
                        source=fallback_result,
                        message=f"Found match using repository name '{repo_only}' (without organization prefix)",
                    )
                elif isinstance(fallback_result, list) and len(fallback_result) > 0:
                    logger.info(f"Found {len(fallback_result)} candidates using repo name only")
                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        message=f"No exact match for '{repository_name}', but found {len(fallback_result)} potential matches using repo name '{repo_only}'.",
                        suggestion="Review the candidates below and determine which source best matches the current repository.",
                        candidates=[
                            SourceCandidate(
                                id=source.get("id"),
                                url=source.get("url"),
                                name=source.get("full_name") or source.get("name"),
                                monitored=source.get("monitored"),
                                deleted_at=source.get("deleted_at"),
                            )
                            for source in fallback_result
                        ],
                    )

            # Absolutely no matches found
            logger.warning(f"No sources found for repository: {repository_name}")
            return FindCurrentSourceIdError(
                repository_name=repository_name,
                error=f"Repository '{repository_name}' not found in GitGuardian",
                message="The repository may not be connected to GitGuardian, or you may not have access to it.",
                suggestion="Check that the repository is properly connected to GitGuardian and that your account has access to it.",
            )

    except Exception as e:
        logger.error(f"Error finding source_id: {str(e)}")
        return FindCurrentSourceIdError(error=f"Failed to find source_id: {str(e)}")
