"""List top contributors of a GitHub repo + their public profile data."""

import logging

import httpx
from pydantic import BaseModel, Field

from ._common import github_get

logger = logging.getLogger(__name__)


class ListGithubRepoContributorsParams(BaseModel):
    """Parameters for ``list_github_repo_contributors``."""

    repo: str = Field(description="Repository in ``owner/name`` form.")
    limit: int = Field(
        default=20,
        ge=0,
        le=100,
        description=(
            "Max contributors to enrich with profile data. Pass ``0`` to "
            "skip the per-user lookup and only return logins+contributions."
        ),
    )


class GithubContributor(BaseModel):
    login: str
    contributions: int
    company: str | None = None
    email: str | None = None
    name: str | None = None


class ListGithubRepoContributorsResult(BaseModel):
    repo: str
    contributors: list[GithubContributor] = Field(default_factory=list)
    rate_limit: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


async def list_github_repo_contributors(
    params: ListGithubRepoContributorsParams,
) -> ListGithubRepoContributorsResult:
    """List top contributors with their public profile data (company, email).

    Strong signal for tying a repo to a specific organization. Pass ``limit=0``
    if you only need contribution counts (avoids burning rate-limit budget on
    per-user lookups).

    Args:
        params: ``ListGithubRepoContributorsParams``.

    Returns:
        ``ListGithubRepoContributorsResult`` with enriched contributors.
    """
    logger.debug(f"list_github_repo_contributors repo={params.repo} limit={params.limit}")

    per_page = max(params.limit, 1) if params.limit else 30
    try:
        body, rate, status = await github_get(
            f"repos/{params.repo}/contributors",
            params={"per_page": per_page},
        )
    except httpx.HTTPError as exc:
        return ListGithubRepoContributorsResult(repo=params.repo, error=f"http_error:{exc.__class__.__name__}")

    if status >= 400 or not isinstance(body, list):
        message = body.get("message") if isinstance(body, dict) else None
        return ListGithubRepoContributorsResult(
            repo=params.repo,
            error=f"http_{status}:{message}" if message else f"http_{status}",
            rate_limit=rate,
        )

    contributors: list[GithubContributor] = []
    for entry in body[: params.limit or len(body)]:
        if not isinstance(entry, dict):
            continue
        login = str(entry.get("login", "")) if entry.get("login") else None
        if not login:
            continue
        contributor = GithubContributor(
            login=login,
            contributions=int(entry.get("contributions", 0)),
        )
        if params.limit:
            try:
                user_body, _, user_status = await github_get(f"users/{login}")
                if user_status < 400 and isinstance(user_body, dict):
                    contributor.company = user_body.get("company")
                    contributor.email = user_body.get("email")
                    contributor.name = user_body.get("name")
            except httpx.HTTPError:
                logger.warning(f"user enrichment failed for {login}")
        contributors.append(contributor)

    return ListGithubRepoContributorsResult(
        repo=params.repo,
        contributors=contributors,
        rate_limit=rate,
    )
