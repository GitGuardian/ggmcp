"""Fetch GitHub repo + owner metadata."""

import logging
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from ._common import github_get

logger = logging.getLogger(__name__)


class GetGithubRepoMetadataParams(BaseModel):
    """Parameters for ``get_github_repo_metadata``."""

    repo: str = Field(description="Repository in ``owner/name`` form.")


class GetGithubRepoMetadataResult(BaseModel):
    repo: str
    description: str | None = None
    homepage: str | None = None
    owner_type: Literal["User", "Organization", "unknown"] = "unknown"
    owner_login: str | None = None
    owner_company: str | None = None
    stars: int = 0
    fork: bool = False
    archived: bool = False
    topics: list[str] = Field(default_factory=list)
    default_branch: str | None = None
    license: str | None = None
    created_at: str | None = None
    pushed_at: str | None = None
    rate_limit: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


async def get_github_repo_metadata(params: GetGithubRepoMetadataParams) -> GetGithubRepoMetadataResult:
    """Fetch repo and owner metadata from GitHub.

    The owner's ``company`` field and the repo ``description`` / ``homepage``
    are direct ownership signals. For Organization-owned repos, this tool
    also fetches ``/orgs/{owner}`` to surface the ``company`` field.

    Args:
        params: ``GetGithubRepoMetadataParams``.

    Returns:
        ``GetGithubRepoMetadataResult`` populated best-effort; ``error`` set
        only if the repo lookup itself failed.
    """
    logger.debug(f"get_github_repo_metadata repo={params.repo}")

    try:
        body, rate, status = await github_get(f"repos/{params.repo}")
    except httpx.HTTPError as exc:
        return GetGithubRepoMetadataResult(repo=params.repo, error=f"http_error:{exc.__class__.__name__}")

    if status >= 400 or not isinstance(body, dict):
        message = body.get("message") if isinstance(body, dict) else None
        return GetGithubRepoMetadataResult(
            repo=params.repo,
            error=f"http_{status}:{message}" if message else f"http_{status}",
            rate_limit=rate,
        )

    owner = body.get("owner") or {}
    owner_type_raw = owner.get("type")
    owner_type: Literal["User", "Organization", "unknown"]
    if owner_type_raw in ("User", "Organization"):
        owner_type = owner_type_raw
    else:
        owner_type = "unknown"
    owner_login = owner.get("login")

    owner_company: str | None = None
    if owner_type == "Organization" and owner_login:
        try:
            org_body, _, org_status = await github_get(f"orgs/{owner_login}")
            if org_status < 400 and isinstance(org_body, dict):
                owner_company = org_body.get("company") or org_body.get("description")
        except httpx.HTTPError:
            logger.warning(f"org metadata fetch failed for {owner_login}")

    license_obj = body.get("license") or {}
    license_name = license_obj.get("spdx_id") or license_obj.get("name") if isinstance(license_obj, dict) else None

    return GetGithubRepoMetadataResult(
        repo=params.repo,
        description=body.get("description"),
        homepage=body.get("homepage"),
        owner_type=owner_type,
        owner_login=owner_login,
        owner_company=owner_company,
        stars=int(body.get("stargazers_count", 0)),
        fork=bool(body.get("fork", False)),
        archived=bool(body.get("archived", False)),
        topics=list(body.get("topics") or []),
        default_branch=body.get("default_branch"),
        license=license_name,
        created_at=body.get("created_at"),
        pushed_at=body.get("pushed_at"),
        rate_limit=rate,
    )
