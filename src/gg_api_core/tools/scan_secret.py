import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ScanDocument(BaseModel):
    """One file's content to scan."""

    model_config = ConfigDict(extra="forbid")

    document: str = Field(description="The content of the file, not its name")
    filename: str | None = Field(
        default=None, max_length=256, description="The file's path or name, which helps detect some secrets"
    )


class ScanSecretsParams(BaseModel):
    """Parameters for scanning secrets."""

    documents: list[ScanDocument] = Field(
        min_length=1,
        description="The files to scan. Send only files that are part of the codebase and not ignored by .gitignore.",
    )


class ScanSecretsResult(BaseModel):
    """Result from scanning secrets."""

    model_config = {"extra": "allow"}  # Allow additional fields from API

    scan_results: list[dict[str, Any]] = Field(default_factory=list, description="Scan results for each document")


async def scan_secrets(params: ScanSecretsParams) -> ScanSecretsResult:
    """Scan multiple content items for secrets and policy breaks.

    Args:
        params: ScanSecretsParams model containing documents to scan
    """
    client = await get_client()

    # Make the API call
    result = await client.multiple_scan([document.model_dump(exclude_none=True) for document in params.documents])

    # Wrap the result in Pydantic model
    if isinstance(result, list):
        return ScanSecretsResult(scan_results=result)
    elif isinstance(result, dict):
        # If API returns a dict with scan_results key
        return ScanSecretsResult(**result)
    else:
        # Fallback: wrap in scan_results
        return ScanSecretsResult(scan_results=[result])
