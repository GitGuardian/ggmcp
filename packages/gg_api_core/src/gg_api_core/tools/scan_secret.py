import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ScanSecretsParams(BaseModel):
    """Parameters for scanning secrets."""

    documents: list[dict[str, str]] = Field(
        description="""
        List of documents to scan, each with 'document' and optional 'filename'.
        Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]
        IMPORTANT:
        - document is the content of the file, not the filename, is a string and is mandatory.
        - Do not send documents that are not related to the codebase, only send files that are part of the codebase.
        - Do not send documents that are in the .gitignore file.
        """
    )


class ScanSecretsResult(BaseModel):
    """Result from scanning secrets."""

    model_config = {"extra": "allow"}  # Allow additional fields from API

    scan_results: list[dict[str, Any]] = Field(default_factory=list, description="Scan results for each document")


async def scan_secrets(params: ScanSecretsParams) -> ScanSecretsResult:
    """
    Scan multiple content items for secrets and policy breaks.

    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.

    IMPORTANT:
    - Only send documents that are part of the codebase
    - Do not send documents that are in .gitignore
    - The 'document' field is the file content (string), not the filename

    Args:
        params: ScanSecretsParams model containing documents to scan

    Returns:
        ScanSecretsResult: Pydantic model containing:
            - scan_results: List of scan result objects for each document, including:
                - policy_break_count: Number of policy violations found
                - policies: List of policies applied
                - policy_breaks: Detailed information about each policy break/secret detected
                - Additional fields from the API response

    Raises:
        Exception: If the scan operation fails or documents are invalid
    """
    try:
        client = await get_client()

        # Validate input documents
        if not params.documents or not isinstance(params.documents, list):
            raise ValueError("Documents parameter must be a non-empty list")

        for i, doc in enumerate(params.documents):
            if not isinstance(doc, dict) or "document" not in doc:
                raise ValueError(f"Document at index {i} must be a dictionary with a 'document' field")

        # Log the scan request (without exposing the full document contents)
        safe_docs_log = []
        for doc in params.documents:
            doc_preview = (
                doc.get("document", "")[:20] + "..." if len(doc.get("document", "")) > 20 else doc.get("document", "")
            )
            safe_docs_log.append(
                {"filename": doc.get("filename", "No filename provided"), "document_preview": doc_preview}
            )

        logger.debug(f"Scanning {len(params.documents)} documents for secrets")
        logger.debug(f"Documents to scan: {safe_docs_log}")

        # Make the API call
        result = await client.multiple_scan(params.documents)
        logger.debug(f"Scanned {len(params.documents)} documents")

        # Wrap the result in Pydantic model
        if isinstance(result, list):
            return ScanSecretsResult(scan_results=result)
        elif isinstance(result, dict):
            # If API returns a dict with scan_results key
            return ScanSecretsResult(**result)
        else:
            # Fallback: wrap in scan_results
            return ScanSecretsResult(scan_results=[result])
    except Exception as e:
        logger.exception(f"Error scanning for secrets: {str(e)}")
        raise
