from pydantic import BaseModel, Field
import logging

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


async def scan_secrets(params: ScanSecretsParams):
    """
    Scan multiple content items for secrets and policy breaks.

    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.

    Args:
        params: ScanSecretsParams model containing documents to scan

    Returns:
        Scan results for all documents, including any detected secrets or policy breaks
    """
    try:
        client = get_client()

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

        return result
    except Exception as e:
        logger.error(f"Error scanning for secrets: {str(e)}")
        raise