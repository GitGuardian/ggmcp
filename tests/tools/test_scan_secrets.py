from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from gg_api_core.tools.scan_secret import ScanSecretsParams, scan_secrets


class TestScanSecrets:
    """Tests for the scan_secrets tool."""

    @pytest.mark.asyncio
    async def test_scan_secrets_without_filename(self, mock_gitguardian_client):
        """
        GIVEN: A document without a filename
        WHEN: Scanning the document
        THEN: The scan completes successfully
        """
        # Mock the client response
        mock_response = [{"policy_break_count": 0, "policies": [], "policy_breaks": []}]
        mock_gitguardian_client.multiple_scan = AsyncMock(return_value=mock_response)

        # Call the function without filename
        documents = [{"document": "print('test')"}]
        await scan_secrets(ScanSecretsParams(documents=documents))

        # Verify client was called
        mock_gitguardian_client.multiple_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_secrets_invalid_document_format(self, mock_gitguardian_client):
        """
        GIVEN: A document with invalid format
        WHEN: Attempting to scan
        THEN: A ValueError is raised
        """
        # Call the function with invalid document format
        with pytest.raises(ValueError) as excinfo:
            await scan_secrets(ScanSecretsParams(documents=[{"invalid_key": "value"}]))

        # Verify error message
        assert "must be a dictionary with a 'document' field" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_scan_secrets_not_a_list(self, mock_gitguardian_client):
        """
        GIVEN: Documents parameter is not a list
        WHEN: Attempting to scan
        THEN: A ValidationError is raised
        """
        # Call the function with non-list parameter
        with pytest.raises(ValidationError) as excinfo:
            ScanSecretsParams(documents={"document": "test"})

        # Verify error message contains validation error
        assert "list" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_scan_secrets_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Attempting to scan documents
        THEN: The exception is propagated
        """
        # Mock the client to raise an exception
        error_message = "API error"
        mock_gitguardian_client.multiple_scan = AsyncMock(side_effect=Exception(error_message))

        # Call the function and expect an error
        with pytest.raises(Exception) as excinfo:
            await scan_secrets(ScanSecretsParams(documents=[{"document": "test", "filename": "test.txt"}]))

        # Verify error message
        assert error_message in str(excinfo.value)
