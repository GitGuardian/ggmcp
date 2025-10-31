from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.scan_secret import ScanSecretsParams, scan_secrets
from pydantic import ValidationError


class TestScanSecrets:
    """Tests for the scan_secrets tool."""

    @pytest.mark.asyncio
    async def test_scan_secrets_success(self, mock_gitguardian_client):
        """
        GIVEN: A document containing a secret
        WHEN: Scanning the document for secrets
        THEN: The API returns detected policy breaks
        """
        # Mock the client response
        mock_response = [
            {
                "policy_break_count": 1,
                "policies": ["File extensions", "Secrets detection"],
                "policy_breaks": [
                    {
                        "type": "AWS Access Key",
                        "policy": "Secrets detection",
                        "matches": [
                            {
                                "type": "apikey",
                                "match": "AKIAIOSFODNN7EXAMPLE",
                                "line_start": 5,
                                "line_end": 5,
                            }
                        ],
                    }
                ],
            }
        ]
        mock_gitguardian_client.multiple_scan = AsyncMock(return_value=mock_response)

        # Call the function
        documents = [{"document": "API_KEY=AKIAIOSFODNN7EXAMPLE", "filename": "test.env"}]
        result = await scan_secrets(ScanSecretsParams(documents=documents))

        # Verify client was called with correct parameters
        mock_gitguardian_client.multiple_scan.assert_called_once_with(documents)

        # Verify response
        assert result.scan_results == mock_response
        assert result.scan_results[0]["policy_break_count"] == 1

    @pytest.mark.asyncio
    async def test_scan_secrets_no_secrets_found(self, mock_gitguardian_client):
        """
        GIVEN: A document with no secrets
        WHEN: Scanning the document for secrets
        THEN: The API returns no policy breaks
        """
        # Mock the client response with no policy breaks
        mock_response = [
            {
                "policy_break_count": 0,
                "policies": ["File extensions", "Secrets detection"],
                "policy_breaks": [],
            }
        ]
        mock_gitguardian_client.multiple_scan = AsyncMock(return_value=mock_response)

        # Call the function
        documents = [{"document": "print('Hello, World!')", "filename": "test.py"}]
        result = await scan_secrets(ScanSecretsParams(documents=documents))

        # Verify response
        assert result.scan_results[0]["policy_break_count"] == 0
        assert len(result.scan_results[0]["policy_breaks"]) == 0

    @pytest.mark.asyncio
    async def test_scan_secrets_multiple_documents(self, mock_gitguardian_client):
        """
        GIVEN: Multiple documents to scan
        WHEN: Scanning all documents at once
        THEN: The API returns results for each document
        """
        # Mock the client response
        mock_response = [
            {"policy_break_count": 1, "policies": [], "policy_breaks": []},
            {"policy_break_count": 0, "policies": [], "policy_breaks": []},
        ]
        mock_gitguardian_client.multiple_scan = AsyncMock(return_value=mock_response)

        # Call the function with multiple documents
        documents = [
            {"document": "secret_key = 'abc123'", "filename": "config1.py"},
            {"document": "print('test')", "filename": "test.py"},
        ]
        result = await scan_secrets(ScanSecretsParams(documents=documents))

        # Verify response
        assert len(result.scan_results) == 2

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
    async def test_scan_secrets_empty_list(self, mock_gitguardian_client):
        """
        GIVEN: An empty documents list
        WHEN: Attempting to scan
        THEN: A ValueError is raised
        """
        # Call the function with empty list and expect an error
        with pytest.raises(ValueError) as excinfo:
            await scan_secrets(ScanSecretsParams(documents=[]))

        # Verify error message
        assert "must be a non-empty list" in str(excinfo.value)

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
