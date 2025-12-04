"""Utility functions for MCP tool schema manipulation."""

import json
import logging

import jsonref

logger = logging.getLogger(__name__)


def compress_pydantic_model_schema(tool_parameters: dict) -> dict:
    """
    Compress a tool schema by flattening nested Pydantic model parameters.
    When FastMCP tools use a single Pydantic model as a parameter (e.g., `params: MyParamsModel`),
    the generated schema nests all the model's fields under that parameter name. This creates
    an extra level of nesting that some MCP clients (like Claude Code) handle incorrectly.
    This function flattens the schema by:
    1. Resolving all JSON references
    2. Extracting the properties from the nested model
    3. Promoting them to top-level parameters
    Example:
        Before compression:
        {
            "type": "object",
            "properties": {
                "params": {
                    "type": "object",
                    "properties": {
                        "source_id": {"type": "integer"},
                        "get_all": {"type": "boolean"}
                    }
                }
            }
        }
        After compression:
        {
            "type": "object",
            "properties": {
                "source_id": {"type": "integer"},
                "get_all": {"type": "boolean"}
            }
        }
    Args:
        tool_parameters: The tool's parameters schema (from tool.parameters)
    Returns:
        Compressed schema with flattened parameters
    """
    try:
        # Resolve all JSON references
        resolved = jsonref.replace_refs(tool_parameters)

        # Convert back to plain dict (jsonref returns a special JsonRef object)
        compressed = json.loads(jsonref.dumps(resolved))

        logger.debug(f"Compressed tool schema: {json.dumps(compressed, indent=2)}")
        return compressed
    except Exception as e:
        logger.exception(f"Failed to compress schema: {str(e)}")
        # Return original schema if compression fails
        return tool_parameters
