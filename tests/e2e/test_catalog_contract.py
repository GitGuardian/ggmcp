"""Catalog-wide contract rules every tool follows.

Each rule checks the whole tools/list answer, so a new tool is held to it without a
test of its own. Where tools still break a rule, the rule names them: the test fails
when the list grows, and also when a tool is fixed without being removed from it, so
the list only shrinks.
"""

import re
from typing import Any

import pytest

from tests.e2e.harness import rpc, rpc_result

READ_VERBS = {"count", "get", "list", "scan"}
WRITE_VERBS = {"add", "assign", "edit", "generate", "update"}
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
# The first part of the server instructions that clients are sure to show the model.
INSTRUCTIONS_HEAD = 512

# Tools that still break a rule. Remove a tool once it follows the rule.
VAGUE_VERB = {"manage_incident_comment", "manage_private_incident", "manage_public_incident"}
LOOSE_NESTED_OBJECTS = {"scan_secrets"}
WRAPPED_OUTPUT = {
    "count_incidents",
    "list_incidents",
    "list_public_incidents",
    "list_public_occurrences",
    "list_repo_occurrences",
}
UNDOCUMENTED_OUTPUT = {"manage_incident_comment", "manage_private_incident", "manage_public_incident"}
MISSING_HINTS = {
    "count_incidents",
    "get_gitguardian_resource",
    "get_incident",
    "get_my_identity",
    "get_public_incident",
    "get_remediation_workflow",
    "list_incidents",
    "list_public_incidents",
    "list_public_occurrences",
    "list_repo_occurrences",
    "list_sources",
    "scan_secrets",
}
OTHER_PAGE_ARGUMENTS = {
    "list_incidents",
    "list_public_incidents",
    "list_public_occurrences",
    "list_repo_occurrences",
    "list_sources",
}
LOOSE_INCIDENT_ID = {
    "assign_incident",
    "get_incident",
    "get_public_incident",
    "list_public_occurrences",
    "manage_incident_comment",
    "manage_private_incident",
    "manage_public_incident",
}


@pytest.fixture
async def catalog(mcp_client, mock_token_scopes) -> dict[str, dict[str, Any]]:
    tools = rpc_result(await rpc(mcp_client, "tools/list", {}))["tools"]
    return {tool["name"]: tool for tool in tools}


def _objects(schema: dict[str, Any], defs: dict[str, Any]):
    """Every object schema inside schema, following $ref, anyOf and array items."""
    if "$ref" in schema:
        schema = defs[schema["$ref"].rsplit("/", 1)[-1]]
    if schema.get("type") == "object":
        yield schema
        for value in schema.get("properties", {}).values():
            yield from _objects(value, defs)
        if isinstance(schema.get("additionalProperties"), dict):
            yield from _objects(schema["additionalProperties"], defs)
    for option in schema.get("anyOf", []):
        yield from _objects(option, defs)
    if "items" in schema:
        yield from _objects(schema["items"], defs)


def _integer_types(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """The non-null alternatives of a property schema."""
    options = schema.get("anyOf", [schema])
    return [option for option in options if option.get("type") != "null"]


class TestNames:
    async def test_tool_names_are_snake_case_and_start_with_a_known_verb(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each name is read
        THEN it is snake_case and starts with a read or write verb, except the tools still listed in VAGUE_VERB
        """
        assert all(re.fullmatch(r"[a-z]+(_[a-z]+)+", name) for name in catalog)
        vague = {name for name in catalog if name.split("_", 1)[0] not in READ_VERBS | WRITE_VERBS}
        assert vague == VAGUE_VERB


class TestArguments:
    async def test_every_argument_is_described(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each input property is read
        THEN it carries a non-empty description
        """
        undescribed = [
            f"{name}.{field}"
            for name, tool in catalog.items()
            for field, schema in tool["inputSchema"].get("properties", {}).items()
            if not schema.get("description", "").strip()
        ]
        assert undescribed == []

    async def test_unknown_fields_are_refused_at_every_level(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN every object in each input schema is read, nested ones included
        THEN none accepts fields it does not declare, except the tools still listed in LOOSE_NESTED_OBJECTS
        """
        loose = {
            name
            for name, tool in catalog.items()
            for obj in _objects(tool["inputSchema"], tool["inputSchema"].get("$defs", {}))
            if obj.get("additionalProperties") is not False
        }
        assert loose == LOOSE_NESTED_OBJECTS

    async def test_incident_ids_are_positive_integers(self, catalog):
        """
        GIVEN the tools that take an incident_id
        WHEN its schema is read
        THEN it is an integer of at least 1, except the tools still listed in LOOSE_INCIDENT_ID
        """
        loose = set()
        for name, tool in catalog.items():
            schema = tool["inputSchema"].get("properties", {}).get("incident_id")
            if schema is None:
                continue
            types = _integer_types(schema)
            if len(types) != 1 or types[0].get("type") != "integer" or types[0].get("minimum", 0) < 1:
                loose.add(name)
        assert loose == LOOSE_INCIDENT_ID

    async def test_paginated_tools_take_page_size_and_cursor(self, catalog):
        """
        GIVEN the tools that return pages
        WHEN their arguments are read
        THEN they take page_size and cursor, except the tools still listed in OTHER_PAGE_ARGUMENTS
        """
        paginated = {
            name
            for name, tool in catalog.items()
            if {"page", "per_page", "page_size", "cursor"} & set(tool["inputSchema"].get("properties", {}))
        }
        other = {
            name
            for name in paginated
            if not {"page_size", "cursor"} <= set(catalog[name]["inputSchema"]["properties"])
            or {"page", "per_page"} & set(catalog[name]["inputSchema"]["properties"])
        }
        assert other == OTHER_PAGE_ARGUMENTS


class TestOutputs:
    async def test_every_tool_declares_an_object_output_schema(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's output schema is read
        THEN every tool has one, and it is an object
        """
        assert [name for name, tool in catalog.items() if tool.get("outputSchema", {}).get("type") != "object"] == []

    async def test_outputs_are_not_wrapped_in_a_result_key(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each output schema is read
        THEN none wraps the output in a generic result key, except the tools still listed in WRAPPED_OUTPUT
        """
        wrapped = {name for name, tool in catalog.items() if tool["outputSchema"].get("x-fastmcp-wrap-result")}
        assert wrapped == WRAPPED_OUTPUT

    async def test_outputs_name_their_fields(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each output schema is read
        THEN it declares its fields, except the tools still listed in UNDOCUMENTED_OUTPUT
        """
        undocumented = {name for name, tool in catalog.items() if not tool["outputSchema"].get("properties")}
        assert undocumented == UNDOCUMENTED_OUTPUT


class TestAnnotations:
    async def test_every_hint_is_set(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's annotations are read
        THEN all four hints are set explicitly, except the tools still listed in MISSING_HINTS
        """
        missing = {
            name for name, tool in catalog.items() if any(hint not in tool.get("annotations", {}) for hint in HINTS)
        }
        assert missing == MISSING_HINTS

    async def test_read_only_matches_the_verb(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's read-only hint is read
        THEN tools named with a read verb are read-only and the others are not
        """
        mismatched = [
            name
            for name, tool in catalog.items()
            if name not in VAGUE_VERB
            and tool.get("annotations", {}).get("readOnlyHint") != (name.split("_", 1)[0] in READ_VERBS)
        ]
        assert mismatched == []


class TestDescriptions:
    async def test_every_tool_is_described(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's description is read
        THEN it is not empty
        """
        assert [name for name, tool in catalog.items() if not tool.get("description", "").strip()] == []

    @pytest.mark.xfail(strict=True, reason="The instructions open with general text; the incident split comes later")
    async def test_the_instructions_open_with_the_internal_public_split(self, mcp_client, mock_token_scopes):
        """
        GIVEN the server instructions
        WHEN their first 512 characters are read
        THEN they name both incident kinds, so a client that shows only the start still gives the model the split
        """
        initialize = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "catalog-contract", "version": "1"},
        }
        head = rpc_result(await rpc(mcp_client, "initialize", initialize))["instructions"][:INSTRUCTIONS_HEAD]
        assert "internal" in head.lower() and "public" in head.lower()
