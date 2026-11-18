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
WRITE_VERBS = {"add", "assign", "edit", "generate", "ignore", "remove", "reopen", "resolve", "unassign"}
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
PAGE_ARGUMENTS = {"page", "per_page", "page_size", "cursor", "get_all"}
# The first part of the server instructions that clients are sure to show the model.
INSTRUCTIONS_HEAD = 512

# Tools that still break a rule. Remove a tool once it follows the rule.
# Identifiers the API defines as strings rather than numbers.
OPAQUE_IDS = {"external_id": None, "ignorer_api_token_id": "uuid", "resolver_api_token_id": "uuid"}
# Arguments that hold numeric IDs without ending in _id.
ID_ARGUMENTS = {"source_ids", "teams", "secret_manager_instance", "similar_to"}
# The internal incident filters take assignee_id 0 to mean unassigned.
ZERO_ALLOWED_IDS = {("list_internal_incidents", "assignee_id"), ("count_internal_incidents", "assignee_id")}


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
        THEN it is snake_case and starts with a read or write verb
        """
        assert all(re.fullmatch(r"[a-z]+(_[a-z]+)+", name) for name in catalog)
        assert [name for name in catalog if name.split("_", 1)[0] not in READ_VERBS | WRITE_VERBS] == []


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
        THEN none accepts fields it does not declare
        """
        loose = {
            name
            for name, tool in catalog.items()
            for obj in _objects(tool["inputSchema"], tool["inputSchema"].get("$defs", {}))
            if obj.get("additionalProperties") is not False
        }
        assert loose == set()

    async def test_numeric_ids_are_positive_integers(self, catalog):
        """
        GIVEN every argument that holds a numeric ID, alone or in a list
        WHEN its schema is read
        THEN it is an integer of at least 1, or of at least 0 where 0 means unassigned
        """
        loose = []
        for name, tool in catalog.items():
            for field, schema in tool["inputSchema"].get("properties", {}).items():
                if field in OPAQUE_IDS or not (field.endswith("_id") or field in ID_ARGUMENTS):
                    continue
                (value,) = _integer_types(schema)
                value = value.get("items", value)
                lowest = 0 if (name, field) in ZERO_ALLOWED_IDS else 1
                if value.get("type") != "integer" or value.get("minimum") != lowest:
                    loose.append(f"{name}.{field}")
        assert loose == []

    async def test_opaque_ids_are_strings_of_their_format(self, catalog):
        """
        GIVEN every argument that holds an identifier the API defines as a string
        WHEN its schema is read
        THEN it is a string, with the uuid format where the API uses UUIDs
        """
        for tool in catalog.values():
            for field, schema in tool["inputSchema"].get("properties", {}).items():
                if field in OPAQUE_IDS:
                    (value,) = _integer_types(schema)
                    assert value["type"] == "string", field
                    assert value.get("format") == OPAQUE_IDS[field], field

    async def test_paginated_tools_take_page_size_cursor_and_get_all(self, catalog):
        """
        GIVEN the tools that return pages
        WHEN their arguments are read
        THEN each takes page_size, cursor and get_all, and none takes page or per_page
        """
        paginated = [name for name, tool in catalog.items() if PAGE_ARGUMENTS & set(tool["inputSchema"]["properties"])]
        assert paginated
        for name in paginated:
            arguments = set(catalog[name]["inputSchema"]["properties"])
            assert {"page_size", "cursor", "get_all"} <= arguments, name
            assert not {"page", "per_page"} & arguments, name

    async def test_paginated_tools_say_how_to_continue(self, catalog):
        """
        GIVEN the tools that return pages
        WHEN their output schemas are read
        THEN each result carries page_size, has_more, stop_reason and next_arguments
        """
        paginated = [name for name, tool in catalog.items() if PAGE_ARGUMENTS & set(tool["inputSchema"]["properties"])]
        for name in paginated:
            outputs = set(catalog[name]["outputSchema"]["properties"])
            assert {"page_size", "has_more", "stop_reason", "next_arguments"} <= outputs, name


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
        THEN none wraps the output in a generic result key
        """
        assert [name for name, tool in catalog.items() if tool["outputSchema"].get("x-fastmcp-wrap-result")] == []

    async def test_outputs_name_their_fields(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each output schema is read
        THEN it declares its fields
        """
        assert [name for name, tool in catalog.items() if not tool["outputSchema"].get("properties")] == []


class TestAnnotations:
    async def test_every_hint_is_set(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's annotations are read
        THEN all four hints are set explicitly
        """
        assert [name for name, tool in catalog.items() if set(HINTS) - set(tool.get("annotations") or {})] == []

    async def test_read_only_matches_the_verb(self, catalog):
        """
        GIVEN the full tool catalog
        WHEN each tool's read-only hint is read
        THEN tools named with a read verb are read-only and the others are not
        """
        mismatched = [
            name
            for name, tool in catalog.items()
            if tool.get("annotations", {}).get("readOnlyHint") != (name.split("_", 1)[0] in READ_VERBS)
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

    async def test_the_instructions_open_with_the_internal_public_split(self, mcp_client, mock_token_scopes):
        """
        GIVEN the server instructions
        WHEN their first 512 characters are read
        THEN they name both incident kinds and the tool that tells them apart, so a client that shows only the
             start still gives the model the split
        """
        initialize = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "catalog-contract", "version": "1"},
        }
        head = rpc_result(await rpc(mcp_client, "initialize", initialize))["instructions"][:INSTRUCTIONS_HEAD]
        assert "internal" in head.lower() and "public" in head.lower()
        assert "get_gitguardian_resource" in head
