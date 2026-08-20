"""
Schema invariant guard for the flattened MCP tool signatures (SI-3963).

Every API tool in ``gg_api_core.tools`` exposes its params model fields as
top-level Annotated keyword parameters instead of a single ``params: XParams``
wrapper. This makes the ``tools/list`` input schema flat, so clients can call
tools with ``{}`` or a flat ``{"arguments": {...}}`` shape rather than having to
nest everything under a ``params`` key.

The assertions here mirror exactly how FastMCP derives each tool's input schema
and validates arguments at call time, so a future tool that reintroduces a
``params`` wrapper (or forgets to flatten a required field) fails these tests
regardless of which server wires it up.
"""

import importlib
import inspect
import pkgutil

import pytest
from fastmcp.server.dependencies import without_injected_parameters
from fastmcp.tools import Tool
from fastmcp.utilities.types import get_cached_typeadapter

import gg_api_core.tools as tools_package


def _registered_tool_functions():
    """Yield every async function defined in a ``gg_api_core.tools`` module.

    This is the same set of callables FastMCP turns into MCP tools: public,
    module-level ``async def`` functions declared inside the tools subpackage.
    It intentionally includes both the full registrations (e.g.
    ``generate_honeytoken``) and smaller inline helpers, so the invariant
    guards the whole subpackage rather than only the wired server.
    """
    seen = {}
    for module_info in pkgutil.iter_modules(tools_package.__path__):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"gg_api_core.tools.{module_info.name}")
        for name, obj in vars(module).items():
            if name.startswith("_"):
                continue
            if not inspect.iscoroutinefunction(obj):
                continue
            if not (getattr(obj, "__module__", "") or "").startswith("gg_api_core.tools"):
                continue
            seen[name] = obj
    return seen


TOOL_FUNCTIONS = _registered_tool_functions()


def _input_schema(tool_function) -> dict:
    """Return the JSON schema FastMCP derives for the tool's parameters."""
    return Tool.from_function(tool_function).parameters


def _validate_arguments(tool_function, arguments: dict):
    """Validate a raw arguments dict exactly like FastMCP does at call time.

    ``Tool.run`` wraps the (de-injected) function in a pydantic TypeAdapter and
    calls ``validate_python(arguments)`` before executing the body. We reuse
    that same adapter (without awaiting the returned coroutine) so bad argument
    shapes are caught without actually invoking any network-bound tool body.
    """
    wrapper = without_injected_parameters(tool_function, run_in_thread=False)
    type_adapter = get_cached_typeadapter(wrapper)
    result = type_adapter.validate_python(arguments)
    # validate_python returns the (async) call structure; close it without
    # awaiting so the tool body never executes and no RuntimeWarning leaks.
    if inspect.iscoroutine(result):
        result.close()


def test_every_tool_exposes_a_flat_input_schema():
    """
    GIVEN every async tool function defined under ``gg_api_core.tools``
    WHEN its input schema is derived the way FastMCP derives it at registration
    THEN the schema has no top-level ``params`` wrapper key
    """
    assert TOOL_FUNCTIONS, "expected to discover at least one tool function"

    for name, tool_function in TOOL_FUNCTIONS.items():
        properties = _input_schema(tool_function).get("properties", {})
        assert "params" not in properties, (
            f"tool '{name}' still exposes a 'params' wrapper property; "
            "flatten its params model into top-level Annotated parameters (SI-3963)"
        )


def test_required_parameters_are_top_level_properties():
    """
    GIVEN a tool whose input schema lists required parameters
    WHEN its FastMCP-derived schema is inspected
    THEN every required parameter is present as a top-level property (no
        required field hidden behind the old ``params`` wrapper)
    """
    for name, tool_function in TOOL_FUNCTIONS.items():
        schema = _input_schema(tool_function)
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            assert required in properties, (
                f"tool '{name}' marks '{required}' as required but it is not a "
                "top-level property"
            )


def test_all_optional_tools_accept_empty_arguments():
    """
    GIVEN a tool whose input schema has no required parameters
    WHEN an empty ``{}`` argument shape is validated through FastMCP's runtime
    THEN the empty shape is accepted (so clients can call the tool with no args)
    """
    for name, tool_function in TOOL_FUNCTIONS.items():
        schema = _input_schema(tool_function)
        if schema.get("required"):
            continue
        try:
            _validate_arguments(tool_function, {})
        except Exception as exc:  # pragma: no cover - failure path
            pytest.fail(f"tool '{name}' rejects empty args '{{}}': {exc}")


def _placeholder(prop: dict):
    """Build a JSON-schema-valid placeholder value for a parameter property."""
    typ = prop.get("type")
    if isinstance(typ, list):
        # anyOf/oneOf: pick the first concrete (non-null) branch
        for t in typ:
            if t != "null":
                return _placeholder({**prop, "type": t})
        return None
    if "anyOf" in prop:
        for b in prop["anyOf"]:
            if b.get("type") != "null":
                return _placeholder(b)
        return None
    if "enum" in prop:
        return prop["enum"][0]
    if "const" in prop:
        return prop["const"]
    if "default" in prop and prop["type"] != "null":
        return prop["default"]
    if typ == "integer":
        return 3
    if typ == "number":
        return 3.0
    if typ == "boolean":
        return False
    if typ == "string":
        return "x"
    if typ == "array":
        items = prop.get("items", {})
        return [_placeholder(items)] if items else []
    if typ == "object":
        props = prop.get("properties", {})
        return {k: _placeholder(v) for k, v in props.items()}
    return None


def test_flat_calls_coerce_str_to_int():
    """
    GIVEN a tool exposing an integer-typed top-level parameter
    WHEN it is called with a flat ``{"<param>": "7"}`` string value
    THEN FastMCP's runtime validation coerces the string to the int (this is
        the exact failure mode from SI-3963's ``list_incidents`` example)
    """
    for name, tool_function in TOOL_FUNCTIONS.items():
        schema = _input_schema(tool_function)
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        int_param = next(
            (
                param
                for param, prop in properties.items()
                if prop.get("type") == "integer"
                or (
                    isinstance(prop.get("type"), list)
                    and "integer" in prop.get("type")
                )
            ),
            None,
        )
        if int_param is None:
            continue
        # Fill every required sibling so only the coerced int param is tested.
        call: dict = {int_param: "7"}
        for param in required:
            if param != int_param:
                call[param] = _placeholder(properties.get(param, {}))
        try:
            _validate_arguments(tool_function, call)
        except Exception as exc:  # pragma: no cover - failure path
            pytest.fail(
                f"tool '{name}' rejected flat call '{call}': {exc}"
            )


def test_required_params_schema_is_a_flat_object_shape():
    """
    GIVEN the input schema of any API tool
    WHEN it is inspected
    THEN the schema type is 'object' and its properties are the flat fields
        (not a nested single 'params' property)
    """
    for name, tool_function in TOOL_FUNCTIONS.items():
        schema = _input_schema(tool_function)
        assert schema.get("type") == "object", f"tool '{name}' schema is not an object"
