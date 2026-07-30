"""Schema-level invariants that every registered tool must satisfy.

These guard the contract clients see in ``tools/list``, independently of any
individual tool's behaviour.
"""

import inspect
from importlib import import_module
from typing import get_args
from unittest.mock import AsyncMock

import pytest
from fastmcp.tools import FunctionTool
from gg_api_core.mcp_server import (
    AbstractGitGuardianFastMCP,
    get_mcp_server,
    register_common_tools,
)
from gg_api_core.scopes import ALL_SCOPES
from gg_mcp_server.register_tools import register_tools
from pydantic import BaseModel

EXPECTED_OPTIONAL_PARAMS_TOOLS = {
    "count_incidents",
    "list_detectors",
    "list_honeytokens",
    "list_incidents",
    "list_public_incidents",
    "list_repo_occurrences",
    "list_sources",
    "list_users",
    "remediate_secret_incidents",
}


class _DownstreamBoundaryReached(BaseException):
    """Stop a tool after params normalization without being caught by its error handling."""


@pytest.fixture
def unified_server() -> AbstractGitGuardianFastMCP:
    """Build a server exposing every tool without fetching token scopes."""
    server = get_mcp_server("tool-schema-contracts")
    register_tools(server)
    register_common_tools(server)
    server._fetch_token_scopes_from_api = AsyncMock(return_value=set(ALL_SCOPES))
    return server


def _params_model(tool: FunctionTool) -> type[BaseModel] | None:
    """Return the single Pydantic params model a tool accepts, if any."""
    parameters = list(inspect.signature(tool.fn).parameters.values())
    if len(parameters) != 1:
        return None

    annotation_candidates = (parameters[0].annotation, *get_args(parameters[0].annotation))
    for annotation in annotation_candidates:
        if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
            return annotation
    return None


async def _all_optional_params_tools(
    unified_server: AbstractGitGuardianFastMCP,
) -> dict[str, tuple[FunctionTool, type[BaseModel]]]:
    """Return registered function tools whose params models have no required fields."""
    tools: dict[str, tuple[FunctionTool, type[BaseModel]]] = {}
    for tool in await unified_server.list_tools():
        if not isinstance(tool, FunctionTool):
            continue
        model = _params_model(tool)
        if model is None:
            continue
        if any(field.is_required() for field in model.model_fields.values()):
            continue
        tools[tool.name] = (tool, model)
    return tools


@pytest.mark.asyncio
async def test_tools_with_all_optional_params_accept_empty_arguments(
    unified_server: AbstractGitGuardianFastMCP,
) -> None:
    """
    GIVEN a tool whose params model has a default for every field
    WHEN a client calls it with no arguments at all
    THEN the ``params`` wrapper must not be required

    Regression test for GIM-MCP-SERVER-13: ``list_detectors`` (and eight
    siblings) declared ``params`` without a default, so Pydantic marked the
    wrapper required and ``{}`` failed validation before the tool ever ran,
    even though every filter inside it was optional.
    """
    offenders: list[str] = []
    optional_params_tools = await _all_optional_params_tools(unified_server)

    for tool, _model in optional_params_tools.values():
        if "params" in tool.parameters.get("required", []):
            offenders.append(tool.name)

    missing_tools = EXPECTED_OPTIONAL_PARAMS_TOOLS - optional_params_tools.keys()
    assert not missing_tools, f"expected all-optional tools were not checked: {sorted(missing_tools)}"
    assert not offenders, (
        "these tools have all-optional params but still require the `params` wrapper, "
        f"so calling them with {{}} raises ValidationError: {sorted(offenders)}"
    )


@pytest.mark.asyncio
async def test_optional_params_wrappers_use_plain_none_defaults(
    unified_server: AbstractGitGuardianFastMCP,
) -> None:
    """
    GIVEN a tool whose params wrapper may be omitted
    WHEN its Python signature and agent-facing JSON Schema are inspected
    THEN it must use a plain None default without publishing a concrete model
    """
    python_default_offenders: list[str] = []
    schema_default_offenders: list[str] = []
    optional_params_tools = await _all_optional_params_tools(unified_server)

    for tool, _model in optional_params_tools.values():
        params_parameter = next(iter(inspect.signature(tool.fn).parameters.values()))
        if params_parameter.default is not None:
            python_default_offenders.append(tool.name)
        params_schema = tool.parameters["properties"]["params"]
        if isinstance(params_schema.get("default"), dict):
            schema_default_offenders.append(tool.name)

    missing_tools = EXPECTED_OPTIONAL_PARAMS_TOOLS - optional_params_tools.keys()
    assert not missing_tools, f"expected all-optional tools were not checked: {sorted(missing_tools)}"
    assert not python_default_offenders, (
        "these tools do not use a plain None Python default, so direct calls may "
        f"receive a shared model or framework metadata: {sorted(python_default_offenders)}"
    )
    assert not schema_default_offenders, (
        "these tools publish a concrete params object as their schema default, "
        f"duplicating defaults in the agent contract: {sorted(schema_default_offenders)}"
    )


@pytest.mark.asyncio
async def test_omitted_params_work_through_python_and_fastmcp_calls(
    unified_server: AbstractGitGuardianFastMCP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    GIVEN each known tool whose params wrapper may be omitted
    WHEN its Python function and FastMCP tool are each called twice without params
    THEN every call must construct a distinct params model before downstream work
    """
    optional_params_tools = await _all_optional_params_tools(unified_server)
    missing_tools = EXPECTED_OPTIONAL_PARAMS_TOOLS - optional_params_tools.keys()
    assert not missing_tools, f"expected all-optional tools were not checked: {sorted(missing_tools)}"

    for tool_name in sorted(EXPECTED_OPTIONAL_PARAMS_TOOLS):
        tool, params_model = optional_params_tools[tool_name]
        tool_module = import_module(tool.fn.__module__)
        created_params: list[BaseModel] = []
        downstream_boundary = AsyncMock(side_effect=_DownstreamBoundaryReached)
        boundary_name = "list_repo_occurrences" if tool_name == "remediate_secret_incidents" else "get_client"

        def create_params() -> BaseModel:
            params = params_model()
            created_params.append(params)
            return params

        with monkeypatch.context() as tool_monkeypatch:
            tool_monkeypatch.setattr(tool_module, params_model.__name__, create_params)
            tool_monkeypatch.setattr(tool_module, boundary_name, downstream_boundary)

            for _ in range(2):
                with pytest.raises(_DownstreamBoundaryReached):
                    await tool.fn()
            for _ in range(2):
                with pytest.raises(_DownstreamBoundaryReached):
                    await tool.run({})

        assert downstream_boundary.await_count == 4, f"{tool_name} did not reach its downstream boundary every time"
        assert len(created_params) == 4, f"{tool_name} did not construct params for every omitted-params call"
        assert len({id(params) for params in created_params}) == 4, f"{tool_name} reused a params model across calls"
