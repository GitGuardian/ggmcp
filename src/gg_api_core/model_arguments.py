"""Tools whose MCP arguments are the fields of one pydantic model.

Each tool function takes a single pydantic model. Registered as is, FastMCP
exposes that model as one required ``params`` argument holding an object, while
clients send the fields at the top level, as with any other MCP server. A
:class:`ModelArgumentsTool` advertises the model's fields as the tool's
top-level arguments and validates them with the model itself, so its defaults,
before-validators and model validators apply exactly as they do on any input.
"""

import inspect
import logging
from typing import Any, get_type_hints

from fastmcp.exceptions import ValidationError
from fastmcp.tools import FunctionTool, ToolResult
from fastmcp.utilities.json_schema import compress_schema
from pydantic import BaseModel, Field
from pydantic import ValidationError as PydanticValidationError
from typing_extensions import override


class ToolBodyError(Exception):
    """A pydantic error raised by a tool's own code, not by its arguments."""


def _describe_invalid_arguments(tool_name: str, error: PydanticValidationError) -> str:
    """Name each rejected argument and why, without the model's class name or the input values."""
    problems = []
    for problem in error.errors(include_url=False, include_input=False):
        location = ".".join(str(part) for part in problem["loc"])
        problems.append(f"{location}: {problem['msg']}" if location else problem["msg"])
    return f"Invalid arguments for tool '{tool_name}': " + "; ".join(problems)


def arguments_model(fn: Any) -> type[BaseModel] | None:
    """The pydantic model ``fn`` takes as its only parameter, or None."""
    parameters = list(inspect.signature(fn).parameters.values())
    if len(parameters) != 1:
        return None
    hint = get_type_hints(fn).get(parameters[0].name)
    return hint if isinstance(hint, type) and issubclass(hint, BaseModel) else None


def model_input_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The model's JSON schema as a tool input schema: its fields are the top-level properties."""
    schema = model.model_json_schema()
    schema.pop("title", None)
    schema.pop("description", None)
    # Unknown arguments are refused, as FastMCP refuses them for any function tool.
    schema["additionalProperties"] = False
    return compress_schema(schema, prune_titles=True)


class ModelArgumentsTool(FunctionTool):
    """A function tool whose arguments are the fields of the model its function takes."""

    arguments_model: type[BaseModel] = Field(exclude=True)

    @classmethod
    def from_function_tool(cls, tool: FunctionTool, model: type[BaseModel]) -> "ModelArgumentsTool":
        fields = {name: getattr(tool, name) for name in FunctionTool.model_fields}
        fields["parameters"] = model_input_schema(model)
        return cls(**fields, arguments_model=model)

    @override
    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        # The model ignores unknown fields, which would let a call in an old or guessed
        # shape run with default arguments. Refuse them instead.
        unknown = sorted(set(arguments) - set(self.arguments_model.model_fields))
        if unknown:
            hint = " Arguments go at the top level, not inside a 'params' object." if "params" in unknown else ""
            raise ValidationError(
                f"Unknown argument(s) for tool '{self.name}': {', '.join(unknown)}.{hint}",
                log_level=logging.WARNING,
            )
        try:
            params = self.arguments_model.model_validate(arguments)
        except PydanticValidationError as e:
            # A bad call, reported the way FastMCP reports invalid tool arguments.
            raise ValidationError(_describe_invalid_arguments(self.name, e), log_level=logging.WARNING) from e
        try:
            result = await self.fn(params)
        except PydanticValidationError as e:
            raise ToolBodyError(str(e)) from e
        return self.convert_result(result)
