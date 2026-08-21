"""Conformance guard: a flattened tool signature must match its params model.

Flattening restates each params model field as a top-level ``Annotated``
parameter, so the field definition now lives in two places. The model is the
source of truth: it is what the tool body constructs, what carries the
cross-field validators, and what the generated filter vocabularies feed. When
the signature drifts from it the tool still imports and still passes its own
tests, but it advertises a contract the body will reject.

Every failure seen while stacking this branch on the generated vocabularies was
one of the three checks below: a parameter naming a type the module no longer
imported, a default the model rejects (``severity=[10, 20, 30, 100]`` against a
names-only Literal), and a parameter typed ``list[str]`` while the model
accepted a Literal.
"""

import importlib
import inspect
import pkgutil
import typing

import gg_api_core.tools as tools_package
import pytest
from pydantic import BaseModel


def _tool_and_model_pairs():
    """Yield ``(tool_name, function, params_model)`` for every flattened tool.

    A tool is paired with the ``*Params`` model in its own module whose name is
    the PascalCase form of the function name. Tools without such a model (they
    take no model, or compose several) are skipped rather than guessed at.
    """
    for module_info in pkgutil.iter_modules(tools_package.__path__):
        module = importlib.import_module(f"gg_api_core.tools.{module_info.name}")
        for name, obj in vars(module).items():
            if name.startswith("_") or not inspect.iscoroutinefunction(obj):
                continue
            if obj.__module__ != module.__name__:
                continue
            expected = "".join(part.title() for part in name.split("_")) + "Params"
            model = getattr(module, expected, None)
            if isinstance(model, type) and issubclass(model, BaseModel):
                yield pytest.param(name, obj, model, id=name)


PAIRS = list(_tool_and_model_pairs())


def test_pairs_were_discovered():
    """A silent zero-pair discovery would make every check below vacuous."""
    assert len(PAIRS) >= 20


@pytest.mark.parametrize(("name", "function", "model"), PAIRS)
def test_signature_exposes_exactly_the_model_fields(name, function, model):
    """
    GIVEN a flattened tool and its params model
    WHEN their field names are compared
    THEN the signature exposes exactly the model's fields
    """
    signature_params = set(inspect.signature(function).parameters)

    assert signature_params == set(model.model_fields)


@pytest.mark.parametrize(("name", "function", "model"), PAIRS)
def test_signature_defaults_match_the_model_defaults(name, function, model):
    """
    GIVEN a flattened tool parameter carrying a default
    WHEN it is compared with the matching model field default
    THEN they are equal

    A signature default the model rejects breaks every call that relies on it,
    which is how `severity=[10, 20, 30, 100]` reached a names-only Literal.
    """
    for field, parameter in inspect.signature(function).parameters.items():
        if parameter.default is inspect.Parameter.empty:
            continue
        expected = model.model_fields[field].get_default(call_default_factory=True)
        assert parameter.default == expected, f"{name}.{field} default drifted from the model"


@pytest.mark.parametrize(("name", "function", "model"), PAIRS)
def test_required_fields_agree(name, function, model):
    """
    GIVEN a model field with no default
    WHEN the signature is inspected
    THEN that parameter is required there too, so the schema marks it required
    """
    signature = inspect.signature(function)

    for field, info in model.model_fields.items():
        if info.is_required():
            assert signature.parameters[field].default is inspect.Parameter.empty, (
                f"{name}.{field} is required on the model but optional in the signature"
            )


def _literal_members(annotation):
    """Every Literal member reachable in an annotation, flattened."""
    members = set()
    stack = [annotation]
    while stack:
        current = stack.pop()
        if typing.get_origin(current) is typing.Literal:
            members.update(typing.get_args(current))
            continue
        stack.extend(typing.get_args(current))
    return members


@pytest.mark.parametrize(("name", "function", "model"), PAIRS)
def test_signature_vocabulary_matches_the_model(name, function, model):
    """
    GIVEN a model field constrained to a Literal vocabulary
    WHEN the matching signature parameter is inspected
    THEN it offers the same members

    The signature is allowed to be wider in shape, accepting a bare value where
    the model wants a list, but it must not advertise a different vocabulary.
    """
    hints = typing.get_type_hints(function, include_extras=True)

    for field, info in model.model_fields.items():
        expected = _literal_members(info.annotation)
        if not expected:
            continue
        assert _literal_members(hints[field]) == expected, f"{name}.{field} vocabulary drifted"
