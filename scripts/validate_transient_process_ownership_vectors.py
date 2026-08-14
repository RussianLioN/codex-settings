#!/usr/bin/env python3
"""Проверка схемы и runtime-контракта долговечного владения v2."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipRecordV2,
    DurableProcessOwnershipV2Error,
)


SCHEMA_PATH = (
    ROOT / "docs/contracts/schemas/transient-process-ownership-v2.schema.json"
)
VECTOR_PATH = (
    ROOT / "docs/contracts/vectors/transient-process-ownership-v2.json"
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("mutation path must be an absolute JSON pointer")
    tokens = [
        token.replace("~1", "/").replace("~0", "~")
        for token in pointer.removeprefix("/").split("/")
    ]
    current = document
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, tokens[-1]


def _fixture_value(fixtures: dict[str, Any], reference: str) -> Any:
    if type(reference) is not str or "." not in reference:
        raise ValueError("fixtureValue must be fixture.property")
    fixture_name, *tokens = reference.split(".")
    value = fixtures[fixture_name]
    for token in tokens:
        value = value[token]
    return copy.deepcopy(value)


def _mutated(
    source: dict[str, Any],
    mutation: dict[str, Any] | None,
    *,
    fixtures: dict[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(source)
    if mutation is None:
        return result
    if type(mutation) is not dict or set(mutation) not in (
        {"operation", "path"},
        {"operation", "path", "value"},
        {"operation", "path", "fixtureValue"},
    ):
        raise ValueError("mutation must match the closed recipe")
    parent, token = _pointer_parent(result, mutation["path"])
    operation = mutation["operation"]
    if operation == "remove":
        if set(mutation) != {"operation", "path"}:
            raise ValueError("remove must not contain a value")
        del parent[token]
        return result
    if operation not in {"add", "replace"}:
        raise ValueError("mutation operation is unsupported")
    if set(mutation) == {"operation", "path"}:
        raise ValueError("add and replace require exactly one value")
    value = (
        _fixture_value(fixtures, mutation["fixtureValue"])
        if "fixtureValue" in mutation
        else copy.deepcopy(mutation["value"])
    )
    if operation == "replace" and token not in parent:
        raise ValueError("replace target is absent")
    parent[token] = value
    return result


def _runtime_valid(document: dict[str, Any]) -> bool:
    try:
        DurableProcessOwnershipRecordV2.from_mapping(document)
    except (DurableProcessOwnershipV2Error, TypeError, ValueError):
        return False
    return True


def main() -> int:
    schema = _load(SCHEMA_PATH)
    vectors = _load(VECTOR_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    if type(vectors) is not dict or set(vectors) != {
        "schemaVersion",
        "fixtures",
        "cases",
    }:
        raise ValueError("vector suite must match the closed top-level contract")
    if vectors["schemaVersion"] != 2:
        raise ValueError("vector suite schemaVersion must be 2")
    fixtures = vectors["fixtures"]
    cases = vectors["cases"]
    if type(fixtures) is not dict or not fixtures or type(cases) is not list:
        raise ValueError("fixtures and cases are required")
    failures: list[str] = []
    names: set[str] = set()
    for case in cases:
        if type(case) is not dict or set(case) != {
            "name",
            "fixture",
            "mutation",
            "expectedSchemaValid",
            "expectedRuntimeValid",
        }:
            raise ValueError("case must match the closed case contract")
        name = case["name"]
        if type(name) is not str or not name or name in names:
            raise ValueError("case names must be non-empty and unique")
        names.add(name)
        fixture_name = case["fixture"]
        if fixture_name not in fixtures:
            raise ValueError(f"unknown fixture: {fixture_name}")
        document = _mutated(
            fixtures[fixture_name],
            case["mutation"],
            fixtures=fixtures,
        )
        schema_valid = not bool(list(validator.iter_errors(document)))
        runtime_valid = _runtime_valid(document)
        if schema_valid is not case["expectedSchemaValid"]:
            failures.append(
                f"{name}: schema={schema_valid}, "
                f"expected={case['expectedSchemaValid']}"
            )
        if runtime_valid is not case["expectedRuntimeValid"]:
            failures.append(
                f"{name}: runtime={runtime_valid}, "
                f"expected={case['expectedRuntimeValid']}"
            )
    if failures:
        for failure in failures:
            print(f"TRANSIENT_PROCESS_OWNERSHIP_VECTOR_FAILED: {failure}")
        return 1
    print(
        "TRANSIENT_PROCESS_OWNERSHIP_VECTORS_OK "
        f"cases={len(cases)} fixtures={len(fixtures)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
