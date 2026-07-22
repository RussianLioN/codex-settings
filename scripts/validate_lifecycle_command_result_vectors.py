#!/usr/bin/env python3
"""Проверка закрытого результата команд жизненного цикла версии 2."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import namedtuple
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/contracts/schemas/lifecycle-command-result-v2.schema.json"
VECTOR_PATH = ROOT / "docs/contracts/vectors/lifecycle-command-result-v2.json"
DOMAIN = "codex-smart/command-result/v2"
CHANGE_ORDER = (
    "migrated_manifest",
    "attested_codex",
    "staged_generation",
    "gate_closed",
    "installed_bootstrap_fence",
    "drained_controller",
    "migrated_database",
    "published_activation",
    "registered_marketplace",
    "enabled_plugin",
    "repaired_launchers",
    "accepted_controller",
    "committed_manifest",
    "gate_opened",
    "retired_generation",
    "removed_installation",
)
SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}
Summary = namedtuple("Summary", "positive_cases negative_cases passed total")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        if not -(1 << 53) + 1 <= value <= (1 << 53) - 1:
            raise ValueError("целое вне безопасного диапазона canonical-json-v1")
        return str(value)
    if type(value) is str:
        value.encode("utf-8")
        encoded = ['"']
        for character in value:
            codepoint = ord(character)
            if character == '"':
                encoded.append('\\"')
            elif character == "\\":
                encoded.append("\\\\")
            elif codepoint <= 0x1F:
                encoded.append(f"\\u{codepoint:04x}")
            else:
                encoded.append(character)
        encoded.append('"')
        return "".join(encoded)
    if type(value) is list:
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("ключ canonical-json-v1 обязан быть строкой")
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return "{" + ",".join(
            _canonical_json(key) + ":" + _canonical_json(value[key])
            for key in keys
        ) + "}"
    raise ValueError(f"неподдерживаемое значение: {type(value).__name__}")


def result_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": result["schemaVersion"],
        "command": result["command"],
        "status": result["status"],
        "readiness": result["readiness"],
        "smokeInvocationId": result["smokeInvocationId"],
        "changes": copy.deepcopy(result["changes"]),
        "problems": [
            {
                "code": problem["code"],
                "severity": problem["severity"],
                "component": problem["component"],
            }
            for problem in result["problems"]
        ],
    }


def result_fingerprint(result: dict[str, Any]) -> str:
    payload = DOMAIN.encode("utf-8") + b"\0" + _canonical_json(
        result_projection(result)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _semantic_errors(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    changes = result.get("changes")
    if isinstance(changes, list):
        kinds = [change.get("kind") for change in changes if isinstance(change, dict)]
        if len(kinds) != len(set(kinds)):
            errors.append("CHANGE_KIND_DUPLICATE")
        if all(kind in CHANGE_ORDER for kind in kinds) and kinds != sorted(
            kinds, key=CHANGE_ORDER.index
        ):
            errors.append("CHANGE_ORDER_INVALID")
        for change in changes:
            if (
                isinstance(change, dict)
                and change.get("beforeFingerprint")
                == change.get("afterFingerprint")
            ):
                errors.append("CHANGE_NO_EFFECT")
                break
        if "retired_generation" in kinds and not (
            result.get("command") == "cleanup" and result.get("status") == "cleaned"
        ):
            errors.append("RETIRED_GENERATION_OUTSIDE_CLEANUP")
        if "removed_installation" in kinds and not (
            result.get("command") == "uninstall"
            and result.get("status") == "uninstalled"
        ):
            errors.append("REMOVED_INSTALLATION_OUTSIDE_UNINSTALL")

    problems = result.get("problems")
    if isinstance(problems, list) and all(
        isinstance(problem, dict)
        and problem.get("severity") in SEVERITY_ORDER
        and isinstance(problem.get("component"), str)
        and isinstance(problem.get("code"), str)
        and isinstance(problem.get("message"), str)
        for problem in problems
    ):
        expected = sorted(
            problems,
            key=lambda problem: (
                SEVERITY_ORDER[problem["severity"]],
                problem["component"].encode("utf-8"),
                problem["code"].encode("utf-8"),
                problem["message"].encode("utf-8"),
            ),
        )
        if problems != expected:
            errors.append("PROBLEM_ORDER_INVALID")

    required_projection_fields = {
        "schemaVersion",
        "command",
        "status",
        "readiness",
        "smokeInvocationId",
        "changes",
        "problems",
        "resultFingerprint",
    }
    if required_projection_fields.issubset(result):
        try:
            if result_fingerprint(result) != result["resultFingerprint"]:
                errors.append("RESULT_FINGERPRINT_MISMATCH")
        except (KeyError, TypeError, ValueError):
            errors.append("RESULT_FINGERPRINT_INPUT_INVALID")
    return errors


def _validation_codes(
    validator: Draft202012Validator,
    result: dict[str, Any],
) -> list[str]:
    codes = []
    if list(validator.iter_errors(result)):
        codes.append("SCHEMA_INVALID")
    codes.extend(_semantic_errors(result))
    return codes


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    tokens = pointer.removeprefix("/").split("/") if pointer != "/" else []
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in tokens]
    current = document
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, tokens[-1]


def _patched(document: Any, mutation: dict[str, Any]) -> Any:
    result = copy.deepcopy(document)
    parent, token = _pointer_parent(result, mutation["path"])
    operation = mutation["operation"]
    if operation == "remove":
        if isinstance(parent, list):
            parent.pop(int(token))
        else:
            del parent[token]
    elif operation == "replace":
        if isinstance(parent, list):
            parent[int(token)] = copy.deepcopy(mutation["value"])
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        if isinstance(parent, list):
            parent.insert(
                len(parent) if token == "-" else int(token),
                copy.deepcopy(mutation["value"]),
            )
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    else:
        raise AssertionError(f"неизвестная мутация: {operation}")
    return result


def validate_all(root: Path = ROOT) -> Summary:
    schema = _load_json(root / SCHEMA_PATH.relative_to(ROOT))
    vectors = _load_json(root / VECTOR_PATH.relative_to(ROOT))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    failures: list[str] = []
    fixtures = vectors.get("fixtures")
    positive_cases = vectors.get("positiveCases")
    negative_cases = vectors.get("negativeCases")
    if not isinstance(fixtures, dict):
        raise ValueError("fixtures обязан быть объектом")
    if not isinstance(positive_cases, list) or not isinstance(negative_cases, list):
        raise ValueError("списки случаев отсутствуют")

    for case in positive_cases:
        name = case["name"]
        result = fixtures[case["fixture"]]
        codes = _validation_codes(validator, result)
        if codes:
            failures.append(f"POSITIVE {name}: {','.join(codes)}")

    for case in negative_cases:
        name = case["name"]
        result = _patched(fixtures[case["fixture"]], case["mutation"])
        codes = _validation_codes(validator, result)
        if case["expectedCode"] not in codes:
            failures.append(
                f"NEGATIVE {name}: ожидалось {case['expectedCode']}, получено {codes}"
            )

    for failure in failures:
        print(failure)
    passed = len(positive_cases) + len(negative_cases) - len(failures)
    summary = Summary(
        positive_cases=len(positive_cases),
        negative_cases=len(negative_cases),
        passed=passed,
        total=len(positive_cases) + len(negative_cases),
    )
    if failures:
        raise AssertionError(f"ошибок договора результата: {len(failures)}")
    return summary


def main() -> int:
    try:
        summary = validate_all(ROOT)
    except (AssertionError, KeyError, OSError, TypeError, ValueError) as error:
        print(f"LIFECYCLE_COMMAND_RESULTS_FAILED {error}", file=sys.stderr)
        return 1
    print("POSITIVE_CASES", summary.positive_cases)
    print("NEGATIVE_CASES", summary.negative_cases)
    print("LIFECYCLE_COMMAND_RESULTS_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
