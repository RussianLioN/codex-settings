#!/usr/bin/env python3
"""Проверка векторов через производственную смысловую маршрутизацию v2."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.semantic_routing_v2 import (  # noqa: E402
    ContractError,
    SemanticRouterV2,
    decide_delegation,
    derive_p_criterion_states,
    legacy_v1_score,
    semantic_v2_score,
    validate_context_bundle,
    validate_role_template,
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fail(code: str, detail: str = "") -> None:
    suffix = f": {detail}" if detail else ""
    raise ContractError(code + suffix)


def _pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        _fail("INVALID_JSON_POINTER", pointer)
    return [
        token.replace("~1", "/").replace("~0", "~")
        for token in pointer[1:].split("/")
    ]


def _pointer_get(document: Any, pointer: str) -> Any:
    current = document
    for token in _pointer_tokens(pointer):
        if type(current) is dict and token in current:
            current = current[token]
        elif type(current) is list and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            _fail("JSON_POINTER_UNRESOLVED", pointer)
    return current


def _pointer_set(document: Any, pointer: str, value: Any, *, add: bool = False) -> None:
    tokens = _pointer_tokens(pointer)
    current = document
    for token in tokens[:-1]:
        if type(current) is dict and token in current:
            current = current[token]
        elif type(current) is list and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            _fail("JSON_POINTER_UNRESOLVED", pointer)
    token = tokens[-1]
    if type(current) is dict:
        if not add and token not in current:
            _fail("JSON_POINTER_UNRESOLVED", pointer)
        if add and token in current:
            _fail("JSON_POINTER_ALREADY_PRESENT", pointer)
        current[token] = copy.deepcopy(value)
        return
    if type(current) is list and token.isdigit() and int(token) < len(current):
        if add:
            _fail("JSON_POINTER_ALREADY_PRESENT", pointer)
        current[int(token)] = copy.deepcopy(value)
        return
    _fail("JSON_POINTER_UNRESOLVED", pointer)


def _deep_merge(base: Any, patch: Any) -> Any:
    if type(base) is dict and type(patch) is dict:
        result = copy.deepcopy(base)
        for key, value in patch.items():
            result[key] = (
                _deep_merge(result[key], value)
                if key in result and type(result[key]) is dict and type(value) is dict
                else copy.deepcopy(value)
            )
        return result
    return copy.deepcopy(patch)


def _resolve_copy_directives(value: Any, vectors: dict[str, Any]) -> Any:
    if type(value) is str and value.startswith("$copy:"):
        current: Any = vectors
        for token in value.removeprefix("$copy:").split("/"):
            if type(current) is not dict or token not in current:
                _fail("VECTOR_COPY_UNRESOLVED", value)
            current = current[token]
        return copy.deepcopy(current)
    if type(value) is list:
        return [_resolve_copy_directives(item, vectors) for item in value]
    if type(value) is dict:
        return {
            key: _resolve_copy_directives(item, vectors)
            for key, item in value.items()
        }
    return copy.deepcopy(value)


def materialize_routing_case(
    case: dict[str, Any], vectors: dict[str, Any]
) -> dict[str, Any]:
    patch = _resolve_copy_directives(case["patch"], vectors)
    return _deep_merge(vectors["baseInput"], patch)


def _policy_snapshot(root: Path) -> dict[str, Any]:
    vector = load_json(root / "docs/contracts/vectors/routing-policy-v2.json")
    return {
        "domain": vector["domain"],
        "policy": vector["policy"],
        "canonicalUtf8": vector["canonicalUtf8"],
        "fingerprint": vector["fingerprint"],
    }


@lru_cache(maxsize=None)
def _router(root: Path) -> SemanticRouterV2:
    delegation = load_json(
        root / "docs/contracts/vectors/delegation-policy-v2.json"
    )["policy"]
    templates = load_json(
        root / "docs/contracts/vectors/role-template-v1.json"
    )["templates"]
    return SemanticRouterV2(
        policy_snapshot=_policy_snapshot(root),
        delegation_policy=delegation,
        role_templates=templates,
    )


def normalize_task_facts(
    value: dict[str, Any], *, root: Path = ROOT
) -> dict[str, Any]:
    return _router(root.resolve()).normalize_task_facts(value)


def evaluate_routing_input(
    value: dict[str, Any], *, root: Path = ROOT
) -> dict[str, Any]:
    return _router(root.resolve()).evaluate(value)


def _apply_task_mutation(base: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(base)
    kind = operation["kind"]
    if kind == "add":
        _pointer_set(candidate, operation["path"], operation["value"], add=True)
    elif kind == "replace":
        _pointer_set(candidate, operation["path"], operation["value"])
    elif kind == "append-copy":
        source = _pointer_get(candidate, operation["path"])
        parent_pointer = operation["path"].rsplit("/", 1)[0]
        target = _pointer_get(candidate, parent_pointer)
        if type(target) is not list:
            _fail("MUTATION_TARGET_NOT_ARRAY")
        target.append(copy.deepcopy(source))
    else:
        _fail("MUTATION_KIND_UNKNOWN")
    return candidate


def _assert_error(expected: str, action: Any) -> None:
    try:
        action()
    except ContractError as error:
        if expected not in str(error):
            raise AssertionError((expected, str(error))) from error
    else:
        raise AssertionError(f"ожидалась ошибка {expected}")


def _delegation_case_result(
    facts: dict[str, Any], delegation_policy: dict[str, Any]
) -> dict[str, Any]:
    decisions = {
        item["reason"]: item["decision"]
        for item in delegation_policy["hardBanReasons"]
    }
    normalized = {
        "hardBanReasons": [
            {"reason": reason, "decision": decisions[reason]}
            for reason in facts["hardBanReasons"]
        ],
        "delegation": {
            "permission": {"value": facts["permission"]},
            "objectivelyVerifiable": {"value": facts["objectivelyVerifiable"]},
            "independentWorkUnits": {"value": facts["independentWorkUnits"]},
        },
    }
    return decide_delegation(normalized, delegation_policy)


def validate_repository(root: Path = ROOT) -> dict[str, int]:
    root = root.resolve()
    passed = 0
    total = 0
    mutation_count = 0

    task_vectors = load_json(root / "docs/contracts/vectors/task-facts-v1.json")
    task_by_name = {
        case["name"]: case for case in task_vectors["normalizationCases"]
    }
    for case in task_vectors["normalizationCases"]:
        normalized = normalize_task_facts(case["value"], root=root)
        if case.get("expected") is not None and normalized != case["expected"]:
            raise AssertionError((case["name"], normalized, case["expected"]))
        if case.get("expectedPStates") is not None:
            actual = derive_p_criterion_states(normalized["workShape"])
            if actual != case["expectedPStates"]:
                raise AssertionError(
                    (case["name"], actual, case["expectedPStates"])
                )
        passed += 1
        total += 1
    for mutation in task_vectors["mutations"]:
        base = task_by_name[mutation["baseCase"]]["value"]
        candidate = _apply_task_mutation(base, mutation["operation"])
        _assert_error(
            mutation["expectedError"],
            lambda candidate=candidate: normalize_task_facts(candidate, root=root),
        )
        passed += 1
        total += 1
        mutation_count += 1

    context_vectors = load_json(
        root / "docs/contracts/vectors/context-bundle-v1.json"
    )
    context_by_name = {
        case["name"]: case for case in context_vectors["positiveCases"]
    }
    for case in context_vectors["positiveCases"]:
        validate_context_bundle(
            case["value"], context_vectors["evidenceSnapshots"][case["name"]]
        )
        passed += 1
        total += 1
    for mutation in context_vectors["mutations"]:
        candidate = copy.deepcopy(
            context_by_name[mutation["baseCase"]]["value"]
        )
        _pointer_set(candidate, mutation["path"], mutation["value"])
        snapshot = context_vectors["evidenceSnapshots"][mutation["baseCase"]]
        _assert_error(
            mutation["expectedError"],
            lambda candidate=candidate, snapshot=snapshot: validate_context_bundle(
                candidate, snapshot
            ),
        )
        passed += 1
        total += 1
        mutation_count += 1

    role_vectors = load_json(root / "docs/contracts/vectors/role-template-v1.json")
    role_by_id = {
        item["templateId"]: item for item in role_vectors["templates"]
    }
    for role in role_vectors["templates"]:
        validate_role_template(role)
        passed += 1
        total += 1
    for mutation in role_vectors["mutations"]:
        candidate = copy.deepcopy(role_by_id[mutation["baseTemplateId"]])
        _pointer_set(candidate, mutation["path"], mutation["value"])
        _assert_error(
            mutation["expectedError"],
            lambda candidate=candidate: validate_role_template(candidate),
        )
        passed += 1
        total += 1
        mutation_count += 1

    delegation_vectors = load_json(
        root / "docs/contracts/vectors/delegation-policy-v2.json"
    )
    schema = load_json(
        root / "docs/contracts/schemas/delegation-policy-v2.schema.json"
    )
    if delegation_vectors["policy"] != schema["const"]:
        raise AssertionError("политика делегирования расходится с точной схемой")
    passed += 1
    total += 1
    for case in delegation_vectors["decisionCases"]:
        actual = _delegation_case_result(
            case["facts"], delegation_vectors["policy"]
        )
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
        total += 1
    for mutation in delegation_vectors["mutations"]:
        candidate = copy.deepcopy(delegation_vectors["policy"])
        _pointer_set(candidate, mutation["path"], mutation["value"])
        if candidate == schema["const"]:
            raise AssertionError(f"неэффективная мутация политики: {mutation['name']}")
        passed += 1
        total += 1
        mutation_count += 1

    policy_vectors = load_json(
        root / "docs/contracts/vectors/routing-policy-v2.json"
    )
    router = _router(root)
    for case in policy_vectors["scoreCases"]:
        actual = router.select_pair(case["factors"])
        expected = {
            "model": case["expected"]["model"],
            "reasoningEffort": case["expected"]["reasoningEffort"],
        }
        if actual != expected:
            raise AssertionError((case["name"], actual, expected))
        passed += 1
        total += 1
    score_factors = {
        case["score"]: case["factors"] for case in policy_vectors["scoreCases"]
    }
    for case in policy_vectors["hardFloorCases"]:
        if case["expected"] == "schema-invalid":
            _assert_error(
                "HARD_FLOOR_REASON_UNKNOWN",
                lambda case=case: router.select_pair(
                    {"q": 0, "p": 0, "v": 0, "o": 0},
                    hard_floor_reasons=case["reasons"],
                ),
            )
        else:
            actual = router.select_pair(
                score_factors[case["score"]],
                hard_floor_reasons=case["reasons"],
            )
            expected = {
                "model": case["expected"]["model"],
                "reasoningEffort": case["expected"]["reasoningEffort"],
            }
            if actual != expected:
                raise AssertionError((case["name"], actual, expected))
        passed += 1
        total += 1

    routing_vectors = load_json(
        root / "docs/contracts/vectors/routing-input-v2.json"
    )
    case_by_name = {
        case["name"]: case for case in routing_vectors["cases"]
    }
    for case in routing_vectors["cases"]:
        value = materialize_routing_case(case, routing_vectors)
        actual = evaluate_routing_input(value, root=root)
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
        total += 1
    for mutation in routing_vectors["mutations"]:
        base_case = case_by_name[mutation["baseCase"]]
        candidate = materialize_routing_case(base_case, routing_vectors)
        _pointer_set(candidate, mutation["path"], mutation["value"])
        try:
            actual = evaluate_routing_input(candidate, root=root)
        except ContractError as error:
            actual_error = str(error).split(":", 1)[0]
        else:
            actual_error = actual.get("errorCode")
        if actual_error != mutation["expectedError"]:
            raise AssertionError(
                (mutation["name"], actual_error, mutation["expectedError"])
            )
        passed += 1
        total += 1
        mutation_count += 1

    return {
        "passed": passed,
        "failed": total - passed,
        "total": total,
        "routingCases": len(routing_vectors["cases"]),
        "mutations": mutation_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    summary = validate_repository(args.root.resolve())
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
