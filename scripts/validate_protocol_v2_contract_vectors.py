#!/usr/bin/env python3
"""Узкая проверка двух протоколов версии 2 и их эталонных векторов."""

from __future__ import annotations

import argparse
import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "docs/contracts/schemas"
VECTOR_ROOT = ROOT / "docs/contracts/vectors"

CONTROLLER_SCHEMA = SCHEMA_ROOT / "controller-protocol-v2.schema.json"
SMART_TURN_SCHEMA = SCHEMA_ROOT / "smart-turn-protocol-v2.schema.json"
ATTESTATION_SCHEMA = SCHEMA_ROOT / "child-attestation-v2.schema.json"
VECTOR_SUITE_SCHEMA = SCHEMA_ROOT / "protocol-vector-suite-v2.schema.json"

CONTROLLER_VECTORS = VECTOR_ROOT / "controller-protocol-v2.json"
SMART_TURN_VECTORS = VECTOR_ROOT / "smart-turn-protocol-v2.json"

CONTROLLER_METHODS = {
    "health",
    "maintenance_begin",
    "maintenance_strengthen",
    "maintenance_status",
    "shutdown",
    "controller_accept",
    "controller_recover",
    "maintenance_resume",
    "admit_node",
    "smart_status",
    "reserve_launch_permit",
    "commit_launch_permit",
}
PUBLIC_METHODS = {
    "issue_turn_binding",
    "smart_plan",
    "route_start",
    "smart_wait",
    "smart_cancel",
}


class ContractError(ValueError):
    """Вектор нарушает смысловой договор поверх JSON Schema."""


class Summary(NamedTuple):
    passed: int
    total: int
    positive_cases: int
    negative_cases: int
    attestation_cases: int


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ContractError(f"некорректный указатель JSON: {pointer}")
    return [
        token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")
    ]


def apply_mutation(
    document: dict[str, Any], mutation: dict[str, Any]
) -> dict[str, Any]:
    candidate = copy.deepcopy(document)
    tokens = _pointer_tokens(mutation["pointer"])
    parent: Any = candidate
    for token in tokens[:-1]:
        if isinstance(parent, dict) and token in parent:
            parent = parent[token]
        elif isinstance(parent, list) and token.isdigit() and int(token) < len(parent):
            parent = parent[int(token)]
        else:
            raise ContractError(
                f"родитель указателя отсутствует: {mutation['pointer']}"
            )

    token = tokens[-1]
    operation = mutation["operation"]
    if operation == "add":
        if not isinstance(parent, dict) or token in parent:
            raise ContractError("add требует отсутствующее поле существующего объекта")
        parent[token] = copy.deepcopy(mutation["value"])
    elif operation == "replace":
        if isinstance(parent, dict) and token in parent:
            parent[token] = copy.deepcopy(mutation["value"])
        elif isinstance(parent, list) and token.isdigit() and int(token) < len(parent):
            parent[int(token)] = copy.deepcopy(mutation["value"])
        else:
            raise ContractError("replace требует существующее значение")
    elif operation == "remove":
        if isinstance(parent, dict) and token in parent:
            del parent[token]
        elif isinstance(parent, list) and token.isdigit() and int(token) < len(parent):
            del parent[int(token)]
        else:
            raise ContractError("remove требует существующее значение")
    else:
        raise ContractError(f"неизвестная мутация: {operation}")
    if candidate == document:
        raise ContractError("мутация не изменила документ")
    return candidate


def _load_jsonschema_runtime() -> tuple[Any, Any, Any, Any]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
    except ModuleNotFoundError as error:
        raise ModuleNotFoundError(
            "для проверки нужны jsonschema[format]==4.25.1 и referencing==0.36.2"
        ) from error
    return Draft202012Validator, FormatChecker, Registry, Resource


def build_registry(schema_root: Path = SCHEMA_ROOT) -> tuple[Any, Any]:
    Draft202012Validator, FormatChecker, Registry, Resource = _load_jsonschema_runtime()
    resources: list[tuple[str, Any]] = []
    for path in sorted(schema_root.glob("*.schema.json")):
        schema = load_json(path)
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    return registry, FormatChecker()


def make_validator(path: Path, registry: Any, format_checker: Any) -> Any:
    Draft202012Validator, _FormatChecker, _Registry, _Resource = (
        _load_jsonschema_runtime()
    )
    schema = load_json(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=format_checker,
    )


def make_ref_validator(ref: str, registry: Any, format_checker: Any) -> Any:
    Draft202012Validator, _FormatChecker, _Registry, _Resource = (
        _load_jsonschema_runtime()
    )
    return Draft202012Validator(
        {"$ref": ref},
        registry=registry,
        format_checker=format_checker,
    )


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_public_semantics(message: dict[str, Any]) -> None:
    method = message["method"]
    if message["messageType"] == "request":
        owner = message["owner"]
        if method == "issue_turn_binding":
            context = message["params"]["requestContext"]
            for key in ("shellSessionId", "sessionId", "turnId"):
                if owner[key] != context[key]:
                    raise ContractError(f"владелец не совпал с requestContext: {key}")
        elif method == "smart_plan":
            binding = message["turnBinding"]
            if owner != binding["owner"]:
                raise ContractError("владелец запроса не совпал с владельцем привязки")
            if binding["state"] != "ACTIVE":
                raise ContractError("smart_plan требует активную привязку")
        elif message["turnBinding"] is not None:
            raise ContractError(
                "операция маршрута проверяет владельца по SQLite, а не по потреблённой привязке"
            )
        if method == "smart_wait":
            wait_deadline = _parse_time(message["params"]["waitDeadlineAt"])
            request_deadline = _parse_time(message["requestDeadlineAt"])
            if wait_deadline > request_deadline:
                raise ContractError("срок ожидания вышел за срок запроса")
        return

    if message["responseKind"] != "SUCCESS":
        category_by_kind = {
            "STALE": "STALE",
            "UNAVAILABLE": "UNAVAILABLE",
            "ERROR": None,
            "ORDINARY": None,
        }
        expected = category_by_kind[message["responseKind"]]
        if (
            expected is not None
            and message["payload"]["problem"]["category"] != expected
        ):
            raise ContractError("категория проблемы не совпала с видом ответа")
        expected_result = (
            "ORDINARY_DECISION" if message["responseKind"] == "ORDINARY" else "PROBLEM"
        )
        if message["payload"]["effect"]["result"]["resultKind"] != expected_result:
            raise ContractError("необычный ответ не связан со своим результатом SQLite")
        return

    expected_results = {
        "issue_turn_binding": "TURN_BINDING",
        "smart_plan": "ROUTE_PLAN",
        "route_start": "START_REQUEST",
        "smart_wait": "WAIT_PAGE",
        "smart_cancel": "CANCELLATION",
    }
    effect = message["payload"]["effect"]
    if effect["result"]["resultKind"] != expected_results[method]:
        raise ContractError("публичный ответ связан не с тем видом результата")
    if method == "route_start" and message["payload"]["admissionId"] is not None:
        raise ContractError("route_start не может создать admissionId")
    if method == "smart_plan":
        for decision in message["payload"]["nodeDecisions"]:
            if decision["disposition"] != "DELEGATE":
                continue
            if decision["score"] != sum(decision["factors"].values()):
                raise ContractError(
                    "оценка решения узла не равна сумме q+p+v+o"
                )
    if method == "route_start":
        evidence_deadline = _parse_time(message["payload"]["evidenceJob"]["deadlineAt"])
        durable_at = _parse_time(effect["completedAt"])
        if (evidence_deadline - durable_at).total_seconds() != 180:
            raise ContractError(
                "единый срок AccountEvidence обязан быть ровно 180 секунд"
            )
    if method == "smart_wait" and effect["operation"] != "READ":
        raise ContractError("smart_wait обязан быть чтением")
    if method == "smart_wait":
        page = message["payload"]["page"]
        if message["payload"]["terminal"] and page["nextCursor"] is not None:
            raise ContractError("терминальная страница не может иметь следующий курсор")
        for event in page["items"]:
            if event["kind"] == "CHILD_ATTESTED":
                if event["attestation"] is None:
                    raise ContractError("CHILD_ATTESTED требует строгую аттестацию")
                attestation = event["attestation"]
                validate_attestation_semantics(attestation)
                if (
                    attestation["startRequestId"]
                    != message["payload"]["startRequestId"]
                ):
                    raise ContractError("аттестация относится к другому startRequestId")
                if attestation["evidenceJobId"] != event["evidenceJobId"]:
                    raise ContractError("аттестация относится к другому evidenceJobId")
                if attestation["admissionId"] != event["admissionId"]:
                    raise ContractError("аттестация относится к другому admissionId")
            elif event["kind"] == "CHILD_FAILED_BEFORE_START":
                if event["startState"] != "FAILED" or event["problem"] is None:
                    raise ContractError(
                        "CHILD_FAILED_BEFORE_START требует FAILED и проблему"
                    )
                attestation = event["attestation"]
                if attestation is not None:
                    validate_attestation_semantics(attestation)
                    if attestation["disposition"] == "MATCH":
                        raise ContractError(
                            "неудачный предмиссионный запуск не может иметь MATCH"
                        )
                    if (
                        attestation["startRequestId"]
                        != message["payload"]["startRequestId"]
                        or attestation["evidenceJobId"] != event["evidenceJobId"]
                        or attestation["admissionId"] != event["admissionId"]
                    ):
                        raise ContractError(
                            "неудачная аттестация относится к другому запуску"
                        )
            elif event["attestation"] is not None:
                raise ContractError(
                    "аттестация разрешена только событиям дочернего запуска"
                )
    if method == "smart_cancel":
        expected_operation = (
            "TRANSITION"
            if message["payload"]["idempotencyStatus"] == "COMMITTED"
            else "READ"
        )
        if effect["operation"] != expected_operation:
            raise ContractError("повтор отмены не должен повторять переход SQLite")


def validate_attestation_semantics(attestation: dict[str, Any]) -> None:
    if attestation["disposition"] != "MATCH":
        return
    requested = attestation["requested"]
    observed = attestation["observed"]
    if observed is None:
        raise ContractError("MATCH требует наблюдённую идентичность")
    for key in (
        "pair",
        "permissionProfileId",
        "argvFingerprint",
        "snapshotIdentityFingerprint",
        "compatibilityFingerprint",
        "accountContextFingerprint",
    ):
        if requested[key] != observed[key]:
            raise ContractError(f"requested/observed расходятся: {key}")


def _assert_method_coverage(suite: dict[str, Any], expected_methods: set[str]) -> None:
    positive = {(case["method"], case["direction"]) for case in suite["positiveCases"]}
    expected_positive = {
        (method, direction)
        for method in expected_methods
        for direction in ("request", "response")
    }
    if not expected_positive <= positive:
        missing = sorted(expected_positive - positive)
        raise ContractError(f"нет положительных направлений методов: {missing}")
    negative_methods = {case["method"] for case in suite["negativeCases"]}
    if negative_methods != expected_methods:
        raise ContractError(
            f"отрицательные методы: ожидались {sorted(expected_methods)}, "
            f"получены {sorted(negative_methods)}"
        )


def _assert_internal_semantics(schema: dict[str, Any], suite: dict[str, Any]) -> None:
    methods = set(schema["$defs"]["method"]["enum"])
    if methods != CONTROLLER_METHODS:
        raise ContractError(f"неверный закрытый набор внутренних методов: {methods}")
    if "smart_start" in methods or "admit_node" not in methods:
        raise ContractError("внутренний smart_start не заменён на admit_node")

    work_counts = schema["$defs"]["workCounts"]
    required = set(work_counts["required"])
    if {"activeEvidenceJobs", "queuedEvidenceJobs"} - required:
        raise ContractError("задания доказательства отсутствуют в workCounts")
    if set(work_counts["properties"]) != required:
        raise ContractError("workCounts содержит необязательное или лишнее поле")

    messages = {case["name"]: case["message"] for case in suite["positiveCases"]}
    admit = messages["admit-node-request"]["params"]
    if "startRequestId" not in admit or "evidenceJobId" not in admit:
        raise ContractError(
            "admit_node не связан с намерением и заданием доказательства"
        )
    gates = [
        admit["activationGate"],
        messages["reserve-launch-permit-request"]["params"]["activationGate"],
        messages["commit-launch-permit-request"]["params"]["activationGate"],
    ]
    if not (gates[0] == gates[1] == gates[2]):
        raise ContractError("три внутренние границы получили разные activationGate")

    shutdown = messages["shutdown-response"]
    replay = messages["shutdown-replay-response"]
    replay_payload = replay["payload"]
    if replay_payload["originalPayload"] != shutdown["payload"]:
        raise ContractError("повтор shutdown не сохраняет исходный payload")
    if replay_payload["commandReceipt"] != shutdown["payload"]["commandReceipt"]:
        raise ContractError("повтор shutdown не сохраняет исходную квитанцию")
    if replay_payload["originalControlEpoch"] != shutdown["controlEpoch"]:
        raise ContractError("повтор shutdown не сохраняет исходную эпоху")
    if replay["controlEpoch"] != replay_payload["originalControlEpoch"]:
        raise ContractError("эпоха повтора расходится с исходной эпохой")
    if (
        replay_payload["originalResponseFingerprint"]
        != shutdown["responseFingerprint"]
    ):
        raise ContractError("повтор shutdown не связан с исходным ответом")

    normal_accept = messages["controller-accept-request"]
    rollback_accept = messages["controller-accept-rollback-rebind-request"]
    recover = messages["controller-recover-request"]
    if normal_accept["params"]["expectedOrphanOperationId"] is not None:
        raise ContractError("обычное принятие не должно перепривязывать orphan")
    expected_orphan = rollback_accept["params"]["expectedOrphanOperationId"]
    if (
        expected_orphan is None
        or expected_orphan == rollback_accept["operationId"]
    ):
        raise ContractError(
            "откат обязан указать точную отличающуюся операцию orphan"
        )
    if "expectedOrphanOperationId" in recover["params"]:
        raise ContractError("controller_recover не имеет права перепривязывать orphan")
    required_rebind_checks = {
        "normal-accept-has-no-orphan-rebind",
        "rollback-accept-rebinds-exact-orphan",
    }
    if not required_rebind_checks <= set(suite["semanticChecks"]):
        raise ContractError("семантические проверки перепривязки не объявлены")


def validate_error_category_cases(
    *,
    schema: dict[str, Any],
    definition: str,
    schema_id: str,
    suite: dict[str, Any],
    registry: Any,
    format_checker: Any,
) -> int:
    definition_schema = schema["$defs"][definition]
    expected_codes = set(definition_schema["properties"]["code"]["enum"])
    categories = set(definition_schema["properties"]["category"]["enum"])
    cases = suite["errorCodeCategoryCases"]
    observed = {case["code"] for case in cases}
    if len(observed) != len(cases):
        raise ContractError("код ошибки повторяется в таблице категорий")
    if observed != expected_codes:
        raise ContractError(
            f"таблица категорий не закрывает коды: "
            f"нет={sorted(expected_codes - observed)}, лишние={sorted(observed - expected_codes)}"
        )

    validator = make_ref_validator(
        f"{schema_id}#/$defs/{definition}", registry, format_checker
    )
    checks = 0
    for case in cases:
        payload = {
            "category": case["category"],
            "code": case["code"],
            "message": "эталонная проблема",
            "retryable": False,
        }
        validator.validate(payload)
        checks += 1
        for wrong_category in categories - {case["category"]}:
            mutant = {**payload, "category": wrong_category}
            if validator.is_valid(mutant):
                raise ContractError(
                    f"код {case['code']} принят с категорией {wrong_category}"
                )
            checks += 1
    return checks


def validate_all(root: Path = ROOT) -> Summary:
    schema_root = root / "docs/contracts/schemas"
    vector_root = root / "docs/contracts/vectors"
    controller_schema_path = schema_root / CONTROLLER_SCHEMA.name
    smart_schema_path = schema_root / SMART_TURN_SCHEMA.name
    attestation_schema_path = schema_root / ATTESTATION_SCHEMA.name
    vector_suite_schema_path = schema_root / VECTOR_SUITE_SCHEMA.name
    controller_vectors_path = vector_root / CONTROLLER_VECTORS.name
    smart_vectors_path = vector_root / SMART_TURN_VECTORS.name

    registry, format_checker = build_registry(schema_root)
    suite_validator = make_validator(vector_suite_schema_path, registry, format_checker)
    controller_validator = make_validator(
        controller_schema_path, registry, format_checker
    )
    smart_validator = make_validator(smart_schema_path, registry, format_checker)
    attestation_validator = make_validator(
        attestation_schema_path, registry, format_checker
    )

    controller_schema = load_json(controller_schema_path)
    smart_schema = load_json(smart_schema_path)
    controller_suite = load_json(controller_vectors_path)
    smart_suite = load_json(smart_vectors_path)

    checks = 0
    suite_validator.validate(controller_suite)
    checks += 1
    suite_validator.validate(smart_suite)
    checks += 1

    controller_methods = set(controller_schema["$defs"]["method"]["enum"])
    public_methods = set(smart_schema["$defs"]["method"]["enum"])
    if controller_methods & public_methods:
        raise ContractError("публичный и внутренний наборы методов пересекаются")
    if public_methods != PUBLIC_METHODS:
        raise ContractError(
            f"неверный закрытый набор публичных методов: {public_methods}"
        )
    checks += 1

    _assert_method_coverage(controller_suite, CONTROLLER_METHODS)
    _assert_method_coverage(smart_suite, PUBLIC_METHODS)
    checks += 2
    _assert_internal_semantics(controller_schema, controller_suite)
    checks += 1

    checks += validate_error_category_cases(
        schema=controller_schema,
        definition="errorPayload",
        schema_id=controller_schema["$id"],
        suite=controller_suite,
        registry=registry,
        format_checker=format_checker,
    )
    checks += validate_error_category_cases(
        schema=smart_schema,
        definition="problem",
        schema_id=smart_schema["$id"],
        suite=smart_suite,
        registry=registry,
        format_checker=format_checker,
    )

    positive_cases = 0
    negative_cases = 0
    attestation_cases = 0
    for suite, validator, semantic in (
        (controller_suite, controller_validator, None),
        (smart_suite, smart_validator, validate_public_semantics),
    ):
        positives = {case["name"]: case for case in suite["positiveCases"]}
        if len(positives) != len(suite["positiveCases"]):
            raise ContractError("имена положительных случаев повторяются")
        for case in suite["positiveCases"]:
            message = case["message"]
            validator.validate(message)
            if message["method"] != case["method"]:
                raise ContractError(f"метод оболочки не совпал: {case['name']}")
            if message["messageType"] != case["direction"]:
                raise ContractError(f"направление оболочки не совпало: {case['name']}")
            if semantic is not None:
                semantic(message)
            positive_cases += 1
            checks += 1

        for case in suite["negativeCases"]:
            base = positives.get(case["baseCase"])
            if base is None:
                raise ContractError(f"нет базового случая: {case['baseCase']}")
            if (
                base["method"] != case["method"]
                or base["direction"] != case["direction"]
            ):
                raise ContractError(
                    f"отрицательный случай сменил метод/направление: {case['name']}"
                )
            candidate = apply_mutation(base["message"], case["mutation"])
            schema_errors = list(validator.iter_errors(candidate))
            semantic_error: ContractError | None = None
            if not schema_errors and semantic is not None:
                try:
                    semantic(candidate)
                except ContractError as error:
                    semantic_error = error
            if not schema_errors and semantic_error is None:
                raise ContractError(f"отрицательная мутация принята: {case['name']}")
            negative_cases += 1
            checks += 1

    attestation_positives = {
        case["name"]: case for case in smart_suite["attestationPositiveCases"]
    }
    for case in smart_suite["attestationPositiveCases"]:
        attestation_validator.validate(case["attestation"])
        validate_attestation_semantics(case["attestation"])
        attestation_cases += 1
        checks += 1
    for case in smart_suite["attestationNegativeCases"]:
        base = attestation_positives.get(case["baseCase"])
        if base is None:
            raise ContractError(f"нет базовой аттестации: {case['baseCase']}")
        candidate = apply_mutation(base["attestation"], case["mutation"])
        schema_errors = list(attestation_validator.iter_errors(candidate))
        semantic_error: ContractError | None = None
        if not schema_errors:
            try:
                validate_attestation_semantics(candidate)
            except ContractError as error:
                semantic_error = error
        if not schema_errors and semantic_error is None:
            raise ContractError(f"отрицательная аттестация принята: {case['name']}")
        attestation_cases += 1
        checks += 1

    return Summary(
        passed=checks,
        total=checks,
        positive_cases=positive_cases,
        negative_cases=negative_cases,
        attestation_cases=attestation_cases,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all", action="store_true", help="проверить все протокольные векторы"
    )
    parser.parse_args()
    summary = validate_all(ROOT)
    print(
        "protocol-v2: "
        f"{summary.passed}/{summary.total}; "
        f"положительных={summary.positive_cases}; "
        f"отрицательных={summary.negative_cases}; "
        f"аттестаций={summary.attestation_cases}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
