#!/usr/bin/env python3
"""Независимый эталонный исполнитель векторов договора задачи 1."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SAFE_INTEGER_MAX = 2**53 - 1
SUBJECT_DOMAIN = "codex-smart/subject/v1"
SEMANTIC_DOMAIN = "codex-smart/semantic/v1"
COMPATIBILITY_DOMAIN = "codex-smart/compatibility/v1"
REQUIREMENTS_DOMAIN = "codex-smart/requirements/v1"
RAW_DOCUMENT_BYTES_MAX = 1_048_576
NORMALIZED_DOCUMENT_BYTES_MAX = 1_048_576
JSON_TREE_NODES_MAX = 4_096
JSON_TREE_DEPTH_MAX = 16


class ContractError(ValueError):
    """Вход нарушает проверяемый договор."""


class JsonTreeGuardError(ContractError):
    """Дерево JSON превысило лимит или содержит цикл контейнеров."""


class ConfigStageError(ContractError):
    """Отказ на конкретной стадии обработки управляемых требований."""

    def __init__(self, phase: str, error_code: str, detail: str) -> None:
        super().__init__(detail)
        self.phase = phase
        self.error_code = error_code


@dataclass(frozen=True)
class CheckSummary:
    passed: int
    total: int


def aggregate_check_summaries(*summaries: CheckSummary) -> CheckSummary:
    return CheckSummary(
        passed=sum(summary.passed for summary in summaries),
        total=sum(summary.total for summary in summaries),
    )


@dataclass(frozen=True)
class JsonTreeMetrics:
    nodes: int
    depth: int


@dataclass(frozen=True)
class ConfigEvaluation:
    normalization: dict[str, Any]
    compatibility: dict[str, Any]


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> Any:
    raise ContractError(f"unsupported JSON number: {value}")


def _parse_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ContractError("unsupported JSON integer") from error
    if not -SAFE_INTEGER_MAX <= parsed <= SAFE_INTEGER_MAX:
        raise ContractError("integer outside canonical-json-v1 safe range")
    return parsed


def _validate_and_measure_loaded_json(
    value: Any,
    *,
    max_nodes: int | None = None,
    max_depth: int | None = None,
) -> JsonTreeMetrics:
    nodes = 0
    depth = 0
    active_containers: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 1, False)]
    while stack:
        current, current_depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(current))
            continue
        nodes += 1
        if max_nodes is not None and nodes > max_nodes:
            raise JsonTreeGuardError("JSON value tree node limit exceeded")
        if max_depth is not None and current_depth > max_depth:
            raise JsonTreeGuardError("JSON value tree depth limit exceeded")
        depth = max(depth, current_depth)
        if current is None or current is True or current is False:
            continue
        if type(current) is int:
            if not -SAFE_INTEGER_MAX <= current <= SAFE_INTEGER_MAX:
                raise ContractError("integer outside canonical-json-v1 safe range")
            continue
        if type(current) is str:
            current.encode("utf-8")
            continue
        if type(current) is list:
            if max_nodes is not None and nodes + len(current) > max_nodes:
                raise JsonTreeGuardError("JSON value tree node limit exceeded")
            container_id = id(current)
            if container_id in active_containers:
                raise JsonTreeGuardError("cyclic JSON container")
            active_containers.add(container_id)
            stack.append((current, current_depth, True))
            stack.extend((item, current_depth + 1, False) for item in current)
            continue
        if type(current) is dict:
            if max_nodes is not None and nodes + len(current) > max_nodes:
                raise JsonTreeGuardError("JSON value tree node limit exceeded")
            container_id = id(current)
            if container_id in active_containers:
                raise JsonTreeGuardError("cyclic JSON container")
            for key, item in current.items():
                if type(key) is not str:
                    raise ContractError("JSON object key must be a string")
                key.encode("utf-8")
            active_containers.add(container_id)
            stack.append((current, current_depth, True))
            stack.extend((item, current_depth + 1, False) for item in current.values())
            continue
        raise ContractError(f"unsupported JSON value: {type(current).__name__}")
    return JsonTreeMetrics(nodes=nodes, depth=depth)


def _validate_loaded_json(value: Any) -> None:
    _validate_and_measure_loaded_json(value)


def _strict_json_decode(raw: str | bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_number,
        parse_float=_reject_number,
        parse_int=_parse_integer,
    )


def strict_json_loads(raw: str | bytes) -> Any:
    value = _strict_json_decode(raw)
    _validate_loaded_json(value)
    return value


def load_json(path: Path) -> Any:
    return strict_json_loads(path.read_bytes())


def canonical_json_v1(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise ContractError("integer outside canonical-json-v1 safe range")
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
        return "[" + ",".join(canonical_json_v1(item) for item in value) + "]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ContractError("canonical-json-v1 object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return (
            "{"
            + ",".join(
                canonical_json_v1(key) + ":" + canonical_json_v1(value[key])
                for key in keys
            )
            + "}"
        )
    raise ContractError(f"unsupported canonical-json-v1 value: {type(value).__name__}")


def domain_fingerprint(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_v1(value).encode("utf-8")
    ).hexdigest()


def measure_json_value_tree(value: Any) -> JsonTreeMetrics:
    """Измеряет дерево значений итеративно; имена членов объектов не являются узлами."""

    nodes = 0
    depth = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, current_depth = stack.pop()
        nodes += 1
        depth = max(depth, current_depth)
        if type(current) is dict:
            stack.extend((child, current_depth + 1) for child in current.values())
        elif type(current) is list:
            stack.extend((child, current_depth + 1) for child in current)
    return JsonTreeMetrics(nodes=nodes, depth=depth)


def _pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ContractError(f"invalid JSON pointer: {pointer}")
    return [
        token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")
    ]


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    tokens = _pointer_tokens(pointer)
    parent = document
    for token in tokens[:-1]:
        if type(parent) is dict and token in parent:
            parent = parent[token]
        elif type(parent) is list and token.isdigit() and int(token) < len(parent):
            parent = parent[int(token)]
        else:
            raise ContractError(f"missing JSON pointer parent: {pointer}")
    return parent, tokens[-1]


def _pointer_get(document: Any, pointer: str) -> Any:
    parent, token = _pointer_parent(document, pointer)
    if type(parent) is dict and token in parent:
        return parent[token]
    if type(parent) is list and token.isdigit() and int(token) < len(parent):
        return parent[int(token)]
    raise ContractError(f"missing JSON pointer value: {pointer}")


def _pointer_set_existing(document: Any, pointer: str, value: Any) -> None:
    parent, token = _pointer_parent(document, pointer)
    if type(parent) is dict and token in parent:
        parent[token] = value
        return
    if type(parent) is list and token.isdigit() and int(token) < len(parent):
        parent[int(token)] = value
        return
    raise ContractError(f"missing JSON pointer value: {pointer}")


def apply_interface_operation(
    document: dict[str, Any], operation: dict[str, Any]
) -> dict[str, Any]:
    candidate = copy.deepcopy(document)
    kind = operation.get("kind")
    if kind == "add-member":
        parent, token = _pointer_parent(candidate, operation["pointer"])
        if type(parent) is not dict or token in parent:
            raise ContractError(
                "add-member requires an existing object parent and an absent member"
            )
        parent[token] = copy.deepcopy(operation["value"])
    elif kind == "replace-value":
        current = _pointer_get(candidate, operation["pointer"])
        if current != operation["before"]:
            raise ContractError("replace-value before mismatch")
        if current == operation["value"]:
            raise ContractError("replace-value must change the value")
        _pointer_set_existing(
            candidate, operation["pointer"], copy.deepcopy(operation["value"])
        )
    elif kind == "swap-values":
        first = _pointer_get(candidate, operation["firstPointer"])
        second = _pointer_get(candidate, operation["secondPointer"])
        if first != operation["firstBefore"] or second != operation["secondBefore"]:
            raise ContractError("swap-values before mismatch")
        if first == second or operation["firstPointer"] == operation["secondPointer"]:
            raise ContractError("swap-values must change two distinct values")
        _pointer_set_existing(
            candidate, operation["firstPointer"], copy.deepcopy(second)
        )
        _pointer_set_existing(
            candidate, operation["secondPointer"], copy.deepcopy(first)
        )
    else:
        raise ContractError(f"unknown interface mutation kind: {kind}")
    if candidate == document:
        raise ContractError("interface mutation is a no-op")
    return candidate


def interface_projection_fingerprints(value: dict[str, Any]) -> dict[str, str]:
    subject = domain_fingerprint(SUBJECT_DOMAIN, value["subject"])
    semantic = domain_fingerprint(SEMANTIC_DOMAIN, value["semantic"])
    compatibility = domain_fingerprint(
        COMPATIBILITY_DOMAIN,
        {
            "contractVersion": value["contractVersion"],
            "semanticFingerprint": semantic,
            "subjectFingerprint": subject,
        },
    )
    return {
        "subjectFingerprint": subject,
        "semanticFingerprint": semantic,
        "compatibilityFingerprint": compatibility,
    }


@dataclass(frozen=True)
class _InterfaceMutationOps:
    apply: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    fingerprints: Callable[[dict[str, Any]], dict[str, str]]


_DEFAULT_INTERFACE_MUTATION_OPS = _InterfaceMutationOps(
    apply=apply_interface_operation,
    fingerprints=interface_projection_fingerprints,
)


def _evaluate_interface_mutation(
    base: dict[str, Any],
    operation: dict[str, Any],
    schema_valid: Callable[[dict[str, Any]], bool],
    ops: _InterfaceMutationOps,
) -> dict[str, Any]:
    candidate = ops.apply(base, operation)
    if not schema_valid(candidate):
        return {"kind": "schema-invalid"}
    base_actual = ops.fingerprints(base)
    candidate_actual = ops.fingerprints(candidate)
    delta = {
        key: "unchanged" if candidate_actual[key] == base_actual[key] else "changed"
        for key in base_actual
    }
    stored = (
        "consistent"
        if all(candidate.get(key) == value for key, value in candidate_actual.items())
        else "inconsistent"
    )
    return {
        "kind": "schema-valid",
        "fingerprintDelta": delta,
        "storedFingerprints": stored,
    }


def evaluate_interface_mutation(
    base: dict[str, Any],
    operation: dict[str, Any],
    schema_valid: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    return _evaluate_interface_mutation(
        base,
        operation,
        schema_valid,
        _DEFAULT_INTERFACE_MUTATION_OPS,
    )


def _jsonschema_validator(schema_path: Path):
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource

    schema = load_json(schema_path)
    registry = Registry()
    for candidate_path in schema_path.parent.glob("*.schema.json"):
        candidate = load_json(candidate_path)
        schema_id = candidate.get("$id")
        if schema_id:
            registry = registry.with_resource(
                schema_id, Resource.from_contents(candidate)
            )
    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
        registry=registry,
    )


def validate_interface_mutation_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    case_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/interface-evidence-mutation-v1.schema.json"
    )
    interface_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/interface-evidence-v1.schema.json"
    )
    passed = 0
    for case in vectors["mutations"]:
        case_validator.validate(case)
        actual = evaluate_interface_mutation(
            vectors["base"], case["operation"], interface_validator.is_valid
        )
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    return CheckSummary(passed=passed, total=len(vectors["mutations"]))


def validate_canonical_json_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    cases = vectors["canonicalJsonV1Cases"]
    passed = 0
    for case in cases["positive"]:
        actual = canonical_json_v1(case["value"])
        if actual != case["canonicalUtf8"]:
            raise AssertionError((case["name"], actual, case["canonicalUtf8"]))
        passed += 1
    constructions: dict[str, Callable[[], Any]] = {
        "float": lambda: 1.5,
        "nan": lambda: float("nan"),
        "positive-infinity": lambda: float("inf"),
        "negative-infinity": lambda: float("-inf"),
        "safe-integer-over": lambda: SAFE_INTEGER_MAX + 1,
        "safe-integer-under": lambda: -SAFE_INTEGER_MAX - 1,
        "unpaired-high-surrogate": lambda: "\ud800",
        "unpaired-low-surrogate": lambda: "\udfff",
        "tuple": lambda: (1,),
        "bytes": lambda: b"x",
        "non-string-object-key": lambda: {1: "x"},
    }
    for case in cases["negativeConstructions"]:
        try:
            canonical_json_v1(constructions[case["construction"]]())
        except (ContractError, UnicodeError):
            passed += 1
        else:
            raise AssertionError(
                f"canonical-json-v1 accepted negative construction: {case['name']}"
            )
    if len(cases["positive"]) != 8 or len(cases["negativeConstructions"]) != 11:
        raise AssertionError("canonical-json-v1 case counts drifted")
    return CheckSummary(passed=passed, total=19)


def validate_bundled_catalog_fixture(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    fixture = vectors["bundledCatalogFixture"]
    if canonical_json_v1(fixture["projection"]) != fixture["canonicalUtf8"]:
        raise AssertionError("bundled catalog canonical bytes drifted")
    if (
        domain_fingerprint(fixture["domain"], fixture["projection"])
        != fixture["fingerprint"]
    ):
        raise AssertionError("bundled catalog fingerprint drifted")
    if (
        fixture["fingerprint"]
        != vectors["base"]["semantic"]["bundledCatalogFingerprint"]
    ):
        raise AssertionError("bundled catalog is not bound to InterfaceEvidence")
    models = fixture["projection"]["models"]
    if models != sorted(models, key=lambda model: model["model"].encode("utf-8")):
        raise AssertionError("bundled catalog models are not sorted")
    for model in models:
        efforts = model["reasoningEfforts"]
        if efforts != sorted(efforts, key=lambda effort: effort.encode("utf-8")):
            raise AssertionError(
                f"bundled catalog efforts are not sorted: {model['model']}"
            )
    return CheckSummary(passed=1, total=1)


def classify_hook_output(event: str, value: Any) -> str:
    if type(value) is not dict:
        return "schema-invalid"
    common = {
        "continue",
        "stopReason",
        "suppressOutput",
        "systemMessage",
        "decision",
        "reason",
    }
    allowed = common | (
        {"hookSpecificOutput"} if event == "UserPromptSubmit" else set()
    )
    if set(value) - allowed:
        return "schema-invalid"
    if "continue" in value and type(value["continue"]) is not bool:
        return "schema-invalid"
    if "suppressOutput" in value and type(value["suppressOutput"]) is not bool:
        return "schema-invalid"
    for key in ("stopReason", "systemMessage", "reason"):
        if key in value and type(value[key]) is not str:
            return "schema-invalid"
    if "decision" in value and value["decision"] != "block":
        return "schema-invalid"
    if value.get("decision") == "block" and not value.get("reason", "").strip():
        return "invalid-empty-trimmed-reason"
    if "hookSpecificOutput" in value:
        hook = value["hookSpecificOutput"]
        if event != "UserPromptSubmit" or type(hook) is not dict:
            return "schema-invalid"
        if set(hook) - {"hookEventName", "additionalContext"}:
            return "schema-invalid"
        if hook.get("hookEventName") != "UserPromptSubmit":
            return "schema-invalid"
        if "additionalContext" in hook:
            additional_context = hook["additionalContext"]
            if type(additional_context) is not str:
                return "invalid-additional-context-type"
            if len(additional_context.encode("utf-8")) > 2_048:
                return "invalid-additional-context-size"
    return "valid"


def validate_hook_output_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    passed = 0
    for case in vectors["hookOutputCases"]:
        if "expectedUtf8Bytes" in case:
            actual_bytes = len(
                case["value"]["hookSpecificOutput"]["additionalContext"].encode("utf-8")
            )
            if actual_bytes != case["expectedUtf8Bytes"]:
                raise AssertionError(
                    (case["name"], actual_bytes, case["expectedUtf8Bytes"])
                )
        actual = classify_hook_output(case["event"], case["value"])
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    return CheckSummary(passed=passed, total=len(vectors["hookOutputCases"]))


def validate_interface_base_artifacts(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    base = vectors["base"]
    _jsonschema_validator(
        root / "docs/contracts/schemas/interface-evidence-v1.schema.json"
    ).validate(base)
    fingerprints = interface_projection_fingerprints(base)
    if any(base[name] != value for name, value in fingerprints.items()):
        raise AssertionError("InterfaceEvidence stored fingerprints drifted")
    compatibility_projection = {
        "contractVersion": base["contractVersion"],
        "semanticFingerprint": fingerprints["semanticFingerprint"],
        "subjectFingerprint": fingerprints["subjectFingerprint"],
    }
    expected_canonical = {
        "subjectUtf8": canonical_json_v1(base["subject"]),
        "semanticUtf8": canonical_json_v1(base["semantic"]),
        "compatibilityUtf8": canonical_json_v1(compatibility_projection),
    }
    if vectors["canonical"] != expected_canonical:
        raise AssertionError("InterfaceEvidence canonical artifacts drifted")
    passed = 1
    schema_dir = root / "docs/contracts/schemas"
    for name, record in base["semantic"]["machineSchemas"].items():
        actual = hashlib.sha256(
            (schema_dir / f"{name}.schema.json").read_bytes()
        ).hexdigest()
        if record != {"schemaId": name, "schemaSha256": actual}:
            raise AssertionError((name, record, actual))
        passed += 1
    if len(base["semantic"]["machineSchemas"]) != 11:
        raise AssertionError("unexpected machineSchemas cardinality")
    return CheckSummary(passed=passed, total=12)


_CONFIG_FIELDS = {
    "allowAppshots",
    "allowManagedHooksOnly",
    "allowRemoteControl",
    "allowedApprovalPolicies",
    "allowedApprovalsReviewers",
    "allowedPermissionProfiles",
    "allowedSandboxModes",
    "allowedWebSearchModes",
    "allowedWindowsSandboxImplementations",
    "computerUse",
    "defaultPermissions",
    "enforceResidency",
    "featureRequirements",
    "hooks",
    "models",
    "network",
}
_SET_FIELDS = {
    "allowedApprovalPolicies",
    "allowedApprovalsReviewers",
    "allowedSandboxModes",
    "allowedWebSearchModes",
    "allowedWindowsSandboxImplementations",
}
_ENUM_FIELDS = {
    "allowedApprovalsReviewers": {"user", "auto_review", "guardian_subagent"},
    "allowedSandboxModes": {"read-only", "workspace-write", "danger-full-access"},
    "allowedWebSearchModes": {"disabled", "cached", "indexed", "live"},
    "allowedWindowsSandboxImplementations": {"elevated", "unelevated"},
}
_NETWORK_SET_FIELDS = {"allowUnixSockets", "allowedDomains", "deniedDomains"}
_TOP_BOOLEAN_FIELDS = {"allowAppshots", "allowManagedHooksOnly", "allowRemoteControl"}
_COMPUTER_USE_FIELDS = {"allowLockedComputerUse"}
_MODELS_FIELDS = {"newThread"}
_NEW_THREAD_FIELDS = {"model", "modelReasoningEffort", "serviceTier"}
_NETWORK_FIELDS = {
    "allowLocalBinding",
    "allowUnixSockets",
    "allowUpstreamProxy",
    "allowedDomains",
    "dangerouslyAllowAllUnixSockets",
    "dangerouslyAllowNonLoopbackProxy",
    "deniedDomains",
    "domains",
    "enabled",
    "httpPort",
    "managedAllowedDomainsOnly",
    "socksPort",
    "unixSockets",
}
_NETWORK_BOOLEAN_FIELDS = {
    "allowLocalBinding",
    "allowUpstreamProxy",
    "dangerouslyAllowAllUnixSockets",
    "dangerouslyAllowNonLoopbackProxy",
    "enabled",
    "managedAllowedDomainsOnly",
}
_HOOK_EVENTS = {
    "PermissionRequest",
    "PostCompact",
    "PostToolUse",
    "PreCompact",
    "PreToolUse",
    "SessionStart",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
}
_HOOK_FIELDS = _HOOK_EVENTS | {"managedDir", "windowsManagedDir"}
_HOOK_GROUP_FIELDS = {"hooks", "matcher"}
_COMMAND_HANDLER_FIELDS = {
    "type",
    "async",
    "command",
    "commandWindows",
    "statusMessage",
    "timeoutSec",
}
_GRANULAR_KEYS = {
    "mcp_elicitations",
    "rules",
    "sandbox_approval",
    "request_permissions",
    "skill_approval",
}
_GRANULAR_REQUIRED_KEYS = {"mcp_elicitations", "rules", "sandbox_approval"}
_GRANULAR_DEFAULT_KEYS = {"request_permissions", "skill_approval"}


def _config_failure(phase: str, error_code: str, detail: str) -> None:
    raise ConfigStageError(phase, error_code, detail)


def _utf8_size(value: str, field: str, limit: int = 4_096) -> None:
    if not value or len(value.encode("utf-8")) > limit:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field} bytes"
        )


def _reject_unknown_members(
    value: dict[str, Any], allowed: set[str], field: str
) -> None:
    unknown = set(value) - allowed
    if unknown:
        _config_failure(
            "structure",
            "MANAGED_REQUIREMENT_UNSUPPORTED",
            f"unknown {field} fields: {sorted(unknown)}",
        )


def _validate_named_boolean_map(value: Any, field: str) -> None:
    if type(value) is not dict or len(value) > 2_048:
        _config_failure(
            "structure",
            "MANAGED_REQUIREMENT_MALFORMED",
            f"{field} must be a bounded object",
        )
    for key, item in value.items():
        if type(key) is not str or type(item) is not bool:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field} member"
            )
        _utf8_size(key, f"{field} property name")


def _validate_string_set(value: Any, field: str) -> None:
    if type(value) is not list or len(value) > 2_048:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
        )
    for item in value:
        if type(item) is not str:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field} member"
            )
        _utf8_size(item, f"{field} member")


def _validate_domain_map(value: Any, field: str) -> None:
    if type(value) is not dict or len(value) > 2_048:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
        )
    for key, item in value.items():
        if (
            type(key) is not str
            or type(item) is not str
            or item not in {"allow", "deny"}
        ):
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field} member"
            )
        _utf8_size(key, f"{field} property name")


def _validate_hook_handler(value: Any) -> None:
    if type(value) is not dict or "type" not in value:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid hook handler"
        )
    handler_type = value["type"]
    if type(handler_type) is not str:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid hook handler type"
        )
    if handler_type == "command":
        _reject_unknown_members(value, _COMMAND_HANDLER_FIELDS, "hook handler")
        if not {"type", "async", "command"} <= set(value):
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", "incomplete command hook"
            )
        if type(value["async"]) is not bool or type(value["command"]) is not str:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid command hook"
            )
        _utf8_size(value["command"], "hook command", 65_536)
        for field in ("commandWindows", "statusMessage"):
            if field in value and value[field] is not None:
                if type(value[field]) is not str:
                    _config_failure(
                        "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
                    )
                _utf8_size(value[field], field)
        if "timeoutSec" in value and value["timeoutSec"] is not None:
            timeout = value["timeoutSec"]
            if type(timeout) is not int or not 0 <= timeout <= SAFE_INTEGER_MAX:
                _config_failure(
                    "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid timeoutSec"
                )
        return
    if handler_type in {"prompt", "agent"}:
        _reject_unknown_members(value, {"type"}, "hook handler")
        return
    _config_failure(
        "structure", "MANAGED_REQUIREMENT_MALFORMED", "unknown hook handler type"
    )


def _validate_hooks(value: Any) -> None:
    if type(value) is not dict:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "hooks must be an object"
        )
    _reject_unknown_members(value, _HOOK_FIELDS, "hooks")
    if not _HOOK_EVENTS <= set(value):
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "hooks omit required events"
        )
    for field in ("managedDir", "windowsManagedDir"):
        if field in value and value[field] is not None:
            if type(value[field]) is not str:
                _config_failure(
                    "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
                )
            _utf8_size(value[field], field)
    for event in _HOOK_EVENTS:
        groups = value[event]
        if type(groups) is not list or len(groups) > 256:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {event} groups"
            )
        for group in groups:
            if type(group) is not dict:
                _config_failure(
                    "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid hook group"
                )
            _reject_unknown_members(group, _HOOK_GROUP_FIELDS, "hook group")
            if (
                "hooks" not in group
                or type(group["hooks"]) is not list
                or len(group["hooks"]) > 256
            ):
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "invalid hook group handlers",
                )
            if "matcher" in group and group["matcher"] is not None:
                if type(group["matcher"]) is not str:
                    _config_failure(
                        "structure",
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "invalid hook matcher",
                    )
                _utf8_size(group["matcher"], "hook matcher")
            for handler in group["hooks"]:
                _validate_hook_handler(handler)


def _validate_models(value: Any) -> None:
    if type(value) is not dict:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "models must be an object"
        )
    _reject_unknown_members(value, _MODELS_FIELDS, "models")
    new_thread = value.get("newThread")
    if new_thread is None:
        return
    if type(new_thread) is not dict:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "newThread must be an object"
        )
    _reject_unknown_members(new_thread, _NEW_THREAD_FIELDS, "newThread")
    for field, item in new_thread.items():
        if item is None:
            continue
        if type(item) is not str:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
            )
        _utf8_size(item, field)


def _validate_network(value: Any) -> None:
    if type(value) is not dict:
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "network must be an object"
        )
    _reject_unknown_members(value, _NETWORK_FIELDS, "network")
    for field in _NETWORK_BOOLEAN_FIELDS:
        if (
            field in value
            and value[field] is not None
            and type(value[field]) is not bool
        ):
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
            )
    for field in ("httpPort", "socksPort"):
        if field in value and value[field] is not None:
            port = value[field]
            if type(port) is not int or not 0 <= port <= 65_535:
                _config_failure(
                    "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
                )
    for field in _NETWORK_SET_FIELDS:
        if field in value and value[field] is not None:
            _validate_string_set(value[field], field)
    for field in ("domains", "unixSockets"):
        if field in value and value[field] is not None:
            _validate_domain_map(value[field], field)


def _validate_source_structure(requirements: Any) -> None:
    if requirements is None:
        return
    if type(requirements) is not dict:
        _config_failure(
            "structure",
            "MANAGED_REQUIREMENT_MALFORMED",
            "requirements must be object or null",
        )
    unknown = set(requirements) - _CONFIG_FIELDS
    if unknown:
        _config_failure(
            "structure",
            "MANAGED_REQUIREMENT_UNSUPPORTED",
            f"unknown protective fields: {sorted(unknown)}",
        )
    for field in _TOP_BOOLEAN_FIELDS:
        value = requirements.get(field)
        if value is not None and type(value) is not bool:
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
            )
    for field, allowed in _ENUM_FIELDS.items():
        value = requirements.get(field)
        if value is None:
            continue
        if type(value) is not list or any(
            type(item) is not str or item not in allowed for item in value
        ):
            _config_failure(
                "structure", "MANAGED_REQUIREMENT_MALFORMED", f"invalid {field}"
            )
    approvals = requirements.get("allowedApprovalPolicies")
    if approvals is not None:
        if type(approvals) is not list:
            _config_failure(
                "structure",
                "MANAGED_REQUIREMENT_MALFORMED",
                "approval allowlist must be an array",
            )
        for policy in approvals:
            if type(policy) is str:
                if policy not in {"untrusted", "on-request", "never"}:
                    _config_failure(
                        "structure",
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "unknown approval policy",
                    )
                continue
            if (
                type(policy) is not dict
                or "granular" not in policy
                or type(policy["granular"]) is not dict
            ):
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "invalid granular approval",
                )
            _reject_unknown_members(policy, {"granular"}, "approval policy")
            granular = policy["granular"]
            _reject_unknown_members(granular, _GRANULAR_KEYS, "granular approval")
            if (
                not _GRANULAR_REQUIRED_KEYS <= set(granular)
                or any(
                    type(granular[key]) is not bool for key in _GRANULAR_REQUIRED_KEYS
                )
                or any(
                    key in granular
                    and granular[key] is not None
                    and type(granular[key]) is not bool
                    for key in _GRANULAR_DEFAULT_KEYS
                )
            ):
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "invalid granular approval flags",
                )
    for field in ("allowedPermissionProfiles", "featureRequirements"):
        value = requirements.get(field)
        if value is not None:
            _validate_named_boolean_map(value, field)
    computer_use = requirements.get("computerUse")
    if computer_use is not None:
        if type(computer_use) is not dict:
            _config_failure(
                "structure",
                "MANAGED_REQUIREMENT_MALFORMED",
                "computerUse must be an object",
            )
        _reject_unknown_members(computer_use, _COMPUTER_USE_FIELDS, "computerUse")
        locked = computer_use.get("allowLockedComputerUse")
        if locked is not None and type(locked) is not bool:
            _config_failure(
                "structure",
                "MANAGED_REQUIREMENT_MALFORMED",
                "invalid allowLockedComputerUse",
            )
    default_permissions = requirements.get("defaultPermissions")
    if default_permissions is not None:
        if type(default_permissions) is not str:
            _config_failure(
                "structure",
                "MANAGED_REQUIREMENT_MALFORMED",
                "invalid defaultPermissions",
            )
        _utf8_size(default_permissions, "defaultPermissions")
    residency = requirements.get("enforceResidency")
    if residency is not None and residency != "us":
        _config_failure(
            "structure", "MANAGED_REQUIREMENT_MALFORMED", "invalid enforceResidency"
        )
    hooks = requirements.get("hooks")
    if hooks is not None:
        _validate_hooks(hooks)
    models = requirements.get("models")
    if models is not None:
        _validate_models(models)
    network = requirements.get("network")
    if network is not None:
        _validate_network(network)


def _remove_optional_nulls(value: Any) -> Any:
    if type(value) is dict:
        return {
            key: _remove_optional_nulls(item)
            for key, item in value.items()
            if item is not None
        }
    if type(value) is list:
        return [_remove_optional_nulls(item) for item in value]
    return copy.deepcopy(value)


def _normalize_set(values: list[Any]) -> list[Any]:
    by_canonical = {canonical_json_v1(value): value for value in values}
    return [
        copy.deepcopy(by_canonical[key])
        for key in sorted(by_canonical, key=lambda item: item.encode("utf-8"))
    ]


def normalize_config_requirements(requirements: Any) -> Any:
    _validate_source_structure(requirements)
    if requirements is None:
        return None
    network_source = requirements.get("network")
    if type(network_source) is dict and type(network_source.get("domains")) is dict:
        domains = network_source["domains"]
        canonical_allowed = {
            name for name, decision in domains.items() if decision == "allow"
        }
        canonical_denied = {
            name for name, decision in domains.items() if decision == "deny"
        }
        for legacy_field, canonical in (
            ("allowedDomains", canonical_allowed),
            ("deniedDomains", canonical_denied),
        ):
            legacy = network_source.get(legacy_field)
            if legacy is not None and set(legacy) != canonical:
                _config_failure(
                    "normalization",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    f"network {legacy_field} disagrees with domains",
                )
    if type(network_source) is dict and type(network_source.get("unixSockets")) is dict:
        canonical_sockets = {
            name
            for name, decision in network_source["unixSockets"].items()
            if decision == "allow"
        }
        legacy_sockets = network_source.get("allowUnixSockets")
        if legacy_sockets is not None and set(legacy_sockets) != canonical_sockets:
            _config_failure(
                "normalization",
                "MANAGED_REQUIREMENT_MALFORMED",
                "network allowUnixSockets disagrees with unixSockets",
            )
    normalized = _remove_optional_nulls(requirements)
    for policy in normalized.get("allowedApprovalPolicies", []):
        if type(policy) is dict:
            granular = policy["granular"]
            for key in sorted(_GRANULAR_DEFAULT_KEYS):
                granular.setdefault(key, False)
    for field in _SET_FIELDS:
        if field in normalized:
            normalized[field] = _normalize_set(normalized[field])
    network = normalized.get("network")
    if type(network) is dict:
        for field in _NETWORK_SET_FIELDS:
            if field in network:
                network[field] = _normalize_set(network[field])
    return normalized


def _profile_for_context(root: Path, context: dict[str, Any]) -> dict[str, Any]:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    matches = [
        case["profile"]
        for case in vectors["cases"]
        if case["name"] == context["profileCase"]
    ]
    if len(matches) != 1:
        raise ContractError(f"unknown profileCase: {context['profileCase']}")
    return matches[0]


def _known_features(root: Path) -> set[str]:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    return {
        feature
        for case in vectors["cases"]
        for feature in case["profile"]["disabledFeatures"]
    }


def _requirements_compatibility(
    normalized: Any, context: dict[str, Any], root: Path
) -> dict[str, Any]:
    if normalized is None:
        return {"status": "compatible"}
    profile = _profile_for_context(root, context)
    features = normalized.get("featureRequirements", {})
    known_features = _known_features(root)
    if any(feature not in known_features for feature in features):
        return {"status": "rejected", "errorCode": "MANAGED_REQUIREMENT_UNSUPPORTED"}

    incompatible = False
    approvals = normalized.get("allowedApprovalPolicies")
    if approvals is not None and "never" not in approvals:
        incompatible = True
    sandbox_modes = normalized.get("allowedSandboxModes")
    if sandbox_modes is not None and profile["sandboxMode"] not in sandbox_modes:
        incompatible = True
    search_modes = normalized.get("allowedWebSearchModes")
    if search_modes is not None and "disabled" not in search_modes:
        incompatible = True
    permission_profiles = normalized.get("allowedPermissionProfiles")
    if (
        permission_profiles is not None
        and permission_profiles.get(profile["permissionProfileId"]) is not True
    ):
        incompatible = True
    default_permissions = normalized.get("defaultPermissions")
    if (
        default_permissions is not None
        and default_permissions != profile["permissionProfileId"]
    ):
        incompatible = True
    if "enforceResidency" in normalized:
        incompatible = True
    new_thread = normalized.get("models", {}).get("newThread", {})
    selected_pair = context["selectedPair"]
    if "model" in new_thread and new_thread["model"] != selected_pair["model"]:
        incompatible = True
    if (
        "modelReasoningEffort" in new_thread
        and new_thread["modelReasoningEffort"] != selected_pair["reasoningEffort"]
    ):
        incompatible = True
    if new_thread.get("serviceTier"):
        incompatible = True
    hooks = normalized.get("hooks")
    if hooks is not None:
        for name, value in hooks.items():
            if name in {"managedDir", "windowsManagedDir"}:
                if value:
                    incompatible = True
            elif value:
                incompatible = True
    disabled = set(profile["disabledFeatures"])
    if any(
        expected is not (feature not in disabled)
        for feature, expected in features.items()
    ):
        incompatible = True
    network = normalized.get("network", {})
    if any(
        network.get(field) is True
        for field in (
            "enabled",
            "allowLocalBinding",
            "allowUpstreamProxy",
            "dangerouslyAllowAllUnixSockets",
            "dangerouslyAllowNonLoopbackProxy",
        )
    ):
        incompatible = True
    if any(network.get(field, 0) != 0 for field in ("httpPort", "socksPort")):
        incompatible = True
    if incompatible:
        return {"status": "rejected", "errorCode": "MANAGED_REQUIREMENT_INCOMPATIBLE"}
    return {"status": "compatible"}


def _validate_normalized_structure(normalized: Any, _root: Path) -> None:
    _validate_source_structure(normalized)
    if normalized is not None:
        stack = [normalized]
        while stack:
            current = stack.pop()
            if type(current) is dict:
                if any(item is None for item in current.values()):
                    _config_failure(
                        "structure",
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "normalized requirements retain optional null",
                    )
                stack.extend(current.values())
            elif type(current) is list:
                if any(item is None for item in current):
                    _config_failure(
                        "structure",
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "normalized requirements retain array null",
                    )
                stack.extend(current)
        for field in _SET_FIELDS:
            values = normalized.get(field)
            if values is not None and len(
                {canonical_json_v1(item) for item in values}
            ) != len(values):
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    f"duplicate normalized {field}",
                )
        network = normalized.get("network", {})
        for field in _NETWORK_SET_FIELDS:
            values = network.get(field)
            if values is not None and len(
                {canonical_json_v1(item) for item in values}
            ) != len(values):
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    f"duplicate normalized {field}",
                )
        for policy in normalized.get("allowedApprovalPolicies", []):
            if type(policy) is dict and set(policy["granular"]) != _GRANULAR_KEYS:
                _config_failure(
                    "structure",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "normalized granular approval is incomplete",
                )


@dataclass(frozen=True)
class _ConfigOps:
    normalize: Callable[[Any], Any]
    validate_normalized: Callable[[Any, Path], None]
    compatibility: Callable[[Any, dict[str, Any], Path], dict[str, Any]]


_DEFAULT_CONFIG_OPS = _ConfigOps(
    normalize=normalize_config_requirements,
    validate_normalized=_validate_normalized_structure,
    compatibility=_requirements_compatibility,
)


def _evaluate_config_requirements(
    source: Any,
    context: dict[str, Any],
    *,
    root: Path,
    ops: _ConfigOps,
) -> ConfigEvaluation:
    try:
        if (
            type(source) is not dict
            or set(source) != {"kind", "value"}
            or type(source.get("kind")) is not str
            or source["kind"] not in {"parsed", "raw-utf8"}
        ):
            _config_failure(
                "envelope", "MANAGED_REQUIREMENT_MALFORMED", "invalid source wrapper"
            )
        if source["kind"] == "raw-utf8":
            raw = source["value"]
            if type(raw) is not str:
                _config_failure(
                    "strict-parse",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "raw source must be UTF-8 text",
                )
            try:
                raw_bytes = raw.encode("utf-8")
            except UnicodeError as error:
                _config_failure(
                    "strict-parse", "MANAGED_REQUIREMENT_MALFORMED", str(error)
                )
            if len(raw_bytes) > RAW_DOCUMENT_BYTES_MAX:
                _config_failure(
                    "raw-guards",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "raw document byte limit exceeded",
                )
            try:
                envelope = _strict_json_decode(raw)
            except (
                ContractError,
                json.JSONDecodeError,
                UnicodeError,
                RecursionError,
            ) as error:
                _config_failure(
                    "strict-parse", "MANAGED_REQUIREMENT_MALFORMED", str(error)
                )
        else:
            envelope = source["value"]
        try:
            _validate_and_measure_loaded_json(
                envelope,
                max_nodes=JSON_TREE_NODES_MAX,
                max_depth=JSON_TREE_DEPTH_MAX,
            )
        except JsonTreeGuardError as error:
            _config_failure(
                "raw-guards",
                "MANAGED_REQUIREMENT_MALFORMED",
                str(error),
            )
        except (ContractError, UnicodeError) as error:
            _config_failure(
                "strict-parse" if source["kind"] == "raw-utf8" else "structure",
                "MANAGED_REQUIREMENT_MALFORMED",
                str(error),
            )
        if source["kind"] == "parsed":
            try:
                parsed_bytes = canonical_json_v1(envelope).encode("utf-8")
            except (ContractError, UnicodeError) as error:
                _config_failure(
                    "raw-guards", "MANAGED_REQUIREMENT_MALFORMED", str(error)
                )
            if len(parsed_bytes) > RAW_DOCUMENT_BYTES_MAX:
                _config_failure(
                    "raw-guards",
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "parsed document byte limit exceeded",
                )
        if type(envelope) is not dict or "requirements" not in envelope:
            _config_failure(
                "envelope",
                "MANAGED_REQUIREMENT_MALFORMED",
                "requirements envelope must contain requirements",
            )
        normalized = ops.normalize(envelope["requirements"])
        ops.validate_normalized(normalized, root)
        normalized_metrics = measure_json_value_tree(normalized)
        if (
            normalized_metrics.nodes > JSON_TREE_NODES_MAX
            or normalized_metrics.depth > JSON_TREE_DEPTH_MAX
        ):
            _config_failure(
                "normalized-guards",
                "MANAGED_REQUIREMENT_MALFORMED",
                "normalized JSON value tree limit exceeded",
            )
        try:
            canonical_utf8 = canonical_json_v1(normalized)
        except (ContractError, UnicodeError) as error:
            _config_failure(
                "canonicalization", "MANAGED_REQUIREMENT_MALFORMED", str(error)
            )
        if len(canonical_utf8.encode("utf-8")) > NORMALIZED_DOCUMENT_BYTES_MAX:
            _config_failure(
                "normalized-guards",
                "MANAGED_REQUIREMENT_MALFORMED",
                "normalized byte limit exceeded",
            )
        normalization = {
            "status": "complete",
            "normalized": normalized,
            "canonicalUtf8": canonical_utf8,
            "fingerprint": domain_fingerprint(REQUIREMENTS_DOMAIN, normalized),
        }
        compatibility = ops.compatibility(normalized, context, root)
        return ConfigEvaluation(
            normalization=normalization, compatibility=compatibility
        )
    except ConfigStageError as error:
        return ConfigEvaluation(
            normalization={
                "status": "rejected",
                "phase": error.phase,
                "errorCode": error.error_code,
            },
            compatibility={"status": "not-run"},
        )


def evaluate_config_requirements(
    source: Any, context: dict[str, Any], *, root: Path = ROOT
) -> ConfigEvaluation:
    return _evaluate_config_requirements(
        source,
        context,
        root=root,
        ops=_DEFAULT_CONFIG_OPS,
    )


def config_evaluation_to_dict(actual: ConfigEvaluation) -> dict[str, Any]:
    return {
        "normalization": copy.deepcopy(actual.normalization),
        "compatibility": copy.deepcopy(actual.compatibility),
    }


def compare_config_expected(actual: ConfigEvaluation, expected: dict[str, Any]) -> None:
    actual_value = config_evaluation_to_dict(actual)
    if actual_value != expected:
        raise AssertionError({"actual": actual_value, "expected": expected})


def _load_config_vectors_exact(root: Path) -> dict[str, Any]:
    vectors = load_json(root / "docs/contracts/vectors/config-requirements-v1.json")
    if (
        type(vectors) is not dict
        or set(vectors)
        != {
            "schemaVersion",
            "contexts",
            "cycle7Cases",
            "cycle8Cases",
            "cases",
        }
        or type(vectors.get("schemaVersion")) is not int
        or vectors["schemaVersion"] != 1
    ):
        raise AssertionError("config requirements vector root is not exact")
    return vectors


def validate_config_expected_independence(root: Path = ROOT) -> CheckSummary:
    vectors_path = root / "docs/contracts/vectors/config-requirements-v1.json"
    child_path = root / "docs/contracts/vectors/child-profile-v1.json"
    vectors = _load_config_vectors_exact(root)
    case = next(
        item for item in vectors["cases"] if item["name"] == "requirements-empty"
    )
    context = vectors["contexts"][case["contextRef"]]
    baseline = evaluate_config_requirements(case["source"], context, root=root)

    with tempfile.TemporaryDirectory() as directory:
        temporary_root = Path(directory)
        for source_path in (vectors_path, child_path):
            relative = source_path.relative_to(root)
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)

        temporary_vectors_path = (
            temporary_root / "docs/contracts/vectors/config-requirements-v1.json"
        )
        poisoned_vectors = _load_config_vectors_exact(temporary_root)
        poisoned_case = next(
            item
            for item in poisoned_vectors["cases"]
            if item["name"] == "requirements-empty"
        )
        poisoned_case["expected"]["normalization"]["fingerprint"] = "0" * 64
        temporary_vectors_path.write_text(
            json.dumps(poisoned_vectors, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        repeated = evaluate_config_requirements(
            poisoned_case["source"],
            poisoned_vectors["contexts"][poisoned_case["contextRef"]],
            root=temporary_root,
        )
        if repeated != baseline:
            raise AssertionError("config evaluator changed after expected poisoning")
        try:
            compare_config_expected(repeated, poisoned_case["expected"])
        except AssertionError:
            pass
        else:
            raise AssertionError("config comparator accepted poisoned expected")
    return CheckSummary(passed=2, total=2)


def validate_config_requirement_cases(root: Path = ROOT) -> CheckSummary:
    vectors = _load_config_vectors_exact(root)
    case_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/config-requirements-vector-case-v1.schema.json"
    )
    for case in vectors["cases"]:
        case_validator.validate(case)
    case_names = [case["name"] for case in vectors["cases"]]
    seen_names: set[str] = set()
    for case_name in case_names:
        if case_name in seen_names:
            raise AssertionError(f"duplicate config case name: {case_name}")
        seen_names.add(case_name)
    for context_name, context in vectors["contexts"].items():
        if type(context) is not dict or set(context) != {"profileCase", "selectedPair"}:
            raise AssertionError(f"config context is not closed: {context_name}")
        if context["profileCase"] not in {"classifier", "reader", "writer"}:
            raise AssertionError(f"unknown config profile case: {context_name}")
        selected_pair = context["selectedPair"]
        if (
            type(selected_pair) is not dict
            or set(selected_pair) != {"model", "reasoningEffort"}
            or not _bounded_string(selected_pair["model"], 128)
            or selected_pair["reasoningEffort"]
            not in {"low", "medium", "high", "xhigh", "max"}
        ):
            raise AssertionError(f"invalid config selected pair: {context_name}")
    passed = 0
    for case in vectors["cases"]:
        if type(case) is not dict or set(case) != {
            "name",
            "contextRef",
            "source",
            "expected",
        }:
            raise AssertionError(f"config case is not closed: {case.get('name')}")
        source = case["source"]
        if (
            type(source) is not dict
            or set(source) != {"kind", "value"}
            or source["kind"] not in {"parsed", "raw-utf8"}
            or (source["kind"] == "raw-utf8" and type(source["value"]) is not str)
        ):
            raise AssertionError(f"invalid config source wrapper: {case['name']}")
        expected = case["expected"]
        if type(expected) is not dict or set(expected) != {
            "normalization",
            "compatibility",
        }:
            raise AssertionError(
                f"config expected result is not closed: {case['name']}"
            )
        if case["contextRef"] not in vectors["contexts"]:
            raise AssertionError(f"unknown contextRef: {case['contextRef']}")
        actual = evaluate_config_requirements(
            case["source"], vectors["contexts"][case["contextRef"]], root=root
        )
        compare_config_expected(actual, case["expected"])
        passed += 1
    return CheckSummary(passed=passed, total=len(vectors["cases"]))


def validate_config_error_cases(root: Path = ROOT) -> dict[str, CheckSummary]:
    vectors = _load_config_vectors_exact(root)
    cases = {case["name"]: case for case in vectors["cases"]}
    error_names = {
        "requirements-missing",
        "unknown-protective-field",
        "empty-approval-allowlist",
        "unknown-feature",
        "network-legacy-conflict",
        "approval-mismatch",
        "sandbox-mismatch",
        "search-mismatch",
        "profile-mismatch",
        "model-mismatch",
        "effort-mismatch",
        "nonempty-managed-hooks",
        "unknown-enum",
        "duplicate-key-raw-bytes",
    }
    if not error_names <= set(cases):
        raise AssertionError("config error case set is incomplete")
    passed = 0
    excluding_raw = 0
    for name in sorted(error_names):
        case = cases[name]
        actual = evaluate_config_requirements(
            case["source"], vectors["contexts"][case["contextRef"]], root=root
        )
        compare_config_expected(actual, case["expected"])
        passed += 1
        if name != "duplicate-key-raw-bytes":
            excluding_raw += 1
    return {
        "all": CheckSummary(passed=passed, total=14),
        "excluding-raw-duplicate": CheckSummary(passed=excluding_raw, total=13),
    }


def validate_config_metamorphic_cases(root: Path = ROOT) -> CheckSummary:
    vectors = _load_config_vectors_exact(root)
    cases = {case["name"]: case for case in vectors["cases"]}
    reader = vectors["contexts"]["reader-luna-medium"]

    def evaluate(name: str, context: dict[str, Any] = reader) -> ConfigEvaluation:
        return evaluate_config_requirements(cases[name]["source"], context, root=root)

    passed = 0
    empty = evaluate("requirements-empty")
    optional_null = evaluate("optional-null-equals-absent")
    if empty.normalization != optional_null.normalization:
        raise AssertionError("optional null is not equivalent to absence")
    passed += 1

    requirements_null = evaluate("requirements-null")
    if requirements_null.normalization == empty.normalization:
        raise AssertionError("requirements null collapsed into empty object")
    passed += 1

    finite_source = copy.deepcopy(cases["finite-enum-natural-set"]["source"])
    finite_source["value"]["requirements"]["allowedWebSearchModes"].reverse()
    if (
        evaluate_config_requirements(finite_source, reader, root=root).normalization
        != evaluate("finite-enum-natural-set").normalization
    ):
        raise AssertionError("finite set permutation changed normalization")
    passed += 1

    duplicate_source = copy.deepcopy(cases["finite-enum-natural-set"]["source"])
    duplicate_source["value"]["requirements"]["allowedWebSearchModes"].append(
        "disabled"
    )
    if (
        evaluate_config_requirements(duplicate_source, reader, root=root).normalization
        != evaluate("finite-enum-natural-set").normalization
    ):
        raise AssertionError("finite set duplicate changed normalization")
    passed += 1

    granular_source = copy.deepcopy(cases["granular-defaults"]["source"])
    granular = granular_source["value"]["requirements"]["allowedApprovalPolicies"][0][
        "granular"
    ]
    granular["request_permissions"] = False
    granular["skill_approval"] = False
    if (
        evaluate_config_requirements(granular_source, reader, root=root).normalization
        != evaluate("granular-defaults").normalization
    ):
        raise AssertionError("explicit false granular defaults changed normalization")
    passed += 1

    normalized_count = 0
    for case in vectors["cases"]:
        actual = evaluate_config_requirements(
            case["source"], vectors["contexts"][case["contextRef"]], root=root
        )
        if actual.normalization["status"] != "complete":
            continue
        normalized_count += 1
        value = actual.normalization["normalized"]
        if normalize_config_requirements(value) != value:
            raise AssertionError(f"normalization is not idempotent: {case['name']}")
    if normalized_count != 17:
        raise AssertionError(f"expected 17 normalizable cases, got {normalized_count}")
    passed += 1

    writer_case = cases["writer-limits"]
    writer_actual = evaluate_config_requirements(
        writer_case["source"], vectors["contexts"]["writer-terra-high"], root=root
    )
    reader_actual = evaluate_config_requirements(
        writer_case["source"], reader, root=root
    )
    if writer_actual.normalization != reader_actual.normalization:
        raise AssertionError("context changed normalization artifacts")
    if writer_actual.compatibility == reader_actual.compatibility:
        raise AssertionError("context substitution did not exercise compatibility")
    passed += 1

    recipes = load_json(
        root / "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
    )
    recipe = next(
        item
        for item in recipes["recipes"]
        if item["name"] == "finite-enum-deduplication"
    )
    at_limit = copy.deepcopy(recipe["seed"])
    target = at_limit["allowedSandboxModes"]
    target.append(recipe["atLimit"])
    over_limit = copy.deepcopy(at_limit)
    over_limit["allowedSandboxModes"].append(recipe["overLimit"])
    if normalize_config_requirements(at_limit) != normalize_config_requirements(
        over_limit
    ):
        raise AssertionError(
            "finite-enum recipe did not deduplicate the over-limit construction"
        )
    passed += 1

    return CheckSummary(passed=passed, total=8)


def validate_config_cycle6_regressions(root: Path = ROOT) -> CheckSummary:
    vectors = _load_config_vectors_exact(root)
    context = vectors["contexts"]["reader-luna-medium"]
    empty_hooks = {event: [] for event in _HOOK_EVENTS}
    passed = 0

    def evaluate(requirements: Any, **neighbors: Any) -> ConfigEvaluation:
        return evaluate_config_requirements(
            {
                "kind": "parsed",
                "value": {"requirements": requirements, **neighbors},
            },
            context,
            root=root,
        )

    if evaluate({}, diagnostic=True).normalization["status"] != "complete":
        raise AssertionError("config envelope neighbor was not ignored")
    passed += 1
    missing = evaluate_config_requirements(
        {"kind": "parsed", "value": {"diagnostic": True}}, context, root=root
    )
    if missing.normalization.get("phase") != "envelope":
        raise AssertionError("missing requirements did not fail at envelope")
    passed += 1

    unknown_cases = [
        {"computerUse": {"future": True}},
        {"models": {"future": {}}},
        {"models": {"newThread": {"future": "x"}}},
        {"network": {"future": True}},
        {"hooks": {**empty_hooks, "future": []}},
        {"hooks": {**empty_hooks, "Stop": [{"hooks": [], "future": True}]}},
        {
            "hooks": {
                **empty_hooks,
                "Stop": [{"hooks": [{"type": "prompt", "future": True}]}],
            }
        },
    ]
    for requirements in unknown_cases:
        actual = evaluate(requirements)
        if actual.normalization.get("errorCode") != "MANAGED_REQUIREMENT_UNSUPPORTED":
            raise AssertionError(("recursive unknown field", requirements, actual))
        passed += 1

    malformed_cases = [
        {"allowAppshots": "false"},
        {"computerUse": {"allowLockedComputerUse": "false"}},
        {"models": {"newThread": {"model": 1}}},
        {"network": {"domains": {"example.test": "future"}}},
        {
            "hooks": {
                **empty_hooks,
                "Stop": [{"hooks": [{"type": "future"}]}],
            }
        },
    ]
    for requirements in malformed_cases:
        actual = evaluate(requirements)
        if actual.normalization.get("errorCode") != "MANAGED_REQUIREMENT_MALFORMED":
            raise AssertionError(("recursive malformed field", requirements, actual))
        passed += 1

    granular_base = {
        "mcp_elicitations": False,
        "rules": False,
        "sandbox_approval": False,
    }
    for missing_key in granular_base:
        incomplete = dict(granular_base)
        del incomplete[missing_key]
        actual = evaluate({"allowedApprovalPolicies": [{"granular": incomplete}]})
        if actual.normalization.get("errorCode") != "MANAGED_REQUIREMENT_MALFORMED":
            raise AssertionError(("incomplete granular", missing_key, actual))
        passed += 1
    granular = evaluate(
        {"allowedApprovalPolicies": [{"granular": dict(granular_base)}]}
    ).normalization["normalized"]["allowedApprovalPolicies"][0]["granular"]
    if granular != {
        **granular_base,
        "request_permissions": False,
        "skill_approval": False,
    }:
        raise AssertionError("granular defaults drifted")
    passed += 1
    granular_unknown = evaluate(
        {"allowedApprovalPolicies": [{"granular": {**granular_base, "future": False}}]}
    )
    if (
        granular_unknown.normalization.get("errorCode")
        != "MANAGED_REQUIREMENT_UNSUPPORTED"
    ):
        raise AssertionError("unknown granular field was not unsupported")
    passed += 1

    matching_network = evaluate(
        {
            "network": {
                "domains": {"allow.test": "allow", "deny.test": "deny"},
                "allowedDomains": ["allow.test"],
                "deniedDomains": ["deny.test"],
            }
        }
    )
    if matching_network.normalization["status"] != "complete":
        raise AssertionError("equivalent network forms were rejected")
    passed += 1
    for network in (
        {"domains": {"allow.test": "allow"}, "allowedDomains": []},
        {"domains": {"deny.test": "deny"}, "deniedDomains": []},
    ):
        actual = evaluate({"network": network})
        if actual.normalization.get("errorCode") != "MANAGED_REQUIREMENT_MALFORMED":
            raise AssertionError(("network form conflict", network, actual))
        passed += 1

    incompatible_cases = [
        {"defaultPermissions": "codex-smart-writer"},
        {"models": {"newThread": {"serviceTier": "priority"}}},
        {"enforceResidency": "us"},
        {"network": {"enabled": True}},
        {"network": {"httpPort": 1}},
        {"network": {"socksPort": 1}},
        {"network": {"allowLocalBinding": True}},
        {"network": {"allowUpstreamProxy": True}},
        {"network": {"dangerouslyAllowAllUnixSockets": True}},
        {"network": {"dangerouslyAllowNonLoopbackProxy": True}},
    ]
    for requirements in incompatible_cases:
        actual = evaluate(requirements)
        if (
            actual.normalization["status"] != "complete"
            or actual.compatibility.get("errorCode")
            != "MANAGED_REQUIREMENT_INCOMPATIBLE"
        ):
            raise AssertionError(("compatibility branch", requirements, actual))
        passed += 1

    for requirements in (
        {"allowAppshots": True},
        {"allowRemoteControl": True},
        {"computerUse": {"allowLockedComputerUse": True}},
    ):
        if evaluate(requirements).compatibility != {"status": "compatible"}:
            raise AssertionError(("permissive boolean", requirements))
        passed += 1

    at_limit = "é" * 2_048
    over_limit = at_limit + "a"
    for requirements, expected in (
        ({"defaultPermissions": at_limit}, "complete"),
        ({"defaultPermissions": over_limit}, "rejected"),
        ({"allowedPermissionProfiles": {at_limit: False}}, "complete"),
        ({"allowedPermissionProfiles": {over_limit: False}}, "rejected"),
    ):
        if evaluate(requirements).normalization["status"] != expected:
            raise AssertionError(("UTF-8 field boundary", expected))
        passed += 1
    if passed != 39:
        raise AssertionError(f"expected 39 cycle-6 config regressions, got {passed}")
    return CheckSummary(passed=passed, total=39)


def validate_config_cycle7_regressions(root: Path = ROOT) -> CheckSummary:
    vectors = _load_config_vectors_exact(root)
    context = vectors["contexts"]["reader-luna-medium"]
    positive_expected = {
        "normalizationStatus": "complete",
        "compatibilityStatus": "compatible",
        "normalizedPolicyCount": 2,
    }
    rejected_expected = {
        "normalizationStatus": "rejected",
        "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
        "compatibilityStatus": "not-run",
    }
    contracts = {
        "granular-optional-absent": (
            "granular-optionals",
            {"mode": "absent"},
            positive_expected,
        ),
        "granular-optional-null": (
            "granular-optionals",
            {"mode": "null"},
            positive_expected,
        ),
        "granular-optional-false": (
            "granular-optionals",
            {"mode": "false"},
            positive_expected,
        ),
        "granular-equivalent-deduplicates": (
            "granular-dedup",
            {},
            positive_expected,
        ),
        "envelope-parsed-1048577-bytes": (
            "envelope-bytes",
            {"sourceKind": "parsed", "utf8Bytes": 1_048_577},
            rejected_expected,
        ),
        "envelope-raw-1048577-bytes": (
            "envelope-bytes",
            {"sourceKind": "raw-utf8", "utf8Bytes": 1_048_577},
            rejected_expected,
        ),
        "raw-lone-surrogate": (
            "raw-unicode-escape",
            {"hexCodeUnit": "d800"},
            rejected_expected,
        ),
        "envelope-parsed-depth-1100": (
            "envelope-depth",
            {"sourceKind": "parsed", "depth": 1_100},
            rejected_expected,
        ),
        "envelope-raw-depth-1100": (
            "envelope-depth",
            {"sourceKind": "raw-utf8", "depth": 1_100},
            rejected_expected,
        ),
        "raw-5000-digit-integer": (
            "raw-integer-digits",
            {"digits": 5_000},
            rejected_expected,
        ),
    }
    cases = vectors.get("cycle7Cases")
    if type(cases) is not list or len(cases) != len(contracts):
        raise AssertionError("cycle7 case set must contain exactly ten descriptors")
    if [case.get("name") if type(case) is dict else None for case in cases] != list(
        contracts
    ):
        raise AssertionError("cycle7 descriptor order or names drifted")

    granular_base = {
        "mcp_elicitations": False,
        "rules": False,
        "sandbox_approval": False,
    }
    normalized_granular = {
        **granular_base,
        "request_permissions": False,
        "skill_approval": False,
    }
    passed = 0
    for case in cases:
        if type(case) is not dict or set(case) != {
            "name",
            "construction",
            "parameters",
            "expected",
        }:
            raise AssertionError("cycle7 descriptor is not closed")
        construction, parameters, expected = contracts[case["name"]]
        if (
            case["construction"] != construction
            or case["parameters"] != parameters
            or case["expected"] != expected
        ):
            raise AssertionError(f"cycle7 descriptor drifted: {case['name']}")

        if construction == "granular-optionals":
            optionals = {
                "absent": {},
                "null": {
                    "request_permissions": None,
                    "skill_approval": None,
                },
                "false": {
                    "request_permissions": False,
                    "skill_approval": False,
                },
            }[parameters["mode"]]
            source = {
                "kind": "parsed",
                "value": {
                    "requirements": {
                        "allowedApprovalPolicies": [
                            "never",
                            {"granular": {**granular_base, **optionals}},
                        ]
                    }
                },
            }
        elif construction == "granular-dedup":
            source = {
                "kind": "parsed",
                "value": {
                    "requirements": {
                        "allowedApprovalPolicies": [
                            "never",
                            {"granular": dict(granular_base)},
                            {"granular": dict(normalized_granular)},
                        ]
                    }
                },
            }
        elif construction == "envelope-bytes":
            empty = {"requirements": {}, "future": ""}
            overhead = len(canonical_json_v1(empty).encode("utf-8"))
            envelope = {
                "requirements": {},
                "future": "x" * (parameters["utf8Bytes"] - overhead),
            }
            raw = canonical_json_v1(envelope)
            if len(raw.encode("utf-8")) != parameters["utf8Bytes"]:
                raise AssertionError(
                    f"cycle7 byte construction drifted: {case['name']}"
                )
            source = {
                "kind": parameters["sourceKind"],
                "value": envelope if parameters["sourceKind"] == "parsed" else raw,
            }
        elif construction == "raw-unicode-escape":
            source = {
                "kind": "raw-utf8",
                "value": (
                    '{"requirements":{},"future":"\\u'
                    + parameters["hexCodeUnit"]
                    + '"}'
                ),
            }
        elif construction == "envelope-depth":
            nested: Any = None
            for _ in range(parameters["depth"]):
                nested = {"x": nested}
            envelope = {"requirements": {}, "future": nested}
            raw = (
                '{"requirements":{},"future":'
                + '{"x":' * parameters["depth"]
                + "null"
                + "}" * parameters["depth"]
                + "}"
            )
            source = {
                "kind": parameters["sourceKind"],
                "value": envelope if parameters["sourceKind"] == "parsed" else raw,
            }
        elif construction == "raw-integer-digits":
            source = {
                "kind": "raw-utf8",
                "value": (
                    '{"requirements":{},"future":' + "9" * parameters["digits"] + "}"
                ),
            }
        else:
            raise AssertionError(f"unknown cycle7 construction: {construction}")

        actual = evaluate_config_requirements(source, context, root=root)
        if actual.normalization["status"] == "complete":
            normalized_policies = actual.normalization["normalized"][
                "allowedApprovalPolicies"
            ]
            granular_policies = [
                policy for policy in normalized_policies if type(policy) is dict
            ]
            if granular_policies != [{"granular": normalized_granular}]:
                raise AssertionError(f"cycle7 granular result drifted: {case['name']}")
            actual_projection = {
                "normalizationStatus": "complete",
                "compatibilityStatus": actual.compatibility["status"],
                "normalizedPolicyCount": len(normalized_policies),
            }
        else:
            actual_projection = {
                "normalizationStatus": actual.normalization["status"],
                "errorCode": actual.normalization["errorCode"],
                "compatibilityStatus": actual.compatibility["status"],
            }
        if actual_projection != case["expected"]:
            raise AssertionError(
                {"cycle7Case": case["name"], "actual": actual_projection}
            )
        passed += 1
    return CheckSummary(passed=passed, total=len(cases))


def validate_config_cycle8_regressions(root: Path = ROOT) -> CheckSummary:
    vectors = _load_config_vectors_exact(root)
    context = vectors["contexts"]["reader-luna-medium"]
    contracts = (
        (
            "allowed-approval-policies-repeat-2049",
            "allowedApprovalPolicies",
            "never",
        ),
        (
            "allowed-approvals-reviewers-repeat-2049",
            "allowedApprovalsReviewers",
            "user",
        ),
        (
            "allowed-sandbox-modes-repeat-2049",
            "allowedSandboxModes",
            "read-only",
        ),
        (
            "allowed-web-search-modes-repeat-2049",
            "allowedWebSearchModes",
            "disabled",
        ),
        (
            "allowed-windows-sandbox-implementations-repeat-2049",
            "allowedWindowsSandboxImplementations",
            "unelevated",
        ),
    )
    expected_cases = [
        {
            "name": name,
            "field": field,
            "value": value,
            "repeatCount": 2_049,
            "expected": {
                "normalizationStatus": "complete",
                "compatibilityStatus": "compatible",
                "normalized": [value],
            },
        }
        for name, field, value in contracts
    ]
    cases = vectors.get("cycle8Cases")
    if cases != expected_cases:
        raise AssertionError("cycle8 finite-set descriptors are not exact")

    def evaluate(requirements: dict[str, Any]) -> ConfigEvaluation:
        return evaluate_config_requirements(
            {"kind": "parsed", "value": {"requirements": requirements}},
            context,
            root=root,
        )

    def assert_malformed(
        requirements: dict[str, Any], *, phase: str | None = None
    ) -> None:
        actual = evaluate(requirements)
        expected_normalization = {
            "status": "rejected",
            "phase": actual.normalization.get("phase"),
            "errorCode": "MANAGED_REQUIREMENT_MALFORMED",
        }
        if actual.normalization != expected_normalization:
            raise AssertionError(("cycle8 malformed", requirements, actual))
        if phase is not None and actual.normalization["phase"] != phase:
            raise AssertionError(("cycle8 phase", requirements, actual))
        if actual.compatibility != {"status": "not-run"}:
            raise AssertionError(("cycle8 compatibility", requirements, actual))

    passed = 0
    for case in cases:
        field = case["field"]
        value = case["value"]
        actual = evaluate({field: [value] * case["repeatCount"]})
        actual_projection = {
            "normalizationStatus": actual.normalization["status"],
            "compatibilityStatus": actual.compatibility["status"],
            "normalized": actual.normalization.get("normalized", {}).get(field),
        }
        if actual_projection != case["expected"]:
            raise AssertionError(
                {"cycle8Case": case["name"], "actual": actual_projection}
            )
        assert_malformed({field: ["future-value"]})
        assert_malformed({field: [value, 7]})
        assert_malformed({field: [value] * 4_094}, phase="raw-guards")
        passed += 1

    assert_malformed({"network": {"allowedDomains": ["example.invalid"] * 2_049}})
    assert_malformed(
        {
            "allowedPermissionProfiles": {
                f"profile-{index:04d}": True for index in range(2_049)
            }
        }
    )
    return CheckSummary(passed=passed, total=len(cases))


def validate_tree_metric_contract(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(
        root / "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
    )
    contract = vectors["treeMetricContract"]
    required_contract = {
        "version": "json-value-tree-v1",
        "nodeCountFormula": "container=1+sum(childNodes); scalar=1",
        "depthFormula": "root=1; nonemptyContainer=1+max(childDepth); emptyContainer=1; scalar=1",
        "objectMemberNameNodeWeight": 0,
        "rootDepth": 1,
        "traversal": "iterative-stack-independent-of-recipe-generator",
    }
    if contract != required_contract:
        raise AssertionError({"actual": contract, "expected": required_contract})
    passed = 0
    for case in vectors["treeMetricCases"]:
        actual = measure_json_value_tree(case["value"])
        expected = JsonTreeMetrics(
            nodes=case["expectedNodes"], depth=case["expectedDepth"]
        )
        if actual != expected:
            raise AssertionError((case["name"], actual, expected))
        passed += 1
    if passed != 5:
        raise AssertionError(f"expected five tree metric calibrations, got {passed}")

    renamed_before = measure_json_value_tree({"a": None})
    renamed_after = measure_json_value_tree({"a-much-longer-member-name": None})
    if renamed_before != renamed_after:
        raise AssertionError("object member names affected tree metrics")
    passed += 1

    add_before = measure_json_value_tree({})
    add_after = measure_json_value_tree({"new": None})
    if add_after.nodes != add_before.nodes + 1:
        raise AssertionError(
            "adding a null member did not add exactly one JSON value node"
        )
    passed += 1

    wrap_before = measure_json_value_tree({"branch": None})
    wrap_after = measure_json_value_tree({"branch": {"leaf": None}})
    if (wrap_after.nodes, wrap_after.depth) != (
        wrap_before.nodes + 1,
        wrap_before.depth + 1,
    ):
        raise AssertionError(
            "wrapping the deepest branch did not add one node and one depth level"
        )
    passed += 1

    recipes = {recipe["name"]: recipe for recipe in vectors["recipes"]}
    required_limits = {
        "raw-tree-nodes": (4_096, 4_097),
        "normalized-tree-nodes": (4_096, 4_097),
        "raw-tree-depth": (16, 17),
    }
    for name, (at_limit, over_limit) in required_limits.items():
        recipe = recipes[name]
        if (recipe["atLimit"], recipe["overLimit"]) != (at_limit, over_limit):
            raise AssertionError((name, recipe["atLimit"], recipe["overLimit"]))
    return CheckSummary(passed=passed, total=8)


def _recipe_pointer_get(document: Any, pointer: str) -> Any:
    if not pointer:
        return document
    current = document
    for token in _pointer_tokens(pointer):
        current = current[int(token)] if type(current) is list else current[token]
    return current


def _recipe_pointer_set(document: Any, pointer: str, value: Any) -> None:
    parent, token = _pointer_parent(document, pointer)
    if type(parent) is list:
        parent[int(token)] = value
    else:
        parent[token] = value


def generate_config_recipe(recipe: dict[str, Any], parameter: Any) -> tuple[Any, bytes]:
    document = copy.deepcopy(recipe["seed"])
    kind = recipe["kind"]
    pointer = recipe["targetPointer"]
    if kind == "replace-integer":
        _recipe_pointer_set(document, pointer, int(parameter))
    elif kind == "replace-ascii-string":
        _recipe_pointer_set(document, pointer, "a" * parameter)
    elif kind == "replace-utf8-string":
        value = "é" * (parameter // 2) + ("a" if parameter % 2 else "")
        if len(value.encode("utf-8")) != parameter:
            raise AssertionError("UTF-8 recipe byte count drifted")
        _recipe_pointer_set(document, pointer, value)
    elif kind == "rename-single-property":
        target = _recipe_pointer_get(document, pointer)
        value = next(iter(target.values()))
        target.clear()
        target["a" * parameter] = value
    elif kind == "replace-map-value":
        _recipe_pointer_set(document, pointer, parameter)
    elif kind == "populate-indexed-array":
        _recipe_pointer_set(
            document, pointer, [f"item-{index:04d}" for index in range(parameter)]
        )
    elif kind == "populate-indexed-object":
        _recipe_pointer_set(
            document, pointer, {f"k{index:04d}": True for index in range(parameter)}
        )
    elif kind == "populate-two-indexed-objects":
        normalization_added_nodes = 2
        raw_fixed_nodes = measure_json_value_tree(document).nodes
        normalized_fixed_nodes = measure_json_value_tree(
            normalize_config_requirements(document)
        ).nodes
        if normalized_fixed_nodes - raw_fixed_nodes != normalization_added_nodes:
            raise AssertionError(
                "normalized-node recipe no longer adds two granular defaults"
            )
        item_count = parameter - normalized_fixed_nodes
        first = min(2_048, item_count)
        second = item_count - first
        if first < 0 or not 0 <= second <= 2_048:
            raise AssertionError("two-object recipe cannot distribute requested nodes")
        document["allowedPermissionProfiles"] = {
            f"p{index:04d}": True for index in range(first)
        }
        document["featureRequirements"] = {
            f"f{index:04d}": False for index in range(second)
        }
        if (
            measure_json_value_tree(normalize_config_requirements(document)).nodes
            != parameter
        ):
            raise AssertionError("two-object normalized node count drifted")
        if (
            measure_json_value_tree(document).nodes
            != parameter - normalization_added_nodes
        ):
            raise AssertionError("two-object raw node count drifted")
    elif kind == "populate-hook-groups":
        _recipe_pointer_set(
            document, pointer, [{"hooks": []} for _ in range(parameter)]
        )
    elif kind == "populate-hook-handlers":
        _recipe_pointer_set(
            document, pointer, [{"type": "prompt"} for _ in range(parameter)]
        )
    elif kind == "append-raw-spaces":
        raw = document.encode("utf-8")
        return document, raw + b" " * (parameter - len(raw))
    elif kind == "solve-normalized-canonical-padding":
        handlers = _recipe_pointer_get(document, pointer)
        for handler in handlers:
            handler["command"] = "a"
        remaining = parameter - len(
            canonical_json_v1(normalize_config_requirements(document)).encode("utf-8")
        )
        for handler in handlers:
            take = min(65_536 - len(handler["command"]), remaining)
            handler["command"] += "a" * take
            remaining -= take
        normalized_bytes = canonical_json_v1(
            normalize_config_requirements(document)
        ).encode("utf-8")
        if remaining != 0 or len(normalized_bytes) != parameter:
            raise AssertionError(
                "normalized canonical padding recipe did not reach exact byte count"
            )
    elif kind == "populate-raw-nodes":
        base_nodes = measure_json_value_tree(document).nodes
        _recipe_pointer_set(document, pointer, [None] * (parameter - base_nodes))
        if measure_json_value_tree(document).nodes != parameter:
            raise AssertionError("raw node recipe drifted")
    elif kind == "wrap-depth":
        while measure_json_value_tree(document).depth < parameter:
            parent, token = _pointer_parent(document, pointer)
            parent[token] = {"x": parent[token]}
        if measure_json_value_tree(document).depth != parameter:
            raise AssertionError("depth recipe drifted")
    elif kind == "append-array-value":
        _recipe_pointer_get(document, pointer).append(parameter)
    else:
        raise ContractError(f"unknown config recipe kind: {kind}")
    try:
        raw = canonical_json_v1(document).encode("utf-8")
    except ContractError:
        unsafe_value = _recipe_pointer_get(document, pointer)
        if (
            kind != "replace-integer"
            or type(unsafe_value) is not int
            or abs(unsafe_value) <= SAFE_INTEGER_MAX
        ):
            raise
        safe_document = copy.deepcopy(document)
        _recipe_pointer_set(safe_document, pointer, 0)
        raw = canonical_json_v1(safe_document).encode("utf-8")
        key = pointer.rsplit("/", 1)[1]
        safe_fragment = (canonical_json_v1(key) + ":0").encode("utf-8")
        unsafe_fragment = (canonical_json_v1(key) + ":" + str(unsafe_value)).encode(
            "utf-8"
        )
        if raw.count(safe_fragment) != 1:
            raise AssertionError("unsafe integer recipe replacement is ambiguous")
        raw = raw.replace(safe_fragment, unsafe_fragment, 1)
    return document, raw


def validate_config_recipe_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(
        root / "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
    )
    recipe_schema = load_json(
        root / "docs/contracts/schemas/config-requirements-vector-recipe-v1.schema.json"
    )
    if vectors != recipe_schema.get("const"):
        raise AssertionError("config recipe vector differs from its exact schema const")
    context = _load_config_vectors_exact(root)["contexts"]["reader-luna-medium"]
    passed = 0
    for recipe in vectors["recipes"]:
        generated: dict[str, tuple[Any, bytes]] = {}
        for side in ("atLimit", "overLimit"):
            effective = recipe
            if side == "overLimit" and recipe["class"] == "deduplication":
                effective = copy.deepcopy(recipe)
                effective["seed"] = generated["atLimit"][0]
            document, raw = generate_config_recipe(effective, recipe[side])
            generated[side] = (document, raw)
            actual_sha = hashlib.sha256(raw).hexdigest()
            if actual_sha != recipe[side + "Sha256"]:
                raise AssertionError(
                    (recipe["name"], side, actual_sha, recipe[side + "Sha256"])
                )
        at_document, at_raw = generated["atLimit"]
        over_document, over_raw = generated["overLimit"]

        def evaluate_generated(document: Any, raw: bytes) -> ConfigEvaluation:
            if recipe["kind"] == "append-raw-spaces":
                source = {"kind": "raw-utf8", "value": raw.decode("utf-8")}
            elif type(document) is dict and set(document) == {"requirements"}:
                source = {"kind": "parsed", "value": document}
            else:
                source = {
                    "kind": "parsed",
                    "value": {"requirements": document},
                }
            return evaluate_config_requirements(source, context, root=root)

        at_evaluation = evaluate_generated(at_document, at_raw)
        over_evaluation = evaluate_generated(over_document, over_raw)
        if recipe["atLimitExpected"] == "guard-valid-then-unsupported":
            if (
                at_evaluation.normalization.get("errorCode")
                != "MANAGED_REQUIREMENT_UNSUPPORTED"
            ):
                raise AssertionError(
                    f"guard at-limit classification drifted: {recipe['name']}"
                )
        elif at_evaluation.normalization["status"] != "complete":
            raise AssertionError(f"at-limit evaluator rejected: {recipe['name']}")
        if recipe["overLimitExpected"] == "malformed":
            if (
                over_evaluation.normalization.get("errorCode")
                != "MANAGED_REQUIREMENT_MALFORMED"
            ):
                raise AssertionError(f"over-limit evaluator accepted: {recipe['name']}")
        elif over_evaluation.normalization["status"] != "complete":
            raise AssertionError(
                f"normalizing over-limit evaluator rejected: {recipe['name']}"
            )
        if recipe["class"] == "deduplication":
            at_normalized = normalize_config_requirements(at_document)
            over_normalized = normalize_config_requirements(over_document)
            if at_normalized != over_normalized:
                raise AssertionError(f"deduplication recipe diverged: {recipe['name']}")
            if at_evaluation.normalization != over_evaluation.normalization:
                raise AssertionError(
                    f"deduplication evaluator diverged: {recipe['name']}"
                )
        if recipe["atLimitExpected"] == "accepted":
            if recipe["kind"] == "append-raw-spaces":
                if len(at_raw) > RAW_DOCUMENT_BYTES_MAX:
                    raise AssertionError(f"raw at-limit rejected: {recipe['name']}")
                strict_json_loads(at_raw)
            elif (
                len(
                    _recipe_pointer_get(at_document, recipe["targetPointer"]).encode(
                        "utf-8"
                    )
                )
                > 4_096
            ):
                raise AssertionError(f"string at-limit rejected: {recipe['name']}")
        if recipe["atLimitExpected"] == "guard-valid-then-unsupported":
            metrics = measure_json_value_tree(at_document)
            if (
                len(at_raw) > RAW_DOCUMENT_BYTES_MAX
                or metrics.nodes > 4_096
                or metrics.depth > 16
            ):
                raise AssertionError(f"guard at-limit rejected: {recipe['name']}")
        if recipe["overLimitExpected"] == "malformed":
            if recipe["kind"] == "append-raw-spaces":
                if len(over_raw) <= NORMALIZED_DOCUMENT_BYTES_MAX:
                    raise AssertionError(
                        f"byte over-limit not crossed: {recipe['name']}"
                    )
            elif recipe["kind"] == "solve-normalized-canonical-padding":
                normalized_at = canonical_json_v1(
                    normalize_config_requirements(at_document)
                ).encode("utf-8")
                normalized_over = canonical_json_v1(
                    normalize_config_requirements(over_document)
                ).encode("utf-8")
                for document, expected_size in (
                    (at_document, recipe["atLimit"]),
                    (over_document, recipe["overLimit"]),
                ):
                    envelope_size = len(
                        canonical_json_v1({"requirements": document}).encode("utf-8")
                    )
                    if envelope_size > RAW_DOCUMENT_BYTES_MAX:
                        raise AssertionError(
                            f"normalized-byte recipe exceeded raw envelope: {recipe['name']}"
                        )
                if (
                    len(normalized_at) != recipe["atLimit"]
                    or len(normalized_over) != recipe["overLimit"]
                ):
                    raise AssertionError(
                        f"normalized byte boundary drifted: {recipe['name']}"
                    )
            elif recipe["kind"] == "populate-raw-nodes":
                if measure_json_value_tree(over_document).nodes <= 4_096:
                    raise AssertionError(
                        f"node over-limit not crossed: {recipe['name']}"
                    )
            elif recipe["kind"] == "populate-two-indexed-objects":
                normalized_over = normalize_config_requirements(over_document)
                if measure_json_value_tree(normalized_over).nodes <= 4_096:
                    raise AssertionError(
                        f"normalized node over-limit not crossed: {recipe['name']}"
                    )
            elif recipe["kind"] == "wrap-depth":
                if measure_json_value_tree(over_document).depth <= 16:
                    raise AssertionError(
                        f"depth over-limit not crossed: {recipe['name']}"
                    )
            elif recipe["kind"] == "replace-utf8-string":
                if (
                    len(
                        _recipe_pointer_get(
                            over_document, recipe["targetPointer"]
                        ).encode("utf-8")
                    )
                    <= 4_096
                ):
                    raise AssertionError(
                        f"UTF-8 over-limit not crossed: {recipe['name']}"
                    )
            elif over_evaluation.normalization["status"] != "rejected":
                raise AssertionError(f"schema over-limit accepted: {recipe['name']}")
        passed += 1
    if len(vectors["recipes"]) != 23:
        raise AssertionError("expected exactly 23 config recipes")
    return CheckSummary(passed=passed, total=23)


def _child_profiles(root: Path) -> dict[str, dict[str, Any]]:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    return {case["name"]: case["profile"] for case in vectors["cases"]}


def _materialize_environment(
    profile: dict[str, Any],
    slot_values: dict[str, str],
    secret_fingerprints: dict[str, str],
) -> tuple[dict[str, str], str]:
    environment: dict[str, str] = {}
    secret_sha256: str | None = None
    for name, source in profile["environmentTemplate"].items():
        if "literal" in source:
            environment[name] = source["literal"]
        elif "slot" in source:
            environment[name] = slot_values[source["slot"]]
        elif "secretSlot" in source:
            if (
                name != "OTEL_EXPORTER_OTLP_HEADERS"
                or source["secretSlot"] != "otelHeaders"
            ):
                raise ContractError("unknown secret environment binding")
            secret_sha256 = secret_fingerprints[source["secretSlot"]]
        else:
            raise ContractError("unknown environment template source")
    if secret_sha256 is None:
        raise ContractError("profile did not bind otelHeaders")
    if "OTEL_EXPORTER_OTLP_HEADERS" in environment:
        raise ContractError("secret leaked into non-secret environment")
    return environment, secret_sha256


def _materialize_argv(
    profile: dict[str, Any],
    arguments: dict[str, str],
    non_secret_environment: dict[str, str],
) -> list[str]:
    result: list[str] = []
    for item in profile["argvTemplate"]:
        if "literal" in item:
            result.append(item["literal"])
            continue
        slot = item["slot"]
        if slot == "shellEnvironmentSet":
            value = canonical_json_v1(non_secret_environment)
        else:
            value = arguments[slot]
            if item["encoding"] == "json-string":
                value = canonical_json_v1(value)
        result.append(item["prefix"] + value)
    for feature in profile["disabledFeatures"]:
        result.extend(["--disable", feature])
    return result


def materialize_launch_binding(
    role: str, trusted_context: dict[str, Any], *, root: Path = ROOT
) -> dict[str, Any]:
    if role != trusted_context["role"]:
        raise ContractError("role does not match trusted context")
    child_vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    profile = _child_profiles(root)[role]
    arguments = {
        "snapshotPath": interface["subject"]["snapshotPath"],
        "model": trusted_context["selectedPair"]["model"],
        "workDir": trusted_context["workDir"],
        "resultSchemaPath": trusted_context["resultSchemaPath"],
        "reasoningEffort": trusted_context["selectedPair"]["reasoningEffort"],
    }
    environment, secret_sha256 = _materialize_environment(
        profile,
        trusted_context["environmentSlotValues"],
        trusted_context["secretSlotFingerprints"],
    )
    concrete_argv = _materialize_argv(profile, arguments, environment)
    environment_projection = {
        "variables": environment,
        "secretBindings": {"OTEL_EXPORTER_OTLP_HEADERS": secret_sha256},
    }
    return {
        "schemaVersion": 1,
        "contractVersion": "codex-child-launch-v1",
        "role": role,
        "compatibilityFingerprint": trusted_context["compatibilityFingerprint"],
        "arguments": arguments,
        "concreteArgv": concrete_argv,
        "nonSecretEnvironment": environment,
        "argvFingerprint": domain_fingerprint(
            child_vectors["argvDomain"], concrete_argv
        ),
        "environmentFingerprint": domain_fingerprint(
            child_vectors["environmentDomain"], environment_projection
        ),
        "secretSha256": secret_sha256,
    }


def _bounded_string(value: Any, limit: int, *, absolute: bool = False) -> bool:
    return (
        type(value) is str
        and bool(value)
        and (not absolute or value.startswith("/"))
        and len(value.encode("utf-8")) <= limit
    )


def _sha256_string(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _trusted_context_shape_valid(trusted_context: Any, profile: dict[str, Any]) -> bool:
    required = {
        "schemaVersion",
        "contractVersion",
        "role",
        "compatibilityFingerprint",
        "selectedPair",
        "resultSchemaPath",
        "workDir",
        "environmentSlotValues",
        "secretSlotFingerprints",
    }
    if type(trusted_context) is not dict or set(trusted_context) != required:
        return False
    if (
        type(trusted_context["schemaVersion"]) is not int
        or trusted_context["schemaVersion"] != 1
        or trusted_context["contractVersion"] != "codex-trusted-launch-context-v1"
        or trusted_context["role"] != profile["role"]
        or not _sha256_string(trusted_context["compatibilityFingerprint"])
        or not _bounded_string(
            trusted_context["resultSchemaPath"], 4_096, absolute=True
        )
        or not _bounded_string(trusted_context["workDir"], 4_096, absolute=True)
    ):
        return False
    selected_pair = trusted_context["selectedPair"]
    if (
        type(selected_pair) is not dict
        or set(selected_pair) != {"model", "reasoningEffort"}
        or not _bounded_string(selected_pair["model"], 128)
        or selected_pair["reasoningEffort"]
        not in {"low", "medium", "high", "xhigh", "max"}
    ):
        return False

    expected_slots = {
        source["slot"]
        for source in profile["environmentTemplate"].values()
        if type(source) is dict and set(source) == {"slot"}
    }
    expected_secret_slots = {
        source["secretSlot"]
        for source in profile["environmentTemplate"].values()
        if type(source) is dict and set(source) == {"secretSlot"}
    }
    slot_values = trusted_context["environmentSlotValues"]
    if type(slot_values) is not dict or set(slot_values) != expected_slots:
        return False
    for slot, value in slot_values.items():
        if not _bounded_string(
            value,
            4_096,
            absolute=slot != "otelEndpoint",
        ):
            return False
    secret_slots = trusted_context["secretSlotFingerprints"]
    return (
        type(secret_slots) is dict
        and set(secret_slots) == expected_secret_slots
        and all(_sha256_string(value) for value in secret_slots.values())
    )


def _binding_shape_valid(binding: Any) -> bool:
    required = {
        "schemaVersion",
        "contractVersion",
        "role",
        "compatibilityFingerprint",
        "arguments",
        "concreteArgv",
        "nonSecretEnvironment",
        "argvFingerprint",
        "environmentFingerprint",
        "secretSha256",
    }
    if type(binding) is not dict or set(binding) != required:
        return False
    if (
        type(binding["schemaVersion"]) is not int
        or binding["schemaVersion"] != 1
        or binding["contractVersion"] != "codex-child-launch-v1"
        or binding["role"] not in {"classifier", "reader", "writer"}
        or not all(
            _sha256_string(binding[field])
            for field in (
                "compatibilityFingerprint",
                "argvFingerprint",
                "environmentFingerprint",
                "secretSha256",
            )
        )
    ):
        return False
    arguments = binding["arguments"]
    if type(arguments) is not dict or set(arguments) != {
        "snapshotPath",
        "model",
        "workDir",
        "resultSchemaPath",
        "reasoningEffort",
    }:
        return False
    if (
        not _bounded_string(arguments["snapshotPath"], 4_096, absolute=True)
        or not _bounded_string(arguments["model"], 128)
        or not _bounded_string(arguments["workDir"], 4_096, absolute=True)
        or not _bounded_string(arguments["resultSchemaPath"], 4_096, absolute=True)
        or arguments["reasoningEffort"] not in {"low", "medium", "high", "xhigh", "max"}
    ):
        return False
    concrete_argv = binding["concreteArgv"]
    if (
        type(concrete_argv) is not list
        or not 1 <= len(concrete_argv) <= 512
        or any(not _bounded_string(item, 65_536) for item in concrete_argv)
    ):
        return False
    environment = binding["nonSecretEnvironment"]
    return type(environment) is dict and all(
        type(name) is str and _bounded_string(value, 4_096)
        for name, value in environment.items()
    )


def resolve_trusted_result_schema_path(
    role: str, trusted_context: dict[str, Any], *, root: Path = ROOT
) -> Path:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    resolution = vectors.get("resultSchemaResolution")
    expected_resolution = {
        "virtualRoot": "/private/schemas",
        "repositoryRoot": "docs/contracts/schemas",
    }
    if resolution != expected_resolution:
        raise ContractError("result schema resolution record is not exact")
    profiles = {case["name"]: case["profile"] for case in vectors["cases"]}
    if role not in profiles or trusted_context.get("role") != role:
        raise ContractError("result schema role is not trusted")
    result_schema_id = profiles[role]["resultSchemaId"]
    filename = f"{result_schema_id}.schema.json"
    expected_logical_path = f"{resolution['virtualRoot']}/{filename}"
    if trusted_context.get("resultSchemaPath") != expected_logical_path:
        raise ContractError("result schema logical path does not match role")
    repository_root = (root / resolution["repositoryRoot"]).resolve()
    resolved = (repository_root / filename).resolve()
    if resolved.parent != repository_root or not resolved.is_file():
        raise ContractError(
            "resolved result schema file is missing or escapes its root"
        )
    return resolved


def verify_trusted_launch_context(
    binding: dict[str, Any], trusted_context: dict[str, Any], *, root: Path = ROOT
) -> bool:
    try:
        interface = load_json(
            root / "docs/contracts/vectors/interface-evidence-v1.json"
        )["base"]
        profiles = _child_profiles(root)
        if (
            type(trusted_context) is not dict
            or trusted_context.get("role") not in profiles
        ):
            return False
        profile = profiles[trusted_context["role"]]
        if not _trusted_context_shape_valid(
            trusted_context, profile
        ) or not _binding_shape_valid(binding):
            return False
        if binding["role"] != trusted_context["role"]:
            return False
        if binding["compatibilityFingerprint"] != interface["compatibilityFingerprint"]:
            return False
        if (
            trusted_context["compatibilityFingerprint"]
            != interface["compatibilityFingerprint"]
        ):
            return False
        child_vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
        profile_case = next(
            case
            for case in child_vectors["cases"]
            if case["name"] == trusted_context["role"]
        )
        actual_profile_fingerprint = domain_fingerprint(
            child_vectors["profileDomain"], profile
        )
        if (
            actual_profile_fingerprint != profile_case["fingerprint"]
            or actual_profile_fingerprint
            != interface["semantic"]["childProfiles"][trusted_context["role"]]
        ):
            return False
        result_schema_id = profile["resultSchemaId"]
        machine_schema = interface["semantic"]["machineSchemas"].get(result_schema_id)
        if type(machine_schema) is not dict or set(machine_schema) != {
            "schemaId",
            "schemaSha256",
        }:
            return False
        if machine_schema["schemaId"] != result_schema_id or not _sha256_string(
            machine_schema["schemaSha256"]
        ):
            return False
        schema_path = resolve_trusted_result_schema_path(
            trusted_context["role"], trusted_context, root=root
        )
        if (
            hashlib.sha256(schema_path.read_bytes()).hexdigest()
            != machine_schema["schemaSha256"]
        ):
            return False
        return binding == materialize_launch_binding(
            trusted_context["role"], trusted_context, root=root
        )
    except (ContractError, KeyError, StopIteration, TypeError, UnicodeError, OSError):
        return False


def validate_environment_binding_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    positive_roles = vectors["concreteLaunch"]["positiveRoles"]
    if set(positive_roles) != {"classifier", "reader", "writer"}:
        raise AssertionError("positiveRoles must cover classifier, reader and writer")
    profiles = _child_profiles(root)
    child_schema_path = root / "docs/contracts/schemas/child-profile-v1.schema.json"
    child_schema = load_json(child_schema_path)
    profile_validator = _jsonschema_validator(child_schema_path)
    trusted_validator = profile_validator.evolve(
        schema={"$ref": "#/$defs/trustedLaunchContext", "$defs": child_schema["$defs"]}
    )
    binding_validator = profile_validator.evolve(
        schema={"$ref": "#/$defs/launchBinding", "$defs": child_schema["$defs"]}
    )
    passed = 0
    for role, fixture in positive_roles.items():
        if set(fixture) != {"trustedContext", "binding"}:
            raise AssertionError(f"positive role fixture is not closed: {role}")
        if not _trusted_context_shape_valid(fixture["trustedContext"], profiles[role]):
            raise AssertionError(
                f"positive trusted context is structurally invalid: {role}"
            )
        if not _binding_shape_valid(fixture["binding"]):
            raise AssertionError(
                f"positive launch binding is structurally invalid: {role}"
            )
        profile_validator.validate(profiles[role])
        trusted_validator.validate(fixture["trustedContext"])
        binding_validator.validate(fixture["binding"])
        actual = materialize_launch_binding(role, fixture["trustedContext"], root=root)
        if actual != fixture["binding"]:
            raise AssertionError((role, actual, fixture["binding"]))
        if not verify_trusted_launch_context(
            actual, fixture["trustedContext"], root=root
        ):
            raise AssertionError(f"positive trusted context rejected: {role}")
        passed += 1

    for case in vectors["environmentNegativeCases"]:
        if set(case) != {"name", "role", "kind", "slot", "before", "value", "expected"}:
            raise AssertionError(
                f"environment negative case is not closed: {case.get('name')}"
            )
        if set(case["expected"]) != {
            "argvFingerprint",
            "environmentFingerprint",
            "fingerprintDelta",
            "verification",
        }:
            raise AssertionError(
                f"environment negative expected is not closed: {case['name']}"
            )
        fixture = positive_roles[case["role"]]
        original_context = fixture["trustedContext"]
        changed_context = copy.deepcopy(original_context)
        if case["kind"] == "regular-slot":
            values = changed_context["environmentSlotValues"]
            if values[case["slot"]] != case["before"]:
                raise AssertionError(f"negative before mismatch: {case['name']}")
            values[case["slot"]] = case["value"]
        elif case["kind"] == "secret-slot-fingerprint":
            values = changed_context["secretSlotFingerprints"]
            if values[case["slot"]] != case["before"]:
                raise AssertionError(f"negative before mismatch: {case['name']}")
            values[case["slot"]] = case["value"]
        else:
            raise AssertionError(f"unknown environment negative kind: {case['kind']}")
        candidate = materialize_launch_binding(case["role"], changed_context, root=root)
        if not _trusted_context_shape_valid(changed_context, profiles[case["role"]]):
            raise AssertionError(
                f"changed trusted context is structurally invalid: {case['name']}"
            )
        if not _binding_shape_valid(candidate):
            raise AssertionError(
                f"changed launch binding is structurally invalid: {case['name']}"
            )
        trusted_validator.validate(changed_context)
        binding_validator.validate(candidate)
        actual_expected = {
            "argvFingerprint": candidate["argvFingerprint"],
            "environmentFingerprint": candidate["environmentFingerprint"],
            "fingerprintDelta": {
                "argvFingerprint": (
                    "unchanged"
                    if candidate["argvFingerprint"]
                    == fixture["binding"]["argvFingerprint"]
                    else "changed"
                ),
                "environmentFingerprint": (
                    "unchanged"
                    if candidate["environmentFingerprint"]
                    == fixture["binding"]["environmentFingerprint"]
                    else "changed"
                ),
            },
            "verification": "trusted-context-invalid",
        }
        if actual_expected != case["expected"]:
            raise AssertionError((case["name"], actual_expected, case["expected"]))
        if not verify_trusted_launch_context(candidate, changed_context, root=root):
            raise AssertionError(
                f"self-consistent rematerialized binding rejected: {case['name']}"
            )
        if verify_trusted_launch_context(candidate, original_context, root=root):
            raise AssertionError(
                f"unchanged trusted context accepted mutation: {case['name']}"
            )
        passed += 1
    if len(vectors["environmentNegativeCases"]) != 8:
        raise AssertionError("expected exactly eight environment negative cases")
    return CheckSummary(passed=passed, total=11)


def validate_trusted_launch_regressions(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    fixture = vectors["concreteLaunch"]["positiveRoles"]["reader"]
    binding = fixture["binding"]
    trusted_context = fixture["trustedContext"]
    passed = 0

    extra_context = copy.deepcopy(trusted_context)
    extra_context["future"] = True
    if verify_trusted_launch_context(binding, extra_context, root=root):
        raise AssertionError("trusted launch accepted an extra context field")
    passed += 1

    missing_version = copy.deepcopy(trusted_context)
    del missing_version["schemaVersion"]
    if verify_trusted_launch_context(binding, missing_version, root=root):
        raise AssertionError("trusted launch accepted missing schemaVersion")
    passed += 1

    foreign_schema = copy.deepcopy(trusted_context)
    foreign_schema["resultSchemaPath"] = "/private/schemas/writer-result-v1.schema.json"
    foreign_binding = materialize_launch_binding("reader", foreign_schema, root=root)
    if verify_trusted_launch_context(foreign_binding, foreign_schema, root=root):
        raise AssertionError("reader trusted launch accepted writer result schema")
    passed += 1

    with tempfile.TemporaryDirectory() as directory:
        temporary_root = Path(directory)
        for relative in (
            "docs/contracts/vectors/child-profile-v1.json",
            "docs/contracts/vectors/interface-evidence-v1.json",
        ):
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination)
        if verify_trusted_launch_context(binding, trusted_context, root=temporary_root):
            raise AssertionError("trusted launch accepted a missing result schema file")
    passed += 1
    return CheckSummary(passed=passed, total=4)


def validate_child_profile_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    validator = _jsonschema_validator(
        root / "docs/contracts/schemas/child-profile-v1.schema.json"
    )
    passed = 0
    for case in vectors["cases"]:
        validator.validate(case["profile"])
        if canonical_json_v1(case["profile"]) != case["canonicalUtf8"]:
            raise AssertionError(f"child profile canonical drift: {case['name']}")
        actual = domain_fingerprint(vectors["profileDomain"], case["profile"])
        if actual != case["fingerprint"]:
            raise AssertionError(f"child profile fingerprint drift: {case['name']}")
        if actual != interface["semantic"]["childProfiles"][case["name"]]:
            raise AssertionError(
                f"InterfaceEvidence child profile reference drift: {case['name']}"
            )
        passed += 1
    fixture = vectors["syntheticSecretFixture"]
    raw_secret_fp = hashlib.sha256(
        fixture["domain"].encode("utf-8")
        + b"\0"
        + fixture["syntheticSecretUtf8"].encode("utf-8")
    ).hexdigest()
    if raw_secret_fp != fixture["secretSha256"]:
        raise AssertionError("synthetic secret raw fingerprint drift")
    if (
        domain_fingerprint(fixture["domain"], fixture["syntheticSecretUtf8"])
        == fixture["secretSha256"]
    ):
        raise AssertionError(
            "synthetic secret incorrectly uses canonical JSON string bytes"
        )
    for role_fixture in vectors["concreteLaunch"]["positiveRoles"].values():
        if role_fixture["binding"]["secretSha256"] != fixture["secretSha256"]:
            raise AssertionError(
                "positive launch does not bind the synthetic secret fingerprint"
            )
    return CheckSummary(passed=passed, total=3)


def _binding_internal_valid(
    binding: dict[str, Any], child_profile_refs: dict[str, str], root: Path
) -> bool:
    child_vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    child_schema = load_json(
        root / "docs/contracts/schemas/child-profile-v1.schema.json"
    )
    binding_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/child-profile-v1.schema.json"
    ).evolve(schema={"$ref": "#/$defs/launchBinding", "$defs": child_schema["$defs"]})
    if not binding_validator.is_valid(binding):
        return False
    if binding["compatibilityFingerprint"] != interface["compatibilityFingerprint"]:
        return False
    profiles = _child_profiles(root)
    profile = profiles[binding["role"]]
    profile_fp = domain_fingerprint(child_vectors["profileDomain"], profile)
    if profile_fp != child_profile_refs[binding["role"]]:
        return False
    expected_argv = _materialize_argv(
        profile, binding["arguments"], binding["nonSecretEnvironment"]
    )
    if expected_argv != binding["concreteArgv"]:
        return False
    if (
        domain_fingerprint(child_vectors["argvDomain"], expected_argv)
        != binding["argvFingerprint"]
    ):
        return False
    environment_projection = {
        "variables": binding["nonSecretEnvironment"],
        "secretBindings": {"OTEL_EXPORTER_OTLP_HEADERS": binding["secretSha256"]},
    }
    return (
        domain_fingerprint(child_vectors["environmentDomain"], environment_projection)
        == binding["environmentFingerprint"]
    )


def validate_child_negative_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    profiles = _child_profiles(root)
    profile_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/child-profile-v1.schema.json"
    )
    child_schema = load_json(
        root / "docs/contracts/schemas/child-profile-v1.schema.json"
    )
    binding_validator = profile_validator.evolve(
        schema={"$ref": "#/$defs/launchBinding", "$defs": child_schema["$defs"]}
    )
    reader_fixture = vectors["concreteLaunch"]["positiveRoles"]["reader"]
    reader_binding = reader_fixture["binding"]
    reader_context = reader_fixture["trustedContext"]
    passed = 0
    for case in vectors["negativeCases"]:
        target_name = case["target"]
        operation = case["mutation"]
        if target_name.startswith("profile:"):
            role = target_name.split(":", 1)[1]
            changed = copy.deepcopy(profiles[role])
            target: Any = changed
            for token in _pointer_tokens(operation["pointer"]):
                target = target[int(token)] if type(target) is list else target[token]
            if operation["kind"] == "swap-array-items":
                first, second = operation["first"], operation["second"]
                target[first], target[second] = target[second], target[first]
            elif operation["kind"] == "remove-array-item":
                del target[operation["index"]]
            elif operation["kind"] == "append-array-item":
                target.append(copy.deepcopy(operation["value"]))
            else:
                raise AssertionError(f"unknown profile mutation: {operation['kind']}")
            actual = (
                "profile-schema-invalid"
                if not profile_validator.is_valid(changed)
                else "profile-schema-valid"
            )
        elif target_name == "interface.semantic.childProfiles":
            changed_refs = copy.deepcopy(interface["semantic"]["childProfiles"])
            changed_refs[operation["pointer"].strip("/")] = operation["value"]
            actual = (
                "profile-resolution-valid"
                if _binding_internal_valid(reader_binding, changed_refs, root)
                else "profile-resolution-invalid"
            )
        elif target_name == "concreteLaunch.positiveRoles.reader.binding":
            changed = copy.deepcopy(reader_binding)
            if operation["kind"] == "replace-argument-and-rematerialize":
                changed["arguments"][operation["argument"]] = operation["value"]
                changed["concreteArgv"] = _materialize_argv(
                    profiles["reader"],
                    changed["arguments"],
                    changed["nonSecretEnvironment"],
                )
                changed["argvFingerprint"] = domain_fingerprint(
                    vectors["argvDomain"], changed["concreteArgv"]
                )
                rematerialized = case["rematerialized"]
                if (
                    changed["concreteArgv"][rematerialized["argvIndex"]]
                    != rematerialized["argvValue"]
                ):
                    raise AssertionError(
                        f"rematerialized argv value drift: {case['name']}"
                    )
                if changed["argvFingerprint"] != rematerialized["argvFingerprint"]:
                    raise AssertionError(
                        f"rematerialized argv fingerprint drift: {case['name']}"
                    )
                if not binding_validator.is_valid(changed):
                    raise AssertionError(
                        f"rematerialized binding schema-invalid: {case['name']}"
                    )
                if not _binding_internal_valid(
                    changed, interface["semantic"]["childProfiles"], root
                ):
                    raise AssertionError(
                        f"rematerialized binding internally invalid: {case['name']}"
                    )
                actual = (
                    "launch-schema-valid-context-valid"
                    if verify_trusted_launch_context(changed, reader_context, root=root)
                    else "launch-schema-valid-context-invalid"
                )
            elif operation["kind"] == "add-shell-environment-key":
                prefix = "shell_environment_policy.set="
                index = next(
                    index
                    for index, value in enumerate(changed["concreteArgv"])
                    if value.startswith(prefix)
                )
                environment = strict_json_loads(
                    changed["concreteArgv"][index][len(prefix) :]
                )
                environment[operation["key"]] = operation["value"]
                changed["concreteArgv"][index] = prefix + canonical_json_v1(environment)
                actual = (
                    "profile-resolution-valid"
                    if _binding_internal_valid(
                        changed, interface["semantic"]["childProfiles"], root
                    )
                    else "profile-resolution-invalid"
                )
            else:
                parent, token = _pointer_parent(changed, operation["pointer"])
                parent[token] = copy.deepcopy(operation["value"])
                if not binding_validator.is_valid(changed):
                    actual = "launch-schema-invalid"
                else:
                    actual = (
                        "profile-resolution-valid"
                        if _binding_internal_valid(
                            changed, interface["semantic"]["childProfiles"], root
                        )
                        else "profile-resolution-invalid"
                    )
        else:
            raise AssertionError(f"stale child negative target: {target_name}")
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    if len(vectors["negativeCases"]) != 15:
        raise AssertionError("expected exactly 15 child negative cases")
    return CheckSummary(passed=passed, total=15)


def normalize_routing_policy_source(
    source: Any, policy: dict[str, Any]
) -> dict[str, Any]:
    if type(source) is not dict:
        return {
            "status": "rejected",
            "phase": "structure",
            "errorCode": "ROUTING_POLICY_MALFORMED",
        }
    defaults = policy["defaults"]
    if set(source) - set(defaults):
        return {
            "status": "rejected",
            "phase": "structure",
            "errorCode": "ROUTING_POLICY_MALFORMED",
        }
    allowed_values = {
        "hardFloor": {
            level["name"] for level in policy["hardFloorDefinitions"]["levels"]
        },
        "intervalPoint": {defaults["intervalPoint"]},
        "unavailablePair": {defaults["unavailablePair"]},
        "reassessment": {defaults["reassessment"]},
    }
    if any(value not in allowed_values[key] for key, value in source.items()):
        return {
            "status": "rejected",
            "phase": "structure",
            "errorCode": "ROUTING_POLICY_MALFORMED",
        }
    normalized = copy.deepcopy(defaults)
    normalized.update(copy.deepcopy(source))
    return {"status": "normalized", "normalized": normalized}


def routing_availability_error(
    selected_pair: dict[str, str], catalogs: dict[str, Any]
) -> str | None:
    selected = (selected_pair["model"], selected_pair["reasoningEffort"])
    for catalog_name in ("policyPairs", "bundledSnapshotPairs", "accountPairs"):
        pairs = {
            (pair["model"], pair["reasoningEffort"]) for pair in catalogs[catalog_name]
        }
        if selected not in pairs:
            return "ROUTING_PAIR_UNAVAILABLE"
    return None


def validate_routing_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/routing-policy-v2.json")
    policy = vectors["policy"]
    if "hardFloors" in policy or "criterionStateOrder" in policy:
        raise AssertionError("duplicated routing model fields remain")
    if canonical_json_v1(policy) != vectors["canonicalUtf8"]:
        raise AssertionError("routing policy canonical bytes drifted")
    if domain_fingerprint(vectors["domain"], policy) != vectors["fingerprint"]:
        raise AssertionError("routing policy fingerprint drifted")
    routing_schema = load_json(
        root / "docs/contracts/schemas/routing-policy-v2.schema.json"
    )
    if policy != routing_schema.get("const"):
        raise AssertionError("routing policy differs from its exact schema const")

    passed = 0
    for case in vectors["normalizationCases"]:
        if set(case) != {"name", "source", "expected"}:
            raise AssertionError(
                f"routing normalization case is not closed: {case.get('name')}"
            )
        actual = normalize_routing_policy_source(case["source"], policy)
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    if len(vectors["normalizationCases"]) != 2:
        raise AssertionError("expected exactly two routing normalization cases")

    for case in vectors["availabilityCases"]:
        if "expectedError" not in case:
            raise AssertionError(
                f"availability case lacks expectedError: {case['name']}"
            )
        actual_error = routing_availability_error(
            case["selectedPair"], case["catalogs"]
        )
        if actual_error != case["expectedError"]:
            raise AssertionError((case["name"], actual_error, case["expectedError"]))
        passed += 1
    if len(vectors["availabilityCases"]) != 7:
        raise AssertionError("expected exactly seven routing availability cases")
    return CheckSummary(passed=passed, total=9)


def routing_interval(
    factor: str, states: dict[str, str], definitions: dict[str, Any]
) -> dict[str, int]:
    criteria = definitions[factor]["criteria"]
    resolution = definitions["resolution"]
    expected_ids = {criterion["id"] for criterion in criteria}
    if set(states) != expected_ids:
        raise ContractError(f"criterion state keys do not match {factor}")
    known_states = set(resolution["criterionStates"])
    if any(state not in known_states for state in states.values()):
        raise ContractError(f"unknown criterion state for {factor}")
    lower = max(
        [resolution["identityValue"]]
        + [
            criterion["level"]
            for criterion in criteria
            if states[criterion["id"]] in resolution["lowerStates"]
        ]
    )
    upper = max(
        [lower]
        + [
            criterion["level"]
            for criterion in criteria
            if states[criterion["id"]] in resolution["upperStates"]
        ]
    )
    return {"min": lower, "max": upper, "selected": upper}


def _boundary_policy_valid(
    value: dict[str, Any], policy: dict[str, Any], definitions: dict[str, Any]
) -> bool:
    try:
        for factor in ("q", "p", "v", "o"):
            interval = routing_interval(
                factor, value["criterionStates"][factor], definitions
            )
            if value[factor] != {"min": interval["min"], "max": interval["max"]}:
                return False
        reason_rank: dict[str, int] = {}
        for index, level in enumerate(policy["hardFloorDefinitions"]["levels"]):
            for reason in level["reasons"]:
                reason_rank[reason] = index
        if any(reason not in reason_rank for reason in value["hardFloorReasons"]):
            return False
        floor_index = max(
            [0] + [reason_rank[reason] for reason in value["hardFloorReasons"]]
        )
        return (
            value["hardFloor"]
            == policy["hardFloorDefinitions"]["levels"][floor_index]["name"]
        )
    except (ContractError, KeyError, TypeError):
        return False


def validate_routing_legacy_cases(root: Path = ROOT) -> dict[str, CheckSummary]:
    vectors = load_json(root / "docs/contracts/vectors/routing-policy-v2.json")
    policy = vectors["policy"]
    definitions = policy["factorDefinitions"]

    criterion_passed = 0
    for case in vectors["criterionCases"]:
        actual = routing_interval(case["factor"], case["criterionStates"], definitions)
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        criterion_passed += 1
    conflict_cases = [
        case for case in vectors["criterionCases"] if case["name"].endswith("-conflict")
    ]
    if {case["name"] for case in conflict_cases} != {
        "q-conflict",
        "p-conflict",
        "v-conflict",
        "o-conflict",
    }:
        raise AssertionError("routing conflict criterion coverage drifted")
    without_conflict = copy.deepcopy(definitions)
    without_conflict["resolution"]["upperStates"].remove("conflict")
    for case in conflict_cases:
        if (
            routing_interval(case["factor"], case["criterionStates"], without_conflict)
            == case["expected"]
        ):
            raise AssertionError(
                f"conflict state is not semantically active: {case['name']}"
            )

    boundary_validator = _jsonschema_validator(
        root / "docs/contracts/schemas/boundary-result-v1.schema.json"
    )
    boundary_passed = 0
    boundary_by_name: dict[str, dict[str, Any]] = {}
    for case in vectors["boundaryCases"]:
        value = case["value"]
        schema_valid = boundary_validator.is_valid(value)
        policy_valid = schema_valid and _boundary_policy_valid(
            value, policy, definitions
        )
        actual = (
            "schema-invalid"
            if not schema_valid
            else "schema-and-policy-valid"
            if policy_valid
            else "policy-invalid"
        )
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        boundary_by_name[case["name"]] = value
        boundary_passed += 1
    if not _boundary_policy_valid(
        boundary_by_name["conflict-consistent"], policy, definitions
    ):
        raise AssertionError("conflict-consistent boundary rejected")
    if _boundary_policy_valid(
        boundary_by_name["conflict-consistent"], policy, without_conflict
    ):
        raise AssertionError("conflict-consistent boundary ignores conflict semantics")
    if _boundary_policy_valid(
        boundary_by_name["conflict-interval-mismatch"], policy, definitions
    ):
        raise AssertionError("conflict interval mismatch accepted")
    if not _boundary_policy_valid(
        boundary_by_name["conflict-interval-mismatch"], policy, without_conflict
    ):
        raise AssertionError("conflict interval mutant witness is ineffective")

    effort_by_score = {
        item["score"]: item["reasoningEffort"] for item in policy["effortByScore"]
    }
    score_passed = 0
    for case in vectors["scoreCases"]:
        score = sum(case["factors"].values())
        tier = next(
            item
            for item in policy["tiers"]
            if item["scoreMin"] <= score <= item["scoreMax"]
        )
        actual = {
            "tier": tier["name"],
            "model": tier["model"],
            "reasoningEffort": effort_by_score[score],
        }
        if score != case["score"] or actual != case["expected"]:
            raise AssertionError((case["name"], score, actual, case["expected"]))
        score_passed += 1

    tier_rank = {item["name"]: index for index, item in enumerate(policy["tiers"])}
    effort_rank = {value: index for index, value in enumerate(policy["effortOrder"])}
    reason_rank: dict[str, int] = {}
    for index, level in enumerate(policy["hardFloorDefinitions"]["levels"]):
        for reason in level["reasons"]:
            reason_rank[reason] = index
    hard_floor_passed = 0
    for case in vectors["hardFloorCases"]:
        if any(reason not in reason_rank for reason in case["reasons"]):
            actual: Any = "schema-invalid"
        else:
            floor_index = max([0] + [reason_rank[reason] for reason in case["reasons"]])
            floor = policy["hardFloorDefinitions"]["levels"][floor_index]
            score_tier = next(
                item
                for item in policy["tiers"]
                if item["scoreMin"] <= case["score"] <= item["scoreMax"]
            )
            floor_tier = next(
                item for item in policy["tiers"] if item["name"] == floor["minimumTier"]
            )
            selected_tier = (
                floor_tier
                if tier_rank[floor_tier["name"]] > tier_rank[score_tier["name"]]
                else score_tier
            )
            selected_effort = max(
                (effort_by_score[case["score"]], selected_tier["minimumEffort"]),
                key=effort_rank.__getitem__,
            )
            actual = {
                "tier": selected_tier["name"],
                "model": selected_tier["model"],
                "reasoningEffort": selected_effort,
            }
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        hard_floor_passed += 1

    pair_rank = {
        (pair["model"], pair["reasoningEffort"]): index
        for index, pair in enumerate(policy["allowedPairs"])
    }
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    account = load_json(root / "docs/contracts/vectors/account-evidence-v1.json")[
        "base"
    ]
    fingerprint_baseline = {
        "policyFingerprint": vectors["fingerprint"],
        "bundledSnapshotFingerprint": interface["semantic"][
            "bundledCatalogFingerprint"
        ],
        "accountFingerprint": account["accountCatalogFingerprint"],
    }
    reassessment_passed = 0
    for case in vectors["reassessmentCases"]:
        if case["catalogFingerprintCheck"]["before"] != fingerprint_baseline:
            raise AssertionError(
                f"reassessment baseline fingerprint drift: {case['name']}"
            )
        before = case["catalogFingerprintCheck"]["before"]
        after = case["catalogFingerprintCheck"]["after"]
        current = case["currentPair"]
        candidate = case["candidatePair"]
        current_available = (
            routing_availability_error(current, case["catalogs"]) is None
        )
        if before != after or not current_available:
            selected = None
            error = "STALE"
        else:
            current_key = (current["model"], current["reasoningEffort"])
            candidate_key = (candidate["model"], candidate["reasoningEffort"])
            selected = (
                candidate
                if pair_rank[candidate_key] > pair_rank[current_key]
                else current
            )
            error = routing_availability_error(selected, case["catalogs"])
            if error is not None:
                selected = None
        if selected != case.get("expected") or error != case.get("expectedError"):
            raise AssertionError(
                (
                    case["name"],
                    selected,
                    error,
                    case.get("expected"),
                    case.get("expectedError"),
                )
            )
        reassessment_passed += 1
    expected_changed_fields = {
        "policy-fingerprint-changed": "policyFingerprint",
        "bundled-snapshot-fingerprint-changed": "bundledSnapshotFingerprint",
        "catalog-fingerprint-changed": "accountFingerprint",
    }
    for name, field in expected_changed_fields.items():
        case = next(
            item for item in vectors["reassessmentCases"] if item["name"] == name
        )
        before = case["catalogFingerprintCheck"]["before"]
        after = case["catalogFingerprintCheck"]["after"]
        if {key for key in before if before[key] != after[key]} != {field}:
            raise AssertionError(f"reassessment fingerprint witness drift: {name}")

    return {
        "criterion": CheckSummary(criterion_passed, len(vectors["criterionCases"])),
        "boundary": CheckSummary(boundary_passed, len(vectors["boundaryCases"])),
        "score": CheckSummary(score_passed, len(vectors["scoreCases"])),
        "hard-floor": CheckSummary(hard_floor_passed, len(vectors["hardFloorCases"])),
        "reassessment": CheckSummary(
            reassessment_passed, len(vectors["reassessmentCases"])
        ),
    }


def _account_fingerprint_chain_valid(account: dict[str, Any], root: Path) -> bool:
    vectors = load_json(root / "docs/contracts/vectors/account-evidence-v1.json")
    interface = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")[
        "base"
    ]
    domains = vectors["domains"]
    expected_subject = {
        "snapshotPath": interface["subject"]["snapshotPath"],
        "snapshotSha256": interface["subject"]["snapshotSha256"],
        "subjectFingerprint": interface["subjectFingerprint"],
    }
    if account["subject"] != expected_subject:
        return False
    if account["compatibilityFingerprint"] != interface["compatibilityFingerprint"]:
        return False
    collection = account["collection"]
    if collection["environment"]["CODEX_HOME"] != account["codexHome"]:
        return False
    requirements_fp = domain_fingerprint(
        domains["requirements"], account["requirements"]
    )
    catalog_fp = domain_fingerprint(
        domains["accountCatalog"], account["availablePairs"]
    )
    environment_fp = domain_fingerprint(
        domains["accountEnvironment"], collection["environment"]
    )
    if requirements_fp != account["requirementsFingerprint"]:
        return False
    if catalog_fp != account["accountCatalogFingerprint"]:
        return False
    if environment_fp != collection["environmentFingerprint"]:
        return False

    process_fps: list[str] = []
    for process in collection["processes"]:
        result_fp = (
            requirements_fp
            if process["resultFingerprintRef"] == "#/requirementsFingerprint"
            else catalog_fp
        )
        projection = {
            "record": {
                "ordinal": process["ordinal"],
                "stage": process["stage"],
                "resultFingerprintRef": process["resultFingerprintRef"],
            },
            "resolved": {
                "executablePath": account["subject"]["snapshotPath"],
                "subjectFingerprint": account["subject"]["subjectFingerprint"],
                "compatibilityFingerprint": account["compatibilityFingerprint"],
                "resultFingerprint": result_fp,
            },
            "argv": collection["argv"],
            "environment": collection["environment"],
            "environmentFingerprint": environment_fp,
        }
        actual_fp = domain_fingerprint(domains["accountProcess"], projection)
        if actual_fp != process["processFingerprint"]:
            return False
        process_fps.append(actual_fp)
    collection_fp = domain_fingerprint(
        domains["accountCollection"], {"processFingerprints": process_fps}
    )
    if collection_fp != collection["collectionFingerprint"]:
        return False
    context_projection = {
        "codexHome": account["codexHome"],
        "subjectFingerprint": account["subject"]["subjectFingerprint"],
        "compatibilityFingerprint": account["compatibilityFingerprint"],
        "requirementsFingerprint": requirements_fp,
        "accountCatalogFingerprint": catalog_fp,
        "collectionFingerprint": collection_fp,
    }
    context_fp = domain_fingerprint(domains["accountContext"], context_projection)
    if context_fp != account["accountContextFingerprint"]:
        return False
    record_projection = {
        "schemaVersion": account["schemaVersion"],
        "contractVersion": account["contractVersion"],
        "subjectFingerprint": account["subject"]["subjectFingerprint"],
        "compatibilityFingerprint": account["compatibilityFingerprint"],
        "requirementsFingerprint": requirements_fp,
        "accountCatalogFingerprint": catalog_fp,
        "accountContextFingerprint": context_fp,
        "collectionFingerprint": collection_fp,
    }
    return (
        domain_fingerprint(domains["accountRecord"], record_projection)
        == account["recordFingerprint"]
    )


def _account_order_valid(account: dict[str, Any]) -> bool:
    pairs = account["availablePairs"]
    expected = sorted(
        pairs,
        key=lambda pair: (
            pair["model"].encode("utf-8"),
            pair["reasoningEffort"].encode("utf-8"),
        ),
    )
    return pairs == expected


def classify_account_evidence_failure(
    value: dict[str, Any], *, root: Path = ROOT
) -> str:
    validator = _jsonschema_validator(
        root / "docs/contracts/schemas/account-evidence-v1.schema.json"
    )
    if not validator.is_valid(value):
        return "schema-invalid"
    for field in ("startedAt", "finishedAt"):
        if field in value:
            try:
                parsed = dt.datetime.fromisoformat(value[field].replace("Z", "+00:00"))
            except (TypeError, ValueError):
                return "schema-invalid"
            if parsed.tzinfo is None:
                return "schema-invalid"
    if not _account_fingerprint_chain_valid(value, root):
        return "fingerprint-invalid"
    if not _account_order_valid(value):
        return "ordering-invalid"
    return "valid"


def _apply_account_operation(value: dict[str, Any], operation: dict[str, Any]) -> None:
    pointer = operation["pointer"]
    tokens = _pointer_tokens(pointer)
    target: Any = value
    if operation["kind"] in {"swap-array-items", "swap-array-items-and-recalculate"}:
        for token in tokens:
            target = target[int(token)] if type(target) is list else target[token]
        first, second = operation["first"], operation["second"]
        target[first], target[second] = target[second], target[first]
        return
    for token in tokens[:-1]:
        target = target[int(token)] if type(target) is list else target[token]
    token = tokens[-1]
    if operation["kind"] in {"replace", "add"}:
        if type(target) is list:
            target[int(token)] = copy.deepcopy(operation["value"])
        else:
            target[token] = copy.deepcopy(operation["value"])
    elif operation["kind"] == "remove":
        if type(target) is list:
            del target[int(token)]
        else:
            del target[token]
    else:
        raise ContractError(f"unknown account mutation kind: {operation['kind']}")


def validate_account_failure_classes(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/account-evidence-v1.json")
    if classify_account_evidence_failure(vectors["base"], root=root) != "valid":
        raise AssertionError("base AccountEvidence is not valid")
    passed = 0
    for case in vectors["mutations"]:
        changed = copy.deepcopy(vectors["base"])
        _apply_account_operation(changed, case["operation"])
        if case["operation"]["kind"] == "swap-array-items-and-recalculate":
            recalculated = case["recalculated"]
            changed["accountCatalogFingerprint"] = recalculated[
                "accountCatalogFingerprint"
            ]
            for process, process_fp in zip(
                changed["collection"]["processes"],
                recalculated["processFingerprints"],
                strict=True,
            ):
                process["processFingerprint"] = process_fp
            changed["collection"]["collectionFingerprint"] = recalculated[
                "collectionFingerprint"
            ]
            changed["accountContextFingerprint"] = recalculated[
                "accountContextFingerprint"
            ]
            changed["recordFingerprint"] = recalculated["recordFingerprint"]
        actual = classify_account_evidence_failure(changed, root=root)
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    return CheckSummary(passed=passed, total=len(vectors["mutations"]))


def interface_utf8_bytes_valid(value: dict[str, Any]) -> bool:
    subject = value["subject"]
    for field in ("snapshotPath", "sourceLocator"):
        if len(subject[field].encode("utf-8")) > 4_096:
            return False
    if len(subject["version"].encode("utf-8")) > 64:
        return False
    stack: list[Any] = [value["semantic"]]
    while stack:
        current = stack.pop()
        if type(current) is str:
            if not current or len(current.encode("utf-8")) > 256:
                return False
        elif type(current) is dict:
            for key, child in current.items():
                if not key or len(key.encode("utf-8")) > 256:
                    return False
                stack.append(child)
        elif type(current) is list:
            stack.extend(current)
    return True


def _recalculate_interface_artifacts(
    value: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    canonical = {
        "subjectUtf8": canonical_json_v1(value["subject"]),
        "semanticUtf8": canonical_json_v1(value["semantic"]),
    }
    fingerprints = interface_projection_fingerprints(value)
    compatibility_projection = {
        "contractVersion": value["contractVersion"],
        "semanticFingerprint": fingerprints["semanticFingerprint"],
        "subjectFingerprint": fingerprints["subjectFingerprint"],
    }
    canonical["compatibilityUtf8"] = canonical_json_v1(compatibility_projection)
    value.update(fingerprints)
    return canonical, fingerprints


def _interface_artifacts_consistent(
    value: dict[str, Any], canonical: dict[str, str], fingerprints: dict[str, str]
) -> bool:
    expected_fingerprints = interface_projection_fingerprints(value)
    expected_compatibility = {
        "contractVersion": value["contractVersion"],
        "semanticFingerprint": expected_fingerprints["semanticFingerprint"],
        "subjectFingerprint": expected_fingerprints["subjectFingerprint"],
    }
    expected_canonical = {
        "subjectUtf8": canonical_json_v1(value["subject"]),
        "semanticUtf8": canonical_json_v1(value["semantic"]),
        "compatibilityUtf8": canonical_json_v1(expected_compatibility),
    }
    return (
        canonical == expected_canonical
        and fingerprints == expected_fingerprints
        and all(
            value[name] == fingerprint for name, fingerprint in fingerprints.items()
        )
    )


@dataclass(frozen=True)
class _InterfaceBoundaryOps:
    utf8_valid: Callable[[dict[str, Any]], bool]


_DEFAULT_INTERFACE_BOUNDARY_OPS = _InterfaceBoundaryOps(
    utf8_valid=interface_utf8_bytes_valid,
)


def _evaluate_interface_utf8_boundary(
    base: dict[str, Any],
    operation: dict[str, Any],
    schema_valid: Callable[[dict[str, Any]], bool],
    ops: _InterfaceBoundaryOps,
) -> dict[str, Any]:
    candidate = apply_interface_operation(base, operation)
    canonical, fingerprints = _recalculate_interface_artifacts(candidate)
    consistency = _interface_artifacts_consistent(candidate, canonical, fingerprints)
    return {
        "schema": "valid" if schema_valid(candidate) else "invalid",
        "byteValidation": "accepted" if ops.utf8_valid(candidate) else "rejected",
        "artifactConsistency": "consistent" if consistency else "inconsistent",
        "recalculatedCanonical": canonical,
        "recalculatedFingerprints": fingerprints,
    }


def evaluate_interface_utf8_boundary(
    base: dict[str, Any],
    operation: dict[str, Any],
    schema_valid: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    return _evaluate_interface_utf8_boundary(
        base,
        operation,
        schema_valid,
        _DEFAULT_INTERFACE_BOUNDARY_OPS,
    )


def validate_interface_utf8_boundary_cases(root: Path = ROOT) -> CheckSummary:
    vectors = load_json(root / "docs/contracts/vectors/interface-evidence-v1.json")
    validator = _jsonschema_validator(
        root / "docs/contracts/schemas/interface-evidence-v1.schema.json"
    )
    base = vectors["base"]
    base_fingerprints = interface_projection_fingerprints(base)
    if any(base[name] != value for name, value in base_fingerprints.items()):
        raise AssertionError("UTF-8 boundary base fingerprints are inconsistent")
    expected_base_canonical = {
        "subjectUtf8": canonical_json_v1(base["subject"]),
        "semanticUtf8": canonical_json_v1(base["semantic"]),
        "compatibilityUtf8": canonical_json_v1(
            {
                "contractVersion": base["contractVersion"],
                "semanticFingerprint": base_fingerprints["semanticFingerprint"],
                "subjectFingerprint": base_fingerprints["subjectFingerprint"],
            }
        ),
    }
    if vectors["canonical"] != expected_base_canonical:
        raise AssertionError("UTF-8 boundary base canonical artifacts are inconsistent")
    passed = 0
    for case in vectors["utf8BoundaryCases"]:
        if set(case) != {
            "name",
            "byteLimit",
            "utf8Bytes",
            "operation",
            "recalculateStoredFingerprints",
            "expected",
        }:
            raise AssertionError(
                f"UTF-8 boundary case is not closed: {case.get('name')}"
            )
        if case["recalculateStoredFingerprints"] is not True:
            raise AssertionError(
                f"UTF-8 boundary case skips fingerprint recalculation: {case['name']}"
            )
        if len(case["operation"]["value"].encode("utf-8")) != case["utf8Bytes"]:
            raise AssertionError(f"UTF-8 byte count drifted: {case['name']}")
        operation = case["operation"]
        if operation.get("kind") != "replace-value" or operation.get("pointer") not in {
            "/semantic/commands/0",
            "/subject/sourceLocator",
        }:
            raise AssertionError(
                f"unknown UTF-8 schema boundary target: {case['name']}"
            )

        actual = evaluate_interface_utf8_boundary(base, operation, validator.is_valid)
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
        passed += 1
    if {case["utf8Bytes"] for case in vectors["utf8BoundaryCases"]} != {
        256,
        257,
        4_096,
        4_097,
    }:
        raise AssertionError("UTF-8 boundary set is incomplete")
    return CheckSummary(passed=passed, total=4)


@dataclass(frozen=True)
class _MutantSpec:
    name: str
    expected: Any
    run: Callable[[], tuple[Any, bool]]


def _mutant_detected(spec: _MutantSpec) -> bool:
    """Инфраструктурная ошибка и не вызванная дефектная ветвь не считаются обнаружением."""

    try:
        actual, invoked = spec.run()
    except Exception:
        return False
    return invoked and actual != spec.expected


def validate_mutant_detector_calibration() -> CheckSummary:
    def raises() -> tuple[Any, bool]:
        raise RuntimeError("detector calibration exception")

    scenarios = [
        (_MutantSpec("equal-invoked", "same", lambda: ("same", True)), False),
        (
            _MutantSpec(
                "different-not-invoked",
                "expected",
                lambda: ("actual", False),
            ),
            False,
        ),
        (_MutantSpec("exception", "expected", raises), False),
        (
            _MutantSpec(
                "different-invoked",
                "expected",
                lambda: ("actual", True),
            ),
            True,
        ),
    ]
    actual = [_mutant_detected(spec) for spec, _expected in scenarios]
    expected = [expected for _spec, expected in scenarios]
    if actual != expected:
        raise AssertionError(
            {"mutantDetectorCalibration": {"actual": actual, "expected": expected}}
        )
    return CheckSummary(passed=4, total=4)


def oracle_mutant_results(root: Path = ROOT) -> dict[str, bool]:
    interface_vectors = load_json(
        root / "docs/contracts/vectors/interface-evidence-v1.json"
    )
    config_vectors = _load_config_vectors_exact(root)
    routing_vectors = load_json(root / "docs/contracts/vectors/routing-policy-v2.json")
    recipe_vectors = load_json(
        root / "docs/contracts/vectors/config-requirements-vector-recipes-v1.json"
    )
    child_vectors = load_json(root / "docs/contracts/vectors/child-profile-v1.json")
    account_vectors = load_json(
        root / "docs/contracts/vectors/account-evidence-v1.json"
    )
    config_cases = {case["name"]: case for case in config_vectors["cases"]}
    specs: list[_MutantSpec] = []

    def config_spec(
        name: str,
        case_name: str,
        *,
        normalize: Callable[[Any], Any] | None = None,
        compatibility: Callable[[Any, dict[str, Any], Path], dict[str, Any]]
        | None = None,
    ) -> _MutantSpec:
        case = config_cases[case_name]
        context = config_vectors["contexts"][case["contextRef"]]

        def run() -> tuple[Any, bool]:
            invoked = False

            def tracked_normalize(value: Any) -> Any:
                nonlocal invoked
                invoked = True
                if normalize is None:
                    return _DEFAULT_CONFIG_OPS.normalize(value)
                return normalize(value)

            def tracked_compatibility(
                value: Any, selected_context: dict[str, Any], selected_root: Path
            ) -> dict[str, Any]:
                nonlocal invoked
                invoked = True
                if compatibility is None:
                    return _DEFAULT_CONFIG_OPS.compatibility(
                        value, selected_context, selected_root
                    )
                return compatibility(value, selected_context, selected_root)

            ops = _ConfigOps(
                normalize=(
                    tracked_normalize
                    if normalize is not None
                    else _DEFAULT_CONFIG_OPS.normalize
                ),
                validate_normalized=_DEFAULT_CONFIG_OPS.validate_normalized,
                compatibility=(
                    tracked_compatibility
                    if compatibility is not None
                    else _DEFAULT_CONFIG_OPS.compatibility
                ),
            )
            actual = _evaluate_config_requirements(
                case["source"], context, root=root, ops=ops
            )
            return config_evaluation_to_dict(actual), invoked

        return _MutantSpec(name=name, expected=case["expected"], run=run)

    def keep_optional_null(requirements: Any) -> Any:
        return copy.deepcopy(requirements)

    def skip_granular_defaults(requirements: Any) -> Any:
        normalized = normalize_config_requirements(requirements)
        for policy in normalized.get("allowedApprovalPolicies", []):
            if type(policy) is dict:
                for key in _GRANULAR_DEFAULT_KEYS:
                    policy["granular"].pop(key, None)
        return normalized

    def skip_set_sort(requirements: Any) -> Any:
        normalized = normalize_config_requirements(requirements)
        normalized["allowedWebSearchModes"] = copy.deepcopy(
            requirements["allowedWebSearchModes"]
        )
        return normalized

    def skip_set_deduplication(requirements: Any) -> Any:
        normalized = normalize_config_requirements(requirements)
        normalized["allowedSandboxModes"] = copy.deepcopy(
            requirements["allowedSandboxModes"]
        )
        return normalized

    def unknown_field_as_malformed(requirements: Any) -> Any:
        try:
            return normalize_config_requirements(requirements)
        except ConfigStageError as error:
            if error.error_code != "MANAGED_REQUIREMENT_UNSUPPORTED":
                raise
            raise ConfigStageError(
                error.phase,
                "MANAGED_REQUIREMENT_MALFORMED",
                "mutant collapses unknown fields into malformed input",
            ) from error

    def always_compatible(
        _normalized: Any, _context: dict[str, Any], _root: Path
    ) -> dict[str, Any]:
        return {"status": "compatible"}

    def accept_network_conflict(requirements: Any) -> Any:
        changed = copy.deepcopy(requirements)
        changed["network"].pop("allowedDomains", None)
        changed["network"].pop("deniedDomains", None)
        return normalize_config_requirements(changed)

    def accept_unknown_enum(requirements: Any) -> Any:
        changed = copy.deepcopy(requirements)
        changed["allowedSandboxModes"] = [
            value if value in _ENUM_FIELDS["allowedSandboxModes"] else "read-only"
            for value in changed["allowedSandboxModes"]
        ]
        return normalize_config_requirements(changed)

    def collapse_null_to_empty(requirements: Any) -> Any:
        return (
            {} if requirements is None else normalize_config_requirements(requirements)
        )

    specs.extend(
        [
            config_spec(
                "config-keep-optional-null",
                "optional-null-equals-absent",
                normalize=keep_optional_null,
            ),
            config_spec(
                "config-skip-granular-defaults",
                "granular-defaults",
                normalize=skip_granular_defaults,
            ),
            config_spec(
                "config-skip-set-sort",
                "finite-enum-natural-set",
                normalize=skip_set_sort,
            ),
            config_spec(
                "config-skip-set-deduplication",
                "finite-enum-duplicate-normalizes",
                normalize=skip_set_deduplication,
            ),
            config_spec(
                "config-unknown-field-as-malformed",
                "unknown-protective-field",
                normalize=unknown_field_as_malformed,
            ),
            config_spec(
                "config-always-compatible",
                "approval-mismatch",
                compatibility=always_compatible,
            ),
            config_spec(
                "config-accept-network-conflict",
                "network-legacy-conflict",
                normalize=accept_network_conflict,
            ),
            config_spec(
                "config-accept-unknown-enum",
                "unknown-enum",
                normalize=accept_unknown_enum,
            ),
            config_spec(
                "config-collapse-null-to-empty",
                "requirements-null",
                normalize=collapse_null_to_empty,
            ),
        ]
    )

    base_interface = interface_vectors["base"]
    no_op_matches = [
        case
        for case in interface_vectors["oracleMutantCases"]
        if type(case) is dict and case.get("name") == "interface-no-op-accepted"
    ]
    if len(no_op_matches) != 1:
        raise AssertionError("interface no-op mutant vector must be unique")
    no_op_case = no_op_matches[0]
    if (
        type(no_op_case) is not dict
        or set(no_op_case) != {"name", "operation", "expected"}
        or type(no_op_case["operation"]) is not dict
        or set(no_op_case["operation"]) != {"kind", "pointer", "before", "value"}
        or no_op_case["operation"]["kind"] != "replace-value"
        or no_op_case["operation"]["before"] != no_op_case["operation"]["value"]
        or no_op_case["expected"] != {"kind": "operation-invalid"}
    ):
        raise AssertionError("interface no-op mutant vector is not closed")

    def run_no_op_mutant() -> tuple[Any, bool]:
        invoked = False
        operation = no_op_case["operation"]

        def permissive_apply(
            document: dict[str, Any], selected_operation: dict[str, Any]
        ) -> dict[str, Any]:
            nonlocal invoked
            invoked = True
            candidate = copy.deepcopy(document)
            _pointer_set_existing(
                candidate,
                selected_operation["pointer"],
                copy.deepcopy(selected_operation["value"]),
            )
            return candidate

        actual = _evaluate_interface_mutation(
            base_interface,
            operation,
            lambda _candidate: True,
            _InterfaceMutationOps(
                apply=permissive_apply,
                fingerprints=interface_projection_fingerprints,
            ),
        )
        return actual, invoked

    specs.append(
        _MutantSpec(
            name="interface-no-op-accepted",
            expected=no_op_case["expected"],
            run=run_no_op_mutant,
        )
    )

    interface_case = next(
        case
        for case in interface_vectors["mutations"]
        if case["name"] == "routing-policy-change"
    )

    def run_stored_fingerprint_mutant() -> tuple[Any, bool]:
        invoked = False

        def stored_fingerprints(value: dict[str, Any]) -> dict[str, str]:
            nonlocal invoked
            invoked = True
            return {
                name: value[name]
                for name in (
                    "subjectFingerprint",
                    "semanticFingerprint",
                    "compatibilityFingerprint",
                )
            }

        actual = _evaluate_interface_mutation(
            base_interface,
            interface_case["operation"],
            lambda _candidate: True,
            _InterfaceMutationOps(
                apply=apply_interface_operation,
                fingerprints=stored_fingerprints,
            ),
        )
        return actual, invoked

    specs.append(
        _MutantSpec(
            name="interface-delta-from-stored-fingerprints",
            expected=interface_case["expected"],
            run=run_stored_fingerprint_mutant,
        )
    )

    utf8_case = next(
        case
        for case in interface_vectors["utf8BoundaryCases"]
        if case["utf8Bytes"] == 257
    )

    def interface_boundary_spec(
        name: str, validator: Callable[[dict[str, Any]], bool]
    ) -> _MutantSpec:
        def run() -> tuple[Any, bool]:
            invoked = False

            def tracked(candidate: dict[str, Any]) -> bool:
                nonlocal invoked
                invoked = True
                return validator(candidate)

            actual = _evaluate_interface_utf8_boundary(
                base_interface,
                utf8_case["operation"],
                lambda _candidate: True,
                _InterfaceBoundaryOps(utf8_valid=tracked),
            )
            return actual, invoked

        return _MutantSpec(name=name, expected=utf8_case["expected"], run=run)

    def character_count_valid(value: dict[str, Any]) -> bool:
        if any(
            len(value["subject"][field]) > 4_096
            for field in ("snapshotPath", "sourceLocator")
        ):
            return False
        if len(value["subject"]["version"]) > 64:
            return False
        stack: list[Any] = [value["semantic"]]
        while stack:
            current = stack.pop()
            if type(current) is str and (not current or len(current) > 256):
                return False
            if type(current) is dict:
                if any(not key or len(key) > 256 for key in current):
                    return False
                stack.extend(current.values())
            elif type(current) is list:
                stack.extend(current)
        return True

    specs.extend(
        [
            interface_boundary_spec(
                "interface-byte-limit-as-character-count", character_count_valid
            ),
            interface_boundary_spec(
                "interface-always-utf8-valid", lambda _candidate: True
            ),
        ]
    )

    calibration = next(
        case
        for case in recipe_vectors["treeMetricCases"]
        if case["name"] == "one-object-value"
    )

    def run_count_names_mutant() -> tuple[Any, bool]:
        metrics = measure_json_value_tree(calibration["value"])
        return metrics.nodes + len(calibration["value"]), True

    def run_root_zero_mutant() -> tuple[Any, bool]:
        return measure_json_value_tree(None).depth - 1, True

    specs.extend(
        [
            _MutantSpec(
                "tree-count-object-member-names",
                calibration["expectedNodes"],
                run_count_names_mutant,
            ),
            _MutantSpec("tree-root-depth-zero", 1, run_root_zero_mutant),
        ]
    )

    regular_environment = next(
        case
        for case in child_vectors["environmentNegativeCases"]
        if case["slot"] == "snapshotRoot"
    )
    secret_environment = next(
        case
        for case in child_vectors["environmentNegativeCases"]
        if case["slot"] == "otelHeaders"
    )

    def environment_delta(
        original: dict[str, Any], argv_fp: str, environment_fp: str
    ) -> dict[str, str]:
        return {
            "argvFingerprint": (
                "unchanged" if argv_fp == original["argvFingerprint"] else "changed"
            ),
            "environmentFingerprint": (
                "unchanged"
                if environment_fp == original["environmentFingerprint"]
                else "changed"
            ),
        }

    def run_regular_environment_mutant() -> tuple[Any, bool]:
        fixture = child_vectors["concreteLaunch"]["positiveRoles"][
            regular_environment["role"]
        ]
        changed = copy.deepcopy(fixture["trustedContext"])
        changed["environmentSlotValues"][regular_environment["slot"]] = (
            regular_environment["value"]
        )
        profile = _child_profiles(root)[regular_environment["role"]]
        changed_environment, secret_sha = _materialize_environment(
            profile,
            changed["environmentSlotValues"],
            changed["secretSlotFingerprints"],
        )
        original_environment, _ = _materialize_environment(
            profile,
            fixture["trustedContext"]["environmentSlotValues"],
            fixture["trustedContext"]["secretSlotFingerprints"],
        )
        arguments = materialize_launch_binding(
            regular_environment["role"], changed, root=root
        )["arguments"]
        mutant_argv = _materialize_argv(profile, arguments, original_environment)
        argv_fp = domain_fingerprint(child_vectors["argvDomain"], mutant_argv)
        environment_fp = domain_fingerprint(
            child_vectors["environmentDomain"],
            {
                "variables": changed_environment,
                "secretBindings": {"OTEL_EXPORTER_OTLP_HEADERS": secret_sha},
            },
        )
        return environment_delta(fixture["binding"], argv_fp, environment_fp), True

    def run_secret_environment_mutant() -> tuple[Any, bool]:
        fixture = child_vectors["concreteLaunch"]["positiveRoles"][
            secret_environment["role"]
        ]
        changed = copy.deepcopy(fixture["trustedContext"])
        changed["secretSlotFingerprints"][secret_environment["slot"]] = (
            secret_environment["value"]
        )
        profile = _child_profiles(root)[secret_environment["role"]]
        environment, secret_sha = _materialize_environment(
            profile,
            changed["environmentSlotValues"],
            changed["secretSlotFingerprints"],
        )
        mutant_environment = copy.deepcopy(environment)
        mutant_environment["OTEL_EXPORTER_OTLP_HEADERS"] = secret_sha
        arguments = materialize_launch_binding(
            secret_environment["role"], changed, root=root
        )["arguments"]
        mutant_argv = _materialize_argv(profile, arguments, mutant_environment)
        argv_fp = domain_fingerprint(child_vectors["argvDomain"], mutant_argv)
        environment_fp = domain_fingerprint(
            child_vectors["environmentDomain"],
            {
                "variables": mutant_environment,
                "secretBindings": {"OTEL_EXPORTER_OTLP_HEADERS": secret_sha},
            },
        )
        return environment_delta(fixture["binding"], argv_fp, environment_fp), True

    specs.extend(
        [
            _MutantSpec(
                "environment-regular-slot-not-in-argv",
                regular_environment["expected"]["fingerprintDelta"],
                run_regular_environment_mutant,
            ),
            _MutantSpec(
                "environment-secret-in-argv",
                secret_environment["expected"]["fingerprintDelta"],
                run_secret_environment_mutant,
            ),
        ]
    )

    splice_case = next(
        case
        for case in routing_vectors["availabilityCases"]
        if case["name"] == "no-splice-policy"
    )

    def run_splice_mutant() -> tuple[Any, bool]:
        selected_model = splice_case["selectedPair"]["model"]
        selected_effort = splice_case["selectedPair"]["reasoningEffort"]
        available = all(
            selected_model in {pair["model"] for pair in catalog}
            and selected_effort in {pair["reasoningEffort"] for pair in catalog}
            for catalog in splice_case["catalogs"].values()
        )
        return None if available else "ROUTING_PAIR_UNAVAILABLE", True

    routing_unknown = next(
        case
        for case in routing_vectors["normalizationCases"]
        if case["name"] == "unknown-policy-field"
    )

    def run_routing_unknown_mutant() -> tuple[Any, bool]:
        defaults = copy.deepcopy(routing_vectors["policy"]["defaults"])
        defaults.update(
            {
                key: value
                for key, value in routing_unknown["source"].items()
                if key in defaults
            }
        )
        return {"status": "normalized", "normalized": defaults}, True

    specs.extend(
        [
            _MutantSpec(
                "routing-splice-model-and-effort",
                splice_case["expectedError"],
                run_splice_mutant,
            ),
            _MutantSpec(
                "routing-accept-unknown-field",
                routing_unknown["expected"],
                run_routing_unknown_mutant,
            ),
        ]
    )

    reordered = copy.deepcopy(account_vectors["base"])
    reordered["availablePairs"][0], reordered["availablePairs"][2] = (
        reordered["availablePairs"][2],
        reordered["availablePairs"][0],
    )
    correct_reordered_class = (
        "fingerprint-invalid"
        if not _account_fingerprint_chain_valid(reordered, root)
        else "ordering-invalid"
        if not _account_order_valid(reordered)
        else "valid"
    )

    def run_ordering_first_mutant() -> tuple[Any, bool]:
        if not _account_order_valid(reordered):
            return "ordering-invalid", True
        if not _account_fingerprint_chain_valid(reordered, root):
            return "fingerprint-invalid", True
        return "valid", True

    schema_mutation = account_vectors["mutations"][0]

    def run_collapsed_failure_mutant() -> tuple[Any, bool]:
        changed = copy.deepcopy(account_vectors["base"])
        _apply_account_operation(changed, schema_mutation["operation"])
        schema_shape_valid = (
            changed["collection"]["rootReferences"]["executablePath"]
            == "#/subject/snapshotPath"
        )
        if not schema_shape_valid:
            return "invalid", True
        if not _account_fingerprint_chain_valid(
            changed, root
        ) or not _account_order_valid(changed):
            return "invalid", True
        return "valid", True

    specs.extend(
        [
            _MutantSpec(
                "account-ordering-before-fingerprint-chain",
                correct_reordered_class,
                run_ordering_first_mutant,
            ),
            _MutantSpec(
                "account-collapse-failure-classes",
                schema_mutation["expected"],
                run_collapsed_failure_mutant,
            ),
        ]
    )

    schema_name = "child-profile-v1"
    stored_schema_sha = interface_vectors["base"]["semantic"]["machineSchemas"][
        schema_name
    ]["schemaSha256"]

    def run_domain_schema_sha_mutant() -> tuple[Any, bool]:
        schema_bytes = (
            root / f"docs/contracts/schemas/{schema_name}.schema.json"
        ).read_bytes()
        return hashlib.sha256(
            b"codex-smart/child-result-schema/v1\0" + schema_bytes
        ).hexdigest(), True

    specs.append(
        _MutantSpec(
            "schema-sha-domain-prefixed",
            stored_schema_sha,
            run_domain_schema_sha_mutant,
        )
    )

    if len(specs) != 22 or len({spec.name for spec in specs}) != 22:
        raise AssertionError("oracle mutant set must contain 22 unique computations")
    return {spec.name: _mutant_detected(spec) for spec in specs}


def validate_oracle_mutants(root: Path = ROOT) -> CheckSummary:
    results = oracle_mutant_results(root)
    undetected = sorted(name for name, detected in results.items() if not detected)
    if undetected:
        raise AssertionError({"undetectedOracleMutants": undetected})
    return CheckSummary(passed=len(results), total=len(results))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", action="store_true")
    parser.add_argument("--config", action="store_true")
    parser.add_argument("--tree", action="store_true")
    parser.add_argument("--recipes", action="store_true")
    parser.add_argument("--environment", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--routing", action="store_true")
    parser.add_argument("--account", action="store_true")
    parser.add_argument("--utf8", action="store_true")
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    if not (
        args.interface
        or args.config
        or args.tree
        or args.recipes
        or args.environment
        or args.child
        or args.routing
        or args.account
        or args.utf8
        or args.mutants
        or args.all
    ):
        parser.error(
            "required one of --interface, --config, --tree, --recipes, --environment, --child, --routing, --account, --utf8, --mutants or --all"
        )
    metamorphic_summaries: list[CheckSummary] = []
    if args.interface or args.all:
        summary = validate_interface_base_artifacts(ROOT)
        print("interface-base=1")
        print(f"machine-schema-sha={summary.passed - 1}/{summary.total - 1}")
        summary = validate_canonical_json_cases(ROOT)
        print(f"canonical-json={summary.passed}/{summary.total}")
        summary = validate_bundled_catalog_fixture(ROOT)
        print(f"bundled-catalog={summary.passed}/{summary.total}")
        summary = validate_interface_mutation_cases(ROOT)
        print(f"interface-mutations={summary.passed}/{summary.total}")
        summary = validate_hook_output_cases(ROOT)
        print(f"hook-output={summary.passed}/{summary.total}")
    if args.config or args.all:
        summary = validate_config_requirement_cases(ROOT)
        print(f"config-cases={summary.passed}/{summary.total}")
        error_summaries = validate_config_error_cases(ROOT)
        print(
            f"config-errors={error_summaries['all'].passed}/{error_summaries['all'].total}"
        )
        print(
            "config-errors-excluding-raw-duplicate="
            f"{error_summaries['excluding-raw-duplicate'].passed}/"
            f"{error_summaries['excluding-raw-duplicate'].total}"
        )
        summary = validate_config_metamorphic_cases(ROOT)
        print(f"config-metamorphic={summary.passed}/{summary.total}")
        metamorphic_summaries.append(summary)
        summary = validate_config_cycle6_regressions(ROOT)
        print(f"config-cycle6-regressions={summary.passed}/{summary.total}")
        summary = validate_config_cycle7_regressions(ROOT)
        print(f"config-cycle7-regressions={summary.passed}/{summary.total}")
        summary = validate_config_cycle8_regressions(ROOT)
        print(f"config-cycle8-regressions={summary.passed}/{summary.total}")
        summary = validate_config_expected_independence(ROOT)
        print(f"config-expected-independence={summary.passed}/{summary.total}")
    if args.tree or args.all:
        summary = validate_tree_metric_contract(ROOT)
        print(f"tree-metric={summary.passed}/{summary.total}")
        print("tree-metric-cases=5/5")
        print("tree-metric-metamorphic=3/3")
        metamorphic_summaries.append(CheckSummary(passed=3, total=3))
    if metamorphic_summaries:
        summary = aggregate_check_summaries(*metamorphic_summaries)
        print(f"metamorphic-cases={summary.passed}/{summary.total}")
    if args.recipes or args.all:
        summary = validate_config_recipe_cases(ROOT)
        print(f"config-recipes={summary.passed}/{summary.total}")
    if args.environment or args.all:
        summary = validate_environment_binding_cases(ROOT)
        print(f"environment-bindings={summary.passed}/{summary.total}")
        print("environment-positive-roles=3/3")
        print("environment-negative-slots=8/8")
        summary = validate_trusted_launch_regressions(ROOT)
        print(f"trusted-launch-regressions={summary.passed}/{summary.total}")
    if args.child or args.all:
        summary = validate_child_profile_cases(ROOT)
        print(f"child-profiles={summary.passed}/{summary.total}")
        summary = validate_child_negative_cases(ROOT)
        print(f"child-negatives={summary.passed}/{summary.total}")
    if args.routing or args.all:
        summary = validate_routing_cases(ROOT)
        print(f"routing-cases={summary.passed}/{summary.total}")
        print("routing-normalization=2/2")
        print("routing-availability=7/7")
        for name, legacy_summary in validate_routing_legacy_cases(ROOT).items():
            print(f"routing-{name}={legacy_summary.passed}/{legacy_summary.total}")
    if args.account or args.all:
        summary = validate_account_failure_classes(ROOT)
        print(f"account-failure-classes={summary.passed}/{summary.total}")
    if args.utf8 or args.all:
        summary = validate_interface_utf8_boundary_cases(ROOT)
        print(f"interface-utf8-boundaries={summary.passed}/{summary.total}")
    if args.mutants or args.all:
        summary = validate_mutant_detector_calibration()
        print(f"mutant-detector-calibration={summary.passed}/{summary.total}")
        summary = validate_oracle_mutants(ROOT)
        print(f"oracle-mutants={summary.passed}/{summary.total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
