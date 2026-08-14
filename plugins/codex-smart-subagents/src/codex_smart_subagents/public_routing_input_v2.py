"""Граница недоверенного смыслового входа ``smart_plan`` версии 2."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .canonical_json import canonical_json_v1


PUBLIC_ROUTING_INPUT_FIELDS = frozenset(
    {"taskFacts", "contextBundle", "roleTemplateId"}
)
PUBLIC_TASK_FACT_FIELDS = frozenset(
    {
        "taskText",
        "evidence",
        "workShape",
        "factorClaims",
        "delegation",
        "hardFloorReasons",
        "hardBanReasons",
    }
)
PUBLIC_DELEGATION_FIELDS = frozenset({"objectivelyVerifiable", "independentWorkUnits"})
SERVER_ONLY_FIELD_NAMES = frozenset(
    {
        "model",
        "reasoningEffort",
        "permission",
        "permissionProfileId",
        "catalogs",
        "accountEvidenceJobs",
        "reassessment",
    }
)
SERVER_EVIDENCE_PREFIX = "server."
SERVER_PERMISSION_EVIDENCE_REF = "server.delegation-policy"
_SERVER_PERMISSION_BANS = frozenset({"delegation-not-explicitly-allowed"})
_PACKAGE = Path(__file__).resolve().parent
_REPOSITORY = _PACKAGE.parents[3]
_BUNDLED_SCHEMA_ROOT = _PACKAGE.parents[1] / "config" / "runtime-schemas"
_SCHEMA_ROOT = (
    _BUNDLED_SCHEMA_ROOT
    if _BUNDLED_SCHEMA_ROOT.is_dir()
    else _REPOSITORY / "docs" / "contracts" / "schemas"
)


@dataclass
class PublicRoutingInputV2Error(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class _SchemaViolation(ValueError):
    path: tuple[str | int, ...]
    message: str


def validate_public_routing_input_v2(value: Any) -> dict[str, Any]:
    """Проверяет только публичную проекцию до серверного обогащения."""

    if type(value) is not dict or set(value) != PUBLIC_ROUTING_INPUT_FIELDS:
        _fail("PUBLIC_ROUTING_INPUT_FIELDS", "routingInput имеет незакрытые поля")
    _reject_server_only_fields(value)

    task_facts = value["taskFacts"]
    if type(task_facts) is not dict or set(task_facts) != PUBLIC_TASK_FACT_FIELDS:
        _fail(
            "PUBLIC_TASK_FACT_FIELDS",
            "routingInput.taskFacts имеет незакрытые поля",
        )
    delegation = task_facts["delegation"]
    if type(delegation) is not dict or set(delegation) != PUBLIC_DELEGATION_FIELDS:
        _fail(
            "PUBLIC_DELEGATION_FIELDS",
            "routingInput.taskFacts.delegation имеет незакрытые поля",
        )
    evidence = task_facts["evidence"]
    if type(evidence) is not list or not 1 <= len(evidence) <= 63:
        _fail(
            "PUBLIC_EVIDENCE_COUNT",
            "routingInput.taskFacts.evidence должен содержать от 1 до 63 записей",
        )
    role_template_id = value["roleTemplateId"]
    if type(role_template_id) is not str or not role_template_id:
        _fail("PUBLIC_ROLE_INVALID", "routingInput.roleTemplateId должен быть строкой")

    _reject_reserved_evidence_refs(value)
    hard_bans = task_facts["hardBanReasons"]
    if type(hard_bans) is list:
        for item in hard_bans:
            if type(item) is dict and item.get("reason") in _SERVER_PERMISSION_BANS:
                _fail(
                    "PUBLIC_PERMISSION_BAN_FORBIDDEN",
                    "routingInput не принимает служебное решение о разрешении",
                )
    _validate_against_public_schema(value)
    try:
        canonical_json_v1(value)
    except Exception as exc:
        _fail("PUBLIC_ROUTING_INPUT_INVALID", f"routingInput не канонизируется: {exc}")
    return copy.deepcopy(value)


def public_routing_input_schema_v2() -> dict[str, Any]:
    """Возвращает самодостаточную схему, общую для сервера и ``tools/list``."""

    return copy.deepcopy(_cached_public_routing_input_schema_v2())


@lru_cache(maxsize=1)
def _cached_public_routing_input_schema_v2() -> dict[str, Any]:
    protocol = _read_schema("smart-turn-protocol-v2.schema.json")
    available = protocol.get("$defs")
    if type(available) is not dict:
        _fail("PUBLIC_SCHEMA_INVALID", "протокол не содержит $defs")
    root = available.get("smartPlanRoutingInput")
    if type(root) is not dict:
        _fail(
            "PUBLIC_SCHEMA_INVALID",
            "протокол не содержит публичный routingInput",
        )
    selected: dict[str, Any] = {}

    def collect(value: Any) -> None:
        if type(value) is dict:
            reference = value.get("$ref")
            if type(reference) is str and reference.startswith("#/$defs/"):
                name = reference[len("#/$defs/") :].split("/", 1)[0]
                if name != "smartPlanRoutingInput" and name not in selected:
                    source = available.get(name)
                    if type(source) is not dict:
                        _fail(
                            "PUBLIC_SCHEMA_INVALID",
                            f"не найдено публичное определение протокола {name}",
                        )
                    selected[name] = copy.deepcopy(source)
                    collect(selected[name])
            for child in value.values():
                collect(child)
        elif type(value) is list:
            for child in value:
                collect(child)

    result = copy.deepcopy(root)
    collect(result)
    result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    result["$defs"] = selected
    standalone = _standalone_schema(result)
    _check_supported_schema(standalone)
    return standalone


def _standalone_schema(source: dict[str, Any]) -> dict[str, Any]:
    root = copy.deepcopy(source)
    embedded: dict[str, Any] = {}

    def key_for(filename: str) -> str:
        return "external_" + re.sub(r"[^A-Za-z0-9_]", "_", filename)

    def rewrite(value: Any, *, internal_prefix: str | None) -> None:
        if type(value) is dict:
            reference = value.get("$ref")
            if type(reference) is str:
                if reference.startswith("#"):
                    if internal_prefix is not None:
                        value["$ref"] = internal_prefix + reference[1:]
                else:
                    filename, separator, fragment = reference.partition("#")
                    loaded = _read_schema(filename)
                    key = key_for(filename)
                    value["$ref"] = f"#/$defs/{key}" + (
                        f"#{fragment}" if separator else ""
                    )
                    value["$ref"] = value["$ref"].replace(
                        "#/$defs/" + key + "#",
                        "#/$defs/" + key,
                    )
                    if key not in embedded:
                        candidate = copy.deepcopy(loaded)
                        candidate.pop("$id", None)
                        candidate.pop("$schema", None)
                        embedded[key] = candidate
                        rewrite(candidate, internal_prefix=f"#/$defs/{key}")
            for child in value.values():
                rewrite(child, internal_prefix=internal_prefix)
        elif type(value) is list:
            for child in value:
                rewrite(child, internal_prefix=internal_prefix)

    rewrite(root, internal_prefix=None)
    definitions = root.setdefault("$defs", {})
    if type(definitions) is not dict:
        _fail("PUBLIC_SCHEMA_INVALID", "публичная схема содержит неверный $defs")
    for key, schema in embedded.items():
        if key in definitions:
            _fail(
                "PUBLIC_SCHEMA_INVALID",
                f"повтор встроенной схемы {key}",
            )
        definitions[key] = schema
    return root


def _read_schema(name: str) -> dict[str, Any]:
    path = _SCHEMA_ROOT / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail("SCHEMA_DEPENDENCY_MISSING", f"не удалось прочитать {name}: {exc}")
    if type(value) is not dict:
        _fail("PUBLIC_SCHEMA_INVALID", f"схема {name} не является объектом")
    return value


def _validate_against_public_schema(value: Any) -> None:
    try:
        _validate_schema_value(
            value,
            _cached_public_routing_input_schema_v2(),
            root=_cached_public_routing_input_schema_v2(),
            path=(),
        )
    except _SchemaViolation as exc:
        path = ".".join(str(part) for part in exc.path) or "routingInput"
        _fail(
            "PUBLIC_SCHEMA_INVALID",
            f"{path} нарушает публичную схему: {exc.message}",
        )


_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "description",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
        "uniqueItems",
    }
)


def _check_supported_schema(schema: Any, *, path: tuple[str, ...] = ()) -> None:
    if type(schema) is not dict:
        _fail(
            "PUBLIC_SCHEMA_INVALID",
            f"определение {'/'.join(path) or '<root>'} не является объектом",
        )
    unknown = sorted(set(schema) - _SCHEMA_KEYWORDS)
    if unknown:
        _fail(
            "PUBLIC_SCHEMA_UNSUPPORTED",
            "самодостаточная проверка не поддерживает ключи: " + ", ".join(unknown),
        )
    for container_name in ("$defs", "properties"):
        container = schema.get(container_name, {})
        if type(container) is not dict:
            _fail(
                "PUBLIC_SCHEMA_INVALID",
                f"{container_name} в {'/'.join(path) or '<root>'} не является объектом",
            )
        for name, child in container.items():
            _check_supported_schema(child, path=(*path, container_name, str(name)))
    for container_name in ("allOf", "anyOf", "oneOf"):
        children = schema.get(container_name, [])
        if type(children) is not list:
            _fail(
                "PUBLIC_SCHEMA_INVALID",
                f"{container_name} в {'/'.join(path) or '<root>'} не является массивом",
            )
        for index, child in enumerate(children):
            _check_supported_schema(
                child,
                path=(*path, container_name, str(index)),
            )
    for name in ("items", "additionalProperties"):
        child = schema.get(name)
        if type(child) is dict:
            _check_supported_schema(child, path=(*path, name))
        elif child is not None and type(child) is not bool:
            _fail(
                "PUBLIC_SCHEMA_INVALID",
                f"{name} в {'/'.join(path) or '<root>'} имеет неверный тип",
            )


def _validate_schema_value(
    value: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: tuple[str | int, ...],
) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        target = _resolve_local_reference(root, reference)
        _validate_schema_value(value, target, root=root, path=path)

    for child in schema.get("allOf", []):
        _validate_schema_value(value, child, root=root, path=path)

    any_of = schema.get("anyOf")
    if any_of is not None and not _matches_any(value, any_of, root=root, path=path):
        raise _SchemaViolation(path, "значение не соответствует ни одному anyOf")

    one_of = schema.get("oneOf")
    if one_of is not None:
        matches = sum(
            _matches_schema(value, child, root=root, path=path) for child in one_of
        )
        if matches != 1:
            raise _SchemaViolation(path, "значение должно соответствовать одному oneOf")

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise _SchemaViolation(path, f"ожидался тип {expected_type}")

    if "const" in schema and not _json_equal(value, schema["const"]):
        raise _SchemaViolation(path, "значение не совпадает с const")
    if "enum" in schema and not any(
        _json_equal(value, candidate) for candidate in schema["enum"]
    ):
        raise _SchemaViolation(path, "значение отсутствует в enum")

    if type(value) is dict:
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            raise _SchemaViolation(path, "отсутствуют поля: " + ", ".join(missing))
        properties = schema.get("properties", {})
        for name, child in properties.items():
            if name in value:
                _validate_schema_value(
                    value[name],
                    child,
                    root=root,
                    path=(*path, name),
                )
        extras = [name for name in value if name not in properties]
        additional = schema.get("additionalProperties", True)
        if extras and additional is False:
            raise _SchemaViolation(
                path,
                "неожиданные поля: " + ", ".join(sorted(extras)),
            )
        if type(additional) is dict:
            for name in extras:
                _validate_schema_value(
                    value[name],
                    additional,
                    root=root,
                    path=(*path, name),
                )

    if type(value) is list:
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise _SchemaViolation(path, "слишком мало элементов")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise _SchemaViolation(path, "слишком много элементов")
        if schema.get("uniqueItems") and any(
            _json_equal(value[left], value[right])
            for left in range(len(value))
            for right in range(left + 1, len(value))
        ):
            raise _SchemaViolation(path, "элементы должны быть уникальны")
        items = schema.get("items")
        if type(items) is dict:
            for index, item in enumerate(value):
                _validate_schema_value(
                    item,
                    items,
                    root=root,
                    path=(*path, index),
                )

    if type(value) is str:
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise _SchemaViolation(path, "строка слишком короткая")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise _SchemaViolation(path, "строка слишком длинная")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise _SchemaViolation(path, "строка не соответствует pattern")

    if _is_number(value):
        if "minimum" in schema and value < schema["minimum"]:
            raise _SchemaViolation(path, "число меньше minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise _SchemaViolation(path, "число больше maximum")


def _matches_any(
    value: Any,
    schemas: list[dict[str, Any]],
    *,
    root: dict[str, Any],
    path: tuple[str | int, ...],
) -> bool:
    return any(_matches_schema(value, child, root=root, path=path) for child in schemas)


def _matches_schema(
    value: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: tuple[str | int, ...],
) -> bool:
    try:
        _validate_schema_value(value, schema, root=root, path=path)
    except _SchemaViolation:
        return False
    return True


def _resolve_local_reference(root: dict[str, Any], reference: Any) -> dict[str, Any]:
    if type(reference) is not str or not reference.startswith("#/"):
        _fail(
            "PUBLIC_SCHEMA_UNSUPPORTED",
            "самодостаточная схема содержит нелокальную ссылку",
        )
    target: Any = root
    for encoded in reference[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if type(target) is not dict or part not in target:
            _fail("PUBLIC_SCHEMA_INVALID", f"не разрешена ссылка {reference}")
        target = target[part]
    if type(target) is not dict:
        _fail("PUBLIC_SCHEMA_INVALID", f"ссылка {reference} ведёт не на схему")
    return target


def _matches_type(value: Any, expected: Any) -> bool:
    names = expected if type(expected) is list else [expected]
    return any(
        (name == "object" and type(value) is dict)
        or (name == "array" and type(value) is list)
        or (name == "string" and type(value) is str)
        or (name == "integer" and type(value) is int)
        or (name == "number" and _is_number(value))
        or (name == "boolean" and type(value) is bool)
        or (name == "null" and value is None)
        for name in names
    )


def _is_number(value: Any) -> bool:
    return type(value) in {int, float}


def _json_equal(left: Any, right: Any) -> bool:
    if _is_number(left) and _is_number(right):
        return left == right
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _reject_server_only_fields(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if type(current) is dict:
            forbidden = sorted(set(current) & SERVER_ONLY_FIELD_NAMES)
            if forbidden:
                _fail(
                    "PUBLIC_SERVER_FIELD_FORBIDDEN",
                    "routingInput содержит служебные поля: " + ", ".join(forbidden),
                )
            stack.extend(current.values())
        elif type(current) is list:
            stack.extend(current)


def _reject_reserved_evidence_refs(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if type(current) is dict:
            for key, child in current.items():
                if key == "evidenceRefId":
                    _reserved_ref(child)
                elif key == "evidenceRefIds" and type(child) is list:
                    for reference in child:
                        _reserved_ref(reference)
                stack.append(child)
        elif type(current) is list:
            stack.extend(current)


def _reserved_ref(value: Any) -> None:
    if type(value) is str and value.startswith(SERVER_EVIDENCE_PREFIX):
        _fail(
            "PUBLIC_SERVER_EVIDENCE_REF_FORBIDDEN",
            "routingInput использует зарезервированную ссылку доказательства",
        )


def _fail(code: str, message: str) -> None:
    raise PublicRoutingInputV2Error(code, message)


__all__ = [
    "PUBLIC_DELEGATION_FIELDS",
    "PUBLIC_ROUTING_INPUT_FIELDS",
    "PUBLIC_TASK_FACT_FIELDS",
    "PublicRoutingInputV2Error",
    "SERVER_EVIDENCE_PREFIX",
    "SERVER_ONLY_FIELD_NAMES",
    "SERVER_PERMISSION_EVIDENCE_REF",
    "public_routing_input_schema_v2",
    "validate_public_routing_input_v2",
]
