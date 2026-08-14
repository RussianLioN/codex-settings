"""Закрытые пользовательские договоры MCP для умного хода версии 2."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical_json import canonical_json_v1
from .public_routing_input_v2 import (
    PublicRoutingInputV2Error,
    public_routing_input_schema_v2,
    validate_public_routing_input_v2,
)
from .smart_turn_runtime_v2 import verify_public_response_v2


TOOL_NAMES = ("smart_plan", "route_start", "smart_wait", "smart_cancel")
_ROUTE = re.compile(r"^route2_[0-9a-f]{32}$")
_NODE = re.compile(r"^node2_[0-9a-f]{32}$")
_START = re.compile(r"^sr2_[0-9a-f]{32}$")
_CURSOR = re.compile(r"^cur2_[0-9a-f]{32}$")
_CLIENT_NODE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
_PACKAGE = Path(__file__).resolve().parent
_REPOSITORY = _PACKAGE.parents[3]
_BUNDLED_SCHEMA_ROOT = _PACKAGE.parents[1] / "config" / "runtime-schemas"
_SCHEMA_ROOT = (
    _BUNDLED_SCHEMA_ROOT
    if _BUNDLED_SCHEMA_ROOT.is_dir()
    else _REPOSITORY / "docs" / "contracts" / "schemas"
)


@dataclass
class MCPContractV2Error(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _strict_object(
    properties: Mapping[str, Any],
    *,
    required: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": copy.deepcopy(dict(properties)),
        "required": list(required if required is not None else properties),
        "additionalProperties": False,
    }


def _string(pattern: str | None = None, *, enum: tuple[str, ...] | None = None):
    result: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 4096}
    if pattern is not None:
        result["pattern"] = pattern
    if enum is not None:
        result["enum"] = list(enum)
    return result


def _load_schema(name: str) -> dict[str, Any] | None:
    path = _SCHEMA_ROOT / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if type(value) is dict else None


def _default_routing_schema() -> dict[str, Any]:
    return public_routing_input_schema_v2()


def _protocol_definition_schema(
    protocol: Mapping[str, Any],
    root_name: str,
) -> dict[str, Any] | None:
    """Выделяет одну достижимую публичную схему без остальных частей протокола."""

    available = protocol.get("$defs")
    if type(available) is not dict or type(available.get(root_name)) is not dict:
        return None
    root = copy.deepcopy(available[root_name])
    selected: dict[str, Any] = {}

    def collect(value: Any) -> None:
        if type(value) is dict:
            reference = value.get("$ref")
            if type(reference) is str and reference.startswith("#/$defs/"):
                name = reference[len("#/$defs/") :].split("/", 1)[0]
                if name != root_name and name not in selected:
                    source = available.get(name)
                    if type(source) is not dict:
                        raise MCPContractV2Error(
                            "SCHEMA_INVALID",
                            f"не найдено публичное определение протокола {name}",
                        )
                    selected[name] = copy.deepcopy(source)
                    collect(selected[name])
            for child in value.values():
                collect(child)
        elif type(value) is list:
            for child in value:
                collect(child)

    collect(root)
    root["$defs"] = selected
    return root


def _standalone_schema(source: Mapping[str, Any]) -> dict[str, Any]:
    """Встраивает локальные ссылки схемы, чтобы MCP не зависел от файловых URI."""

    root = copy.deepcopy(dict(source))
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
                    loaded = _load_schema(filename)
                    if loaded is None:
                        raise MCPContractV2Error(
                            "SCHEMA_DEPENDENCY_MISSING",
                            f"не найдена зависимость схемы {filename}",
                        )
                    key = key_for(filename)
                    value["$ref"] = f"#/$defs/{key}" + (
                        f"#{fragment}" if separator else ""
                    )
                    # JSON Pointer после встроенного корня не содержит второго '#'.
                    value["$ref"] = value["$ref"].replace(
                        "#/$defs/" + key + "#", "#/$defs/" + key
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
        raise MCPContractV2Error(
            "SCHEMA_INVALID",
            "корень схемы содержит неверный $defs",
        )
    for key, schema in embedded.items():
        if key in definitions:
            raise MCPContractV2Error(
                "SCHEMA_INVALID",
                f"повтор встроенной схемы {key}",
            )
        definitions[key] = schema
    return root


def _common_response_properties() -> dict[str, Any]:
    return {
        "messageType": {"const": "response"},
        "protocolVersion": {"const": 2},
        "release": {"const": "0.2.0"},
        "requestId": _string(r"^strq2_[0-9a-f]{32}$"),
        "owner": {"type": "object"},
        "method": {"enum": list(TOOL_NAMES)},
        "responseKind": {
            "enum": ["SUCCESS", "ORDINARY", "STALE", "UNAVAILABLE", "ERROR"]
        },
        "requestFingerprint": _string(r"^[0-9a-f]{64}$"),
        "payload": {"type": "object"},
        "responseFingerprint": _string(r"^[0-9a-f]{64}$"),
        "extensions": {"type": "object", "maxProperties": 32},
    }


def _response_definitions(
    protocol: Mapping[str, Any],
    roots: list[str],
) -> dict[str, Any]:
    """Оставляет только достижимые определения ответа и встраивает их ссылки."""

    available = protocol.get("$defs")
    if type(available) is not dict:
        raise MCPContractV2Error("SCHEMA_INVALID", "протокол не содержит $defs")
    selected: dict[str, Any] = {}

    def add_protocol(name: str) -> None:
        if name in selected:
            return
        source = available.get(name)
        if type(source) is not dict:
            raise MCPContractV2Error(
                "SCHEMA_INVALID",
                f"не найдено определение протокола {name}",
            )
        candidate = copy.deepcopy(source)
        selected[name] = candidate
        rewrite(candidate, internal_prefix=None)

    def add_external(filename: str) -> str:
        key = "external_" + re.sub(r"[^A-Za-z0-9_]", "_", filename)
        if key in selected:
            return key
        loaded = _load_schema(filename)
        if loaded is None:
            raise MCPContractV2Error(
                "SCHEMA_DEPENDENCY_MISSING",
                f"не найдена зависимость схемы {filename}",
            )
        candidate = copy.deepcopy(loaded)
        candidate.pop("$id", None)
        candidate.pop("$schema", None)
        selected[key] = candidate
        rewrite(candidate, internal_prefix=f"#/$defs/{key}")
        return key

    def rewrite(value: Any, *, internal_prefix: str | None) -> None:
        if type(value) is dict:
            reference = value.get("$ref")
            if type(reference) is str:
                if reference.startswith("#/$defs/"):
                    if internal_prefix is None:
                        definition = reference[len("#/$defs/") :].split("/", 1)[0]
                        add_protocol(definition)
                    else:
                        value["$ref"] = internal_prefix + reference[1:]
                elif not reference.startswith("#"):
                    filename, separator, fragment = reference.partition("#")
                    key = add_external(filename)
                    value["$ref"] = f"#/$defs/{key}" + (fragment if separator else "")
            for child in value.values():
                rewrite(child, internal_prefix=internal_prefix)
        elif type(value) is list:
            for child in value:
                rewrite(child, internal_prefix=internal_prefix)

    for root in roots:
        add_protocol(root)
    return selected


def _output_schema(method: str) -> dict[str, Any]:
    protocol = _load_schema("smart-turn-protocol-v2.schema.json")
    common = _strict_object(_common_response_properties())
    common["properties"]["method"] = {"const": method}
    if protocol is None:
        return common
    success = {
        "smart_plan": "smartPlanResponse",
        "route_start": "routeStartResponse",
        "smart_wait": "smartWaitResponse",
        "smart_cancel": "smartCancelResponse",
    }[method]
    roots = [success]
    if method in {"smart_plan", "route_start"}:
        roots.append("ordinaryResponse")
    roots.extend(("staleResponse", "unavailableResponse", "errorResponse"))
    variants = [{"$ref": f"#/$defs/{name}"} for name in roots]
    common["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    common["$defs"] = _response_definitions(protocol, roots)
    common["allOf"] = [{"oneOf": variants}]
    return common


def get_tool_definitions_v2(
    *,
    routing_input_schema: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Возвращает ровно четыре пользовательских инструмента в устойчивом порядке."""

    routing_schema = _standalone_schema(
        dict(routing_input_schema)
        if routing_input_schema is not None
        else _default_routing_schema()
    )
    routing_definitions = routing_schema.pop("$defs", {})
    client_node_id_schema = {
        "type": "string",
        "minLength": 3,
        "maxLength": 64,
        "pattern": r"^[A-Za-z][A-Za-z0-9_-]{2,63}$",
    }
    plan_node_schema = _strict_object(
        {
            "clientNodeId": client_node_id_schema,
            "dependencyIds": {
                "type": "array",
                "minItems": 0,
                "maxItems": 20,
                "uniqueItems": True,
                "items": copy.deepcopy(client_node_id_schema),
            },
            "routingInput": routing_schema,
        }
    )
    inputs = {
        "smart_plan": _strict_object(
            {
                "nodes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 20,
                    "items": plan_node_schema,
                }
            }
        ),
        "route_start": _strict_object(
            {
                "routeId": _string(r"^route2_[0-9a-f]{32}$"),
                "nodeId": _string(r"^node2_[0-9a-f]{32}$"),
            }
        ),
        "smart_wait": _strict_object(
            {
                "startRequestId": _string(r"^sr2_[0-9a-f]{32}$"),
                "cursor": {
                    "oneOf": [
                        _string(r"^cur2_[0-9a-f]{32}$"),
                        {"type": "null"},
                    ]
                },
                "pageSize": {"type": "integer", "minimum": 1, "maximum": 100},
                "waitSeconds": {"type": "integer", "minimum": 0, "maximum": 60},
            }
        ),
        "smart_cancel": _strict_object(
            {
                "startRequestId": _string(r"^sr2_[0-9a-f]{32}$"),
                "reasonCode": {
                    "type": "string",
                    "enum": ["USER_REQUESTED", "TURN_ENDED", "ROUTE_SUPERSEDED"],
                },
            }
        ),
    }
    if routing_definitions:
        inputs["smart_plan"]["$defs"] = routing_definitions
    descriptions = {
        "smart_plan": (
            "Передай ограниченный граф задач и определи необходимость делегирования "
            "каждого узла по доказуемым фактам. Модель и уровень рассуждения каждого "
            "узла выбирает служба, а не вызывающая модель."
        ),
        "route_start": (
            "Поставь выбранный узел в очередь свежего свидетельства. "
            "Шлюз активации добавляет сервер."
        ),
        "smart_wait": "Прочитай очередную ограниченную страницу событий запуска.",
        "smart_cancel": "Повторяемо запроси отмену незавершённого запуска.",
    }
    annotations = {
        "smart_plan": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        "route_start": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        "smart_wait": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        "smart_cancel": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    }
    return [
        {
            "name": name,
            "description": descriptions[name],
            "inputSchema": copy.deepcopy(inputs[name]),
            "outputSchema": _output_schema(name),
            "annotations": copy.deepcopy(annotations[name]),
        }
        for name in TOOL_NAMES
    ]


def validate_tool_input_v2(
    name: str,
    payload: Any,
    *,
    routing_input_validator: Callable[[Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    if name not in TOOL_NAMES:
        _fail("UNKNOWN_TOOL", "неизвестный инструмент")
    if type(payload) is not dict:
        _fail("INVALID_TOOL_INPUT", "аргументы должны быть объектом")
    expected = {
        "smart_plan": {"nodes"},
        "route_start": {"routeId", "nodeId"},
        "smart_wait": {"startRequestId", "cursor", "pageSize", "waitSeconds"},
        "smart_cancel": {"startRequestId", "reasonCode"},
    }[name]
    extras = sorted(set(payload) - expected)
    missing = sorted(expected - set(payload))
    if extras:
        _fail("INVALID_TOOL_INPUT", "неожиданные поля: " + ", ".join(extras))
    if missing:
        _fail("INVALID_TOOL_INPUT", "отсутствуют поля: " + ", ".join(missing))
    value = copy.deepcopy(payload)
    try:
        canonical_json_v1(value)
    except Exception as exc:
        _fail("INVALID_TOOL_INPUT", f"аргументы не канонизируются: {exc}")
    if name == "smart_plan":
        _validate_plan_nodes(value["nodes"], routing_input_validator)
    elif name == "route_start":
        _pattern(value["routeId"], _ROUTE, "routeId")
        _pattern(value["nodeId"], _NODE, "nodeId")
    elif name == "smart_wait":
        _pattern(value["startRequestId"], _START, "startRequestId")
        if value["cursor"] is not None:
            _pattern(value["cursor"], _CURSOR, "cursor")
        if type(value["pageSize"]) is not int or not 1 <= value["pageSize"] <= 100:
            _fail("INVALID_TOOL_INPUT", "pageSize вне диапазона 1..100")
        if type(value["waitSeconds"]) is not int or not 0 <= value["waitSeconds"] <= 60:
            _fail("INVALID_TOOL_INPUT", "waitSeconds вне диапазона 0..60")
    else:
        _pattern(value["startRequestId"], _START, "startRequestId")
        if value["reasonCode"] not in {
            "USER_REQUESTED",
            "TURN_ENDED",
            "ROUTE_SUPERSEDED",
        }:
            _fail("INVALID_TOOL_INPUT", "неизвестный reasonCode")
    return value


def validate_tool_output_v2(name: str, payload: Any) -> dict[str, Any]:
    if name not in TOOL_NAMES:
        _fail("UNKNOWN_TOOL", "неизвестный инструмент")
    try:
        value = verify_public_response_v2(payload)
    except Exception as exc:
        _fail("INVALID_TOOL_OUTPUT", f"ответ нарушил публичный договор: {exc}")
    if value["method"] != name:
        _fail("INVALID_TOOL_OUTPUT", "ответ относится к другому методу")
    return value


def _validate_plan_nodes(
    nodes: Any,
    routing_input_validator: Callable[[Mapping[str, Any]], Any] | None,
) -> None:
    if type(nodes) is not list or not 1 <= len(nodes) <= 20:
        _fail("INVALID_TOOL_INPUT", "nodes должен содержать от 1 до 20 узлов")
    known: set[str] = set()
    edge_count = 0
    for index, node in enumerate(nodes):
        if type(node) is not dict or set(node) != {
            "clientNodeId",
            "dependencyIds",
            "routingInput",
        }:
            _fail(
                "INVALID_TOOL_INPUT",
                f"узел {index} имеет незакрытый набор полей",
            )
        client_node_id = node["clientNodeId"]
        if (
            type(client_node_id) is not str
            or _CLIENT_NODE.fullmatch(client_node_id) is None
            or client_node_id in known
        ):
            _fail(
                "INVALID_TOOL_INPUT",
                f"узел {index} имеет неверный или повторный clientNodeId",
            )
        known.add(client_node_id)
        dependencies = node["dependencyIds"]
        if (
            type(dependencies) is not list
            or len(dependencies) > 20
            or len(dependencies) != len(set(dependencies))
            or any(
                type(dependency) is not str
                or _CLIENT_NODE.fullmatch(dependency) is None
                for dependency in dependencies
            )
        ):
            _fail(
                "INVALID_TOOL_INPUT",
                f"узел {client_node_id} имеет неверные dependencyIds",
            )
        edge_count += len(dependencies)
        routing = node["routingInput"]
        if type(routing) is not dict:
            _fail(
                "INVALID_TOOL_INPUT",
                f"узел {client_node_id}: routingInput должен быть объектом",
            )
        try:
            public_routing = validate_public_routing_input_v2(routing)
        except PublicRoutingInputV2Error as exc:
            _fail("INVALID_TOOL_INPUT", f"routingInput отклонён: {exc}")
        if routing_input_validator is not None:
            try:
                checked = routing_input_validator(copy.deepcopy(public_routing))
            except Exception as exc:
                _fail("INVALID_TOOL_INPUT", f"routingInput отклонён: {exc}")
            if checked is not None and checked != public_routing:
                _fail("INVALID_TOOL_INPUT", "проверка routingInput изменила вход")
    if edge_count > 60:
        _fail("INVALID_TOOL_INPUT", "граф содержит более 60 рёбер")
    for node in nodes:
        dependencies = node["dependencyIds"]
        if node["clientNodeId"] in dependencies or not set(dependencies).issubset(
            known
        ):
            _fail(
                "INVALID_TOOL_INPUT",
                f"узел {node['clientNodeId']} имеет неверные dependencyIds",
            )


def _pattern(value: Any, pattern: re.Pattern[str], name: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("INVALID_TOOL_INPUT", f"неверный {name}")


def _fail(code: str, message: str) -> None:
    raise MCPContractV2Error(code, message)


__all__ = [
    "MCPContractV2Error",
    "TOOL_NAMES",
    "get_tool_definitions_v2",
    "validate_tool_input_v2",
    "validate_tool_output_v2",
]
