"""Strict MCP contracts and a dependency-free JSON Schema subset validator."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1"
ROUTE_PATTERN = r"^rt1_[A-Za-z0-9_-]{43}$"
TURN_BINDING_PATTERN = r"^tb1_[A-Za-z0-9_-]{43}$"
CATALOG_PATTERN = r"^cg1_[a-f0-9]{16}$"
OPAQUE_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]{2,63}$"


@dataclass
class ContractError(ValueError):
    code: str
    message: str
    path: str = "$"

    def __str__(self) -> str:
        return f"{self.code} at {self.path}: {self.message}"


def _strict_object(
    properties: dict[str, Any],
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required if required is not None else list(properties),
        "additionalProperties": False,
    }


def _string(
    *,
    minimum: int = 0,
    maximum: int = 4096,
    pattern: str | None = None,
    enum: list[str] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "string",
        "minLength": minimum,
        "maxLength": maximum,
    }
    if pattern is not None:
        schema["pattern"] = pattern
    if enum is not None:
        schema["enum"] = enum
    return schema


def _integer(minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def _array(
    items: dict[str, Any],
    *,
    minimum: int = 0,
    maximum: int,
    unique: bool = False,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "items": items,
        "minItems": minimum,
        "maxItems": maximum,
    }
    if unique:
        schema["uniqueItems"] = True
    return schema


INTERVAL_SCHEMA = _strict_object(
    {"min": _integer(0, 2), "max": _integer(0, 2)}
)
DELEGATION_SCHEMA = _strict_object(
    {
        "q": INTERVAL_SCHEMA,
        "p": INTERVAL_SCHEMA,
        "v": INTERVAL_SCHEMA,
        "o": INTERVAL_SCHEMA,
    }
)
COMPLEXITY_SCHEMA = _strict_object(
    {
        "ambiguity": _integer(0, 2),
        "dependencyDepth": _integer(0, 2),
        "breadth": _integer(0, 2),
        "novelty": _integer(0, 2),
        "harm": _integer(0, 2),
        "crossDomain": _integer(0, 2),
    }
)
REASONING_SCHEMA = _strict_object(
    {
        "evidence": _integer(0, 2),
        "verification": _integer(0, 2),
        "harm": _integer(0, 2),
    }
)
ASSESSMENT_SCHEMA = _strict_object(
    {
        "delegation": DELEGATION_SCHEMA,
        "complexity": COMPLEXITY_SCHEMA,
        "reasoning": REASONING_SCHEMA,
    }
)
NODE_SCHEMA = _strict_object(
    {
        "clientNodeId": _string(minimum=1, maximum=64, pattern=OPAQUE_ID_PATTERN),
        "mission": _string(minimum=1, maximum=2000),
        "role": _string(
            minimum=1,
            maximum=32,
            enum=[
                "researcher",
                "diagnostician",
                "implementer",
                "validator",
                "risk_auditor",
            ],
        ),
        "dependencyIds": _array(
            _string(minimum=1, maximum=64, pattern=OPAQUE_ID_PATTERN),
            maximum=20,
            unique=True,
        ),
        "contextRefs": _array(
            _string(minimum=1, maximum=128, pattern=OPAQUE_ID_PATTERN),
            maximum=32,
            unique=True,
        ),
        "scopeId": _string(minimum=3, maximum=64, pattern=OPAQUE_ID_PATTERN),
        "artifactProfileId": _string(
            minimum=3, maximum=64, pattern=OPAQUE_ID_PATTERN
        ),
        "validationProfileId": _string(
            minimum=3, maximum=64, pattern=OPAQUE_ID_PATTERN
        ),
        "assessment": ASSESSMENT_SCHEMA,
        "riskFlags": _array(
            _string(
                minimum=1,
                maximum=32,
                enum=[
                    "security",
                    "architecture",
                    "public_contract",
                    "risky_migration",
                    "irreversible",
                    "critical_incident",
                    "writer_final_validation",
                ],
            ),
            maximum=7,
            unique=True,
        ),
    }
)
LINEAGE_SCHEMA = _strict_object(
    {
        "generation": _integer(0, 2),
        "parentNodeId": _string(
            minimum=1, maximum=64, pattern=OPAQUE_ID_PATTERN
        ),
    }
)

PLAN_INPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "turnBinding": _string(
            minimum=47, maximum=47, pattern=TURN_BINDING_PATTERN
        ),
        "requestKey": _string(
            minimum=8,
            maximum=128,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
        "catalogGeneration": _string(
            minimum=20, maximum=20, pattern=CATALOG_PATTERN
        ),
        "nodes": _array(NODE_SCHEMA, minimum=1, maximum=20),
        "lineage": LINEAGE_SCHEMA,
    },
    required=[
        "schemaVersion",
        "turnBinding",
        "requestKey",
        "catalogGeneration",
        "nodes",
    ],
)
START_INPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "routeId": _string(minimum=47, maximum=47, pattern=ROUTE_PATTERN),
    }
)
WAIT_INPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "routeId": _string(minimum=47, maximum=47, pattern=ROUTE_PATTERN),
        "afterSequence": _integer(0, 2_147_483_647),
        "timeoutSeconds": _integer(0, 60),
    }
)
CANCEL_INPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "routeId": _string(minimum=47, maximum=47, pattern=ROUTE_PATTERN),
        "reasonCode": _string(
            enum=[
                "user_requested",
                "superseded",
                "timeout",
                "session_shutdown",
            ]
        ),
    }
)

NODE_DECISION_SCHEMA = _strict_object(
    {
        "clientNodeId": _string(minimum=1, maximum=64),
        "disposition": _string(enum=["direct", "delegate", "clarify"]),
        "selectedModel": _string(
            enum=["gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"]
        ),
        "reasoningEffort": _string(
            enum=["low", "medium", "high", "xhigh", "max"]
        ),
        "permissionProfileId": _string(minimum=3, maximum=64),
        "reasonCode": _string(minimum=1, maximum=64),
    }
)
EVENT_SCHEMA = _strict_object(
    {
        "sequence": _integer(1, 2_147_483_647),
        "event": _string(minimum=1, maximum=64),
        "state": _string(minimum=1, maximum=32),
        "nodeId": _string(minimum=0, maximum=64),
        "code": _string(minimum=1, maximum=64),
        "message": _string(minimum=0, maximum=1000),
    }
)
TERMINAL_RESULT_SCHEMA = _strict_object(
    {
        "artifactId": _string(minimum=3, maximum=80),
        "fingerprint": _string(
            minimum=64, maximum=64, pattern=r"^[a-f0-9]{64}$"
        ),
        "summary": _string(minimum=0, maximum=4000),
        "validationState": _string(
            enum=["not_applicable", "passed", "failed", "quarantined"]
        ),
    }
)
PLAN_OUTPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "ok": {"type": "boolean"},
        "code": _string(minimum=1, maximum=64),
        "message": _string(minimum=0, maximum=1000),
        "routeId": _string(minimum=0, maximum=47),
        "routeGeneration": _integer(0, 2_147_483_647),
        "expiresAt": _string(minimum=0, maximum=64),
        "startable": {"type": "boolean"},
        "overallDisposition": _string(
            enum=["direct", "delegate", "clarify", "error"]
        ),
        "nodeDecisions": _array(NODE_DECISION_SCHEMA, maximum=20),
        "clarificationQuestions": _array(
            _string(minimum=1, maximum=500),
            maximum=3,
        ),
        "catalogGeneration": _string(minimum=0, maximum=20),
    }
)
START_OUTPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "ok": {"type": "boolean"},
        "code": _string(minimum=1, maximum=64),
        "message": _string(minimum=0, maximum=1000),
        "routeId": _string(minimum=0, maximum=47),
        "runId": _string(minimum=0, maximum=80),
        "state": _string(minimum=1, maximum=32),
        "acceptedAt": _string(minimum=0, maximum=64),
    }
)
WAIT_OUTPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "ok": {"type": "boolean"},
        "code": _string(minimum=1, maximum=64),
        "message": _string(minimum=0, maximum=1000),
        "routeId": _string(minimum=0, maximum=47),
        "state": _string(minimum=1, maximum=32),
        "sequence": _integer(0, 2_147_483_647),
        "events": _array(EVENT_SCHEMA, maximum=100),
        "truncated": {"type": "boolean"},
        "terminalResult": TERMINAL_RESULT_SCHEMA,
    },
    required=[
        "schemaVersion",
        "ok",
        "code",
        "message",
        "routeId",
        "state",
        "sequence",
        "events",
        "truncated",
    ],
)
CANCEL_OUTPUT_SCHEMA = _strict_object(
    {
        "schemaVersion": _string(enum=[SCHEMA_VERSION]),
        "ok": {"type": "boolean"},
        "code": _string(minimum=1, maximum=64),
        "message": _string(minimum=0, maximum=1000),
        "routeId": _string(minimum=0, maximum=47),
        "previousState": _string(minimum=1, maximum=32),
        "newState": _string(minimum=1, maximum=32),
        "accepted": {"type": "boolean"},
    }
)

TOOL_SCHEMAS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "smart_plan": (PLAN_INPUT_SCHEMA, PLAN_OUTPUT_SCHEMA),
    "smart_start": (START_INPUT_SCHEMA, START_OUTPUT_SCHEMA),
    "smart_wait": (WAIT_INPUT_SCHEMA, WAIT_OUTPUT_SCHEMA),
    "smart_cancel": (CANCEL_INPUT_SCHEMA, CANCEL_OUTPUT_SCHEMA),
}

TOOL_DESCRIPTIONS = {
    "smart_plan": (
        "Validate a bounded task graph and deterministically choose direct work, "
        "clarification, or isolated Codex subagents."
    ),
    "smart_start": "Idempotently start a previously planned route.",
    "smart_wait": "Wait up to 60 seconds for route events or terminal state.",
    "smart_cancel": "Idempotently request cancellation of a route.",
}


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return immutable MCP tool definitions in the public order."""

    annotations = {
        "smart_plan": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        "smart_start": {
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
    definitions: list[dict[str, Any]] = []
    for name in ("smart_plan", "smart_start", "smart_wait", "smart_cancel"):
        input_schema, output_schema = TOOL_SCHEMAS[name]
        definitions.append(
            {
                "name": name,
                "description": TOOL_DESCRIPTIONS[name],
                "inputSchema": copy.deepcopy(input_schema),
                "outputSchema": copy.deepcopy(output_schema),
                "annotations": copy.deepcopy(annotations[name]),
            }
        )
    return definitions


def validate_tool_input(name: str, payload: Any) -> dict[str, Any]:
    """Validate and detach untrusted MCP arguments."""

    if name not in TOOL_SCHEMAS:
        raise ContractError("UNKNOWN_TOOL", f"unknown tool: {name}")
    _validate(payload, TOOL_SCHEMAS[name][0], "$")
    normalized = json.loads(json.dumps(payload, ensure_ascii=False))
    if name == "smart_plan":
        _validate_plan_semantics(normalized)
    return normalized


def validate_tool_output(name: str, payload: Any) -> dict[str, Any]:
    """Validate a server-generated result before exposing it to MCP."""

    if name not in TOOL_SCHEMAS:
        raise ContractError("UNKNOWN_TOOL", f"unknown tool: {name}")
    _validate(payload, TOOL_SCHEMAS[name][1], "$")
    return json.loads(json.dumps(payload, ensure_ascii=False))


def export_tool_schemas(destination: Path) -> None:
    """Write canonical public tool schemas for review and packaging."""

    destination.mkdir(parents=True, exist_ok=True)
    for tool in get_tool_definitions():
        for key, suffix in (
            ("inputSchema", "input"),
            ("outputSchema", "output"),
        ):
            path = destination / f"{tool['name']}-{suffix}.schema.json"
            path.write_text(
                json.dumps(
                    tool[key],
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )



def _validate(value: Any, schema: dict[str, Any], path: str) -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            _invalid(path, "must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                _invalid(path, f"missing required property {name!r}")
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                _invalid(path, f"unexpected properties: {', '.join(extras)}")
        for name, child in value.items():
            if name in properties:
                _validate(child, properties[name], f"{path}.{name}")
        return

    if expected == "array":
        if not isinstance(value, list):
            _invalid(path, "must be an array")
        if len(value) < schema.get("minItems", 0):
            _invalid(path, "has too few items")
        if len(value) > schema.get("maxItems", len(value)):
            _invalid(path, "has too many items")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(item, sort_keys=True) for item in value]
            if len(serialized) != len(set(serialized)):
                _invalid(path, "items must be unique")
        for index, child in enumerate(value):
            _validate(child, schema["items"], f"{path}[{index}]")
        return

    if expected == "string":
        if not isinstance(value, str):
            _invalid(path, "must be a string")
        if len(value) < schema.get("minLength", 0):
            _invalid(path, "is too short")
        if len(value) > schema.get("maxLength", len(value)):
            _invalid(path, "is too long")
        if "enum" in schema and value not in schema["enum"]:
            _invalid(path, "is not an allowed value")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            _invalid(path, "does not match the required pattern")
        return

    if expected == "integer":
        if type(value) is not int:
            _invalid(path, "must be an integer")
        if value < schema.get("minimum", value):
            _invalid(path, "is below the minimum")
        if value > schema.get("maximum", value):
            _invalid(path, "is above the maximum")
        return

    if expected == "boolean":
        if type(value) is not bool:
            _invalid(path, "must be a boolean")
        return

    _invalid(path, f"unsupported schema type: {expected!r}")


def _validate_plan_semantics(payload: dict[str, Any]) -> None:
    node_ids = [node["clientNodeId"] for node in payload["nodes"]]
    if len(node_ids) != len(set(node_ids)):
        _invalid("$.nodes", "clientNodeId values must be unique")
    known = set(node_ids)
    for index, node in enumerate(payload["nodes"]):
        for dependency in node["dependencyIds"]:
            if dependency not in known:
                _invalid(
                    f"$.nodes[{index}].dependencyIds",
                    f"unknown dependency {dependency!r}",
                )
            if dependency == node["clientNodeId"]:
                _invalid(
                    f"$.nodes[{index}].dependencyIds",
                    "a node cannot depend on itself",
                )
        delegation = node["assessment"]["delegation"]
        for factor in ("q", "p", "v", "o"):
            interval = delegation[factor]
            if interval["min"] > interval["max"]:
                _invalid(
                    f"$.nodes[{index}].assessment.delegation.{factor}",
                    "min must not exceed max",
                )


def _invalid(path: str, message: str) -> None:
    raise ContractError("INVALID_INPUT", message, path)
