#!/usr/bin/env python3
"""Детерминированно обновляет договор кандидатов координатора и его каскад."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)
from update_otel_contract_cascade import (  # noqa: E402
    load,
    profile_references,
    replace_strings,
    update_account,
    update_child,
    update_interface,
)


COORDINATOR_CONTRACT = {
    "selection": "first-verified-available",
    "candidates": [
        {
            "model": "gpt-5.6-sol",
            "reasoningEffort": "medium",
        },
        {
            "model": "gpt-5.6-terra",
            "reasoningEffort": "medium",
        },
    ],
}

ROUTING_VECTOR = Path("docs/contracts/vectors/routing-policy-v2.json")
ROUTING_SCHEMA = Path("docs/contracts/schemas/routing-policy-v2.schema.json")
INTERFACE_VECTOR = Path("docs/contracts/vectors/interface-evidence-v1.json")
ACCOUNT_VECTOR = Path("docs/contracts/vectors/account-evidence-v1.json")
CHILD_VECTOR = Path("docs/contracts/vectors/child-profile-v1.json")
CONTROLLER_SCHEMA = Path(
    "docs/contracts/schemas/controller-protocol-v2.schema.json"
)
CONTROLLER_VECTOR = Path(
    "docs/contracts/vectors/controller-protocol-v2.json"
)
LIFECYCLE_VECTOR = Path("docs/contracts/vectors/lifecycle-v2.json")


def _serialized(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def _schema_hashes(
    interface: dict[str, Any],
    *,
    generated: dict[Path, bytes],
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for schema_id in interface["base"]["semantic"]["machineSchemas"]:
        relative = Path(f"docs/contracts/schemas/{schema_id}.schema.json")
        content = generated.get(relative)
        if content is None:
            content = (ROOT / relative).read_bytes()
        hashes[schema_id] = hashlib.sha256(content).hexdigest()
    return hashes


def _replace_once(value: str, old: str, new: str, *, label: str) -> str:
    count = value.count(old)
    if count != 1:
        raise RuntimeError(
            f"{label}: ожидалось одно вхождение, найдено {count}"
        )
    return value.replace(old, new, 1)


def _update_controller_protocol() -> tuple[bytes, bytes]:
    """Расширяет компактные артефакты без переформатирования соседних строк."""

    schema = (ROOT / CONTROLLER_SCHEMA).read_text(encoding="utf-8")
    definitions = """    "coordinatorPair": {
      "type": "object", "additionalProperties": false,
      "required": ["model", "reasoningEffort"],
      "properties": {"model": {"type": "string", "minLength": 1, "maxLength": 128}, "reasoningEffort": {"type": "string", "minLength": 1, "maxLength": 32}}
    },
    "coordinatorSelection": {
      "type": "object", "additionalProperties": false,
      "required": ["selection", "status", "reasonCode", "selectedPair", "candidateIndex", "accountCatalogFingerprint", "accountContextFingerprint"],
      "properties": {
        "selection": {"const": "first-verified-available"},
        "status": {"enum": ["SELECTED", "UNAVAILABLE"]},
        "reasonCode": {"enum": ["COORDINATOR_PAIR_SELECTED", "COORDINATOR_PAIR_UNAVAILABLE", "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE", "COORDINATOR_ACCOUNT_CATALOG_INVALID"]},
        "selectedPair": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/coordinatorPair"}]},
        "candidateIndex": {"oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0, "maximum": 7}]},
        "accountCatalogFingerprint": {"$ref": "#/$defs/nullableSha256"},
        "accountContextFingerprint": {"$ref": "#/$defs/nullableSha256"}
      },
      "oneOf": [
        {"properties": {"status": {"const": "SELECTED"}, "reasonCode": {"const": "COORDINATOR_PAIR_SELECTED"}, "selectedPair": {"$ref": "#/$defs/coordinatorPair"}, "candidateIndex": {"type": "integer", "minimum": 0, "maximum": 7}, "accountCatalogFingerprint": {"$ref": "#/$defs/sha256"}, "accountContextFingerprint": {"$ref": "#/$defs/sha256"}}},
        {"properties": {"status": {"const": "UNAVAILABLE"}, "reasonCode": {"const": "COORDINATOR_PAIR_UNAVAILABLE"}, "selectedPair": {"type": "null"}, "candidateIndex": {"type": "null"}, "accountCatalogFingerprint": {"$ref": "#/$defs/sha256"}, "accountContextFingerprint": {"$ref": "#/$defs/sha256"}}},
        {"properties": {"status": {"const": "UNAVAILABLE"}, "reasonCode": {"enum": ["COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE", "COORDINATOR_ACCOUNT_CATALOG_INVALID"]}, "selectedPair": {"type": "null"}, "candidateIndex": {"type": "null"}, "accountCatalogFingerprint": {"type": "null"}, "accountContextFingerprint": {"$ref": "#/$defs/sha256"}}}
      ]
    },
"""
    if '"coordinatorSelection": {' not in schema:
        schema = _replace_once(
            schema,
            '    "workCounts": {\n',
            definitions + '    "workCounts": {\n',
            label="определения выбора координатора",
        )
        schema = _replace_once(
            schema,
            '"databaseSchemaVersion", "workCounts"]',
            '"databaseSchemaVersion", "coordinatorSelection", "workCounts"]',
            label="обязательное поле выбора координатора",
        )
        schema = _replace_once(
            schema,
            '"databaseSchemaVersion": {"const": 2}, "workCounts"',
            '"databaseSchemaVersion": {"const": 2}, '
            '"coordinatorSelection": {"$ref": "#/$defs/coordinatorSelection"}, '
            '"workCounts"',
            label="схема поля выбора координатора",
        )
    failed_context_null = (
        '"reasonCode": {"enum": '
        '["COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE", '
        '"COORDINATOR_ACCOUNT_CATALOG_INVALID"]}, '
        '"selectedPair": {"type": "null"}, '
        '"candidateIndex": {"type": "null"}, '
        '"accountCatalogFingerprint": {"type": "null"}, '
        '"accountContextFingerprint": {"type": "null"}'
    )
    if failed_context_null in schema:
        schema = _replace_once(
            schema,
            failed_context_null,
            failed_context_null.replace(
                '"accountContextFingerprint": {"type": "null"}',
                '"accountContextFingerprint": {"$ref": "#/$defs/sha256"}',
            ),
            label="контекстный отпечаток отказа координатора",
        )
    expected_definitions = json.loads(
        "{\n" + definitions + '    "__end": null\n}'
    )
    expected_definitions.pop("__end")
    parsed_schema = json.loads(schema)
    actual_definitions = parsed_schema.get("$defs")
    if not isinstance(actual_definitions, dict) or any(
        actual_definitions.get(name) != expected
        for name, expected in expected_definitions.items()
    ):
        raise RuntimeError("семантика схемы выбора координатора отличается")
    health = actual_definitions.get("healthPayload")
    if (
        not isinstance(health, dict)
        or health.get("required", []).count("coordinatorSelection") != 1
        or health.get("properties", {}).get("coordinatorSelection")
        != {"$ref": "#/$defs/coordinatorSelection"}
    ):
        raise RuntimeError("семантика health выбора координатора отличается")

    vector = (ROOT / CONTROLLER_VECTOR).read_text(encoding="utf-8")
    if '"accountContextFingerprint": "6666666666666666' not in vector:
        selection = """          "coordinatorSelection": {
            "selection": "first-verified-available",
            "status": "SELECTED",
            "reasonCode": "COORDINATOR_PAIR_SELECTED",
            "selectedPair": {"model": "gpt-5.6-sol", "reasoningEffort": "medium"},
            "candidateIndex": 0,
            "accountCatalogFingerprint": "5555555555555555555555555555555555555555555555555555555555555555",
            "accountContextFingerprint": "6666666666666666666666666666666666666666666666666666666666666666"
          },
"""
        vector = _replace_once(
            vector,
            '          "workCounts": {\n',
            selection + '          "workCounts": {\n',
            label="положительный вектор выбора координатора",
        )
    negative_name = "health-without-coordinator-selection-rejected"
    if negative_name not in vector:
        anchor = (
            '    {"name": "health-live-fence-rejected", "method": "health", '
            '"direction": "request", "baseCase": "health-request", '
            '"mutation": {"operation": "replace", '
            '"pointer": "/controllerIdentity", '
            '"value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, '
            '"expectedViolation": "SCHEMA_REJECT"},\n'
        )
        negative = (
            '    {"name": "health-without-coordinator-selection-rejected", '
            '"method": "health", "direction": "response", '
            '"baseCase": "health-response", "mutation": {"operation": "remove", '
            '"pointer": "/payload/coordinatorSelection"}, '
            '"expectedViolation": "SCHEMA_REJECT"},\n'
        )
        vector = _replace_once(
            vector,
            anchor,
            anchor + negative,
            label="отрицательный вектор выбора координатора",
        )
    expected_selection = {
        "selection": "first-verified-available",
        "status": "SELECTED",
        "reasonCode": "COORDINATOR_PAIR_SELECTED",
        "selectedPair": {
            "model": "gpt-5.6-sol",
            "reasoningEffort": "medium",
        },
        "candidateIndex": 0,
        "accountCatalogFingerprint": "5" * 64,
        "accountContextFingerprint": "6" * 64,
    }
    expected_negative = {
        "name": negative_name,
        "method": "health",
        "direction": "response",
        "baseCase": "health-response",
        "mutation": {
            "operation": "remove",
            "pointer": "/payload/coordinatorSelection",
        },
        "expectedViolation": "SCHEMA_REJECT",
    }
    parsed_vector = json.loads(vector)
    health_cases = [
        case
        for case in parsed_vector.get("positiveCases", [])
        if case.get("name") == "health-response"
    ]
    negative_cases = [
        case
        for case in parsed_vector.get("negativeCases", [])
        if case.get("name") == negative_name
    ]
    if (
        len(health_cases) != 1
        or health_cases[0].get("message", {})
        .get("payload", {})
        .get("coordinatorSelection")
        != expected_selection
        or negative_cases != [expected_negative]
    ):
        raise RuntimeError("семантика вектора выбора координатора отличается")
    return schema.encode("utf-8"), vector.encode("utf-8")


def _update_lifecycle_health_vector() -> bytes:
    """Синхронизирует зависимую health-фикстуру без переформатирования."""

    vector = (ROOT / LIFECYCLE_VECTOR).read_text(encoding="utf-8")
    if '"coordinatorSelection"' not in vector:
        selection = """        "coordinatorSelection": {
          "selection": "first-verified-available",
          "status": "SELECTED",
          "reasonCode": "COORDINATOR_PAIR_SELECTED",
          "selectedPair": {"model": "gpt-5.6-sol", "reasoningEffort": "medium"},
          "candidateIndex": 0,
          "accountCatalogFingerprint": "5555555555555555555555555555555555555555555555555555555555555555",
          "accountContextFingerprint": "6666666666666666666666666666666666666666666666666666666666666666"
        },
"""
        anchor = (
            '        "databaseId": "db2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\n'
            '        "databaseSchemaVersion": 2,\n'
            '        "workCounts": {\n'
        )
        vector = _replace_once(
            vector,
            anchor,
            anchor.replace(
                '        "workCounts": {\n',
                selection + '        "workCounts": {\n',
            ),
            label="зависимый health-вектор жизненного цикла",
        )
    parsed = json.loads(vector)
    actual_selection = parsed.get("fixtures", {}).get(
        "healthResponse", {}
    ).get("payload", {}).get("coordinatorSelection")
    expected_selection = {
        "selection": "first-verified-available",
        "status": "SELECTED",
        "reasonCode": "COORDINATOR_PAIR_SELECTED",
        "selectedPair": {
            "model": "gpt-5.6-sol",
            "reasoningEffort": "medium",
        },
        "candidateIndex": 0,
        "accountCatalogFingerprint": "5" * 64,
        "accountContextFingerprint": "6" * 64,
    }
    if actual_selection != expected_selection:
        raise RuntimeError(
            "семантика health-вектора жизненного цикла отличается"
        )
    return vector.encode("utf-8")


def generate() -> dict[Path, bytes]:
    routing = load(ROOT / ROUTING_VECTOR)
    old_policy_fingerprint = routing["fingerprint"]
    policy = copy.deepcopy(routing["policy"])
    policy["coordinator"] = copy.deepcopy(COORDINATOR_CONTRACT)
    canonical = canonical_json_v1(policy)
    new_policy_fingerprint = domain_fingerprint(routing["domain"], policy)
    routing = replace_strings(
        routing,
        {old_policy_fingerprint: new_policy_fingerprint},
    )
    routing["policy"] = policy
    routing["canonicalUtf8"] = canonical
    routing["fingerprint"] = new_policy_fingerprint

    schema = load(ROOT / ROUTING_SCHEMA)
    schema["const"] = copy.deepcopy(policy)
    controller_schema, controller_vector = _update_controller_protocol()
    lifecycle_vector = _update_lifecycle_health_vector()
    generated = {
        ROUTING_VECTOR: _serialized(routing),
        ROUTING_SCHEMA: _serialized(schema),
        CONTROLLER_SCHEMA: controller_schema,
        CONTROLLER_VECTOR: controller_vector,
        LIFECYCLE_VECTOR: lifecycle_vector,
    }

    child = load(ROOT / CHILD_VECTOR)
    old_profiles, new_profiles = profile_references(child)
    interface = replace_strings(
        load(ROOT / INTERFACE_VECTOR),
        {old_policy_fingerprint: new_policy_fingerprint},
    )
    interface, old_compatibility, new_compatibility = update_interface(
        interface,
        old_profiles=old_profiles,
        new_profiles=new_profiles,
        machine_schema_sha256=_schema_hashes(interface, generated=generated),
    )
    child = update_child(
        child,
        old_profiles=old_profiles,
        new_profiles=new_profiles,
        compatibility_fingerprint=new_compatibility,
    )
    account = update_account(
        load(ROOT / ACCOUNT_VECTOR),
        old_compatibility=old_compatibility,
        new_compatibility=new_compatibility,
    )
    generated.update(
        {
            INTERFACE_VECTOR: _serialized(interface),
            ACCOUNT_VECTOR: _serialized(account),
            CHILD_VECTOR: _serialized(child),
        }
    )
    return generated


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    generated = generate()
    changed = [
        path
        for path, content in generated.items()
        if not (ROOT / path).exists() or (ROOT / path).read_bytes() != content
    ]
    if arguments.check:
        if changed:
            print(
                "каскад договора координатора требует обновления: "
                + ", ".join(str(path) for path in changed),
                file=sys.stderr,
            )
            return 1
        print("каскад договора координатора воспроизводим")
        return 0
    for path in changed:
        (ROOT / path).write_bytes(generated[path])
    print(
        "обновлено файлов: "
        + str(len(changed))
        + (": " + ", ".join(str(path) for path in changed) if changed else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
