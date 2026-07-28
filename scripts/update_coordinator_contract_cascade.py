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
    generated = {
        ROUTING_VECTOR: _serialized(routing),
        ROUTING_SCHEMA: _serialized(schema),
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
