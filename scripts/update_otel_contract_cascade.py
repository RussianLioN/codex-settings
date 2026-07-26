#!/usr/bin/env python3
"""Согласованная регенерация каскада договора дочернего запуска."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0,
    str(ROOT / "plugins" / "codex-smart-subagents" / "src"),
)

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)


SUBJECT_DOMAIN = "codex-smart/subject/v1"
SEMANTIC_DOMAIN = "codex-smart/semantic/v1"
COMPATIBILITY_DOMAIN = "codex-smart/compatibility/v1"

OTEL_ARGV_SUFFIX = [
    {"literal": "-c"},
    {"literal": 'otel.environment="adaptive-child"'},
    {"literal": "-c"},
    {"literal": "otel.log_user_prompt=false"},
    {"literal": "-c"},
    {"literal": 'otel.metrics_exporter="none"'},
    {"literal": "-c"},
    {"literal": 'otel.trace_exporter="none"'},
    {"literal": "-c"},
    {
        "slot": "otelExporterConfig",
        "prefix": "",
        "encoding": "raw",
    },
]
PERMISSION_ARGUMENT_SLOTS = (
    "permissionDescriptionConfig",
    "permissionFilesystemConfig",
    "permissionNetworkConfig",
)
PERMISSION_DESCRIPTIONS = {
    "classifier": "Adaptive child classifier",
    "reader": "Adaptive child reader",
    "writer": "Adaptive child writer",
}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def replace_strings(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        for before, after in replacements.items():
            value = value.replace(before, after)
        return value
    if isinstance(value, list):
        return [replace_strings(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_strings(item, replacements) for key, item in value.items()}
    return value


def profile_references(child: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for case in child["cases"]:
        role = case["name"]
        before[role] = case["fingerprint"]
        profile = case["profile"]
        template = profile["argvTemplate"]
        ensure_permission_argv(profile)
        ensure_shell_environment_argv(profile)
        if not any(item.get("slot") == "otelExporterConfig" for item in template):
            template.extend(copy.deepcopy(OTEL_ARGV_SUFFIX))
        case["canonicalUtf8"] = canonical_json_v1(profile)
        case["fingerprint"] = domain_fingerprint(
            child["profileDomain"],
            profile,
        )
        after[role] = case["fingerprint"]
    ensure_permission_negative_case(child)
    return before, after


def ensure_shell_environment_argv(profile: dict[str, Any]) -> None:
    items = [
        item
        for item in profile["argvTemplate"]
        if item.get("slot") == "shellEnvironmentSet"
    ]
    if len(items) != 1:
        raise ValueError("child profile must have one shell environment slot")
    item = items[0]
    if item.get("prefix") != "shell_environment_policy.set=":
        raise ValueError("child profile has another shell environment prefix")
    item["encoding"] = "toml-inline-table"


def ensure_permission_argv(profile: dict[str, Any]) -> None:
    template = profile["argvTemplate"]
    observed = tuple(
        item.get("slot")
        for item in template
        if item.get("slot") in PERMISSION_ARGUMENT_SLOTS
    )
    if observed == PERMISSION_ARGUMENT_SLOTS:
        return
    if observed:
        raise ValueError("child profile has a partial permission table")
    expected_default = "default_permissions=" + canonical_json_v1(
        profile["permissionProfileId"]
    )
    default_index = next(
        index
        for index, item in enumerate(template)
        if item.get("literal") == expected_default
    )
    permission_items: list[dict[str, str]] = []
    for slot in PERMISSION_ARGUMENT_SLOTS:
        permission_items.extend(
            (
                {"literal": "-c"},
                {"slot": slot, "prefix": "", "encoding": "raw"},
            )
        )
    template[default_index + 1 : default_index + 1] = permission_items


def ensure_permission_negative_case(child: dict[str, Any]) -> None:
    name = "profile-permission-table-removed"
    if any(case["name"] == name for case in child["negativeCases"]):
        return
    child["negativeCases"].insert(
        2,
        {
            "name": name,
            "target": "profile:reader",
            "mutation": {
                "kind": "remove-permission-table",
                "pointer": "/argvTemplate",
                "slots": list(PERMISSION_ARGUMENT_SLOTS),
            },
            "expected": "profile-schema-invalid",
        },
    )


def update_child_schema(
    schema: dict[str, Any],
    child: dict[str, Any],
) -> dict[str, Any]:
    schema["$defs"]["childProfile"]["oneOf"] = [
        {"const": copy.deepcopy(case["profile"])} for case in child["cases"]
    ]
    arguments = schema["$defs"]["launchArguments"]
    for slot in PERMISSION_ARGUMENT_SLOTS:
        if slot not in arguments["required"]:
            arguments["required"].append(slot)
        arguments["properties"][slot] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 16384,
        }
    return schema


def interface_fingerprints(value: dict[str, Any]) -> dict[str, str]:
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


def interface_canonical(value: dict[str, Any]) -> dict[str, str]:
    fingerprints = interface_fingerprints(value)
    return {
        "subjectUtf8": canonical_json_v1(value["subject"]),
        "semanticUtf8": canonical_json_v1(value["semantic"]),
        "compatibilityUtf8": canonical_json_v1(
            {
                "contractVersion": value["contractVersion"],
                "semanticFingerprint": fingerprints["semanticFingerprint"],
                "subjectFingerprint": fingerprints["subjectFingerprint"],
            }
        ),
    }


def pointer_get(value: Any, pointer: str) -> Any:
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def pointer_set(value: Any, pointer: str, replacement: Any) -> None:
    tokens = pointer.lstrip("/").split("/")
    for raw in tokens[:-1]:
        token = raw.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    token = tokens[-1].replace("~1", "/").replace("~0", "~")
    if isinstance(value, list):
        value[int(token)] = replacement
    else:
        value[token] = replacement


def apply_interface_operation(
    base: dict[str, Any],
    operation: dict[str, Any],
) -> dict[str, Any]:
    candidate = copy.deepcopy(base)
    if operation["kind"] == "replace-value":
        assert pointer_get(candidate, operation["pointer"]) == operation["before"]
        pointer_set(candidate, operation["pointer"], copy.deepcopy(operation["value"]))
    else:
        raise ValueError("UTF-8 case uses an unsupported operation")
    return candidate


def update_interface(
    interface: dict[str, Any],
    *,
    old_profiles: dict[str, str],
    new_profiles: dict[str, str],
    machine_schema_sha256: dict[str, str],
) -> tuple[dict[str, Any], str, str]:
    old_semantic = interface["base"]["semanticFingerprint"]
    old_compatibility = interface["base"]["compatibilityFingerprint"]
    replacements = {old_profiles[role]: new_profiles[role] for role in old_profiles}
    machine_schemas = interface["base"]["semantic"]["machineSchemas"]
    if set(machine_schema_sha256) != set(machine_schemas):
        raise ValueError("machine schema files differ from InterfaceEvidence")
    for schema_id, sha256 in machine_schema_sha256.items():
        replacements[machine_schemas[schema_id]["schemaSha256"]] = sha256
    interface = replace_strings(interface, replacements)
    base = interface["base"]
    base["semantic"]["childProfiles"] = copy.deepcopy(new_profiles)
    base["semantic"]["machineSchemas"] = {
        schema_id: {
            "schemaId": schema_id,
            "schemaSha256": machine_schema_sha256[schema_id],
        }
        for schema_id in sorted(machine_schema_sha256)
    }
    new_fingerprints = interface_fingerprints(base)
    interface = replace_strings(
        interface,
        {
            old_semantic: new_fingerprints["semanticFingerprint"],
            old_compatibility: new_fingerprints["compatibilityFingerprint"],
        },
    )
    base = interface["base"]
    base.update(interface_fingerprints(base))
    interface["canonical"] = interface_canonical(base)
    for case in interface["utf8BoundaryCases"]:
        candidate = apply_interface_operation(base, case["operation"])
        candidate_fingerprints = interface_fingerprints(candidate)
        candidate.update(candidate_fingerprints)
        case["expected"]["recalculatedCanonical"] = interface_canonical(candidate)
        case["expected"]["recalculatedFingerprints"] = candidate_fingerprints
    return (
        interface,
        old_compatibility,
        base["compatibilityFingerprint"],
    )


def materialize_binding(
    child: dict[str, Any],
    profile: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    endpoint = context["environmentSlotValues"]["otelEndpoint"].rstrip("/")
    arguments = {
        "snapshotPath": "/private/codex",
        "model": context["selectedPair"]["model"],
        "workDir": context["workDir"],
        "resultSchemaPath": context["resultSchemaPath"],
        "reasoningEffort": context["selectedPair"]["reasoningEffort"],
        **permission_arguments(profile, context["environmentSlotValues"]),
        "otelExporterConfig": (
            "otel.exporter={ otlp-http = { endpoint="
            + canonical_json_v1(endpoint + "/v1/logs")
            + ', protocol="json", headers={} } }'
        ),
    }
    environment: dict[str, str] = {}
    secret_sha256 = ""
    for name, source in profile["environmentTemplate"].items():
        if "literal" in source:
            environment[name] = source["literal"]
        elif "slot" in source:
            environment[name] = context["environmentSlotValues"][source["slot"]]
        else:
            secret_sha256 = context["secretSlotFingerprints"][source["secretSlot"]]
    argv = materialize_argv(profile, arguments, environment)
    environment_projection = {
        "variables": environment,
        "secretBindings": {
            "OTEL_EXPORTER_OTLP_HEADERS": secret_sha256,
        },
    }
    return {
        "schemaVersion": 1,
        "contractVersion": "codex-child-launch-v1",
        "role": profile["role"],
        "compatibilityFingerprint": context["compatibilityFingerprint"],
        "arguments": arguments,
        "concreteArgv": argv,
        "nonSecretEnvironment": environment,
        "argvFingerprint": domain_fingerprint(child["argvDomain"], argv),
        "environmentFingerprint": domain_fingerprint(
            child["environmentDomain"],
            environment_projection,
        ),
        "secretSha256": secret_sha256,
    }


def permission_arguments(
    profile: dict[str, Any],
    environment_slots: dict[str, str],
) -> dict[str, str]:
    name = profile["permissionProfileId"]
    role = profile["role"]
    entries = [
        '":root"="deny"',
        '":minimal"="read"',
        '":tmpdir"="write"',
        '":workspace_roots"={"."="write"}',
        canonical_json_v1(environment_slots["snapshotRoot"]) + '="read"',
    ]
    if role == "writer":
        entries.append(
            canonical_json_v1(environment_slots["workspaceRoot"]) + '="write"'
        )
    prefix = f"permissions.{name}"
    return {
        "permissionDescriptionConfig": (
            prefix + ".description=" + canonical_json_v1(PERMISSION_DESCRIPTIONS[role])
        ),
        "permissionFilesystemConfig": (
            prefix + ".filesystem={" + ",".join(entries) + "}"
        ),
        "permissionNetworkConfig": prefix + ".network.enabled=false",
    }


def materialize_argv(
    profile: dict[str, Any],
    arguments: dict[str, str],
    environment: dict[str, str],
) -> list[str]:
    argv: list[str] = []
    for item in profile["argvTemplate"]:
        if "literal" in item:
            argv.append(item["literal"])
            continue
        if item["slot"] == "shellEnvironmentSet":
            raw = toml_inline_string_map(environment)
        else:
            raw = arguments[item["slot"]]
            if item["encoding"] == "json-string":
                raw = canonical_json_v1(raw)
        argv.append(item["prefix"] + raw)
    for feature in profile["disabledFeatures"]:
        argv.extend(("--disable", feature))
    return argv


def toml_inline_string_map(value: dict[str, str]) -> str:
    entries = ",".join(
        canonical_json_v1(name) + "=" + canonical_json_v1(item)
        for name, item in sorted(value.items())
    )
    return "{" + entries + "}"


def update_child(
    child: dict[str, Any],
    *,
    old_profiles: dict[str, str],
    new_profiles: dict[str, str],
    compatibility_fingerprint: str,
) -> dict[str, Any]:
    child = replace_strings(
        child,
        {old_profiles[role]: new_profiles[role] for role in old_profiles},
    )
    child["concreteLaunch"]["shellEnvironmentSetProjection"] = (
        "all nonSecretEnvironment entries in sorted TOML inline-table order; "
        "OTEL_EXPORTER_OTLP_HEADERS is forbidden"
    )
    profiles = {case["name"]: case["profile"] for case in child["cases"]}
    for case in child["cases"]:
        case["canonicalUtf8"] = canonical_json_v1(case["profile"])
        case["fingerprint"] = domain_fingerprint(
            child["profileDomain"],
            case["profile"],
        )
    for role, fixture in child["concreteLaunch"]["positiveRoles"].items():
        context = fixture["trustedContext"]
        context["compatibilityFingerprint"] = compatibility_fingerprint
        fixture["binding"] = materialize_binding(
            child,
            profiles[role],
            context,
        )
    for case in child["environmentNegativeCases"]:
        fixture = child["concreteLaunch"]["positiveRoles"][case["role"]]
        changed_context = copy.deepcopy(fixture["trustedContext"])
        if case["kind"] == "regular-slot":
            changed_context["environmentSlotValues"][case["slot"]] = case["value"]
        else:
            changed_context["secretSlotFingerprints"][case["slot"]] = case["value"]
        candidate = materialize_binding(
            child,
            profiles[case["role"]],
            changed_context,
        )
        case["expected"] = {
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
    reader_profile = profiles["reader"]
    reader_binding = child["concreteLaunch"]["positiveRoles"]["reader"]["binding"]
    for case in child["negativeCases"]:
        operation = case["mutation"]
        if operation["kind"] != "replace-argument-and-rematerialize":
            continue
        arguments = copy.deepcopy(reader_binding["arguments"])
        arguments[operation["argument"]] = operation["value"]
        argv = materialize_argv(
            reader_profile,
            arguments,
            reader_binding["nonSecretEnvironment"],
        )
        case["rematerialized"]["argvFingerprint"] = domain_fingerprint(
            child["argvDomain"],
            argv,
        )
    return child


def account_chain(
    account: dict[str, Any],
    domains: dict[str, str],
) -> tuple[dict[str, str], list[str]]:
    collection = account["collection"]
    requirements_fp = domain_fingerprint(
        domains["requirements"], account["requirements"]
    )
    catalog_fp = domain_fingerprint(
        domains["accountCatalog"], account["availablePairs"]
    )
    environment_fp = domain_fingerprint(
        domains["accountEnvironment"],
        collection["environment"],
    )
    process_utf8: list[str] = []
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
        process_utf8.append(canonical_json_v1(projection))
        process_fps.append(domain_fingerprint(domains["accountProcess"], projection))
    collection_projection = {"processFingerprints": process_fps}
    collection_fp = domain_fingerprint(
        domains["accountCollection"],
        collection_projection,
    )
    context_projection = {
        "codexHome": account["codexHome"],
        "subjectFingerprint": account["subject"]["subjectFingerprint"],
        "compatibilityFingerprint": account["compatibilityFingerprint"],
        "requirementsFingerprint": requirements_fp,
        "accountCatalogFingerprint": catalog_fp,
        "collectionFingerprint": collection_fp,
    }
    context_fp = domain_fingerprint(domains["accountContext"], context_projection)
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
    record_fp = domain_fingerprint(domains["accountRecord"], record_projection)
    account["requirementsFingerprint"] = requirements_fp
    account["accountCatalogFingerprint"] = catalog_fp
    account["accountContextFingerprint"] = context_fp
    account["recordFingerprint"] = record_fp
    collection["environmentFingerprint"] = environment_fp
    for process, fingerprint in zip(
        collection["processes"],
        process_fps,
        strict=True,
    ):
        process["processFingerprint"] = fingerprint
    collection["collectionFingerprint"] = collection_fp
    canonical = {
        "requirementsUtf8": canonical_json_v1(account["requirements"]),
        "accountCatalogUtf8": canonical_json_v1(account["availablePairs"]),
        "environmentUtf8": canonical_json_v1(collection["environment"]),
        "processUtf8": process_utf8,
        "collectionUtf8": canonical_json_v1(collection_projection),
        "accountContextUtf8": canonical_json_v1(context_projection),
        "recordUtf8": canonical_json_v1(record_projection),
    }
    return canonical, process_fps


def update_account(
    account_vectors: dict[str, Any],
    *,
    old_compatibility: str,
    new_compatibility: str,
) -> dict[str, Any]:
    old_base = copy.deepcopy(account_vectors["base"])
    new_base = copy.deepcopy(old_base)
    new_base["compatibilityFingerprint"] = new_compatibility
    new_canonical, _ = account_chain(new_base, account_vectors["domains"])
    replacements = {old_compatibility: new_compatibility}
    for name in (
        "requirementsFingerprint",
        "accountCatalogFingerprint",
        "accountContextFingerprint",
        "recordFingerprint",
    ):
        replacements[old_base[name]] = new_base[name]
    replacements[old_base["collection"]["environmentFingerprint"]] = new_base[
        "collection"
    ]["environmentFingerprint"]
    replacements[old_base["collection"]["collectionFingerprint"]] = new_base[
        "collection"
    ]["collectionFingerprint"]
    for old_process, new_process in zip(
        old_base["collection"]["processes"],
        new_base["collection"]["processes"],
        strict=True,
    ):
        replacements[old_process["processFingerprint"]] = new_process[
            "processFingerprint"
        ]
    account_vectors = replace_strings(account_vectors, replacements)
    account_vectors["base"] = new_base
    account_vectors["canonical"] = new_canonical
    for case in account_vectors["mutations"]:
        if case["operation"]["kind"] != "swap-array-items-and-recalculate":
            continue
        changed = copy.deepcopy(new_base)
        first = case["operation"]["first"]
        second = case["operation"]["second"]
        changed["availablePairs"][first], changed["availablePairs"][second] = (
            changed["availablePairs"][second],
            changed["availablePairs"][first],
        )
        canonical, process_fps = account_chain(changed, account_vectors["domains"])
        case["recalculated"] = {
            "accountCatalogUtf8": canonical["accountCatalogUtf8"],
            "accountCatalogFingerprint": changed["accountCatalogFingerprint"],
            "processFingerprints": process_fps,
            "collectionFingerprint": changed["collection"]["collectionFingerprint"],
            "accountContextFingerprint": changed["accountContextFingerprint"],
            "recordFingerprint": changed["recordFingerprint"],
        }
    return account_vectors


def main() -> None:
    child_path = ROOT / "docs/contracts/vectors/child-profile-v1.json"
    interface_path = ROOT / "docs/contracts/vectors/interface-evidence-v1.json"
    account_path = ROOT / "docs/contracts/vectors/account-evidence-v1.json"
    child_schema_path = ROOT / "docs/contracts/schemas/child-profile-v1.schema.json"

    child = load(child_path)
    old_profiles, new_profiles = profile_references(child)
    child_schema = update_child_schema(load(child_schema_path), child)
    write(child_schema_path, child_schema)
    machine_schema_sha256 = {
        schema_id: hashlib.sha256(
            (ROOT / "docs/contracts/schemas" / f"{schema_id}.schema.json").read_bytes()
        ).hexdigest()
        for schema_id in load(interface_path)["base"]["semantic"]["machineSchemas"]
    }
    interface, old_compatibility, new_compatibility = update_interface(
        load(interface_path),
        old_profiles=old_profiles,
        new_profiles=new_profiles,
        machine_schema_sha256=machine_schema_sha256,
    )
    child = update_child(
        child,
        old_profiles=old_profiles,
        new_profiles=new_profiles,
        compatibility_fingerprint=new_compatibility,
    )
    account = update_account(
        load(account_path),
        old_compatibility=old_compatibility,
        new_compatibility=new_compatibility,
    )
    write(child_path, child)
    write(interface_path, interface)
    write(account_path, account)


if __name__ == "__main__":
    main()
