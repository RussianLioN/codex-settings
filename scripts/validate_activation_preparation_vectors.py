#!/usr/bin/env python3
"""Независимая проверка долговечного контура подготовки активации версии 2."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "docs/contracts/schemas"
VECTOR_PATH = ROOT / "docs/contracts/vectors/activation-preparation-v2.json"
SAFE_INTEGER_MAX = (1 << 53) - 1
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise ValueError("integer outside canonical-json-v1 safe range")
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
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("canonical-json-v1 object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return "{" + ",".join(
            canonical_json(key) + ":" + canonical_json(value[key])
            for key in keys
        ) + "}"
    raise ValueError(f"unsupported canonical-json-v1 value: {type(value).__name__}")


def fingerprint(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("utf-8")
        + b"\0"
        + canonical_json(value).encode("utf-8")
    ).hexdigest()


def projection(
    schema_id: str,
    schema_sha256: str,
    value: dict[str, Any],
) -> dict[str, Any]:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": schema_sha256,
        "value": copy.deepcopy(value),
    }
    envelope["valueFingerprint"] = fingerprint(
        {
            "file-object-v2": "codex-smart/file-object/v2",
            "tree-object-v2": "codex-smart/tree-object/v2",
            "activation-v2": "codex-smart/activation/v2",
            "database-binding-target-v2": (
                "codex-smart/database-binding-target/v2"
            ),
        }[schema_id],
        envelope,
    )
    return envelope


def empty_bundle() -> dict[str, Any]:
    result = {
        "fileObjects": [],
        "treeObjects": [],
        "symlinks": [],
        "manifest": None,
        "activation": None,
        "database": None,
        "controller": None,
        "controllerCandidates": [],
        "watchdogs": [],
        "registry": None,
        "launchers": None,
        "legacyProcesses": None,
        "quiescence": None,
        "externalCommands": [],
        "receipts": [],
        "absenceProofs": [],
    }
    result["bundleFingerprint"] = fingerprint(
        "codex-smart/state-bundle/v2", result
    )
    return result


def refresh_projection(document: dict[str, Any]) -> None:
    domain = {
        "file-object-v2": "codex-smart/file-object/v2",
        "tree-object-v2": "codex-smart/tree-object/v2",
        "activation-v2": "codex-smart/activation/v2",
        "database-binding-target-v2": "codex-smart/database-binding-target/v2",
    }[document["schemaId"]]
    envelope = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "valueFingerprint"
    }
    document["valueFingerprint"] = fingerprint(domain, envelope)


def refresh_bundle(document: dict[str, Any]) -> None:
    array_fields = (
        "fileObjects",
        "treeObjects",
        "symlinks",
        "controllerCandidates",
        "watchdogs",
        "externalCommands",
        "receipts",
        "absenceProofs",
    )
    scalar_fields = (
        "manifest",
        "activation",
        "database",
        "controller",
        "registry",
        "launchers",
        "legacyProcesses",
        "quiescence",
    )
    for name in array_fields:
        for item in document[name]:
            refresh_projection(item)
    for name in scalar_fields:
        if document[name] is not None:
            refresh_projection(document[name])
    value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "bundleFingerprint"
    }
    document["bundleFingerprint"] = fingerprint(
        "codex-smart/state-bundle/v2", value
    )


def refresh_intent(document: dict[str, Any]) -> None:
    value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "activationIntentFingerprint"
    }
    document["activationIntentFingerprint"] = fingerprint(
        "codex-smart/activation-preparation-intent/v2", value
    )


def refresh_logical(document: dict[str, Any]) -> None:
    value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "logicalFingerprint"
    }
    document["logicalFingerprint"] = fingerprint(
        "codex-smart/preparation-logical-object/v2", value
    )


def refresh_step(document: dict[str, Any]) -> None:
    refresh_logical(document["expectedLogical"])
    if document["observedPhysical"] is not None:
        refresh_projection(document["observedPhysical"])
    for companion in document["observedCompanions"]:
        refresh_projection(companion)
    value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "stepFingerprint"
    }
    document["stepFingerprint"] = fingerprint(
        "codex-smart/activation-preparation-step/v2", value
    )


def refresh_journal(document: dict[str, Any]) -> None:
    definition = document["definition"]
    refresh_intent(definition["activationIntent"])
    refresh_bundle(definition["desiredSeed"])
    refresh_projection(definition["snapshotFile"])
    for name in (
        "activationTreeLogical",
        "activationFileLogical",
        "databaseEmptyFileLogical",
    ):
        refresh_logical(definition[name])
    document["definitionFingerprint"] = fingerprint(
        "codex-smart/activation-preparation-definition/v2", definition
    )
    document["intentBoundary"]["activationIntentFingerprint"] = definition[
        "activationIntent"
    ]["activationIntentFingerprint"]
    document["intentBoundary"]["desiredSeedFingerprint"] = definition[
        "desiredSeed"
    ]["bundleFingerprint"]
    for step in document["steps"]:
        refresh_step(step)
    if document["desired"] is not None:
        refresh_bundle(document["desired"])
    without_journal = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "journalFingerprint"
    }
    if document["phase"] == "PREPARATION_FROZEN":
        without_journal["frozenJournalFingerprint"] = None
        document["frozenJournalFingerprint"] = fingerprint(
            "codex-smart/activation-preparation-frozen-journal/v2",
            without_journal,
        )
    final_value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "journalFingerprint"
    }
    document["journalFingerprint"] = fingerprint(
        "codex-smart/activation-preparation-journal/v2", final_value
    )


def refresh_receipt(document: dict[str, Any]) -> None:
    refresh_intent(document["activationIntent"])
    for name in (
        "snapshotFile",
        "activationTree",
        "activationFile",
        "databaseEmptyFile",
        "databaseBindingTarget",
    ):
        refresh_projection(document[name])
    refresh_bundle(document["desired"])
    value = {
        key: copy.deepcopy(item)
        for key, item in document.items()
        if key != "receiptFingerprint"
    }
    document["receiptFingerprint"] = fingerprint(
        "codex-smart/activation-preparation-receipt/v2", value
    )


def build_fixtures(seed: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    root = seed["root"].rstrip("/")
    state_home = root + "/state"
    snapshot_path = root + "/snapshots/" + seed["snapshotSha256"]
    database_path = (
        state_home
        + "/databases/"
        + seed["databaseId"]
        + "/smart-subagents.sqlite3"
    )
    bundled_catalog = {
        "models": [
            {"model": "gpt-test", "reasoningEfforts": ["low", "high"]}
        ]
    }
    bundled_catalog_fingerprint = fingerprint(
        "codex-smart/bundled-catalog/v1", bundled_catalog
    )
    identity = {
        "schemaVersion": 2,
        "generationId": "gen2_" + "c" * 64,
        "release": "0.2.0",
        "pluginId": "codex-smart-subagents",
        "database": {
            "databaseId": seed["databaseId"],
            "absolutePath": database_path,
            "schemaVersion": 2,
            "schemaFingerprint": seed["schemaFingerprint"],
            "schemaArtifactSha256": seed["schemaArtifactSha256"],
            "activationBindingNonce": seed["activationBindingNonce"],
        },
        "codexSnapshot": {
            "absolutePath": snapshot_path,
            "sha256": seed["snapshotSha256"],
        },
        "compatibilityFingerprint": seed["compatibilityFingerprint"],
        "routingPolicyFingerprint": seed["routingPolicyFingerprint"],
        "bundledCatalogFingerprint": bundled_catalog_fingerprint,
        "minimumGatewayVersion": "0.2.0",
        "marketplaceTreeSha256": "4" * 64,
        "generationTreeSha256": "5" * 64,
    }
    activation_fingerprint = fingerprint("codex-smart/activation/v2", identity)
    activation_id = "act2_" + activation_fingerprint
    activation_dir = root + "/activations/" + activation_id
    activation_document = {
        "schemaVersion": 2,
        "activationId": activation_id,
        "activationFingerprint": activation_fingerprint,
        "identity": copy.deepcopy(identity),
    }
    codex_home = root + "/codex-home"
    controller_identity = fingerprint(
        "codex-smart/controller-identity/v2",
        {
            "protocolVersion": 2,
            "release": "0.2.0",
            "namespace": "codex-smart-subagents-v2",
            "codexHomeHash": hashlib.sha256(
                codex_home.encode("utf-8")
            ).hexdigest(),
            "stateHome": state_home,
            "activationFingerprint": activation_fingerprint,
            "compatibilityFingerprint": seed["compatibilityFingerprint"],
            "routingPolicyFingerprint": seed["routingPolicyFingerprint"],
            "bundledCatalogFingerprint": bundled_catalog_fingerprint,
            "databaseId": seed["databaseId"],
            "databaseSchemaVersion": 2,
        },
    )
    intent = {
        "sourceRoot": root + "/source",
        "codexHome": codex_home,
        "codexBinary": root + "/bin/codex",
        "stateHome": state_home,
        "socketPath": state_home + "/controller.sock",
        "controllerLockPath": state_home + "/controller.lock",
        "installationId": seed["installationId"],
        "operationId": seed["operationId"],
        "databaseId": seed["databaseId"],
        "activationBindingNonce": seed["activationBindingNonce"],
        "activationId": activation_id,
        "activationFingerprint": activation_fingerprint,
        "controllerIdentity": controller_identity,
        "compatibilityFingerprint": seed["compatibilityFingerprint"],
        "routingPolicyFingerprint": seed["routingPolicyFingerprint"],
        "bundledCatalogFingerprint": bundled_catalog_fingerprint,
        "schemaFingerprint": seed["schemaFingerprint"],
        "schemaArtifactSha256": seed["schemaArtifactSha256"],
        "activationDir": activation_dir,
        "snapshotPath": snapshot_path,
        "databasePath": database_path,
        "bundledCatalogPath": (
            activation_dir + "/marketplace/bundled-catalog-v1.json"
        ),
        "identity": copy.deepcopy(identity),
        "activationDocument": activation_document,
        "sourceLocator": {
            "lexicalPath": root + "/bin/codex",
            "resolvedPathAtCapture": root + "/bin/codex",
            "argv0Policy": "lexical",
            "sourceObservedSha256": seed["snapshotSha256"],
        },
        "snapshotLocator": {
            "absolutePath": snapshot_path,
            "sha256": seed["snapshotSha256"],
        },
        "bundledCatalog": bundled_catalog,
        "interfaceEvidence": {
            "schemaVersion": 1,
            "compatibilityFingerprint": seed["compatibilityFingerprint"],
        },
        "completedAt": seed["createdAt"],
    }
    refresh_intent(intent)
    schema_sha256 = seed["schemaSha256"]
    snapshot_file = projection(
        "file-object-v2",
        schema_sha256,
        {
            "path": snapshot_path,
            "device": 1,
            "inode": 101,
            "ownerUid": 501,
            "ownerGid": 20,
            "mode": "0500",
            "linkCount": 1,
            "size": 4096,
            "sha256": seed["snapshotSha256"],
        },
    )
    activation_file_sha = hashlib.sha256(
        canonical_json(activation_document).encode("utf-8")
    ).hexdigest()
    activation_file = projection(
        "file-object-v2",
        schema_sha256,
        {
            "path": activation_dir + "/activation.json",
            "device": 1,
            "inode": 202,
            "ownerUid": 501,
            "ownerGid": 20,
            "mode": "0600",
            "linkCount": 1,
            "size": len(canonical_json(activation_document).encode("utf-8")),
            "sha256": activation_file_sha,
        },
    )
    activation_tree = projection(
        "tree-object-v2",
        schema_sha256,
        {
            "path": activation_dir,
            "device": 1,
            "inode": 201,
            "ownerUid": 501,
            "ownerGid": 20,
            "mode": "0700",
            "entryCount": 3,
            "treeSha256": "6" * 64,
        },
    )
    database_empty_file = projection(
        "file-object-v2",
        schema_sha256,
        {
            "path": database_path,
            "device": 1,
            "inode": 301,
            "ownerUid": 501,
            "ownerGid": 20,
            "mode": "0600",
            "linkCount": 1,
            "size": 0,
            "sha256": EMPTY_SHA256,
        },
    )
    database_target = projection(
        "database-binding-target-v2",
        schema_sha256,
        {
            "path": database_path,
            "device": 1,
            "inode": 301,
            "ownerUid": 501,
            "ownerGid": 20,
            "mode": "0600",
            "linkCount": 1,
            "databaseId": seed["databaseId"],
            "activationBindingNonce": seed["activationBindingNonce"],
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "schemaFingerprint": seed["schemaFingerprint"],
            "schemaArtifactSha256": seed["schemaArtifactSha256"],
        },
    )
    database_identity = {
        "databaseId": seed["databaseId"],
        "activationBindingNonce": seed["activationBindingNonce"],
        "activationId": activation_id,
        "activationFingerprint": activation_fingerprint,
    }
    activation = projection(
        "activation-v2",
        schema_sha256,
        {
            "directory": copy.deepcopy(activation_tree["value"]),
            "activationFile": copy.deepcopy(activation_file["value"]),
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "generationId": identity["generationId"],
            "release": identity["release"],
            "databaseId": seed["databaseId"],
            "databaseIdentityFingerprint": fingerprint(
                "codex-smart/database-identity/v2", database_identity
            ),
            "marketplaceTreeSha256": identity["marketplaceTreeSha256"],
            "generationTreeSha256": identity["generationTreeSha256"],
        },
    )
    desired_seed = empty_bundle()
    desired = empty_bundle()
    desired["fileObjects"] = [copy.deepcopy(snapshot_file)]
    desired["activation"] = copy.deepcopy(activation)
    desired["database"] = copy.deepcopy(database_target)
    refresh_bundle(desired)

    def logical(path: str, kind: str, mode: str, sha256: str) -> dict[str, Any]:
        result = {
            "path": path,
            "objectType": kind,
            "mode": mode,
            "contentSha256": sha256,
        }
        refresh_logical(result)
        return result

    definition = {
        "journalPath": root + "/control/activation-preparation-v2.json",
        "receiptPath": root + "/receipts/" + seed["operationId"] + ".json",
        "lockPath": root + "/control/installation.lock",
        "activationIntent": copy.deepcopy(intent),
        "desiredSeed": desired_seed,
        "snapshotFile": copy.deepcopy(snapshot_file),
        "activationTreeLogical": logical(
            activation_dir, "directory", "0700", activation_tree["value"]["treeSha256"]
        ),
        "activationFileLogical": logical(
            activation_dir + "/activation.json",
            "regular-file",
            "0600",
            activation_file_sha,
        ),
        "databaseEmptyFileLogical": logical(
            database_path, "regular-file", "0600", EMPTY_SHA256
        ),
    }
    definition_fingerprint = fingerprint(
        "codex-smart/activation-preparation-definition/v2", definition
    )

    def step(
        ordinal: int,
        kind: str,
        expected: dict[str, Any],
        physical: dict[str, Any],
        companions: list[dict[str, Any]],
        completed_at: str,
    ) -> dict[str, Any]:
        result = {
            "stepId": "pst2_"
            + fingerprint(
                "codex-smart/activation-preparation-step-id/v2",
                {
                    "operationId": seed["operationId"],
                    "ordinal": ordinal,
                    "kind": kind,
                },
            )[:32],
            "ordinal": ordinal,
            "kind": kind,
            "state": "COMPLETED",
            "expectedLogical": copy.deepcopy(expected),
            "observedPhysical": copy.deepcopy(physical),
            "observedCompanions": copy.deepcopy(companions),
            "intentAt": seed["intentAt"],
            "completedAt": completed_at,
        }
        refresh_step(result)
        return result

    steps = [
        step(
            1,
            "activation_tree",
            definition["activationTreeLogical"],
            activation_tree,
            [activation_file],
            seed["activationCompletedAt"],
        ),
        step(
            2,
            "database_empty_file",
            definition["databaseEmptyFileLogical"],
            database_empty_file,
            [],
            seed["databaseCompletedAt"],
        ),
    ]
    journal = {
        "schemaVersion": 2,
        "journalKind": "activation-preparation",
        "installationId": seed["installationId"],
        "operationId": seed["operationId"],
        "phase": "PREPARATION_FROZEN",
        "definitionFingerprint": definition_fingerprint,
        "definition": definition,
        "intentBoundary": {
            "kind": "preparation_intent",
            "state": "COMPLETED",
            "activationIntentFingerprint": intent["activationIntentFingerprint"],
            "desiredSeedFingerprint": desired_seed["bundleFingerprint"],
            "completedAt": seed["createdAt"],
        },
        "steps": steps,
        "contentGeneration": 6,
        "createdAt": seed["createdAt"],
        "updatedAt": seed["frozenAt"],
        "frozenAt": seed["frozenAt"],
        "frozenJournalFingerprint": None,
        "desired": desired,
        "journalFingerprint": "0" * 64,
    }
    refresh_journal(journal)
    receipt = {
        "schemaVersion": 2,
        "receiptKind": "activation-preparation",
        "installationId": seed["installationId"],
        "operationId": seed["operationId"],
        "activationIntent": copy.deepcopy(intent),
        "snapshotFile": copy.deepcopy(snapshot_file),
        "activationTree": copy.deepcopy(activation_tree),
        "activationFile": copy.deepcopy(activation_file),
        "databaseEmptyFile": copy.deepcopy(database_empty_file),
        "databaseBindingTarget": copy.deepcopy(database_target),
        "desired": copy.deepcopy(desired),
        "frozenJournalFingerprint": journal["frozenJournalFingerprint"],
        "completedAt": seed["receiptCompletedAt"],
        "receiptFingerprint": "0" * 64,
    }
    refresh_receipt(receipt)
    return journal, receipt


def semantic_errors(
    target: str,
    document: dict[str, Any],
    *,
    baseline_journal: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, code: str) -> None:
        if not condition and code not in errors:
            errors.append(code)

    def check_projection(item: dict[str, Any]) -> None:
        original = item["valueFingerprint"]
        candidate = copy.deepcopy(item)
        refresh_projection(candidate)
        require(candidate["valueFingerprint"] == original, "PROJECTION_FINGERPRINT")

    def check_bundle(bundle: dict[str, Any]) -> None:
        original = bundle["bundleFingerprint"]
        candidate = copy.deepcopy(bundle)
        refresh_bundle(candidate)
        require(candidate["bundleFingerprint"] == original, "BUNDLE_FINGERPRINT")

    def check_intent(intent: dict[str, Any]) -> None:
        original = intent["activationIntentFingerprint"]
        candidate = copy.deepcopy(intent)
        refresh_intent(candidate)
        require(
            candidate["activationIntentFingerprint"] == original,
            "ACTIVATION_INTENT_FINGERPRINT",
        )
        identity = intent["identity"]
        require(
            intent["activationFingerprint"]
            == fingerprint("codex-smart/activation/v2", identity),
            "ACTIVATION_IDENTITY_BINDING",
        )
        require(
            intent["activationId"] == "act2_" + intent["activationFingerprint"],
            "ACTIVATION_IDENTITY_BINDING",
        )
        require(
            intent["activationDir"].rsplit("/", 1)[-1] == intent["activationId"],
            "ACTIVATION_PATH_BINDING",
        )
        require(
            intent["socketPath"] == intent["stateHome"] + "/controller.sock"
            and intent["controllerLockPath"]
            == intent["stateHome"] + "/controller.lock",
            "CONTROL_PATH_BINDING",
        )
        require(
            intent["activationDocument"].get("activationId")
            == intent["activationId"]
            and intent["activationDocument"].get("activationFingerprint")
            == intent["activationFingerprint"]
            and intent["activationDocument"].get("identity") == identity,
            "ACTIVATION_DOCUMENT_BINDING",
        )
        database = identity.get("database", {})
        require(
            (
                database.get("databaseId"),
                database.get("absolutePath"),
                database.get("activationBindingNonce"),
                database.get("schemaFingerprint"),
                database.get("schemaArtifactSha256"),
            )
            == (
                intent["databaseId"],
                intent["databasePath"],
                intent["activationBindingNonce"],
                intent["schemaFingerprint"],
                intent["schemaArtifactSha256"],
            ),
            "DATABASE_IDENTITY_BINDING",
        )
        require(
            intent["interfaceEvidence"].get("compatibilityFingerprint")
            == intent["compatibilityFingerprint"],
            "INTERFACE_EVIDENCE_BINDING",
        )
        for name in (
            "compatibilityFingerprint",
            "routingPolicyFingerprint",
            "bundledCatalogFingerprint",
        ):
            require(identity.get(name) == intent[name], "IDENTITY_FINGERPRINT_BINDING")
        require(
            identity.get("codexSnapshot") == intent["snapshotLocator"]
            and intent["snapshotLocator"].get("absolutePath")
            == intent["snapshotPath"],
            "SNAPSHOT_BINDING",
        )
        require(
            fingerprint("codex-smart/bundled-catalog/v1", intent["bundledCatalog"])
            == intent["bundledCatalogFingerprint"],
            "CATALOG_BINDING",
        )
        require(
            intent["sourceLocator"].get("lexicalPath") == intent["codexBinary"],
            "SOURCE_LOCATOR_BINDING",
        )
        expected_controller = fingerprint(
            "codex-smart/controller-identity/v2",
            {
                "protocolVersion": 2,
                "release": identity.get("release"),
                "namespace": "codex-smart-subagents-v2",
                "codexHomeHash": hashlib.sha256(
                    intent["codexHome"].encode("utf-8")
                ).hexdigest(),
                "stateHome": intent["stateHome"],
                "activationFingerprint": intent["activationFingerprint"],
                "compatibilityFingerprint": intent["compatibilityFingerprint"],
                "routingPolicyFingerprint": intent["routingPolicyFingerprint"],
                "bundledCatalogFingerprint": intent["bundledCatalogFingerprint"],
                "databaseId": intent["databaseId"],
                "databaseSchemaVersion": 2,
            },
        )
        require(
            intent["controllerIdentity"] == expected_controller,
            "CONTROLLER_IDENTITY_BINDING",
        )

    def check_desired(
        desired: dict[str, Any],
        *,
        snapshot: dict[str, Any],
        tree: dict[str, Any],
        activation_file: dict[str, Any],
        database_target: dict[str, Any],
    ) -> None:
        check_bundle(desired)
        require(snapshot in desired["fileObjects"], "DESIRED_SNAPSHOT_BINDING")
        activation = desired["activation"]
        require(
            activation is not None
            and activation["value"].get("directory") == tree["value"]
            and activation["value"].get("activationFile")
            == activation_file["value"],
            "DESIRED_ACTIVATION_BINDING",
        )
        require(desired["database"] == database_target, "DESIRED_DATABASE_BINDING")

    if target == "journal":
        definition = document["definition"]
        check_intent(definition["activationIntent"])
        check_bundle(definition["desiredSeed"])
        for name in (
            "snapshotFile",
        ):
            check_projection(definition[name])
        for name in (
            "activationTreeLogical",
            "activationFileLogical",
            "databaseEmptyFileLogical",
        ):
            original = definition[name]["logicalFingerprint"]
            candidate = copy.deepcopy(definition[name])
            refresh_logical(candidate)
            require(candidate["logicalFingerprint"] == original, "LOGICAL_FINGERPRINT")
        require(
            document["definitionFingerprint"]
            == fingerprint(
                "codex-smart/activation-preparation-definition/v2", definition
            ),
            "DEFINITION_FINGERPRINT",
        )
        require(
            document["intentBoundary"]["activationIntentFingerprint"]
            == definition["activationIntent"]["activationIntentFingerprint"]
            and document["intentBoundary"]["desiredSeedFingerprint"]
            == definition["desiredSeed"]["bundleFingerprint"],
            "PREPARATION_INTENT_BINDING",
        )
        completed = True
        for ordinal, (step, kind, logical_name) in enumerate(
            zip(
                document["steps"],
                ("activation_tree", "database_empty_file"),
                ("activationTreeLogical", "databaseEmptyFileLogical"),
                strict=True,
            ),
            start=1,
        ):
            expected_id = "pst2_" + fingerprint(
                "codex-smart/activation-preparation-step-id/v2",
                {
                    "operationId": document["operationId"],
                    "ordinal": ordinal,
                    "kind": kind,
                },
            )[:32]
            require(step["stepId"] == expected_id, "STEP_ID_BINDING")
            require(
                step["ordinal"] == ordinal
                and step["kind"] == kind
                and step["expectedLogical"] == definition[logical_name],
                "STEP_ORDER_BINDING",
            )
            candidate = copy.deepcopy(step)
            refresh_step(candidate)
            require(
                candidate["stepFingerprint"] == step["stepFingerprint"],
                "STEP_FINGERPRINT",
            )
            if step["state"] != "COMPLETED":
                completed = False
            elif not completed:
                require(False, "STEP_COMPLETION_ORDER")
        if document["phase"] == "PREPARATION_FROZEN":
            require(completed, "FROZEN_STEPS_COMPLETE")
            activation_step, database_step = document["steps"]
            tree = activation_step["observedPhysical"]
            activation_file = activation_step["observedCompanions"][0]
            database_file = database_step["observedPhysical"]
            check_desired(
                document["desired"],
                snapshot=definition["snapshotFile"],
                tree=tree,
                activation_file=activation_file,
                database_target=document["desired"]["database"],
            )
            require(
                tree["value"]["path"]
                == definition["activationTreeLogical"]["path"]
                and tree["value"]["mode"]
                == definition["activationTreeLogical"]["mode"]
                and tree["value"]["treeSha256"]
                == definition["activationTreeLogical"]["contentSha256"],
                "ACTIVATION_TREE_PHYSICAL_BINDING",
            )
            require(
                activation_file["value"]["path"]
                == definition["activationFileLogical"]["path"]
                and activation_file["value"]["mode"]
                == definition["activationFileLogical"]["mode"]
                and activation_file["value"]["sha256"]
                == definition["activationFileLogical"]["contentSha256"],
                "ACTIVATION_FILE_PHYSICAL_BINDING",
            )
            require(
                database_file["value"]["path"]
                == definition["databaseEmptyFileLogical"]["path"]
                and database_file["value"]["mode"]
                == definition["databaseEmptyFileLogical"]["mode"]
                and database_file["value"]["size"] == 0
                and database_file["value"]["sha256"] == EMPTY_SHA256,
                "DATABASE_EMPTY_FILE",
            )
            frozen_value = {
                key: copy.deepcopy(item)
                for key, item in document.items()
                if key != "journalFingerprint"
            }
            frozen_value["frozenJournalFingerprint"] = None
            require(
                document["frozenJournalFingerprint"]
                == fingerprint(
                    "codex-smart/activation-preparation-frozen-journal/v2",
                    frozen_value,
                ),
                "FROZEN_JOURNAL_FINGERPRINT",
            )
        journal_value = {
            key: copy.deepcopy(item)
            for key, item in document.items()
            if key != "journalFingerprint"
        }
        require(
            document["journalFingerprint"]
            == fingerprint(
                "codex-smart/activation-preparation-journal/v2", journal_value
            ),
            "JOURNAL_FINGERPRINT",
        )
    else:
        check_intent(document["activationIntent"])
        for name in (
            "snapshotFile",
            "activationTree",
            "activationFile",
            "databaseEmptyFile",
            "databaseBindingTarget",
        ):
            check_projection(document[name])
        empty_value = document["databaseEmptyFile"]["value"]
        target_value = document["databaseBindingTarget"]["value"]
        require(
            all(
                empty_value[name] == target_value[name]
                for name in (
                    "path",
                    "device",
                    "inode",
                    "ownerUid",
                    "ownerGid",
                    "mode",
                    "linkCount",
                )
            ),
            "DATABASE_TARGET_PHYSICAL_BINDING",
        )
        require(
            empty_value["size"] == 0 and empty_value["sha256"] == EMPTY_SHA256,
            "DATABASE_EMPTY_FILE",
        )
        intent = document["activationIntent"]
        require(
            all(
                target_value[name] == intent[intent_name]
                for name, intent_name in (
                    ("databaseId", "databaseId"),
                    ("activationBindingNonce", "activationBindingNonce"),
                    ("activationId", "activationId"),
                    ("activationFingerprint", "activationFingerprint"),
                    ("schemaFingerprint", "schemaFingerprint"),
                    ("schemaArtifactSha256", "schemaArtifactSha256"),
                )
            ),
            "DATABASE_TARGET_IDENTITY_BINDING",
        )
        check_desired(
            document["desired"],
            snapshot=document["snapshotFile"],
            tree=document["activationTree"],
            activation_file=document["activationFile"],
            database_target=document["databaseBindingTarget"],
        )
        require(
            document["frozenJournalFingerprint"]
            == baseline_journal["frozenJournalFingerprint"],
            "RECEIPT_FROZEN_JOURNAL_BINDING",
        )
        receipt_value = {
            key: copy.deepcopy(item)
            for key, item in document.items()
            if key != "receiptFingerprint"
        }
        require(
            document["receiptFingerprint"]
            == fingerprint(
                "codex-smart/activation-preparation-receipt/v2", receipt_value
            ),
            "RECEIPT_FINGERPRINT",
        )
    return errors


def pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    tokens = pointer.removeprefix("/").split("/")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in tokens]
    current = document
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, tokens[-1]


def mutate(document: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    parent, token = pointer_parent(result, case["path"])
    operation = case["operation"]
    if operation == "add" or operation == "replace":
        if isinstance(parent, list):
            parent[int(token)] = copy.deepcopy(case["value"])
        else:
            parent[token] = copy.deepcopy(case["value"])
    elif operation == "remove":
        if isinstance(parent, list):
            parent.pop(int(token))
        else:
            del parent[token]
    else:
        raise ValueError(f"unknown mutation operation: {operation}")
    if case["rehash"]:
        if case["target"] == "journal":
            refresh_journal(result)
        else:
            refresh_receipt(result)
    return result


def validate_vector_shape(vector: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(vector) != {
        "schemaVersion",
        "fixtureSeed",
        "expectedFingerprints",
        "negativeCases",
    }:
        errors.append("VECTOR_TOP_LEVEL")
    if vector.get("schemaVersion") != 2:
        errors.append("VECTOR_VERSION")
    cases = vector.get("negativeCases")
    if type(cases) is not list or not cases:
        errors.append("VECTOR_NEGATIVE_CASES")
        return errors
    names = [case.get("name") for case in cases if type(case) is dict]
    if len(names) != len(cases) or len(names) != len(set(names)):
        errors.append("VECTOR_CASE_NAMES")
    for case in cases:
        required = {
            "name",
            "target",
            "operation",
            "path",
            "value",
            "rehash",
            "expectedLayer",
        }
        if case.get("expectedLayer") == "semantic":
            required.add("expectedCode")
        if set(case) != required:
            errors.append("VECTOR_CASE_FIELDS:" + str(case.get("name")))
        if case.get("target") not in {"journal", "receipt"}:
            errors.append("VECTOR_CASE_TARGET:" + str(case.get("name")))
    return errors


def main() -> int:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in SCHEMA_DIR.glob("*.json")
    }
    metaschema_failures: list[tuple[str, str]] = []
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # pragma: no cover - диагностический путь
            metaschema_failures.append((name, str(exc)))
    print("PREPARATION_METASCHEMA_FAILURES", len(metaschema_failures))
    for name, message in metaschema_failures:
        print("PREPARATION_METASCHEMA", name, message)

    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    vector_errors = validate_vector_shape(vector)
    print("PREPARATION_VECTOR_ERRORS", len(vector_errors))
    for error in vector_errors:
        print("PREPARATION_VECTOR", error)

    resources = [
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
    ]
    registry = Registry().with_resources(resources)
    format_checker = FormatChecker()
    validators = {
        "journal": Draft202012Validator(
            schemas["activation-preparation-journal-v2.schema.json"],
            registry=registry,
            format_checker=format_checker,
        ),
        "receipt": Draft202012Validator(
            schemas["activation-preparation-receipt-v2.schema.json"],
            registry=registry,
            format_checker=format_checker,
        ),
    }
    journal, receipt = build_fixtures(vector["fixtureSeed"])
    fixtures = {"journal": journal, "receipt": receipt}
    positive_failures: list[tuple[str, str]] = []
    for name, document in fixtures.items():
        errors = list(validators[name].iter_errors(document))
        if errors:
            positive_failures.append((name, errors[0].message))
    print("PREPARATION_POSITIVE_FAILURES", len(positive_failures))
    for failure in positive_failures:
        print("PREPARATION_POSITIVE", *failure)

    semantic_baseline = {
        name: semantic_errors(
            name,
            document,
            baseline_journal=journal,
        )
        for name, document in fixtures.items()
    }
    baseline_errors = [
        f"{name}:{code}"
        for name, codes in semantic_baseline.items()
        for code in codes
    ]
    print("PREPARATION_SEMANTIC_BASELINE_ERRORS", len(baseline_errors))
    for error in baseline_errors:
        print("PREPARATION_BASELINE", error)

    actual_fingerprints = {
        "activationIntent": journal["definition"]["activationIntent"][
            "activationIntentFingerprint"
        ],
        "definition": journal["definitionFingerprint"],
        "activationTreeStep": journal["steps"][0]["stepFingerprint"],
        "databaseInodeStep": journal["steps"][1]["stepFingerprint"],
        "frozenJournal": journal["frozenJournalFingerprint"],
        "journal": journal["journalFingerprint"],
        "receipt": receipt["receiptFingerprint"],
    }
    pinned_failures = []
    for name, actual in actual_fingerprints.items():
        expected = vector["expectedFingerprints"].get(name)
        if expected != actual:
            pinned_failures.append((name, expected, actual))
    print("PREPARATION_PINNED_FINGERPRINT_FAILURES", len(pinned_failures))
    for name, expected, actual in pinned_failures:
        print("PREPARATION_PIN", name, expected, actual)

    negative_failures: list[tuple[str, str]] = []
    for case in vector["negativeCases"]:
        target = case["target"]
        mutant = mutate(fixtures[target], case)
        schema_errors = list(validators[target].iter_errors(mutant))
        semantic = semantic_errors(
            target,
            mutant,
            baseline_journal=journal,
        )
        if case["expectedLayer"] == "schema":
            if not schema_errors:
                negative_failures.append((case["name"], "schema accepted"))
        elif schema_errors:
            negative_failures.append(
                (case["name"], "unexpected schema rejection: " + schema_errors[0].message)
            )
        elif case["expectedCode"] not in semantic:
            negative_failures.append(
                (case["name"], "semantic codes: " + ",".join(semantic))
            )
    print("PREPARATION_NEGATIVE_FAILURES", len(negative_failures))
    for failure in negative_failures:
        print("PREPARATION_NEGATIVE", *failure)

    failed = any(
        (
            metaschema_failures,
            vector_errors,
            positive_failures,
            baseline_errors,
            pinned_failures,
            negative_failures,
        )
    )
    if failed:
        return 1
    print("ACTIVATION_PREPARATION_CONTRACTS_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
