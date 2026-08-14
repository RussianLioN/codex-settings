#!/usr/bin/env python3
"""Воспроизводимая проверка договора жизненного цикла версии 2."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


SCRIPT_PATH = Path(__file__)
ROOT = Path.cwd() if str(SCRIPT_PATH) == "<stdin>" else SCRIPT_PATH.resolve().parents[1]
SCHEMA_DIR = ROOT / "docs/contracts/schemas"
VECTOR_PATH = ROOT / "docs/contracts/vectors/lifecycle-v2.json"


def load_json(path: Path):
    return json.loads(path.read_text())


schemas = {path.name: load_json(path) for path in SCHEMA_DIR.glob("*.json")}
metaschema_failures = []
for schema_name, schema in schemas.items():
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        metaschema_failures.append((schema_name, str(error)))
print("METASCHEMA_FAILURES", len(metaschema_failures))
for failure in metaschema_failures:
    print("METASCHEMA", *failure)
resources = [(schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()]
registry = Registry().with_resources(resources)
format_checker = FormatChecker()
suite_schema = schemas["lifecycle-vector-suite-v2.schema.json"]
suite = load_json(VECTOR_PATH)
semantic_only = os.environ.get("TASK2_SEMANTIC_ONLY") == "1"
proof_metrics = {}


CANONICAL_SAFE_INTEGER_MAX = (1 << 53) - 1


def canonical_json_v1(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        if not -CANONICAL_SAFE_INTEGER_MAX <= value <= CANONICAL_SAFE_INTEGER_MAX:
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
        return "[" + ",".join(canonical_json_v1(item) for item in value) + "]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("canonical-json-v1 object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return "{" + ",".join(
            canonical_json_v1(key) + ":" + canonical_json_v1(value[key])
            for key in keys
        ) + "}"
    raise ValueError(f"unsupported canonical-json-v1 value: {type(value).__name__}")


def domain_fingerprint(domain, value):
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_v1(value).encode("utf-8")
    ).hexdigest()


def validator(schema):
    return Draft202012Validator(schema, registry=registry, format_checker=format_checker)


def pointer_parent(document, pointer):
    tokens = pointer.removeprefix("/").split("/") if pointer != "/" else []
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in tokens]
    current = document
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, tokens[-1]


def patched(document, mutation):
    result = copy.deepcopy(document)
    parent, token = pointer_parent(result, mutation["path"])
    operation = mutation["operation"]
    if operation == "remove":
        if isinstance(parent, list):
            parent.pop(int(token))
        else:
            del parent[token]
    elif operation == "replace":
        if isinstance(parent, list):
            parent[int(token)] = copy.deepcopy(mutation["value"])
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        if isinstance(parent, list):
            parent.insert(len(parent) if token == "-" else int(token), copy.deepcopy(mutation["value"]))
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    else:
        raise AssertionError(operation)
    return result


suite_errors = [] if semantic_only else list(validator(suite_schema).iter_errors(suite))
print("SUITE_ERRORS", len(suite_errors))
for error in suite_errors[:50]:
    print("SUITE", "/" + "/".join(map(str, error.absolute_path)), error.message)

schema_files = {
    name.removesuffix(".schema.json"): name for name in schemas
}
positive_failures = []
for case in ([] if semantic_only else suite["positiveCases"]):
    instance = suite["fixtures"][case["fixture"]]
    errors = list(validator(schemas[schema_files[case["schema"]]]).iter_errors(instance))
    if errors:
        positive_failures.append((case["name"], errors[0].message))
print("POSITIVE_FAILURES", len(positive_failures))
for failure in positive_failures:
    print("POSITIVE", *failure)

negative_failures = []
for case in ([] if semantic_only else suite["negativeCases"]):
    instance = patched(suite["fixtures"][case["fixture"]], case["mutation"])
    errors = list(validator(schemas[schema_files[case["schema"]]]).iter_errors(instance))
    diagnostic = " | ".join(error.message for error in errors)
    if not errors or case["expectedFailureContains"].lower() not in diagnostic.lower():
        negative_failures.append((case["name"], diagnostic or "ACCEPTED"))
print("NEGATIVE_FAILURES", len(negative_failures))
for failure in negative_failures:
    print("NEGATIVE", *failure)

fixture_properties = suite_schema["properties"]["fixtures"]["properties"]
semantic_schema_failures = []
for mutant in ([] if semantic_only else suite["semanticMutants"]):
    mutated = patched(suite["fixtures"][mutant["fixture"]], mutant["patch"])
    fixture_schema = {
        "$schema": suite_schema["$schema"],
        "$id": "https://codex-settings.local/schemas/lifecycle-vector-semantic-fixture-v2.schema.json",
        "$defs": suite_schema["$defs"],
        "allOf": [fixture_properties[mutant["fixture"]]],
    }
    errors = list(validator(fixture_schema).iter_errors(mutated))
    if errors:
        semantic_schema_failures.append((mutant["name"], errors[0].message))
print("SEMANTIC_SCHEMA_FAILURES", len(semantic_schema_failures))
for failure in semantic_schema_failures:
    print("SEMANTIC_SCHEMA", *failure)


def semantic_errors(override_name=None, override_value=None):
    errors = []

    def f(name):
        if name == override_name:
            return override_value
        return suite["fixtures"][name]

    def require(condition, code):
        if not condition:
            errors.append(code)

    automaton = f("automaton")
    registry_doc = f("fingerprintRegistry")

    domains = [value["domain"] for value in registry_doc.values() if isinstance(value, dict) and "domain" in value]
    require(len(domains) == len(set(domains)), "fingerprint-domains-unique")
    require(len(domains) == 37, "fingerprint-domain-count-37")
    preparation_specs = {
        "activationPreparationDefinition": "codex-smart/activation-preparation-definition/v2",
        "activationPreparationIntent": "codex-smart/activation-preparation-intent/v2",
        "preparationLogicalObject": "codex-smart/preparation-logical-object/v2",
        "activationPreparationStep": "codex-smart/activation-preparation-step/v2",
        "activationPreparationJournal": "codex-smart/activation-preparation-journal/v2",
        "activationPreparationFrozenJournal": "codex-smart/activation-preparation-frozen-journal/v2",
        "databaseBindingTarget": "codex-smart/database-binding-target/v2",
        "activationPreparationReceipt": "codex-smart/activation-preparation-receipt/v2",
    }
    for name, domain in preparation_specs.items():
        require(registry_doc.get(name, {}).get("domain") == domain, f"preparation-domain:{name}")
    database_binding_spec = registry_doc.get("databaseBinding", {})
    require(
        database_binding_spec.get("domain") == "codex-smart/database-binding/v2",
        "database-binding-domain",
    )
    require(
        database_binding_spec.get("projectionFields")
        == ["schemaId", "schemaSha256", "value"],
        "database-binding-projection-fields",
    )
    require(
        database_binding_spec.get("excludedFields") == ["valueFingerprint"],
        "database-binding-excluded-fields",
    )
    database_predicates_spec = registry_doc.get("databasePredicates", {})
    require(
        database_predicates_spec.get("domain")
        == "codex-smart/database-predicates/v2",
        "database-predicates-domain",
    )
    require(
        database_predicates_spec.get("projectionFields") == ["predicates"],
        "database-predicates-projection-fields",
    )
    require(
        database_predicates_spec.get("excludedFields")
        == ["databasePredicatesFingerprint"],
        "database-predicates-excluded-fields",
    )
    activation_gate_spec = registry_doc.get("activationGate", {})
    require(activation_gate_spec.get("domain") == "codex-smart/activation-gate/v2", "activation-gate-domain")
    require(
        activation_gate_spec.get("projectionFields")
        == ["manifestSemanticFingerprint", "activationReceiptFingerprint", "journalAbsenceProof"],
        "activation-gate-projection-fields",
    )
    require(activation_gate_spec.get("excludedFields") == ["gateFingerprint"], "activation-gate-excluded-fields")
    absence_proof_projection_spec = registry_doc.get("absenceProofProjection", {})
    require(
        absence_proof_projection_spec.get("domain") == "codex-smart/absence-proof-projection/v2",
        "absence-proof-projection-domain",
    )
    require(
        absence_proof_projection_spec.get("projectionFields") == ["schemaId", "schemaSha256", "value"],
        "absence-proof-projection-fields",
    )
    require(
        absence_proof_projection_spec.get("excludedFields") == ["valueFingerprint"],
        "absence-proof-projection-excluded-fields",
    )
    require("controllerCommandResult" in registry_doc, "controller-result-domain-present")
    result_spec = registry_doc.get("controllerCommandResult", {})
    require("payload.commandReceipt" in result_spec.get("excludedFields", []), "controller-result-excludes-receipt")
    require("responseFingerprint" in result_spec.get("excludedFields", []), "controller-result-excludes-response-hash")
    for name, spec in registry_doc.items():
        if not isinstance(spec, dict) or "projectionFields" not in spec:
            continue
        require(not set(spec["projectionFields"]) & set(spec["excludedFields"]), f"fingerprint-projection-disjoint:{name}")

    operation_schema = schemas["operation-step-v2.schema.json"]
    step_refs = operation_schema["allOf"][2]["oneOf"]
    schema_kinds = []
    for ref in step_refs:
        def_name = ref["$ref"].split("/")[-1]
        schema_kinds.append(operation_schema["$defs"][def_name]["properties"]["kind"]["const"])
    declared_kinds = suite_schema["$defs"]["fixtureStepKind"]["enum"]
    require(len(schema_kinds) == 69 and len(set(schema_kinds)) == 69, "step-schema-69-unique")
    require(set(schema_kinds) == set(declared_kinds) == set(suite["stepCoherenceRules"]), "step-kind-bidirectional-coverage")

    carrier_rules = operation_schema["allOf"][1]["oneOf"]
    atomic_kinds = set(carrier_rules[0]["properties"]["kind"]["enum"])
    frozen_executor_kinds = set(carrier_rules[1]["properties"]["kind"]["enum"])
    mutable_exclusions = set(carrier_rules[2]["properties"]["kind"]["not"]["enum"])
    self_hosting_kinds = atomic_kinds | frozen_executor_kinds
    require(mutable_exclusions == self_hosting_kinds, "step-carrier-partition-exact")

    declared_occurrences = []
    for machine_id, machine in automaton["machines"].items():
        for ordinal, kind in enumerate(machine["orderedSteps"]):
            declared_occurrences.append((f"machines/{machine_id}/orderedSteps/{ordinal}", kind))
        for branch_id, branch in machine.get("conditionalBranches", {}).items():
            for ordinal, kind in enumerate(branch["orderedSteps"]):
                declared_occurrences.append((
                    f"machines/{machine_id}/conditionalBranches/{branch_id}/orderedSteps/{ordinal}",
                    kind,
                ))
    require(len(declared_occurrences) == 215, "automaton-step-occurrences-215")
    require(all(kind in schema_kinds for _, kind in declared_occurrences), "automaton-occurrences-declared")
    crash = automaton["crashWindowRule"]
    require(set(crash["selfHostingBoundaryKinds"]) == self_hosting_kinds, "self-hosting-carriers-exact")
    mutable_occurrences = [item for item in declared_occurrences if item[1] not in self_hosting_kinds]
    self_hosting_occurrences = [item for item in declared_occurrences if item[1] in self_hosting_kinds]
    require(len(mutable_occurrences) == 167, "mutable-step-occurrences-167")
    require(len(self_hosting_occurrences) == 48, "self-hosting-step-occurrences-48")
    mutable_windows = crash["mutableJournalStepWindows"]
    require(mutable_windows == [
        "AFTER_INTENT_DURABLE_BEFORE_ACTION",
        "AFTER_ACTION_BEFORE_COMPLETED",
    ], "mutable-crash-window-set-exact")
    enumerated_windows = [
        (occurrence_path, kind, window)
        for occurrence_path, kind in mutable_occurrences
        for window in mutable_windows
    ]
    require(len(enumerated_windows) == 334, "mutable-crash-windows-334")
    require(len(set(enumerated_windows)) == len(enumerated_windows), "mutable-crash-windows-unique")
    require(all(
        sum(1 for candidate in enumerated_windows if candidate[0] == path) == 2
        for path, _ in mutable_occurrences
    ), "each-mutable-occurrence-has-two-windows")
    require(not any(
        candidate[0] == path
        for path, _ in self_hosting_occurrences
        for candidate in enumerated_windows
    ), "self-hosting-occurrences-exclude-mutable-windows")
    if override_name is None:
        proof_metrics.update({
            "declared_step_occurrences": len(declared_occurrences),
            "mutable_step_occurrences": len(mutable_occurrences),
            "self_hosting_step_occurrences": len(self_hosting_occurrences),
            "enumerated_crash_windows": len(enumerated_windows),
        })

    expected_recovery = schemas["lifecycle-automaton-v2.schema.json"]["$defs"]["recoveryMatrix"]["const"]
    actual_recovery = automaton["machines"]["recovery"]["conditionalBranches"]
    require(actual_recovery == expected_recovery, "recovery-matrix-exact")
    require(len(actual_recovery) == 30, "recovery-matrix-30-branches")
    for key in ["journal-absent-unsynced-standard-receipt-present", "journal-absent-unsynced-uninstall-receipt-present-tombstone-matched"]:
        branch = actual_recovery.get(key, {})
        require(branch.get("phasePredicate") == "JOURNAL_ABSENT_UNSYNCED", f"absence-unsynced-phase:{key}")
        require(branch.get("orderedSteps") == ["recovery_absence_verify"], f"absence-unsynced-finalizer:{key}")
    for key in ["journal-absent-standard-receipt-present", "journal-absent-uninstall-receipt-present-tombstone-matched"]:
        branch = actual_recovery.get(key, {})
        require(branch.get("phasePredicate") == "JOURNAL_ABSENT_SYNCHRONIZED", f"absence-synced-phase:{key}")
        require(branch.get("orderedSteps") == [], f"absence-synced-complete:{key}")
    require(crash.get("operationJournalCreationBoundary") == "ATOMIC_CREATE_AND_PARENT_FSYNC_YIELDS_GATE_CLOSE_COMPLETED_WITH_FROZEN_PLAN_DEFINITION", "operation-journal-creation-boundary")
    require(crash.get("cleanupJournalCreationBoundary") == "ATOMIC_CREATE_AND_PARENT_FSYNC_YIELDS_VALID_CLEANUP_PLAN_CURSOR_ZERO_BEFORE_FIRST_OBJECT_INTENT", "cleanup-journal-creation-boundary")
    require("AFTER_JOURNAL_DELETE_BEFORE_DIRECTORY_SYNC" in crash.get("fixedWindows", []), "absence-sync-crash-window")
    require(automaton["planSelectionRule"].get("durableBeforeFirstEffect") == ["planId", "machineId", "selectedBranchId", "selectionSource", "composedStepKinds", "planDefinitionFingerprint"], "plan-selection-durable-complete")

    expected_work_count_fields = {
        "nonterminalRoutes",
        "nonterminalNodes",
        "activeAttempts",
        "activeLeases",
        "openIntents",
        "inflightLaunchPermits",
        "activeRuntimeArtifacts",
        "pendingCandidatePublications",
        "activeEvidenceJobs",
        "queuedEvidenceJobs",
    }
    health_payload = f("healthResponse")["payload"]
    require(
        health_payload["state"] == "ACCEPTING"
        and health_payload["maintenanceMode"] is None
        and health_payload["operationId"] is None
        and health_payload["acceptingNewRoutes"] is True,
        "controller-health-accepting-state-coherent",
    )
    for fixture_name, projection in [
        ("healthResponse", health_payload),
        ("runtimeQuiescenceProjection", f("runtimeQuiescenceProjection")["value"]),
        ("legacyQuiescenceProjection", f("legacyQuiescenceProjection")["value"]),
    ]:
        work_counts = projection["workCounts"]
        require(
            set(work_counts) == expected_work_count_fields,
            f"work-count-fields-exact:{fixture_name}",
        )
        require(
            projection["quiescent"]
            == all(value == 0 for value in work_counts.values()),
            f"quiescent-iff-all-work-counts-zero:{fixture_name}",
        )

    expected_presence_matrix = [
        {"journalPresent": True, "receiptPresent": False, "disposition": "INSPECT_PHASE_AND_RECOVER"},
        {"journalPresent": True, "receiptPresent": True, "disposition": "VERIFY_TERMINAL_THEN_DELETE"},
        {"journalPresent": False, "receiptPresent": True, "disposition": "VERIFY_COMPLETION_ARTIFACTS"},
        {"journalPresent": False, "receiptPresent": False, "disposition": "INVALID_ABSENCE_WITHOUT_RECEIPT"},
    ]
    presence_matrix = automaton["terminalProtocol"]["presenceMatrix"]
    require(presence_matrix == expected_presence_matrix, "terminal-presence-matrix-exact")
    require(
        {(item["journalPresent"], item["receiptPresent"]) for item in presence_matrix}
        == {(True, True), (True, False), (False, True), (False, False)},
        "terminal-presence-pairs-complete",
    )
    if override_name is None:
        proof_metrics["terminal_presence_pairs"] = len(presence_matrix)

    database = f("databaseProjection")["value"]
    require(database["databaseId"] == database["databaseIdentity"]["databaseId"], "database-id-nested")
    require(database["databaseIdentity"]["activationId"] == database["activationIdentity"]["activationId"], "database-activation-id")
    require(database["databaseIdentity"]["activationFingerprint"] == database["activationIdentity"]["activationFingerprint"], "database-activation-fingerprint")
    require(database["sidecars"]["wal"]["path"] == database["path"] + "-wal", "database-wal-role")
    require(database["sidecars"]["shm"]["path"] == database["path"] + "-shm", "database-shm-role")
    activation_scenario = f("activationBindingScenario")
    scenario_database = activation_scenario["database"]["value"]
    require(database["databaseId"] == scenario_database["databaseId"], "database-cross-fixture-id")
    require(database["schemaFingerprint"] == scenario_database["schemaFingerprint"], "database-cross-fixture-schema")

    socket_step = f("shutdownSocketCleanupStep")
    shutdown = socket_step["before"]
    shutdown_step = f("controllerShutdownStep")
    require(
        shutdown == shutdown_step["expectedAfter"],
        "shutdown-cleanup-consumes-planned-constraint",
    )
    shutdown_value = shutdown["value"]
    require(
        shutdown_value["status"] == "EXPECTED_SHUTDOWN_PROOF"
        and shutdown_value["processExitProofFingerprint"] is None
        and shutdown_value["exclusiveLockProofFingerprint"] is None,
        "shutdown-cleanup-before-has-no-late-results",
    )
    socket = shutdown_value["socket"]
    action = socket_step["action"]
    for source_key, action_key in [
        ("path", "socketPath"), ("device", "socketDevice"), ("inode", "socketInode"),
        ("ownerUid", "socketOwnerUid"), ("ownerGid", "socketOwnerGid"), ("mode", "socketMode"),
    ]:
        require(socket[source_key] == action[action_key], f"shutdown-socket:{source_key}")
    for source_key, action_key in [
        ("targetPid", "targetPid"), ("targetStartMarker", "targetStartMarker"),
        ("targetProcessGroupId", "targetProcessGroupId"),
        ("lockPath", "lockPath"),
    ]:
        require(shutdown_value[source_key] == action[action_key], f"shutdown-proof:{source_key}")
    require(action["proofSourceId"] == shutdown_value["commandId"], "shutdown-command-binding")
    require(
        not {
            "proofSourceFingerprint",
            "processExitProofFingerprint",
            "exclusiveLockProofFingerprint",
        }
        & set(action),
        "shutdown-action-input-constraints-only",
    )
    absence_entry = socket_step["expectedAfter"]["value"]["entries"][0]
    require(absence_entry["path"] == action["socketPath"], "shutdown-absence-path")
    require(
        absence_entry["parentDevice"] == action["socketParentDevice"]
        and absence_entry["parentInode"] == action["socketParentInode"],
        "shutdown-absence-parent-binding",
    )

    shutdown_expected = shutdown_step["expectedAfter"]["value"]
    shutdown_actual = shutdown_step["observedAfter"]["value"]
    require(
        shutdown_expected["status"] == "EXPECTED_SHUTDOWN_PROOF"
        and shutdown_expected["processExitProofFingerprint"] is None
        and shutdown_expected["exclusiveLockProofFingerprint"] is None,
        "shutdown-expected-proof-has-no-late-results",
    )
    require(
        shutdown_actual["status"]
        == "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN"
        and shutdown_actual["processExitProofFingerprint"] is not None
        and shutdown_actual["exclusiveLockProofFingerprint"] is not None,
        "shutdown-observed-proof-is-actual",
    )
    for key in [
        "controllerAfter", "operationId", "commandId", "requestFingerprint",
        "commandReceiptFingerprint", "previousControlEpoch", "newControlEpoch",
        "targetPid", "targetStartMarker", "targetProcessGroupId", "socket",
        "lockPath",
    ]:
        require(
            shutdown_actual[key] == shutdown_expected[key],
            f"shutdown-constraint-actual:{key}",
        )
    require(
        shutdown_step["observedAfter"] == f("shutdownIntentProjection"),
        "shutdown-observed-proof-reuses-final-intent",
    )
    require(
        shutdown_step["action"]["operationId"]
        == shutdown_expected["operationId"]
        and shutdown_step["commandId"] == shutdown_expected["commandId"]
        and shutdown_step["action"]["expectedControlEpoch"]
        == shutdown_step["before"]["value"]["controlEpoch"]
        == shutdown_expected["previousControlEpoch"],
        "shutdown-action-constraint-binding",
    )

    accept_step = f("controllerAcceptStep")
    candidate_spawn_step = f("controllerCandidateSpawnStep")
    accepted_constraint = accept_step["before"]["value"]
    registered_candidate = candidate_spawn_step["observedAfter"]["value"]
    require(
        accept_step["before"] == candidate_spawn_step["expectedAfter"],
        "controller-accept-consumes-registration-constraint",
    )
    require(
        accepted_constraint["status"] == "EXPECTED_REGISTRATION"
        and registered_candidate["status"] == "REGISTERED_READY",
        "controller-accept-registration-constraint-actual",
    )
    for key in [
        "candidateId", "controllerIdentity", "controllerStartId", "operationId",
        "activationId", "activationFingerprint", "databaseId", "argvFingerprint",
        "snapshotFingerprint", "privateReadyChannelPath", "readinessTokenHash",
        "readinessWindowMs", "processGroupPolicy",
        "workingSocketPublished", "acceptingNewRoutes", "exitProofFingerprint",
    ]:
        require(
            registered_candidate[key] == accepted_constraint[key],
            f"controller-accept-registration-binding:{key}",
        )
    maintenance_expected = accept_step["expectedAfter"]["value"]
    maintenance_actual = accept_step["observedAfter"]["value"]
    require(
        maintenance_expected["state"] == "EXPECTED_MAINTENANCE"
        and all(
            maintenance_expected[key] is None
            for key in [
                "instanceId", "pid", "processStartMarker", "processGroupId", "socket"
            ]
        ),
        "controller-accept-expected-runtime-is-unbound",
    )
    require(
        maintenance_actual["state"] == "MAINTENANCE"
        and all(
            maintenance_actual[key] is not None
            for key in [
                "instanceId", "pid", "processStartMarker", "processGroupId", "socket"
            ]
        ),
        "controller-accept-observed-runtime-is-bound",
    )
    for key in [
        "controllerIdentity", "controllerStartId", "controlEpoch", "maintenanceMode",
        "operationId", "activationId", "activationFingerprint", "databaseId",
        "lockHeld", "acceptingNewRoutes", "quiescent",
    ]:
        require(
            maintenance_actual[key] == maintenance_expected[key],
            f"controller-accept-constraint-actual:{key}",
        )
    for controller_key, candidate_key in [
        ("controllerIdentity", "controllerIdentity"),
        ("controllerStartId", "controllerStartId"),
        ("pid", "pid"),
        ("processStartMarker", "processStartMarker"),
        ("processGroupId", "processGroupId"),
        ("activationId", "activationId"),
        ("activationFingerprint", "activationFingerprint"),
        ("databaseId", "databaseId"),
    ]:
        require(
            maintenance_actual[controller_key] == registered_candidate[candidate_key],
            f"controller-accept-candidate-actual:{controller_key}",
        )

    resume_step = next(
        step
        for step in f("abortTerminalJournal")["steps"]
        if step["kind"] == "maintenance_resume"
    )
    accepting_expected = resume_step["expectedAfter"]["value"]
    accepting_actual = resume_step["observedAfter"]["value"]
    require(
        accepting_expected["state"] == "EXPECTED_ACCEPTING"
        and all(
            accepting_expected[key] is None
            for key in [
                "instanceId", "pid", "processStartMarker", "processGroupId", "socket"
            ]
        ),
        "maintenance-resume-expected-runtime-is-unbound",
    )
    require(
        accepting_actual["state"] == "ACCEPTING"
        and all(
            accepting_actual[key] is not None
            for key in [
                "instanceId", "pid", "processStartMarker", "processGroupId", "socket"
            ]
        ),
        "maintenance-resume-observed-runtime-is-bound",
    )
    for key in [
        "controllerIdentity", "controllerStartId", "controlEpoch", "maintenanceMode",
        "operationId", "activationId", "activationFingerprint", "databaseId",
        "lockHeld", "acceptingNewRoutes", "quiescent",
    ]:
        require(
            accepting_actual[key] == accepting_expected[key],
            f"maintenance-resume-constraint-actual:{key}",
        )

    manifest_step = f("manifestCommitStep")
    require(
        manifest_step["action"]["sourcePath"]
        != manifest_step["action"]["targetPath"],
        "manifest-prepared-source-distinct",
    )
    require(
        manifest_step["action"]["targetPath"]
        == manifest_step["expectedAfter"]["value"]["file"]["path"],
        "manifest-prepared-target-binding",
    )

    signal_step = f("legacySigtermStep")
    process = signal_step["before"]["value"]["processes"][0]["identity"]
    for key in ["pid", "processStartMarker", "processGroupId"]:
        require(signal_step["action"][key] == process[key], f"signal-process:{key}")

    file_step = f("legacyGatewayFenceStep")
    require(file_step["action"]["targetPath"] == file_step["expectedAfter"]["value"]["path"], "file-target-path")

    for fixture_name in ["legacyBridgeSwapStep", "legacyBridgeSwapRestoreStep"]:
        step = f(fixture_name)
        before, after, action = step["before"]["value"], step["expectedAfter"]["value"], step["action"]
        require(action["leftPath"] == before["leftPath"] == after["leftPath"], f"swap-left-path:{fixture_name}")
        require(action["rightPath"] == before["rightPath"] == after["rightPath"], f"swap-right-path:{fixture_name}")
        for side in ["left", "right"]:
            title = side.capitalize()
            require(action[f"{side}BeforeRole"] == before[f"{side}Role"], f"swap-before-role:{fixture_name}:{side}")
            require(action[f"{side}BeforeTreeFingerprint"] == before[f"{side}TreeFingerprint"], f"swap-before-fp:{fixture_name}:{side}")
            require(action[f"{side}AfterRole"] == after[f"{side}Role"], f"swap-after-role:{fixture_name}:{side}")
            require(action[f"{side}AfterTreeFingerprint"] == after[f"{side}TreeFingerprint"], f"swap-after-fp:{fixture_name}:{side}")
    require(f("legacyBridgeSwapStep")["before"] == f("legacyBridgeSwapRestoreStep")["expectedAfter"], "swap-forward-restore-before")
    require(f("legacyBridgeSwapStep")["expectedAfter"] == f("legacyBridgeSwapRestoreStep")["before"], "swap-forward-restore-after")

    link_step = f("activationLinkStep")
    require(link_step["action"]["path"] == link_step["expectedAfter"]["value"]["path"], "symlink-path")
    require(link_step["action"]["target"] == link_step["expectedAfter"]["value"]["target"], "symlink-target")

    receipt_step = f("commitReceiptPublishStep")
    receipt_value = receipt_step["expectedAfter"]["value"]
    require(receipt_step["action"]["receiptKind"] == receipt_value["receiptKind"], "receipt-kind")
    require(receipt_step["action"]["path"] == receipt_value["file"]["path"], "receipt-path")
    require(receipt_step["recordCarrier"] == "FROZEN_TERMINAL_EXECUTOR", "receipt-frozen-carrier")

    freeze_step = f("terminalJournalFreezeStep")
    require(freeze_step["action"]["journalPath"] == freeze_step["before"]["value"]["path"] == freeze_step["expectedAfter"]["value"]["path"], "journal-freeze-path")
    require(freeze_step["recordCarrier"] == "JOURNAL_ATOMIC_BOUNDARY", "journal-freeze-carrier")

    external_step = f("externalProcessObserveStep")
    ext_before, ext_after, ext_action = external_step["before"]["value"], external_step["expectedAfter"]["value"], external_step["action"]
    require(external_step["commandId"] == ext_before["externalCommandId"] == ext_after["externalCommandId"], "external-command-id")
    for source_key, action_key in [("pid", "observerPid"), ("processStartMarker", "observerStartMarker")]:
        require(ext_before["observer"][source_key] == ext_action[action_key], f"external-observer:{source_key}")
    for source_key, action_key in [("pid", "targetPid"), ("processStartMarker", "targetStartMarker"), ("processGroupId", "processGroupId")]:
        require(ext_before["target"][source_key] == ext_action[action_key], f"external-target:{source_key}")
    require(ext_before["status"] == "RUNNING" and ext_before["signalSent"] is None, "external-before-running")
    require(ext_after["status"] == "EXTERNAL_PROCESS_STILL_RUNNING" and ext_after["signalSent"] == "SIGTERM", "external-after-finite-sigterm")
    require(ext_action["onDeadline"] == "SIGTERM_THEN_RECORD_STILL_RUNNING", "external-no-sigkill")

    candidate_step = f("controllerCandidateSpawnStep")
    candidate = candidate_step["expectedAfter"]["value"]
    require(candidate["status"] == "EXPECTED_REGISTRATION", "candidate-expected-registration")
    candidate_argv = candidate_step["action"]["argv"]
    require(
        len(candidate_argv) == 3
        and all(path.startswith("/") for path in candidate_argv[:2])
        and candidate_argv[2] == "--serve-candidate-v2",
        "candidate-argv-canonical-shape",
    )
    require(
        candidate_step["action"]["argvFingerprint"]
        == domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2",
            {"argv": candidate_argv},
        ),
        "candidate-argv-fingerprint",
    )
    for key in ["candidateId", "controllerIdentity", "controllerStartId", "operationId", "activationId", "activationFingerprint", "databaseId", "argvFingerprint", "snapshotFingerprint", "privateReadyChannelPath", "readinessTokenHash", "readinessWindowMs", "processGroupPolicy"]:
        require(candidate_step["action"][key] == candidate[key], f"candidate-action:{key}")
    registered_candidate = candidate_step["observedAfter"]["value"]
    require(
        registered_candidate["status"] == "REGISTERED_READY",
        "candidate-observed-registered-ready",
    )
    require(
        candidate_step["expectedAfter"] != candidate_step["observedAfter"],
        "candidate-constraint-not-copied-as-observation",
    )
    for key in [
        "candidateId", "controllerIdentity", "controllerStartId", "operationId",
        "activationId", "activationFingerprint", "databaseId", "argvFingerprint",
        "snapshotFingerprint", "privateReadyChannelPath", "readinessTokenHash",
        "readinessWindowMs", "processGroupPolicy",
    ]:
        require(
            registered_candidate[key] == candidate[key],
            f"candidate-constraint-actual:{key}",
        )
    require(
        registered_candidate["pid"] is not None
        and registered_candidate["processStartMarker"] is not None
        and registered_candidate["processGroupId"] is not None
        and registered_candidate["privateReadyChannel"] is not None
        and registered_candidate["registrationFingerprint"] is not None
        and registered_candidate["databaseLeaseProofFingerprint"] is not None
        and registered_candidate["databaseOpened"] is True,
        "candidate-observed-runtime-binding-complete",
    )

    watchdog_spawn = f("watchdogSpawnStep")
    watchdog_expected = watchdog_spawn["expectedAfter"]["value"]
    require(watchdog_expected["state"] == "EXPECTED_REGISTRATION", "watchdog-expected-registration")
    for key in ["watchdogId", "argvFingerprint", "imageFingerprint", "readinessTokenHash", "absoluteDeadlineMs", "processGroupPolicy"]:
        require(watchdog_spawn["action"][key] == watchdog_expected[key], f"watchdog-spawn:{key}")
    watchdog_arm = f("watchdogArmStep")
    armed = watchdog_arm["expectedAfter"]["value"]
    require(watchdog_arm["before"]["value"]["state"] == "REGISTERED" and armed["state"] == "ARMED", "watchdog-arm-phases")
    for key in ["watchdogId", "pid", "processStartMarker", "processGroupId", "registrationFingerprint", "targetPid", "targetStartMarker", "targetProcessGroupId"]:
        require(watchdog_arm["action"][key] == armed[key], f"watchdog-arm:{key}")
    watchdog_disarm = f("watchdogDisarmStep")
    require(watchdog_disarm["before"]["value"]["state"] == "ARMED" and watchdog_disarm["expectedAfter"]["value"]["state"] == "EXITED", "watchdog-disarm-phases")
    for key in ["targetPid", "targetStartMarker", "targetProcessGroupId"]:
        require(watchdog_disarm["action"][key] == watchdog_disarm["before"]["value"][key], f"watchdog-disarm:{key}")
    legacy_order = automaton["machines"]["legacyMigration"]["orderedSteps"]
    require(legacy_order.index("watchdog_disarm") > legacy_order.index("legacy_sigcont"), "watchdog-disarm-after-resume")

    launcher_step = f("launcherInstallStep")
    launchers = {item["name"]: item for item in launcher_step["expectedAfter"]["value"]["launchers"]}
    for operation in launcher_step["action"]["operations"]:
        launcher = launchers.get(operation["name"])
        require(launcher is not None, f"launcher-name:{operation['name']}")
        if launcher:
            require(operation["role"] == launcher["role"], f"launcher-role:{operation['name']}")
            require(operation["targetPath"] == launcher["file"]["path"], f"launcher-path:{operation['name']}")
            require(operation["expectedAfterFingerprint"] == launcher["file"]["sha256"], f"launcher-fingerprint:{operation['name']}")

    absence_step = f("recoveryAbsenceSyncStep")
    require(absence_step["before"]["value"]["directorySyncCompleted"] is False, "absence-before-unsynced")
    require(absence_step["expectedAfter"]["value"]["directorySyncCompleted"] is True, "absence-after-synced")
    require(absence_step["before"]["value"]["entries"] == absence_step["expectedAfter"]["value"]["entries"], "absence-entry-stable")
    require(absence_step["recordCarrier"] == "FROZEN_TERMINAL_EXECUTOR", "absence-frozen-carrier")

    def expected_execution_steps(plan):
        machine = automaton["machines"][plan["machineId"]]
        prefix = []
        if plan["selectedBranchId"] is not None:
            prefix = machine["conditionalBranches"][plan["selectedBranchId"]]["orderedSteps"]
        return prefix + machine["orderedSteps"]

    operation_journal_names = [
        "migrationDiscoveredJournal", "migrationExitPendingJournal", "migrationFencedJournal",
        "activationFencedJournal", "abortReversibleJournal", "abortTerminalJournal", "recoveryOverlayJournal",
    ]
    journals = {name: f(name) for name in operation_journal_names}
    for name, journal in journals.items():
        plan = journal["executionPlan"]
        require(plan["composedStepKinds"] == expected_execution_steps(plan), f"execution-plan-composition:{name}")
        require(bool(journal["steps"]), f"journal-has-gate:{name}")
        if journal["steps"]:
            first = journal["steps"][0]
            require(first["kind"] == "gate_close" and first["state"] == "COMPLETED" and first["recordCarrier"] == "JOURNAL_ATOMIC_BOUNDARY", f"journal-completed-gate:{name}")
        require(plan["firstIncompleteOrdinal"] >= 1, f"journal-cursor-after-gate:{name}")
        require([step["ordinal"] for step in journal["steps"]] == list(range(len(journal["steps"]))), f"journal-global-ordinals:{name}")
        plan_by_id = {plan["planId"]: plan}
        if journal["abortPlan"] is not None:
            plan_by_id[journal["abortPlan"]["planId"]] = journal["abortPlan"]
        plan_by_id.update({plan_item["planId"]: plan_item for plan_item in journal["recoveryPlans"]})
        for step in journal["steps"]:
            bound_plan = plan_by_id.get(step["planId"])
            require(bound_plan is not None, f"step-plan-id:{name}:{step['stepId']}")
            if bound_plan is None:
                continue
            sequence = bound_plan.get("composedStepKinds", bound_plan.get("overlayStepKinds", []))
            ordinal = step["planOrdinal"]
            require(ordinal < len(sequence), f"step-plan-ordinal-range:{name}:{step['stepId']}")
            if ordinal < len(sequence):
                require(step["kind"] == sequence[ordinal], f"step-plan-kind:{name}:{step['stepId']}")
        require(all(step["recordCarrier"] != "FROZEN_TERMINAL_EXECUTOR" for step in journal["steps"]), f"journal-no-frozen-executor:{name}")

    migration_names = ["migrationDiscoveredJournal", "migrationExitPendingJournal", "migrationFencedJournal"]
    migration_journals = [journals[name] for name in migration_names]
    plan_identity = [(journal["executionPlan"]["planId"], journal["executionPlan"]["planDefinitionFingerprint"], journal["executionPlan"]["composedStepKinds"]) for journal in migration_journals]
    require(plan_identity[0] == plan_identity[1] == plan_identity[2], "migration-same-plan-lineage")
    require(migration_journals[0]["desired"] is None and migration_journals[1]["desired"] is None, "migration-desired-null-before-fenced")
    require(migration_journals[2]["desired"] is not None and migration_journals[2]["fencedBefore"] is not None, "migration-fenced-bundles-present")
    for journal in migration_journals:
        cursor = journal["executionPlan"]["firstIncompleteOrdinal"]
        require([step["kind"] for step in journal["steps"]] == journal["executionPlan"]["composedStepKinds"][:cursor], f"migration-prefix:{journal['phase']}")
    snapshot = migration_journals[2]["steps"][-1]
    require(snapshot["action"]["discoveryBundleFingerprint"] == migration_journals[2]["discoveryBefore"]["bundleFingerprint"], "migration-discovery-fingerprint")
    require(snapshot["action"]["fencedBeforeBundleFingerprint"] == migration_journals[2]["fencedBefore"]["bundleFingerprint"], "migration-fenced-fingerprint")
    require(snapshot["action"]["desiredBundleFingerprint"] == migration_journals[2]["desired"]["bundleFingerprint"], "migration-desired-fingerprint")

    abort_reversible = journals["abortReversibleJournal"]
    abort_terminal = journals["abortTerminalJournal"]
    for journal in [abort_reversible, abort_terminal]:
        abort_plan = journal["abortPlan"]
        machine = automaton["machines"]["abort"]
        require(abort_plan["composedStepKinds"] == machine["conditionalBranches"][abort_plan["selectedBranchId"]]["orderedSteps"] + machine["orderedSteps"], f"abort-plan-composition:{journal['phase']}")
        require(abort_plan["sourceCompletedForwardStepKinds"] == journal["executionPlan"]["composedStepKinds"][:journal["executionPlan"]["firstIncompleteOrdinal"]], f"abort-forward-prefix:{journal['phase']}")
        abort_steps = [step for step in journal["steps"] if step["planId"] == abort_plan["planId"]]
        require([step["kind"] for step in abort_steps] == abort_plan["composedStepKinds"][:abort_plan["firstIncompleteOrdinal"]], f"abort-reverse-prefix:{journal['phase']}")
    prefix_length = len(abort_reversible["steps"])
    require(abort_terminal["steps"][:prefix_length] == abort_reversible["steps"], "terminal-prefix-immutable")
    require(abort_terminal["terminalDeleteIntent"]["completedStepIds"] == [step["stepId"] for step in abort_terminal["steps"] if step["state"] == "COMPLETED"], "terminal-completed-ids-exact")

    recovery_scenario = f("recoveryAppendOnlyScenario")
    recovery_before, recovery_after = recovery_scenario["beforeJournal"], recovery_scenario["afterJournal"]
    require(recovery_after["recoveryPlans"][:len(recovery_before["recoveryPlans"])] == recovery_before["recoveryPlans"], "recovery-plans-append-only")
    require(recovery_after["steps"][:len(recovery_before["steps"])] == recovery_before["steps"], "recovery-steps-append-only")
    overlay_lengths = {
        "external-still-running": 2, "controller-not-applicable": 1, "controller-live": 1,
        "controller-missing-proven": 3, "current-candidate-registered": 2,
        "previous-candidate-registered": 2, "mismatched-or-unowned": 0,
    }
    for plan in recovery_after["recoveryPlans"]:
        length = overlay_lengths[plan["selectedRecoveryBranchId"]]
        if plan["status"] == "COMPLETED":
            require(plan["overlayCursorOrdinal"] == length, f"recovery-completed-cursor:{plan['planId']}")
        elif plan["status"] == "ACTIVE":
            require(length > 0 and plan["overlayCursorOrdinal"] < length, f"recovery-active-cursor:{plan['planId']}")
        elif plan["status"] == "PLANNED":
            require(plan["overlayCursorOrdinal"] == 0, f"recovery-planned-cursor:{plan['planId']}")
        else:
            require(plan["selectedRecoveryBranchId"] == "mismatched-or-unowned" and plan["overlayCursorOrdinal"] == 0, f"recovery-ambiguous-cursor:{plan['planId']}")
        require(plan["sourcePlanDefinitionFingerprint"] == recovery_after["executionPlan"]["planDefinitionFingerprint"], f"recovery-source-plan:{plan['planId']}")
        if plan["sourceStepState"] == "DURABLE_STEP_EXISTS":
            source_steps = [step for step in recovery_after["steps"] if step["stepId"] == plan["firstIncompleteStepId"]]
            require(len(source_steps) == 1, f"recovery-source-step:{plan['planId']}")
            if source_steps:
                source_step = source_steps[0]
                require(source_step["planOrdinal"] == plan["firstIncompleteOrdinal"] and source_step["kind"] == plan["firstIncompleteKind"], f"recovery-source-position:{plan['planId']}")
                require(source_step["actionFingerprint"] == plan["firstIncompleteActionFingerprint"], f"recovery-source-action:{plan['planId']}")

    cleanup = f("cleanupBoundaryJournal")
    cleanup_receipt = f("cleanupBoundaryReceipt")
    require(len(cleanup["objects"]) == 127 and len(cleanup["steps"]) == 128, "cleanup-127-plus-freeze")
    require(cleanup["cleanupPlan"]["firstIncompleteOrdinal"] == 128, "cleanup-cursor-128")
    require(cleanup["cleanupPlan"]["objectOrderIds"] == [item["objectId"] for item in cleanup["objects"]], "cleanup-object-order")
    require([step["ordinal"] for step in cleanup["steps"]] == list(range(128)), "cleanup-global-ordinals")
    for index, (item, step) in enumerate(zip(cleanup["objects"], cleanup["steps"][:127])):
        require(step["planId"] == cleanup["cleanupPlan"]["planId"] and step["planOrdinal"] == index and step["kind"] == "cleanup_object_delete", f"cleanup-plan-binding:{index}")
        require(step["action"]["path"] == item["before"]["value"]["path"], f"cleanup-path:{index}")
        require(step["action"]["ownershipFingerprint"] == item["before"]["valueFingerprint"], f"cleanup-ownership:{index}")
        require(step["expectedAfter"] == item["expectedAbsence"], f"cleanup-absence:{index}")
    require(cleanup["steps"][-1]["kind"] == "terminal_journal_freeze" and cleanup["steps"][-1]["recordCarrier"] == "JOURNAL_ATOMIC_BOUNDARY", "cleanup-terminal-freeze")
    require(cleanup["terminalDeleteIntent"]["completedStepIds"] == [step["stepId"] for step in cleanup["steps"]], "cleanup-terminal-step-ids")
    removed = [item["before"] for item in cleanup["objects"]]
    require(cleanup_receipt["removedObjects"] == removed, "cleanup-receipt-removed-exact")
    require(cleanup["terminalDeleteIntent"]["receiptPayloadIntent"]["removedObjects"] == removed, "cleanup-intent-removed-exact")

    receipt = activation_scenario["receipt"]
    require(receipt["manifest"] == activation_scenario["manifest"], "activation-receipt-manifest")
    require(receipt["activation"] == activation_scenario["activation"], "activation-receipt-activation")
    activation_value = activation_scenario["activation"]["value"]
    database_value = activation_scenario["database"]["value"]
    database_binding = receipt["databaseBinding"]
    database_binding_value = database_binding["value"]
    controller_value = activation_scenario["controller"]["value"]
    manifest_value = activation_scenario["manifest"]["value"]
    require(manifest_value["activeActivationId"] == activation_value["activationId"], "activation-manifest-id")
    require(database_binding_value == {
        field: database_value[field]
        for field in database_binding_value
    }, "activation-database-binding-stable-projection")
    require(
        database_binding["valueFingerprint"]
        == domain_fingerprint(
            "codex-smart/database-binding/v2",
            {
                field: database_binding[field]
                for field in ["schemaId", "schemaSha256", "value"]
            },
        ),
        "activation-database-binding-fingerprint-recomputed",
    )
    require(database_binding_value["activationIdentity"]["activationId"] == activation_value["activationId"], "activation-database-id")
    require(database_binding_value["databaseIdentity"]["activationId"] == activation_value["activationId"], "activation-database-nested-id")
    require(database_binding_value["databaseId"] == activation_value["databaseId"] == controller_value["databaseId"], "activation-database-cross-id")
    require(database_binding_value["databaseIdentityFingerprint"] == activation_value["databaseIdentityFingerprint"], "activation-database-identity-fingerprint")
    require(controller_value["activationId"] == activation_value["activationId"], "activation-controller-id")
    require(controller_value["controllerIdentity"] == receipt["controllerIdentity"], "activation-controller-identity")
    manifest_document = receipt["manifestDocument"]
    manifest_raw = canonical_json_v1(manifest_document).encode("utf-8")
    manifest_file = manifest_value["file"]
    require(
        manifest_file["size"] == len(manifest_raw)
        and manifest_file["sha256"] == hashlib.sha256(manifest_raw).hexdigest(),
        "activation-manifest-document-file-binding",
    )
    require(
        manifest_value["installationId"] == manifest_document["installationId"]
        and manifest_value["activeActivationId"]
        == manifest_document["activeActivation"]["activationId"]
        and manifest_value["previousActivationId"] is None
        and manifest_document["previousActivation"] is None
        and manifest_value["lastCommittedOperation"]
        == manifest_document["lastCommittedOperation"],
        "activation-manifest-document-identity-binding",
    )
    require(
        manifest_value["sourceLocatorFingerprint"]
        == hashlib.sha256(
            canonical_json_v1(manifest_document["sourceLocator"]).encode("utf-8")
        ).hexdigest()
        and manifest_value["artifactsFingerprint"]
        == hashlib.sha256(
            canonical_json_v1(manifest_document["artifacts"]).encode("utf-8")
        ).hexdigest()
        and manifest_value["semanticFingerprint"]
        == domain_fingerprint(
            "codex-smart/manifest-semantic/v2",
            {
                key: value
                for key, value in manifest_document.items()
                if key != "extensions"
            },
        ),
        "activation-manifest-document-semantic-binding",
    )
    lineage = receipt["transitionLineage"]
    lineage_projection = {
        key: value for key, value in lineage.items() if key != "lineageFingerprint"
    }
    require(
        lineage["transitionKind"] == "initial"
        and lineage["sourceReceipt"] is None
        and lineage["activationProofFingerprint"] is None
        and lineage["shutdownCommandIds"] is None
        and lineage["stoppedController"] is None
        and lineage["lineageFingerprint"]
        == domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            lineage_projection,
        ),
        "activation-transition-lineage-recomputed",
    )
    for fixture_name, transition_kind, receipt_kind, source_suffix in (
        (
            "updateTransitionLineage",
            "update",
            "activation-preparation",
            ".preparation.json",
        ),
        (
            "rollbackTransitionLineage",
            "rollback",
            "rollback-manifest-preparation",
            ".rollback-preparation.json",
        ),
    ):
        transition = f(fixture_name)
        source = transition["sourceReceipt"]
        stopped = transition["stoppedController"]
        transition_projection = {
            key: value
            for key, value in transition.items()
            if key != "lineageFingerprint"
        }
        require(
            transition["transitionKind"] == transition_kind
            and source["receiptKind"] == receipt_kind
            and source["path"].endswith(
                f"/{stopped['operationId']}{source_suffix}"
            )
            and transition["activationProofFingerprint"] is not None
            and transition["shutdownCommandIds"] is not None
            and stopped["operationId"] in source["path"]
            and transition["lineageFingerprint"]
            == domain_fingerprint(
                "codex-smart/activation-transition-lineage/v2",
                transition_projection,
            ),
            f"activation-transition-lineage-variant:{transition_kind}",
        )
    receipt_spec = registry_doc["activationCommitReceipt"]
    receipt_projection = {
        field: receipt[field] for field in receipt_spec["projectionFields"]
    }
    require(
        receipt["receiptFingerprint"]
        == domain_fingerprint(receipt_spec["domain"], receipt_projection),
        "activation-receipt-fingerprint-recomputed",
    )
    terminal = activation_scenario["terminalDeleteIntent"]
    require(terminal["completedStepIds"] == receipt["completedStepIds"], "terminal-receipt-step-ids")
    payload = terminal["receiptPayloadIntent"]
    for key in ["manifest", "manifestDocument", "transitionLineage", "activation", "databaseBinding", "journalAbsenceTarget", "controllerIdentity", "completedStepIds", "completedAt"]:
        require(payload[key] == receipt[key], f"terminal-receipt-payload:{key}")

    gates = [f(name)["params"]["activationGate"] for name in ["admitNodeRequest", "reserveLaunchPermitRequest", "commitLaunchPermitRequest"]]
    gate_bytes = [canonical_json_v1(gate).encode("utf-8") for gate in gates]
    require(gate_bytes[0] == gate_bytes[1] == gate_bytes[2], "controller-activation-gates-byte-identical")
    for gate in gates:
        proof = gate["journalAbsenceProof"]
        require(set(proof) == {"schemaId", "schemaSha256", "value", "valueFingerprint"}, "controller-gate-full-absence-projection")
        require(proof["schemaId"] == "absence-proof-v2", "controller-gate-absence-schema")
        require(proof["value"]["directorySyncCompleted"] is True, "controller-gate-synced-absence")
        proof_projection = {
            field: proof["value"][field]
            for field in ["proofId", "installationId", "operationId", "entries", "directorySyncCompleted"]
        }
        require(
            proof["value"]["proofFingerprint"]
            == domain_fingerprint("codex-smart/absence-proof/v2", proof_projection),
            "controller-gate-proof-fingerprint-recomputed",
        )
        envelope_projection = {
            field: proof[field]
            for field in ["schemaId", "schemaSha256", "value"]
        }
        require(
            proof["valueFingerprint"]
            == domain_fingerprint("codex-smart/absence-proof-projection/v2", envelope_projection),
            "controller-gate-value-fingerprint-recomputed",
        )
        target = receipt["journalAbsenceTarget"]
        require(
            proof["value"]["proofId"] == target["value"]["proofId"]
            and proof["value"]["installationId"]
            == target["value"]["installationId"]
            and proof["value"]["operationId"] == target["value"]["operationId"]
            and proof["value"]["entries"] == target["value"]["entries"],
            "controller-gate-reobserves-receipt-absence-target",
        )
        projection = {
            field: gate[field]
            for field in ["manifestSemanticFingerprint", "activationReceiptFingerprint", "journalAbsenceProof"]
        }
        require(
            gate["gateFingerprint"]
            == domain_fingerprint("codex-smart/activation-gate/v2", projection),
            "controller-gate-fingerprint-recomputed",
        )

    shutdown_request = f("shutdownRequest")
    shutdown_response = f("shutdownResponse")
    shutdown_payload = shutdown_response["payload"]
    shutdown_receipt = shutdown_payload["commandReceipt"]
    shutdown_projection = f("shutdownIntentProjection")
    final_shutdown = shutdown_projection["value"]
    socket_intent = shutdown_payload["socketIntent"]
    committed_shutdown = copy.deepcopy(
        f("controllerShutdownStep")["expectedAfter"]
    )
    committed_shutdown["value"]["status"] = "SHUTDOWN_COMMITTED"
    committed_errors = list(
        validator(schemas["lifecycle-projection-v2.schema.json"]).iter_errors(
            committed_shutdown
        )
    )
    require(not committed_errors, "shutdown-intermediate-projection-valid")
    require(
        set(shutdown_payload) == {"status", "previousControlEpoch", "newControlEpoch", "socketIntent", "commandReceipt"},
        "shutdown-transaction-has-no-late-proofs",
    )
    require(shutdown_payload["status"] == "SHUTDOWN_COMMITTED", "shutdown-transaction-committed")
    require(final_shutdown["status"] == "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN", "shutdown-final-intent-late-proof-status")
    require(final_shutdown["operationId"] == shutdown_request["operationId"], "shutdown-final-operation")
    require(final_shutdown["commandId"] == shutdown_receipt["commandId"] == shutdown_response["commandId"], "shutdown-final-command-receipt")
    require(final_shutdown["requestFingerprint"] == shutdown_receipt["requestFingerprint"] == shutdown_response["requestFingerprint"], "shutdown-final-request-receipt")
    require(final_shutdown["commandReceiptFingerprint"] == shutdown_receipt["resultFingerprint"], "shutdown-final-receipt-result-fingerprint")
    require(final_shutdown["previousControlEpoch"] == shutdown_payload["previousControlEpoch"] == shutdown_request["expectedControlEpoch"], "shutdown-final-previous-epoch")
    require(final_shutdown["newControlEpoch"] == shutdown_payload["newControlEpoch"] == shutdown_receipt["controlEpoch"] == shutdown_response["controlEpoch"], "shutdown-final-new-epoch")
    for final_key, socket_key in [
        ("targetPid", "controllerPid"),
        ("targetStartMarker", "controllerStartMarker"),
        ("targetProcessGroupId", "controllerProcessGroupId"),
        ("lockPath", "lockPath"),
    ]:
        require(final_shutdown[final_key] == socket_intent[socket_key], f"shutdown-final-socket-intent:{final_key}")
    for key in ["path", "device", "inode", "ownerUid", "ownerGid", "mode"]:
        require(final_shutdown["socket"][key] == socket_intent[key], f"shutdown-final-socket:{key}")
    controller_after = final_shutdown["controllerAfter"]
    require(controller_after["controllerIdentity"] == shutdown_request["controllerIdentity"], "shutdown-controller-request-identity")
    require(controller_after["instanceId"] == shutdown_request["instanceId"], "shutdown-controller-request-instance")
    require(controller_after["controllerStartId"] == shutdown_request["controllerStartId"], "shutdown-controller-request-start-id")
    require(controller_after["state"] == "STOPPED" and controller_after["controlEpoch"] == final_shutdown["newControlEpoch"], "shutdown-controller-stopped-epoch")
    require(controller_after["pid"] == final_shutdown["targetPid"], "shutdown-controller-audit-pid")
    require(controller_after["processStartMarker"] == final_shutdown["targetStartMarker"], "shutdown-controller-audit-marker")
    require(controller_after["processGroupId"] == final_shutdown["targetProcessGroupId"], "shutdown-controller-audit-group")
    require("processExitProofFingerprint" not in shutdown_payload and "exclusiveLockProofFingerprint" not in shutdown_payload, "shutdown-late-proofs-external")
    require(final_shutdown["processExitProofFingerprint"] != final_shutdown["exclusiveLockProofFingerprint"], "shutdown-late-proofs-distinct")

    exchanges = f("controllerMutationExchanges")
    expected_methods = {"maintenance_begin", "maintenance_strengthen", "shutdown", "controller_accept", "controller_recover", "maintenance_resume"}
    require({item["method"] for item in exchanges} == expected_methods and len(exchanges) == 6, "controller-six-mutating-methods")
    for exchange in exchanges:
        request, response = exchange["request"], exchange["response"]
        payload, command_receipt = response["payload"], response["payload"]["commandReceipt"]
        require(exchange["method"] == request["method"] == response["method"], f"controller-method:{exchange['method']}")
        require(request["expectedControlEpoch"] == payload["previousControlEpoch"], f"controller-previous-epoch:{exchange['method']}")
        require(payload["newControlEpoch"] == payload["previousControlEpoch"] + 1, f"controller-increment:{exchange['method']}")
        require(response["controlEpoch"] == payload["newControlEpoch"] == command_receipt["controlEpoch"], f"controller-new-epoch:{exchange['method']}")
        require(response["commandId"] == request["commandId"] == command_receipt["commandId"], f"controller-command:{exchange['method']}")
        require(response["requestFingerprint"] == request["requestFingerprint"] == command_receipt["requestFingerprint"], f"controller-request-fingerprint:{exchange['method']}")
    replay = f("controllerReplayExchange")
    source = next(item for item in exchanges if item["method"] == replay["request"]["method"])
    require(replay["request"] == source["request"], "controller-replay-request-exact")
    require(replay["response"]["controlEpoch"] == source["response"]["controlEpoch"], "controller-replay-no-increment")
    require(replay["response"]["payload"]["commandReceipt"] == source["response"]["payload"]["commandReceipt"], "controller-replay-receipt-exact")
    require(replay["response"]["payload"]["originalControlEpoch"] == source["response"]["controlEpoch"], "controller-replay-original-epoch")
    require(replay["response"]["payload"]["originalPayload"] == source["response"]["payload"], "controller-replay-original-payload")
    require(replay["response"]["payload"]["originalResponseFingerprint"] == source["response"]["responseFingerprint"], "controller-replay-original-response")

    uninstall_steps = automaton["machines"]["uninstall"]["orderedSteps"]
    require(
        not {
            "uninstall_database_remove",
            "uninstall_fallback_remove",
            "uninstall_admin_remove",
        }
        & set(uninstall_steps),
        "uninstall-retains-data-and-recovery-bootstrap",
    )
    require(
        uninstall_steps[-4:]
        == [
            "terminal_journal_freeze",
            "uninstall_receipt_publish",
            "uninstall_tombstone_publish",
            "uninstall_journal_close",
        ],
        "uninstall-terminal-publication-order",
    )

    return errors


baseline_semantic_errors = semantic_errors()
print("SEMANTIC_BASELINE_ERRORS", len(baseline_semantic_errors))
print("DECLARED_STEP_OCCURRENCES", proof_metrics.get("declared_step_occurrences", 0))
print("MUTABLE_STEP_OCCURRENCES", proof_metrics.get("mutable_step_occurrences", 0))
print("SELF_HOSTING_STEP_OCCURRENCES", proof_metrics.get("self_hosting_step_occurrences", 0))
print("ENUMERATED_CRASH_WINDOWS", proof_metrics.get("enumerated_crash_windows", 0))
print("TERMINAL_PRESENCE_PAIRS", proof_metrics.get("terminal_presence_pairs", 0))
for error in baseline_semantic_errors:
    print("SEMANTIC_BASELINE", error)

semantic_mutant_failures = []
for mutant in suite["semanticMutants"]:
    mutated = patched(suite["fixtures"][mutant["fixture"]], mutant["patch"])
    mutant_errors = semantic_errors(mutant["fixture"], mutated)
    if not mutant_errors:
        semantic_mutant_failures.append(mutant["name"])
print("SEMANTIC_MUTANT_FAILURES", len(semantic_mutant_failures))
for failure in semantic_mutant_failures:
    print("SEMANTIC_MUTANT_ACCEPTED", failure)

raise SystemExit(bool(
    metaschema_failures
    or suite_errors
    or positive_failures
    or negative_failures
    or semantic_schema_failures
    or baseline_semantic_errors
    or semantic_mutant_failures
))
