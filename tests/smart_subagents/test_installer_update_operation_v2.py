from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UPDATE_MATCHED_ACTIVE_STEPS_V2,
    ActivationCommitReceiptStoreV2,
    PreparationReceiptGateV2,
    PreparationReceiptObservationV2,
    UpdateControllerProofProvidersV2,
    UpdateMatchedActiveOperationV2,
    UpdateOperationV2Error,
    UpdateStepPortV2,
    UpdateStepPortsV2,
    build_activation_link_step_port_v2,
    build_manifest_commit_step_port_v2,
    build_rehydrating_controller_proof_providers_v2,
    build_upgrade_database_step_port_v2,
    build_upgrade_preparation_gate_v2,
)
from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    ActivationPreparationExecutorV2,
)
from codex_smart_subagents.installer_upgrade_v2 import (  # noqa: E402
    build_upgrade_database_binding_v2,
    build_upgrade_preparation_v2,
    prepare_upgrade_database_v2,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    MainJournalRecoveryV2,
    execute_recovery_v2,
    inspect_recovery_v2,
    plan_recovery_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    ExecutionPlanV2,
    FailurePointV2,
    InjectedCrashV2,
    JournalIntegrityErrorV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    TerminalDefinitionV2,
    StoppedControllerLineageV2,
    TransitionSourceReceiptV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)

INSTALLATION_ID = "ins2_" + "1" * 32
OPERATION_ID = "op2_" + "2" * 32
PLAN_ID = "pl2_" + "3" * 32
SCHEMA_SHA = "4" * 64


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(microseconds=1)
        return result


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}_{self.value:032x}"


class _MonotonicNanoseconds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


def _projection(schema_id: str, token: str) -> ProjectionV2:
    value = {"token": token}
    return _projection_value(schema_id, value)


def _projection_value(schema_id: str, value: dict[str, object]) -> ProjectionV2:
    domain = {
        "manifest-v2": "codex-smart/journal-state/v2",
        "activation-v2": "codex-smart/journal-state/v2",
        "database-binding-v2": "codex-smart/database-binding/v2",
    }.get(schema_id, f"codex-smart/test-{schema_id}")
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": SCHEMA_SHA,
        "value": value,
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=SCHEMA_SHA,
        value=value,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _absence(path: Path, *, token: int) -> ProjectionV2:
    parent = path.parent.stat()
    entry = {
        "path": str(path),
        "basename": path.name,
        "parentDevice": parent.st_dev,
        "parentInode": parent.st_ino,
        "absent": True,
    }
    value_without_fingerprint = {
        "proofId": f"ap2_{token:032x}",
        "installationId": INSTALLATION_ID,
        "operationId": OPERATION_ID,
        "entries": [entry],
        "directorySyncCompleted": True,
    }
    value = {
        **value_without_fingerprint,
        "proofFingerprint": domain_fingerprint(
            "codex-smart/absence-proof/v2", value_without_fingerprint
        ),
    }
    envelope = {
        "schemaId": "absence-proof-v2",
        "schemaSha256": SCHEMA_SHA,
        "value": value,
    }
    return ProjectionV2(
        schema_id="absence-proof-v2",
        schema_sha256=SCHEMA_SHA,
        value=value,
        value_fingerprint=domain_fingerprint(
            "codex-smart/absence-proof-projection/v2", envelope
        ),
    )


def _manifest_document(root: Path) -> dict[str, object]:
    interface_evidence = json.loads(
        (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
            encoding="utf-8"
        )
    )["base"]
    return {
        "schemaVersion": 2,
        "installationId": INSTALLATION_ID,
        "release": "0.2.0",
        "pluginId": "codex-smart-subagents",
        "marketplaceName": "codex-settings-adaptive",
        "stateHome": str(root / "state"),
        "sourceLocator": {
            "lexicalPath": str(root / "codex"),
            "resolvedPathAtCapture": str(root / "codex"),
            "argv0Policy": "lexical",
            "sourceObservedSha256": "6" * 64,
        },
        "codexSnapshot": {
            "absolutePath": str(root / "snapshot"),
            "sha256": "7" * 64,
        },
        "activeActivation": {
            "activationId": "act2_" + "8" * 64,
            "activationFingerprint": "8" * 64,
            "symlinkTarget": "activations/new/marketplace",
            "generationId": "gen2_" + "9" * 64,
            "databaseId": "db2_" + "a" * 32,
        },
        "previousActivation": {
            "activationId": "act2_" + "b" * 64,
            "activationFingerprint": "b" * 64,
            "symlinkTarget": "activations/old/marketplace",
            "generationId": "gen2_" + "c" * 64,
            "databaseId": "db2_" + "d" * 32,
        },
        "interfaceEvidence": interface_evidence,
        "routingPolicyFingerprint": "e" * 64,
        "bundledCatalogFingerprint": "f" * 64,
        "artifacts": [],
        "originalBackup": {
            "type": "absent",
            "path": str(root / "original-codex"),
            "parentPath": str(root),
            "name": "original-codex",
        },
        "lastCommittedOperation": OPERATION_ID,
        "databaseSchemaVersion": 2,
        "extensions": {},
    }


def _manifest_projection(
    root: Path, document: dict[str, object]
) -> ProjectionV2:
    raw = canonical_json_bytes(document)
    active = document["activeActivation"]
    previous = document["previousActivation"]
    assert isinstance(active, dict)
    assert isinstance(previous, dict)
    value = {
        "file": {
            "path": str(root / "manifest.json"),
            "device": 1,
            "inode": 2,
            "ownerUid": os.getuid(),
            "ownerGid": os.getgid(),
            "mode": "0600",
            "linkCount": 1,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "schemaVersion": document["schemaVersion"],
        "installationId": document["installationId"],
        "release": document["release"],
        "pluginId": document["pluginId"],
        "stateHome": document["stateHome"],
        "activeActivationId": active["activationId"],
        "previousActivationId": previous["activationId"],
        "lastCommittedOperation": document["lastCommittedOperation"],
        "sourceLocatorFingerprint": hashlib.sha256(
            canonical_json_bytes(document["sourceLocator"])
        ).hexdigest(),
        "artifactsFingerprint": hashlib.sha256(
            canonical_json_bytes(document["artifacts"])
        ).hexdigest(),
        "semanticFingerprint": domain_fingerprint(
            "codex-smart/manifest-semantic/v2",
            {key: value for key, value in document.items() if key != "extensions"},
        ),
    }
    return _projection_value("manifest-v2", value)


def _empty_bundle() -> StateBundleV2:
    return StateBundleV2(
        file_objects=(),
        tree_objects=(),
        symlinks=(),
        manifest=None,
        activation=None,
        database=None,
        controller=None,
        controller_candidates=(),
        watchdogs=(),
        registry=None,
        launchers=None,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(),
        absence_proofs=(),
    )


def _assert_definition_passes_normative_journal_schema(
    *,
    root: Path,
    definition: StepDefinitionV2,
    token: int,
) -> None:
    journal_path = root / f"contract-{token}.operation.json"
    plan = ExecutionPlanV2(
        plan_id=f"pl2_{token:032x}",
        machine_id="apply",
        selected_branch_id="update-matched-active",
        composed_step_kinds=("gate_close", definition.kind),
    )
    gate = StepDefinitionV2(
        kind="gate_close",
        command_id=None,
        action={
            "actionKind": "journal-transition",
            "transition": "gate-close",
            "journalPath": str(journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=_absence(journal_path, token=token),
        expected_after=_projection_value(
            "journal-state-v2",
            {
                "path": str(journal_path),
                "journalKind": "operation",
                "ownerId": OPERATION_ID,
                "phase": "DISCOVERED",
                "recoveryPolicy": "REVERSIBLE",
                "executionPlanDefinitionFingerprint": (
                    plan.plan_definition_fingerprint
                ),
                "contentGeneration": 1,
                "frozen": False,
            },
        ),
    )
    operation = OperationDefinitionV2(
        kind="activation",
        installation_id=INSTALLATION_ID,
        operation_id=OPERATION_ID,
        operation="apply",
        execution_plan=plan,
        discovery_before=_empty_bundle(),
        fenced_before=_empty_bundle(),
        desired=_empty_bundle(),
        gate_close=gate,
        mutable_steps=(definition,),
    )
    state = [definition.before]
    executor = OperationExecutorV2(
        store=OperationJournalStoreV2(
            journal_path=journal_path,
            lock_path=root / f"contract-{token}.operation.lock",
            validate_document=build_operation_journal_validator_v2(
                ROOT / "docs" / "contracts" / "schemas"
            ),
        ),
        now=_Clock(),
        id_factory=_Ids(),
    )

    executor.execute(
        operation,
        callbacks=StepCallbacksV2(
            observe=lambda _definition: state[0],
            apply=lambda _definition: state.__setitem__(0, definition.expected_after),
        ),
    )


class InstallerUpdateOperationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="cs-update-operation-v2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.journal_path = self.root / "operation.json"
        self.lock_path = self.root / "operation.lock"
        self.receipt_root = self.root / "receipts" / INSTALLATION_ID
        self.receipt_root.mkdir(parents=True, mode=0o700)
        (self.root / "receipts").chmod(0o700)
        self.receipt_path = self.receipt_root / f"{OPERATION_ID}.commit.json"
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        self.registry = LifecyclePlanRegistryV2.from_document(automaton)
        self.plan = self.registry.select(
            machine_id="apply",
            branch_id="update-matched-active",
            plan_id=PLAN_ID,
        )
        self.activation_tree = _projection("tree-object-v2", "prepared")
        self.database_empty = _projection("file-object-v2", "database-empty")
        self.database_prepared = _projection("database-binding-v2", "database-prepared")
        self.manifest_before = _projection("manifest-v2", "manifest-before")
        self.manifest_document = _manifest_document(self.root)
        self.manifest_after = _manifest_projection(
            self.root, self.manifest_document
        )
        self.definition = self._definition()
        self.store = OperationJournalStoreV2(
            journal_path=self.journal_path,
            lock_path=self.lock_path,
            validate_document=lambda _document: None,
        )
        self.executor = OperationExecutorV2(
            store=self.store,
            now=_Clock(),
            id_factory=_Ids(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _definition(self) -> OperationDefinitionV2:
        kinds = UPDATE_MATCHED_ACTIVE_STEPS_V2
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={"kind": "gate"},
            before=_absence(self.journal_path, token=1),
            expected_after=_projection("journal-state-v2", "gate-closed"),
        )
        steps: list[StepDefinitionV2] = []
        previous = self.activation_tree
        for ordinal, kind in enumerate(kinds[1:17], start=1):
            if kind == "recovery_forward_only":
                before = _projection("journal-state-v2", "reversible")
                after = _projection("journal-state-v2", "forward-only")
            elif kind == "database_prepare":
                before = self.database_empty
                after = self.database_prepared
            elif kind == "manifest_commit":
                before = self.manifest_before
                after = self.manifest_after
            else:
                before = previous
                after = _projection(f"{kind}-v2", f"after-{ordinal}")
            steps.append(
                StepDefinitionV2(
                    kind=kind,
                    command_id=None,
                    action={"kind": kind},
                    before=before,
                    expected_after=after,
                )
            )
            previous = after

        absence_target = _absence(self.journal_path, token=3)
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action={"kind": "freeze"},
            before=_projection("journal-state-v2", "committing"),
            expected_after=_projection("journal-state-v2", "frozen"),
        )
        terminal = TerminalDefinitionV2(
            terminal_kind="COMMIT",
            receipt_kind="activation-commit",
            receipt_path=self.receipt_path,
            freeze=freeze,
            journal_absence_target=absence_target,
            receipt_payload=ActivationCommitPayloadIntentV2(
                manifest=self.manifest_after,
                manifest_document=self.manifest_document,
                transition_lineage=ActivationTransitionLineageV2(
                    transition_kind="update",
                    source_receipt=TransitionSourceReceiptV2(
                        receipt_kind="activation-preparation",
                        path=(
                            self.receipt_path.parent
                            / f"{OPERATION_ID}.preparation.json"
                        ),
                        raw_sha256="6" * 64,
                        receipt_fingerprint="7" * 64,
                    ),
                    activation_proof_fingerprint="8" * 64,
                    shutdown_command_ids=ControllerShutdownLineageV2(
                        maintenance_begin="cc2_" + "9" * 32,
                        maintenance_strengthen="cc2_" + "a" * 32,
                        shutdown="cc2_" + "b" * 32,
                    ),
                    stopped_controller=StoppedControllerLineageV2(
                        operation_id=OPERATION_ID,
                        activation_id="act2_" + "b" * 64,
                        database_id="db2_" + "d" * 32,
                        controller_identity="c" * 64,
                        control_epoch=4,
                    ),
                ),
                activation=_projection("activation-v2", "activation"),
                database_binding=self.database_prepared,
                journal_absence_target=absence_target,
                controller_identity="5" * 64,
            ),
        )
        return OperationDefinitionV2(
            kind="activation",
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            operation="apply",
            execution_plan=self.plan,
            discovery_before=_empty_bundle(),
            fenced_before=_empty_bundle(),
            desired=_empty_bundle(),
            gate_close=gate,
            mutable_steps=tuple(steps),
            terminal=terminal,
        )

    def _gate(self, calls: list[tuple[str, bool]]) -> PreparationReceiptGateV2:
        observation = PreparationReceiptObservationV2(
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            receipt_fingerprint="6" * 64,
            activation_tree=self.activation_tree,
            database_empty_file=self.database_empty,
            manifest_expected_after=self.manifest_after,
        )

        def verify_before_journal() -> PreparationReceiptObservationV2:
            calls.append(("before_journal", self.journal_path.exists()))
            return observation

        def verify_resume(_journal) -> PreparationReceiptObservationV2:
            calls.append(("resume", self.journal_path.exists()))
            return observation

        return PreparationReceiptGateV2(
            expected=observation,
            verify_before_journal=verify_before_journal,
            verify_resume=verify_resume,
        )

    def _ports(
        self,
        effects: list[str],
        *,
        states: dict[str, list[ProjectionV2]] | None = None,
    ) -> UpdateStepPortsV2:
        states = states if states is not None else {}
        ports = {}
        for step in self.definition.mutable_steps:
            if step.kind == "recovery_forward_only":
                continue
            state = states.setdefault(step.kind, [step.before])

            def observe(_definition, *, state=state):
                return state[0]

            def apply(definition, *, state=state):
                effects.append(definition.kind)
                state[0] = definition.expected_after

            ports[step.kind] = UpdateStepPortV2(observe=observe, apply=apply)
        return UpdateStepPortsV2(ports)

    def test_executes_exact_20_step_update_and_publishes_terminal_receipt(
        self,
    ) -> None:
        preparation_calls: list[tuple[str, bool]] = []
        effects: list[str] = []
        receipt_store = ActivationCommitReceiptStoreV2(definition=self.definition)
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate(preparation_calls),
            ports=self._ports(effects),
            receipt_store=receipt_store,
        )

        result = operation.execute()

        self.assertEqual("COMPLETED", result.status)
        self.assertFalse(self.journal_path.exists())
        self.assertTrue(self.receipt_path.is_file())
        self.assertEqual(
            [("before_journal", False)],
            preparation_calls,
        )
        expected_effects = [
            kind
            for kind in UPDATE_MATCHED_ACTIVE_STEPS_V2[1:17]
            if kind != "recovery_forward_only"
        ]
        self.assertEqual(expected_effects, effects)
        self.assertLess(
            effects.index("database_prepare"), effects.index("activation_link")
        )
        self.assertEqual(0o600, self.receipt_path.stat().st_mode & 0o777)

        repeated = operation.execute()

        self.assertEqual("ALREADY_COMPLETED", repeated.status)
        self.assertEqual(expected_effects, effects)
        self.assertFalse(self.journal_path.exists())
        self.assertEqual([("before_journal", False)], preparation_calls)
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(18, len(receipt["completedStepIds"]))

    def test_completed_receipt_probe_cannot_return_after_operation_deadline(
        self,
    ) -> None:
        receipt_store = ActivationCommitReceiptStoreV2(
            definition=self.definition
        )
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate([]),
            ports=self._ports([]),
            receipt_store=receipt_store,
        )
        monotonic = _MonotonicNanoseconds()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=monotonic,
        )

        def slow_completed_probe() -> bool:
            monotonic.value = 1_000_000_000
            return True

        with (
            scoped_current_deadline_v2(deadline),
            mock.patch.object(
                receipt_store,
                "completed_matches_definition",
                side_effect=slow_completed_probe,
            ),
        ):
            with self.assertRaises(OperationDeadlineExceededV2):
                operation.execute()

    def test_rejects_non_registry_definition_before_creating_gate(self) -> None:
        wrong_plan = ExecutionPlanV2(
            plan_id=PLAN_ID,
            machine_id="apply",
            selected_branch_id="update-matched-active",
            composed_step_kinds=(
                "gate_close",
                *UPDATE_MATCHED_ACTIVE_STEPS_V2[2:],
            ),
        )
        changed = object.__new__(OperationDefinitionV2)
        for name, value in vars(self.definition).items():
            object.__setattr__(changed, name, value)
        object.__setattr__(changed, "execution_plan", wrong_plan)

        with self.assertRaises(UpdateOperationV2Error) as caught:
            UpdateMatchedActiveOperationV2(
                registry=self.registry,
                executor=self.executor,
                definition=changed,
                preparation=self._gate([]),
                ports=self._ports([]),
                receipt_store=ActivationCommitReceiptStoreV2(
                    definition=self.definition
                ),
            )

        self.assertEqual("UPDATE_PLAN_INVALID", caught.exception.code)
        self.assertFalse(self.journal_path.exists())

    def test_preparation_mismatch_stops_before_gate_close(self) -> None:
        expected = PreparationReceiptObservationV2(
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            receipt_fingerprint="6" * 64,
            activation_tree=self.activation_tree,
            database_empty_file=self.database_empty,
            manifest_expected_after=self.manifest_after,
        )
        changed = PreparationReceiptObservationV2(
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            receipt_fingerprint="7" * 64,
            activation_tree=self.activation_tree,
            database_empty_file=self.database_empty,
            manifest_expected_after=self.manifest_after,
        )
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=PreparationReceiptGateV2(
                expected=expected,
                verify_before_journal=lambda: changed,
                verify_resume=lambda _journal: changed,
            ),
            ports=self._ports([]),
            receipt_store=ActivationCommitReceiptStoreV2(definition=self.definition),
        )

        with self.assertRaises(UpdateOperationV2Error) as caught:
            operation.execute()

        self.assertEqual("PREPARATION_RECEIPT_CHANGED", caught.exception.code)
        self.assertFalse(self.journal_path.exists())

    def test_resume_uses_resume_gate_without_reexecuting_preparation(self) -> None:
        preparation_calls: list[tuple[str, bool]] = []
        effects: list[str] = []
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate(preparation_calls),
            ports=self._ports(effects),
            receipt_store=ActivationCommitReceiptStoreV2(definition=self.definition),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "database_prepare"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash)

        interrupted = self.store.read()
        database_step = next(
            step for step in interrupted["steps"] if step["kind"] == "database_prepare"
        )
        self.assertEqual("INTENT_DURABLE", database_step["state"])
        self.assertEqual(1, effects.count("database_prepare"))

        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertFalse(self.journal_path.exists())
        self.assertEqual(
            [("before_journal", False), ("resume", True)],
            preparation_calls,
        )
        self.assertEqual(1, effects.count("database_prepare"))

    def test_resume_rechecks_every_completed_external_effect(self) -> None:
        effects: list[str] = []
        states: dict[str, list[ProjectionV2]] = {}
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate([]),
            ports=self._ports(effects, states=states),
            receipt_store=ActivationCommitReceiptStoreV2(definition=self.definition),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "activation_link"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash)

        states["database_prepare"][0] = _projection(
            "database-binding-v2", "substituted-after-crash"
        )
        effects_before_resume = list(effects)

        with self.assertRaises(UpdateOperationV2Error) as caught:
            operation.execute()

        self.assertEqual("UPDATE_RESUME_EFFECT_CHANGED", caught.exception.code)
        self.assertEqual(effects_before_resume, effects)

    def test_main_recovery_rechecks_terminal_frozen_effects_before_receipt(
        self,
    ) -> None:
        effects: list[str] = []
        states: dict[str, list[ProjectionV2]] = {}
        ports = self._ports(effects, states=states)
        receipt_store = ActivationCommitReceiptStoreV2(definition=self.definition)
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate([]),
            ports=ports,
            receipt_store=receipt_store,
        )

        def crash(point: FailurePointV2, _kind: str) -> None:
            if point is FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT:
                raise InjectedCrashV2(point, "terminal_journal_freeze")

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash)

        self.assertEqual("TERMINAL_FROZEN", self.store.read()["phase"])
        states["database_prepare"][0] = _projection(
            "database-binding-v2", "drift-after-terminal-freeze"
        )
        lock_events: list[str] = []

        @contextmanager
        def installation_lock():
            lock_events.append("entered")
            try:
                yield
            finally:
                lock_events.append("exited")

        inspection = inspect_recovery_v2(
            journal_root=self.root,
            preparation_journal_path=self.root / "preparation.json",
            operation_journal_path=self.journal_path,
        )
        recovery = plan_recovery_v2(
            inspection=inspection,
            main=MainJournalRecoveryV2(
                executor=self.executor,
                definition=self.definition,
                callbacks=StepCallbacksV2(
                    observe=lambda definition: ports.require(definition.kind).observe(
                        definition
                    ),
                    apply=lambda definition: ports.require(definition.kind).apply(
                        definition
                    ),
                ),
                terminal_callbacks=receipt_store.callbacks(),
                installation_lock=installation_lock,
                execute_operation=operation.execute,
            ),
        )

        with self.assertRaises(UpdateOperationV2Error) as caught:
            execute_recovery_v2(plan=recovery, preview=False)

        self.assertEqual("UPDATE_RESUME_EFFECT_CHANGED", caught.exception.code)
        self.assertEqual(["entered", "exited"], lock_events)
        self.assertTrue(self.journal_path.is_file())
        self.assertFalse(self.receipt_path.exists())

    def test_resume_does_not_observe_future_planned_step_before_predecessor(
        self,
    ) -> None:
        accepting = _projection("controller-state-v2", "accepting")
        draining = _projection("controller-state-v2", "draining")
        quiescent = _projection("quiescence-proof-v2", "quiescent")
        rewritten: list[StepDefinitionV2] = []
        for step in self.definition.mutable_steps:
            if step.kind == "maintenance_begin":
                step = replace(step, before=accepting, expected_after=draining)
            elif step.kind == "wait_runtime_quiescent":
                step = replace(step, before=draining, expected_after=quiescent)
            rewritten.append(step)
        definition = replace(self.definition, mutable_steps=tuple(rewritten))
        shared_controller = [accepting]
        effects: list[str] = []
        ports: dict[str, UpdateStepPortV2] = {}
        for step in definition.mutable_steps:
            if step.kind == "recovery_forward_only":
                continue
            if step.kind in {"maintenance_begin", "wait_runtime_quiescent"}:

                def observe(_definition, *, state=shared_controller):
                    return state[0]

                def apply(received, *, state=shared_controller):
                    effects.append(received.kind)
                    state[0] = received.expected_after

            else:
                state = [step.before]

                def observe(_definition, *, state=state):
                    return state[0]

                def apply(received, *, state=state):
                    effects.append(received.kind)
                    state[0] = received.expected_after

            ports[step.kind] = UpdateStepPortV2(observe=observe, apply=apply)
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=definition,
            preparation=self._gate([]),
            ports=UpdateStepPortsV2(ports),
            receipt_store=ActivationCommitReceiptStoreV2(definition=definition),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "maintenance_begin"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash)

        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertEqual(1, effects.count("maintenance_begin"))
        self.assertEqual(1, effects.count("wait_runtime_quiescent"))

    def test_resume_accepts_only_explicitly_proven_completed_successor(
        self,
    ) -> None:
        before = _projection("controller-state-v2", "accepting")
        drained = _projection("controller-state-v2", "draining")
        quiescent = _projection("controller-state-v2", "quiescent")
        rewritten_steps = []
        for step in self.definition.mutable_steps:
            if step.kind == "maintenance_begin":
                step = replace(step, before=before, expected_after=drained)
            elif step.kind == "wait_runtime_quiescent":
                step = replace(step, before=drained, expected_after=quiescent)
            rewritten_steps.append(step)
        definition = replace(
            self.definition,
            mutable_steps=tuple(rewritten_steps),
        )
        current = [before]
        successor_receipt_durable = [False]
        effects: list[str] = []
        ports: dict[str, UpdateStepPortV2] = {}
        for step in definition.mutable_steps:
            if step.kind == "recovery_forward_only":
                continue
            if step.kind in {"maintenance_begin", "wait_runtime_quiescent"}:

                def observe(_definition, *, current=current):
                    return current[0]

                def apply(
                    step_definition,
                    *,
                    current=current,
                    successor_receipt_durable=successor_receipt_durable,
                ):
                    effects.append(step_definition.kind)
                    current[0] = step_definition.expected_after
                    if step_definition.kind == "wait_runtime_quiescent":
                        successor_receipt_durable[0] = True

                if step.kind == "maintenance_begin":

                    def completed_current_matches(
                        persisted_after,
                        current_observed,
                        step_definition,
                    ):
                        return bool(
                            persisted_after == current_observed
                            or (
                                persisted_after == drained
                                and current_observed == quiescent
                                and step_definition.kind == "maintenance_begin"
                                and successor_receipt_durable[0]
                            )
                        )

                    ports[step.kind] = UpdateStepPortV2(
                        observe=observe,
                        apply=apply,
                        completed_current_matches=completed_current_matches,
                    )
                else:
                    ports[step.kind] = UpdateStepPortV2(
                        observe=observe,
                        apply=apply,
                    )
                continue
            state = [step.before]

            def observe(_definition, *, state=state):
                return state[0]

            def apply(step_definition, *, state=state):
                effects.append(step_definition.kind)
                state[0] = step_definition.expected_after

            ports[step.kind] = UpdateStepPortV2(observe=observe, apply=apply)

        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=definition,
            preparation=self._gate([]),
            ports=UpdateStepPortsV2(ports),
            receipt_store=ActivationCommitReceiptStoreV2(definition=definition),
        )

        def crash_after_successor_effect(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "wait_runtime_quiescent"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash_after_successor_effect)

        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertEqual(1, effects.count("maintenance_begin"))
        self.assertEqual(1, effects.count("wait_runtime_quiescent"))

    def test_dynamic_after_projection_is_persisted_and_replayed_exactly(
        self,
    ) -> None:
        expected_candidate = _projection_value(
            "controller-candidate-v2",
            {
                "activationId": "act2_dynamic",
                "status": "EXPECTED_REGISTRATION",
                "pid": None,
            },
        )
        actual_candidate = _projection_value(
            "controller-candidate-v2",
            {
                "activationId": "act2_dynamic",
                "status": "REGISTERED_READY",
                "pid": 4242,
            },
        )
        mutable_steps = tuple(
            replace(step, expected_after=expected_candidate)
            if step.kind == "controller_candidate_spawn"
            else step
            for step in self.definition.mutable_steps
        )
        definition = replace(self.definition, mutable_steps=mutable_steps)
        effects: list[str] = []
        states: dict[str, list[ProjectionV2]] = {}
        ports: dict[str, UpdateStepPortV2] = {}
        for step in definition.mutable_steps:
            if step.kind == "recovery_forward_only":
                continue
            state = states.setdefault(step.kind, [step.before])
            after = (
                actual_candidate
                if step.kind == "controller_candidate_spawn"
                else step.expected_after
            )

            def observe(_definition, *, state=state):
                return state[0]

            def apply(step_definition, *, state=state, after=after):
                effects.append(step_definition.kind)
                state[0] = after

            if step.kind == "controller_candidate_spawn":

                def matches_after(observed, step_definition):
                    expected = step_definition.expected_after.value
                    actual = observed.value
                    return bool(
                        observed.schema_id == step_definition.expected_after.schema_id
                        and expected.get("status") == "EXPECTED_REGISTRATION"
                        and actual.get("status") == "REGISTERED_READY"
                        and actual.get("activationId") == expected.get("activationId")
                        and isinstance(actual.get("pid"), int)
                    )

                ports[step.kind] = UpdateStepPortV2(
                    observe=observe,
                    apply=apply,
                    matches_after=matches_after,
                )
            else:
                ports[step.kind] = UpdateStepPortV2(
                    observe=observe,
                    apply=apply,
                )
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=definition,
            preparation=self._gate([]),
            ports=UpdateStepPortsV2(ports),
            receipt_store=ActivationCommitReceiptStoreV2(definition=definition),
        )

        def crash_after_spawn_action(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "controller_candidate_spawn"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash_after_spawn_action)

        self.assertNotEqual(expected_candidate, actual_candidate)

        def crash_at_accept_intent(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "controller_accept"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash_at_accept_intent)

        interrupted = self.store.read()
        candidate = next(
            step
            for step in interrupted["steps"]
            if step["kind"] == "controller_candidate_spawn"
        )
        self.assertEqual("COMPLETED", candidate["state"])
        self.assertEqual(actual_candidate.to_document(), candidate["observedAfter"])
        self.assertNotEqual(
            candidate["expectedAfter"],
            candidate["observedAfter"],
        )

        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertEqual(1, effects.count("controller_candidate_spawn"))

    def test_receipt_publication_crash_resumes_without_mutable_effects(self) -> None:
        effects: list[str] = []
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=self.definition,
            preparation=self._gate([]),
            ports=self._ports(effects),
            receipt_store=ActivationCommitReceiptStoreV2(definition=self.definition),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_RECEIPT_BEFORE_JOURNAL_DELETE:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash)

        self.assertTrue(self.journal_path.exists())
        self.assertTrue(self.receipt_path.exists())
        first_effects = list(effects)

        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertFalse(self.journal_path.exists())
        self.assertEqual(first_effects, effects)

    def test_same_state_verify_candidate_replays_only_with_explicit_port_policy(
        self,
    ) -> None:
        mutable_steps = tuple(
            replace(step, expected_after=step.before)
            if step.kind == "verify_candidate"
            else step
            for step in self.definition.mutable_steps
        )
        definition = replace(self.definition, mutable_steps=mutable_steps)
        effects: list[str] = []
        ports: dict[str, UpdateStepPortV2] = {}
        for step in definition.mutable_steps:
            if step.kind == "recovery_forward_only":
                continue
            state = [step.before]

            def observe(_definition, *, state=state):
                return state[0]

            def apply(step_definition, *, state=state):
                effects.append(step_definition.kind)
                state[0] = step_definition.expected_after

            if step.kind == "verify_candidate":
                ports[step.kind] = UpdateStepPortV2(
                    observe=observe,
                    apply=apply,
                    replay_safe_when_indistinguishable=(
                        lambda observed, step_definition: (
                            observed == step_definition.before
                            and observed == step_definition.expected_after
                        )
                    ),
                )
            else:
                ports[step.kind] = UpdateStepPortV2(
                    observe=observe,
                    apply=apply,
                )
        operation = UpdateMatchedActiveOperationV2(
            registry=self.registry,
            executor=self.executor,
            definition=definition,
            preparation=self._gate([]),
            ports=UpdateStepPortsV2(ports),
            receipt_store=ActivationCommitReceiptStoreV2(definition=definition),
        )

        def crash_at_verify_intent(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "verify_candidate"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            operation.execute(failure_injector=crash_at_verify_intent)

        self.assertEqual(0, effects.count("verify_candidate"))
        resumed = operation.execute()

        self.assertEqual("COMPLETED", resumed.status)
        self.assertEqual(1, effects.count("verify_candidate"))


class UpgradePreparationGateV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.smart_subagents.test_activation_transition_v2 import (
            ActivationTransitionV2Tests,
        )

        self.fixture = ActivationTransitionV2Tests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_real_gate_uses_full_verifier_only_before_main_journal(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "9" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        gate = build_upgrade_preparation_gate_v2(
            proof=proof,
            preparation=preparation,
            expected_receipt=receipt,
        )

        first = gate.verify_before_journal_exact()
        second = gate.verify_before_journal_exact()

        self.assertEqual(receipt.receipt_fingerprint, first.receipt_fingerprint)
        self.assertEqual(first, second)
        self.assertEqual(receipt.activation_tree, first.activation_tree)

        prepare_upgrade_database_v2(receipt)
        resumed = gate.verify_resume_exact({"steps": []})

        self.assertEqual(first, resumed)

    def test_database_port_observes_and_applies_exact_receipt_binding(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "7" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        expected_after = build_upgrade_database_binding_v2(receipt)
        intent = receipt.activation_intent
        definition = StepDefinitionV2(
            kind="database_prepare",
            command_id=None,
            action={
                "actionKind": "database-mutation",
                "method": "prepare",
                "databaseId": intent.database_id,
                "path": str(intent.database_path),
                "expectedSchemaFingerprint": intent.schema_fingerprint,
            },
            before=receipt.database_empty_file,
            expected_after=expected_after,
        )
        port = build_upgrade_database_step_port_v2(receipt)

        _assert_definition_passes_normative_journal_schema(
            root=self.fixture.root,
            definition=definition,
            token=90,
        )

        self.assertEqual(definition.before, port.observe(definition))

        port.apply(definition)

        self.assertEqual(expected_after, port.observe(definition))
        port.apply(definition)
        self.assertEqual(expected_after, port.observe(definition))

        wrong_definition = StepDefinitionV2(
            kind="database_prepare",
            command_id=None,
            action=definition.action,
            before=definition.before,
            expected_after=_projection("database-binding-v2", "wrong"),
        )
        with self.assertRaises(UpdateOperationV2Error) as caught:
            port.observe(wrong_definition)
        self.assertEqual("DATABASE_STEP_DEFINITION_INVALID", caught.exception.code)

        substituted_action = dict(definition.action)
        substituted_action["databaseId"] = "db2_" + "f" * 32
        with self.assertRaises(UpdateOperationV2Error) as caught:
            port.observe(replace(definition, action=substituted_action))
        self.assertEqual("DATABASE_STEP_DEFINITION_INVALID", caught.exception.code)

        database_object = ProjectionV2.from_document(
            json.loads(
                (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                    encoding="utf-8"
                )
            )["fixtures"]["databaseProjection"]
        )
        database_object_definition = replace(
            definition,
            expected_after=database_object,
        )
        with self.assertRaises(UpdateOperationV2Error) as caught:
            port.observe(database_object_definition)
        self.assertEqual("DATABASE_STEP_DEFINITION_INVALID", caught.exception.code)
        with self.assertRaises(JournalIntegrityErrorV2):
            _assert_definition_passes_normative_journal_schema(
                root=self.fixture.root,
                definition=database_object_definition,
                token=89,
            )

    def test_database_port_accepts_only_owned_intermediate_after_durable_intent(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "6" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        expected_after = build_upgrade_database_binding_v2(receipt)
        intent = receipt.activation_intent
        definition = StepDefinitionV2(
            kind="database_prepare",
            command_id=None,
            action={
                "actionKind": "database-mutation",
                "method": "prepare",
                "databaseId": intent.database_id,
                "path": str(intent.database_path),
                "expectedSchemaFingerprint": intent.schema_fingerprint,
            },
            before=receipt.database_empty_file,
            expected_after=expected_after,
        )
        interrupted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import os,sqlite3,sys;"
                    "connection=sqlite3.connect(sys.argv[1],isolation_level=None);"
                    "connection.execute('pragma journal_mode=WAL');"
                    "connection.execute('BEGIN IMMEDIATE');"
                    "connection.execute('create table interrupted(value text)');"
                    "os._exit(94)"
                ),
                str(intent.database_path),
            ],
            check=False,
        )
        self.assertEqual(94, interrupted.returncode)
        port = build_upgrade_database_step_port_v2(receipt)

        observed = port.observe(definition)

        self.assertFalse(port.matches_before(observed, definition))
        self.assertFalse(port.matches_after(observed, definition))
        self.assertTrue(port.matches_intent_resume(observed, definition))

        port.apply(definition)

        self.assertEqual(expected_after, port.observe(definition))

    def test_link_and_manifest_ports_authorize_pure_plans_at_apply_time(
        self,
    ) -> None:
        from codex_smart_subagents.activation_gateway_v2 import _tree_sha256
        from codex_smart_subagents.activation_transition_v2 import (
            accept_upgrade_candidate_v2,
            build_activation_link_plan_v2,
            build_manifest_commit_plan_v2,
            prepare_manifest_file_v2,
            shutdown_current_activation_v2,
        )
        from tests.smart_subagents.test_activation_transition_v2 import (
            _ControllerPort,
        )

        proof = self.fixture.capture()
        operation_id = "op2_" + "6" * 32
        self.fixture.create_gate_journal(operation_id)
        staged = self.fixture.stage(proof, operation_id)
        prepared_manifest = prepare_manifest_file_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=_tree_sha256(staged.activation_dir),
        )
        link_plan = build_activation_link_plan_v2(
            proof=proof,
            staged=staged,
        )
        manifest_plan = build_manifest_commit_plan_v2(
            proof=proof,
            staged=staged,
            prepared=prepared_manifest,
        )
        controller = _ControllerPort(
            control_epoch=int(proof.controller_row["control_epoch"])
        )
        shutdown = shutdown_current_activation_v2(
            proof=proof,
            operation_id=operation_id,
            controller_port=controller,
        )
        accepted: dict[str, object] = {}
        providers = UpdateControllerProofProvidersV2(
            shutdown=lambda: shutdown,
            acceptance=lambda: accepted["proof"],
        )
        link_definition = StepDefinitionV2(
            kind="activation_link",
            command_id=None,
            action=link_plan.action,
            before=link_plan.before,
            expected_after=link_plan.expected_after,
        )
        _assert_definition_passes_normative_journal_schema(
            root=self.fixture.root,
            definition=link_definition,
            token=91,
        )
        link_port = build_activation_link_step_port_v2(
            plan=link_plan,
            proof=proof,
            staged=staged,
            proof_providers=providers,
        )

        self.assertEqual(link_plan.before, link_port.observe(link_definition))
        link_port.apply(link_definition)
        self.assertEqual(
            link_plan.expected_after,
            link_port.observe(link_definition),
        )
        link_port.apply(link_definition)

        accepted["proof"] = accept_upgrade_candidate_v2(
            proof=proof,
            staged=staged,
            shutdown=shutdown,
            controller_port=controller,
            pid=os.getpid(),
            process_start_marker="update-port-test-process",
            process_group_id=os.getpgrp(),
        )
        manifest_definition = StepDefinitionV2(
            kind="manifest_commit",
            command_id=None,
            action=manifest_plan.action,
            before=manifest_plan.before,
            expected_after=manifest_plan.expected_after,
        )
        _assert_definition_passes_normative_journal_schema(
            root=self.fixture.root,
            definition=manifest_definition,
            token=92,
        )
        manifest_port = build_manifest_commit_step_port_v2(
            plan=manifest_plan,
            proof=proof,
            staged=staged,
            proof_providers=providers,
        )
        substituted_action = dict(manifest_definition.action)
        substituted_action["sourcePath"] = str(
            Path(str(substituted_action["sourcePath"])).with_name(
                "substituted.manifest.json"
            )
        )
        with self.assertRaises(UpdateOperationV2Error) as caught:
            manifest_port.observe(
                replace(manifest_definition, action=substituted_action)
            )
        self.assertEqual(
            "MANIFEST_COMMIT_STEP_DEFINITION_INVALID",
            caught.exception.code,
        )

        self.assertEqual(
            manifest_plan.before,
            manifest_port.observe(manifest_definition),
        )
        manifest_port.apply(manifest_definition)
        self.assertEqual(
            manifest_plan.expected_after,
            manifest_port.observe(manifest_definition),
        )
        manifest_port.apply(manifest_definition)

    def test_controller_proof_providers_rehydrate_on_every_call(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "8" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        command_ids = {
            "maintenance_begin": "cc2_" + "1" * 32,
            "maintenance_strengthen": "cc2_" + "2" * 32,
            "controller_shutdown": "cc2_" + "3" * 32,
            "controller_accept": "cc2_" + "4" * 32,
        }
        definition = object.__new__(OperationDefinitionV2)
        object.__setattr__(definition, "installation_id", proof.installation_id)
        object.__setattr__(definition, "operation_id", receipt.operation_id)
        object.__setattr__(
            definition,
            "mutable_steps",
            tuple(
                StepDefinitionV2(
                    kind=kind,
                    command_id=command_id,
                    action={"kind": kind},
                    before=receipt.activation_tree,
                    expected_after=receipt.activation_tree,
                )
                for kind, command_id in command_ids.items()
            ),
        )
        shutdown_calls: list[dict[str, object]] = []
        acceptance_calls: list[dict[str, object]] = []
        shutdown_proof = SimpleNamespace(proof_fingerprint="a" * 64)
        acceptance_proof = SimpleNamespace(proof_fingerprint="b" * 64)

        def load_shutdown(**arguments):
            shutdown_calls.append(arguments)
            return shutdown_proof

        def load_acceptance(**arguments):
            acceptance_calls.append(arguments)
            return acceptance_proof

        providers = build_rehydrating_controller_proof_providers_v2(
            definition=definition,
            proof=proof,
            preparation_receipt=receipt,
            shutdown_loader=load_shutdown,
            acceptance_loader=load_acceptance,
        )

        self.assertIs(shutdown_proof, providers.shutdown())
        self.assertIs(acceptance_proof, providers.acceptance())
        self.assertIs(acceptance_proof, providers.acceptance())

        self.assertEqual(3, len(shutdown_calls))
        self.assertEqual(2, len(acceptance_calls))
        self.assertEqual(proof.database_path, shutdown_calls[0]["database_path"])
        self.assertEqual(
            receipt.activation_intent.database_path,
            acceptance_calls[0]["database_path"],
        )
        self.assertEqual(
            command_ids["controller_accept"],
            acceptance_calls[0]["command_id"],
        )


if __name__ == "__main__":
    unittest.main()
