from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ExecutionPlanV2,
    FailurePointV2,
    InjectedCrashV2,
    InstallationUninstallPayloadIntentV2,
    JournalConflictV2,
    JournalIntegrityErrorV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    RecoveryStateAmbiguousV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    TerminalCallbacksV2,
    TerminalDefinitionV2,
    TerminalProofFailedV2,
    TombstonePayloadIntentV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.operation_definition_rehydration_v2 import (  # noqa: E402
    operation_definition_from_journal_v2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


SCHEMA_DIR = ROOT / "docs" / "contracts" / "schemas"
VECTOR_PATH = ROOT / "docs" / "contracts" / "vectors" / "lifecycle-v2.json"
INSTALLATION_ID = "ins2_1234567890abcdef1234567890abcdef"
OPERATION_ID = "op2_1234567890abcdef1234567890abcdef"
PLAN_ID = "pl2_1234567890abcdef1234567890abcdef"
SCHEMA_SHA256 = hashlib.sha256(
    (SCHEMA_DIR / "lifecycle-projection-v2.schema.json").read_bytes()
).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _Ids:
    def __init__(self) -> None:
        self.value = 1

    def __call__(self, prefix: str) -> str:
        value = f"{prefix}_{self.value:032x}"
        self.value += 1
        return value


class _MonotonicNanoseconds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


class _Effects:
    def __init__(self, states: dict[str, ProjectionV2]) -> None:
        self.states = dict(states)
        self.calls: list[str] = []

    def callbacks(self) -> StepCallbacksV2:
        return StepCallbacksV2(observe=self.observe, apply=self.apply)

    def observe(self, step: StepDefinitionV2) -> ProjectionV2:
        return self.states[step.kind]

    def apply(self, step: StepDefinitionV2) -> None:
        self.calls.append(step.kind)
        self.states[step.kind] = step.expected_after


class _TerminalEffects:
    def __init__(self, *, prove_after_publish: bool = True) -> None:
        self.receipt_present = False
        self.prove_after_publish = prove_after_publish
        self.publish_calls = 0
        self.proof_calls = 0
        self.frozen_fingerprints: list[str] = []

    def callbacks(self) -> TerminalCallbacksV2:
        return TerminalCallbacksV2(
            receipt_matches=self.receipt_matches,
            publish_receipt=self.publish_receipt,
        )

    def receipt_matches(self, journal: dict[str, object]) -> bool:
        self.proof_calls += 1
        self.frozen_fingerprints.append(str(journal["journalFingerprint"]))
        return self.receipt_present

    def publish_receipt(self, journal: dict[str, object]) -> None:
        self.publish_calls += 1
        self.frozen_fingerprints.append(str(journal["journalFingerprint"]))
        if self.prove_after_publish:
            self.receipt_present = True


class _UninstallTerminalEffects(_TerminalEffects):
    def __init__(self) -> None:
        super().__init__()
        self.tombstone_present = False
        self.tombstone_publish_calls = 0
        self.tombstone_proof_calls = 0

    def callbacks(self) -> TerminalCallbacksV2:
        return TerminalCallbacksV2(
            receipt_matches=self.receipt_matches,
            publish_receipt=self.publish_receipt,
            tombstone_matches=self.tombstone_matches,
            publish_tombstone=self.publish_tombstone,
        )

    def tombstone_matches(self, journal: dict[str, object]) -> bool:
        self.tombstone_proof_calls += 1
        self.frozen_fingerprints.append(str(journal["journalFingerprint"]))
        return self.tombstone_present

    def publish_tombstone(self, journal: dict[str, object]) -> None:
        self.tombstone_publish_calls += 1
        self.frozen_fingerprints.append(str(journal["journalFingerprint"]))
        self.tombstone_present = True


def _projection(schema_id: str, value: dict[str, object], domain: str) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": SCHEMA_SHA256,
        "value": value,
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _absence(
    path: Path, *, token: int, parent_inode_offset: int = 0
) -> ProjectionV2:
    parent = path.parent.stat()
    value_without_fingerprint: dict[str, object] = {
        "proofId": f"ap2_{token:032x}",
        "installationId": INSTALLATION_ID,
        "operationId": OPERATION_ID,
        "entries": [
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino + parent_inode_offset,
                "absent": True,
            }
        ],
        "directorySyncCompleted": True,
    }
    value = {
        **value_without_fingerprint,
        "proofFingerprint": domain_fingerprint(
            "codex-smart/absence-proof/v2", value_without_fingerprint
        ),
    }
    return _projection(
        "absence-proof-v2",
        value,
        "codex-smart/absence-proof-projection/v2",
    )


def _journal_state(
    path: Path,
    plan_fingerprint: str,
    *,
    phase: str,
    recovery_policy: str,
    generation: int,
    frozen: bool = False,
) -> ProjectionV2:
    return _projection(
        "journal-state-v2",
        {
            "path": str(path),
            "journalKind": "operation",
            "ownerId": OPERATION_ID,
            "phase": phase,
            "recoveryPolicy": recovery_policy,
            "executionPlanDefinitionFingerprint": plan_fingerprint,
            "contentGeneration": generation,
            "frozen": frozen,
        },
        "codex-smart/journal-state/v2",
    )


def _initial_commit_manifest(
    root: Path,
) -> tuple[ProjectionV2, dict[str, object], ActivationTransitionLineageV2]:
    interface_evidence = json.loads(
        (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
            encoding="utf-8"
        )
    )["base"]
    activation_id = "act2_" + "a" * 64
    document: dict[str, object] = {
        "schemaVersion": 2,
        "installationId": INSTALLATION_ID,
        "release": "0.2.0",
        "pluginId": "codex-smart-subagents",
        "marketplaceName": "codex-settings-adaptive",
        "stateHome": str(root / "state"),
        "sourceLocator": {
            "lexicalPath": str(root / "bin" / "codex"),
            "resolvedPathAtCapture": str(root / "bin" / "codex"),
            "argv0Policy": "lexical",
            "sourceObservedSha256": "1" * 64,
        },
        "codexSnapshot": {
            "absolutePath": str(root / "snapshots" / "codex"),
            "sha256": "1" * 64,
        },
        "activeActivation": {
            "activationId": activation_id,
            "activationFingerprint": "a" * 64,
            "symlinkTarget": f"activations/{activation_id}/marketplace",
            "generationId": "gen2_" + "b" * 64,
            "databaseId": "db2_" + "c" * 32,
        },
        "previousActivation": None,
        "interfaceEvidence": interface_evidence,
        "routingPolicyFingerprint": "2" * 64,
        "bundledCatalogFingerprint": "3" * 64,
        "artifacts": [],
        "originalBackup": {
            "type": "absent",
            "path": str(root / "original-backup"),
            "parentPath": str(root),
            "name": "original-backup",
        },
        "lastCommittedOperation": OPERATION_ID,
        "databaseSchemaVersion": 2,
        "extensions": {},
    }
    raw = canonical_json_bytes(document)
    file_value = {
        "path": str(root / "manifest.json"),
        "device": 1,
        "inode": 2,
        "ownerUid": os.getuid(),
        "ownerGid": os.getgid(),
        "mode": "0600",
        "linkCount": 1,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    manifest = _projection(
        "manifest-v2",
        {
            "file": file_value,
            "schemaVersion": 2,
            "installationId": INSTALLATION_ID,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "stateHome": str(root / "state"),
            "activeActivationId": activation_id,
            "previousActivationId": None,
            "lastCommittedOperation": OPERATION_ID,
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(document["sourceLocator"])
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes(document["artifacts"])
            ).hexdigest(),
            "semanticFingerprint": domain_fingerprint(
                "codex-smart/manifest-semantic/v2",
                {
                    key: copy.deepcopy(value)
                    for key, value in document.items()
                    if key != "extensions"
                },
            ),
        },
        "codex-smart/journal-state/v2",
    )
    lineage = ActivationTransitionLineageV2(
        transition_kind="initial",
        source_receipt=None,
        activation_proof_fingerprint=None,
        shutdown_command_ids=None,
        stopped_controller=None,
    )
    return manifest, document, lineage


class LifecycleOperationV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.validate_journal = staticmethod(
            build_operation_journal_validator_v2(SCHEMA_DIR)
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="lifecycle-operation-v2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.journal_path = self.root / "operation.transaction.json"
        self.lock_path = self.root / "operation.lock"
        self.stage_path = self.root / "candidate"
        self.stage = StepDefinitionV2(
            kind="stage",
            command_id=None,
            action={
                "actionKind": "file-mutation",
                "method": "mkdir-stage",
                "targetPath": str(self.stage_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_absence(self.stage_path, token=2),
            expected_after=_projection(
                "tree-object-v2",
                {
                    "path": str(self.stage_path),
                    "device": 1,
                    "inode": 2,
                    "ownerUid": os.getuid(),
                    "ownerGid": os.getgid(),
                    "mode": "0700",
                    "entryCount": 0,
                    "treeSha256": "2" * 64,
                },
                "codex-smart/tree-object/v2",
            ),
        )
        self.verify = StepDefinitionV2(
            kind="verify_staged",
            command_id=None,
            action={
                "actionKind": "verify",
                "predicate": "staged",
                "timeoutMs": 1_000,
            },
            before=self.stage.expected_after,
            expected_after=self.stage.expected_after,
        )
        self.definition = self._definition(self.stage)
        self.store = OperationJournalStoreV2(
            journal_path=self.journal_path,
            lock_path=self.lock_path,
            validate_document=self.validate_journal,
        )
        self.executor = OperationExecutorV2(
            store=self.store,
            now=_Clock(),
            id_factory=_Ids(),
        )

    def test_activation_commit_payload_requires_exact_projection_domains(
        self,
    ) -> None:
        absence = _absence(self.journal_path, token=90)
        manifest, manifest_document, transition_lineage = _initial_commit_manifest(
            self.root
        )
        valid = ActivationCommitPayloadIntentV2(
            manifest=manifest,
            manifest_document=manifest_document,
            transition_lineage=transition_lineage,
            activation=_projection(
                "activation-v2",
                {"token": "activation"},
                "codex-smart/journal-state/v2",
            ),
            database_binding=_projection(
                "database-binding-v2",
                {"token": "database"},
                "codex-smart/database-binding/v2",
            ),
            journal_absence_target=absence,
            controller_identity="9" * 64,
        )
        mutations = {
            "manifest schema": {
                "manifest": _projection(
                    "other-manifest-v2",
                    {"token": "manifest"},
                    "codex-smart/journal-state/v2",
                )
            },
            "manifest domain": {
                "manifest": _projection(
                    "manifest-v2",
                    {"token": "manifest"},
                    "codex-smart/activation/v2",
                )
            },
            "activation schema": {
                "activation": _projection(
                    "other-activation-v2",
                    {"token": "activation"},
                    "codex-smart/journal-state/v2",
                )
            },
            "activation preparation domain": {
                "activation": _projection(
                    "activation-v2",
                    {"token": "activation"},
                    "codex-smart/activation/v2",
                )
            },
            "database schema": {
                "database_binding": _projection(
                    "other-database-binding-v2",
                    {"token": "database"},
                    "codex-smart/database-binding/v2",
                )
            },
            "database domain": {
                "database_binding": _projection(
                    "database-binding-v2",
                    {"token": "database"},
                    "codex-smart/journal-state/v2",
                )
            },
            "absence schema": {
                "journal_absence_target": _projection(
                    "other-absence-proof-v2",
                    {"token": "absence"},
                    "codex-smart/absence-proof-projection/v2",
                )
            },
            "absence domain": {
                "journal_absence_target": _projection(
                    "absence-proof-v2",
                    {"token": "absence"},
                    "codex-smart/journal-state/v2",
                )
            },
        }

        for name, changes in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(JournalIntegrityErrorV2):
                    replace(valid, **changes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_journal_validator_never_imports_external_schema_packages(self) -> None:
        real_import = __import__

        def guarded_import(name, *args, **kwargs):
            if name == "jsonschema" or name.startswith("jsonschema."):
                raise ImportError("jsonschema is unavailable")
            if name == "referencing" or name.startswith("referencing."):
                raise ImportError("referencing is unavailable")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=guarded_import):
            validate = build_operation_journal_validator_v2(SCHEMA_DIR)

        validate(self.vectors["fixtures"]["activationFencedJournal"])

    def _definition(
        self, *steps: StepDefinitionV2
    ) -> OperationDefinitionV2:
        plan = ExecutionPlanV2(
            plan_id=PLAN_ID,
            machine_id="apply",
            selected_branch_id="update-matched-active",
            composed_step_kinds=("gate_close", *(step.kind for step in steps)),
        )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "gate-close",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_absence(self.journal_path, token=1),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="DISCOVERED",
                recovery_policy="REVERSIBLE",
                generation=1,
            ),
        )
        fixture = self.vectors["fixtures"]["activationFencedJournal"]
        return OperationDefinitionV2(
            kind="activation",
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            operation="apply",
            execution_plan=plan,
            discovery_before=StateBundleV2.from_document(fixture["discoveryBefore"]),
            fenced_before=StateBundleV2.from_document(fixture["fencedBefore"]),
            desired=StateBundleV2.from_document(fixture["desired"]),
            gate_close=gate,
            mutable_steps=steps,
        )

    def _terminal_definition(
        self,
        *,
        kind: str = "activation",
        operation: str = "apply",
        machine_id: str = "apply",
        selected_branch_id: str = "update-matched-active",
        journal_absence_target: ProjectionV2 | None = None,
    ) -> OperationDefinitionV2:
        plan = ExecutionPlanV2(
            plan_id=PLAN_ID,
            machine_id=machine_id,
            selected_branch_id=selected_branch_id,
            composed_step_kinds=(
                "gate_close",
                "stage",
                "recovery_forward_only",
                "terminal_journal_freeze",
                "commit_receipt_publish",
                "gate_open",
            ),
        )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "gate-close",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_absence(self.journal_path, token=10),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="DISCOVERED",
                recovery_policy="REVERSIBLE",
                generation=1,
            ),
        )
        forward_only = StepDefinitionV2(
            kind="recovery_forward_only",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "forward-only",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="REVERSIBLE",
                generation=4,
            ),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="FORWARD_ONLY",
                generation=5,
            ),
        )
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "freeze-delete-intent",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="COMMITTING",
                recovery_policy="FORWARD_ONLY",
                generation=6,
            ),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="TERMINAL_FROZEN",
                recovery_policy="FORWARD_ONLY",
                generation=7,
                frozen=True,
            ),
        )
        absence_target = journal_absence_target or _absence(
            self.journal_path, token=11
        )
        receipt = self.vectors["fixtures"]["activationCommitReceipt"]

        def receipt_projection(name: str, domain: str) -> ProjectionV2:
            document = receipt[name]
            envelope = {
                "schemaId": document["schemaId"],
                "schemaSha256": document["schemaSha256"],
                "value": copy.deepcopy(document["value"]),
            }
            return ProjectionV2(
                schema_id=str(envelope["schemaId"]),
                schema_sha256=str(envelope["schemaSha256"]),
                value=envelope["value"],
                value_fingerprint=domain_fingerprint(domain, envelope),
            )

        manifest, manifest_document, transition_lineage = _initial_commit_manifest(
            self.root
        )

        terminal = TerminalDefinitionV2(
            terminal_kind="COMMIT",
            receipt_kind="activation-commit",
            receipt_path=self.root / "receipts" / "operation.commit.json",
            freeze=freeze,
            journal_absence_target=absence_target,
            receipt_payload=ActivationCommitPayloadIntentV2(
                manifest=manifest,
                manifest_document=manifest_document,
                transition_lineage=transition_lineage,
                activation=receipt_projection(
                    "activation", "codex-smart/journal-state/v2"
                ),
                database_binding=receipt_projection(
                    "databaseBinding", "codex-smart/database-binding/v2"
                ),
                journal_absence_target=absence_target,
                controller_identity="c" * 64,
            ),
        )
        fixture = self.vectors["fixtures"]["activationFencedJournal"]
        return OperationDefinitionV2(
            kind=kind,
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            operation=operation,
            execution_plan=plan,
            discovery_before=StateBundleV2.from_document(fixture["discoveryBefore"]),
            fenced_before=StateBundleV2.from_document(fixture["fencedBefore"]),
            desired=StateBundleV2.from_document(fixture["desired"]),
            gate_close=gate,
            mutable_steps=(self.stage, forward_only),
            terminal=terminal,
        )

    def _uninstall_definition(self) -> OperationDefinitionV2:
        plan = ExecutionPlanV2(
            plan_id=PLAN_ID,
            machine_id="uninstall",
            selected_branch_id="disabled-or-missing-proven",
            composed_step_kinds=(
                "gate_close",
                "recovery_forward_only",
                "terminal_journal_freeze",
                "uninstall_receipt_publish",
                "uninstall_tombstone_publish",
                "uninstall_journal_close",
            ),
        )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "gate-close",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_absence(self.journal_path, token=20),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="DISCOVERED",
                recovery_policy="REVERSIBLE",
                generation=1,
            ),
        )
        forward_only = StepDefinitionV2(
            kind="recovery_forward_only",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "forward-only",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="REVERSIBLE",
                generation=2,
            ),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="FORWARD_ONLY",
                generation=3,
            ),
        )
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "freeze-delete-intent",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="COMMITTING",
                recovery_policy="FORWARD_ONLY",
                generation=4,
            ),
            expected_after=_journal_state(
                self.journal_path,
                plan.plan_definition_fingerprint,
                phase="TERMINAL_FROZEN",
                recovery_policy="FORWARD_ONLY",
                generation=5,
                frozen=True,
            ),
        )
        absence_target = _absence(self.journal_path, token=21)
        tombstone_path = self.root / "installation-tombstone.json"
        fixture = self.vectors["fixtures"]["activationFencedJournal"]
        removed_state = StateBundleV2.from_document(fixture["desired"])
        terminal = TerminalDefinitionV2(
            terminal_kind="UNINSTALL",
            receipt_kind="installation-uninstall",
            receipt_path=self.root / "receipts" / "operation.uninstall.json",
            freeze=freeze,
            journal_absence_target=absence_target,
            receipt_payload=InstallationUninstallPayloadIntentV2(
                removed_state=removed_state,
                restored_original_backup=_absence(
                    self.root / "original-backup", token=22
                ),
                absence_proof=_absence(self.root / "managed-object", token=23),
                retained_data={
                    "databaseBinding": _projection(
                        "database-binding-v2",
                        {
                            "path": str(self.root / "state" / "database.sqlite3"),
                            "device": 1,
                            "inode": 2,
                            "ownerUid": os.getuid(),
                            "ownerGid": os.getgid(),
                            "mode": "0600",
                            "linkCount": 1,
                            "databaseId": "db2_" + "1" * 32,
                            "databaseIdentity": {
                                "databaseId": "db2_" + "1" * 32,
                                "activationBindingNonce": "2" * 64,
                                "activationId": "act2_" + "3" * 64,
                                "activationFingerprint": "4" * 64,
                            },
                            "activationIdentity": {
                                "activationId": "act2_" + "3" * 64,
                                "activationFingerprint": "4" * 64,
                            },
                            "databaseVersion": "0.2.0",
                            "schemaVersion": 2,
                            "userVersion": 2,
                            "schemaFingerprint": "5" * 64,
                            "schemaArtifactSha256": "6" * 64,
                            "databaseIdentityFingerprint": "7" * 64,
                        },
                        "codex-smart/database-binding/v2",
                    ).to_document(),
                    "backupsRoot": str(self.root / "state" / "backups"),
                    "quarantineRoot": str(self.root / "state" / "quarantine"),
                    "recoveryEntrypoint": _projection(
                        "file-object-v2",
                        {
                            "path": str(self.root / "recover.py"),
                            "device": 1,
                            "inode": 3,
                            "ownerUid": os.getuid(),
                            "ownerGid": os.getgid(),
                            "mode": "0600",
                            "linkCount": 1,
                            "size": 1,
                            "sha256": "8" * 64,
                        },
                        "codex-smart/file-object/v2",
                    ).to_document(),
                },
                activation_proof_fingerprint="9" * 64,
            ),
            tombstone_payload=TombstonePayloadIntentV2(
                path=tombstone_path,
                before=_absence(tombstone_path, token=24),
                replacement_authorization="CREATE_IF_ABSENT",
            ),
        )
        return OperationDefinitionV2(
            kind="uninstall",
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            operation="uninstall",
            execution_plan=plan,
            discovery_before=StateBundleV2.from_document(
                fixture["discoveryBefore"]
            ),
            fenced_before=StateBundleV2.from_document(fixture["fencedBefore"]),
            desired=removed_state,
            gate_close=gate,
            mutable_steps=(forward_only,),
            terminal=terminal,
        )

    def test_first_durable_document_is_private_atomic_and_freezes_mutable_plan(
        self,
    ) -> None:
        definition = self._definition(self.stage, self.verify)
        with mock.patch(
            "codex_smart_subagents.lifecycle_operation_v2.os.fsync",
            wraps=os.fsync,
        ) as fsync:
            result = self.executor.begin(definition)

        journal = self.store.read()
        self.validate_journal(journal)
        self.assertEqual("STARTED", result.status)
        self.assertEqual(OPERATION_ID, result.operation_id)
        self.assertRegex(result.attempt_id, r"^opa2_[0-9a-f]{32}$")
        self.assertEqual("DISCOVERED", journal["phase"])
        self.assertEqual("REVERSIBLE", journal["recoveryPolicy"])
        self.assertEqual(1, journal["executionPlan"]["firstIncompleteOrdinal"])
        self.assertEqual(
            definition.execution_plan.to_document(1),
            journal["executionPlan"],
        )
        self.assertEqual(3, len(journal["steps"]))
        gate = journal["steps"][0]
        self.assertEqual(
            (0, 0, "gate_close", "COMPLETED", "JOURNAL_ATOMIC_BOUNDARY"),
            (
                gate["ordinal"],
                gate["planOrdinal"],
                gate["kind"],
                gate["state"],
                gate["recordCarrier"],
            ),
        )
        self.assertEqual(gate["expectedAfter"], gate["observedAfter"])
        for plan_ordinal, (persisted, expected) in enumerate(
            zip(journal["steps"][1:], definition.mutable_steps, strict=True),
            start=1,
        ):
            self.assertEqual(plan_ordinal, persisted["ordinal"])
            self.assertEqual(plan_ordinal, persisted["planOrdinal"])
            self.assertEqual(definition.execution_plan.plan_id, persisted["planId"])
            self.assertEqual("JOURNAL_MUTABLE", persisted["recordCarrier"])
            self.assertEqual("PLANNED", persisted["state"])
            self.assertEqual(expected.kind, persisted["kind"])
            self.assertEqual(expected.command_id, persisted["commandId"])
            self.assertEqual(expected.action, persisted["action"])
            self.assertEqual(
                expected.action_fingerprint,
                persisted["actionFingerprint"],
            )
            self.assertEqual(expected.before.to_document(), persisted["before"])
            self.assertEqual(
                expected.expected_after.to_document(),
                persisted["expectedAfter"],
            )
            self.assertIsNone(persisted["observedAfter"])
            self.assertIsNone(persisted["intentAt"])
            self.assertIsNone(persisted["completedAt"])
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertEqual(0o600, stat.S_IMODE(self.journal_path.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.lock_path.stat().st_mode))
        self.assertEqual(
            canonical_json_bytes(journal),
            self.journal_path.read_bytes(),
        )
        projection = {key: value for key, value in journal.items() if key != "journalFingerprint"}
        self.assertEqual(
            domain_fingerprint("codex-smart/operation-journal/v2", projection),
            journal["journalFingerprint"],
        )

    def test_deadline_after_durable_intent_preserves_journal_and_skips_effect(
        self,
    ) -> None:
        monotonic = _MonotonicNanoseconds()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=monotonic,
        )
        effects = _Effects({"stage": self.stage.before})

        def expire_after_intent(point: FailurePointV2, _kind: str) -> None:
            if point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION:
                monotonic.value = 1_000_000_000

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2):
                self.executor.execute(
                    self.definition,
                    callbacks=effects.callbacks(),
                    failure_injector=expire_after_intent,
                )

        journal = self.store.read()
        self.assertEqual([], effects.calls)
        self.assertTrue(self.journal_path.is_file())
        self.assertEqual("INTENT_DURABLE", journal["steps"][1]["state"])
        self.assertEqual(1, journal["executionPlan"]["firstIncompleteOrdinal"])

    def test_first_document_freezes_static_terminal_definition(self) -> None:
        definition = self._terminal_definition()
        self.executor.begin(definition)

        journal = self.store.read()
        snapshot = journal["terminalDefinitionSnapshot"]
        self.assertEqual("COMMIT", snapshot["terminalKind"])
        self.assertEqual("activation-commit", snapshot["receiptKind"])
        self.assertEqual(str(definition.terminal.receipt_path), snapshot["receiptPath"])
        self.assertEqual(
            definition.terminal.freeze.action,
            snapshot["freeze"]["action"],
        )
        self.assertEqual(
            definition.terminal.journal_absence_target.to_document(),
            snapshot["journalAbsenceTarget"],
        )
        unsigned = {
            key: value
            for key, value in snapshot.items()
            if key != "snapshotFingerprint"
        }
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/terminal-definition-snapshot/v2",
                unsigned,
            ),
            snapshot["snapshotFingerprint"],
        )

        changed_terminal = replace(
            definition.terminal,
            receipt_path=self.root / "receipts" / "changed.commit.json",
        )
        changed_definition = replace(definition, terminal=changed_terminal)
        effects = _Effects({"stage": self.stage.before})

        with self.assertRaisesRegex(
            JournalConflictV2,
            "immutable terminal definition changed",
        ):
            self.executor.execute(
                changed_definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=_TerminalEffects().callbacks(),
            )

        self.assertEqual([], effects.calls)

    def test_full_operation_definition_rehydrates_before_and_after_freeze(
        self,
    ) -> None:
        definition = self._terminal_definition()
        effects = _Effects({"stage": self.stage.before})
        self.executor.begin(definition)

        planned = operation_definition_from_journal_v2(self.store.read())
        self.assertEqual(definition, planned)

        def crash_after_freeze(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=_TerminalEffects().callbacks(),
                failure_injector=crash_after_freeze,
            )

        frozen = operation_definition_from_journal_v2(self.store.read())
        self.assertEqual(definition, frozen)

    def test_definition_rehydration_rejects_unbound_or_incomplete_steps(self) -> None:
        definition = self._terminal_definition()

        def crash_after_freeze(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=_Effects({"stage": self.stage.before}).callbacks(),
                terminal_callbacks=_TerminalEffects().callbacks(),
                failure_injector=crash_after_freeze,
            )

        frozen = self.store.read()

        def resigned(mutator) -> dict[str, object]:
            document = copy.deepcopy(frozen)
            mutator(document)
            unsigned = {
                key: value
                for key, value in document.items()
                if key != "journalFingerprint"
            }
            document["journalFingerprint"] = domain_fingerprint(
                "codex-smart/operation-journal/v2",
                unsigned,
            )
            return document

        def make_freeze_incomplete(document: dict[str, object]) -> None:
            document["steps"][-1].update(
                state="INTENT_DURABLE",
                observedAfter=None,
                completedAt=None,
            )

        cases = (
            (
                "foreign-plan",
                lambda document: document["steps"][1].__setitem__(
                    "planId", "pl2_ffffffffffffffffffffffffffffffff"
                ),
            ),
            (
                "wrong-carrier",
                lambda document: document["steps"][1].__setitem__(
                    "recordCarrier", "JOURNAL_ATOMIC_BOUNDARY"
                ),
            ),
            (
                "incomplete-freeze",
                make_freeze_incomplete,
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                with self.assertRaises(JournalIntegrityErrorV2):
                    operation_definition_from_journal_v2(resigned(mutate))

    def test_resume_rejects_changed_future_step_before_any_effect(self) -> None:
        original = self._definition(self.stage, self.verify)
        self.executor.begin(original)
        changed_verify = StepDefinitionV2(
            kind=self.verify.kind,
            command_id=self.verify.command_id,
            action={**self.verify.action, "timeoutMs": 2_000},
            before=self.verify.before,
            expected_after=self.verify.expected_after,
        )
        changed = self._definition(self.stage, changed_verify)
        effects = _Effects(
            {
                "stage": self.stage.before,
                "verify_staged": self.verify.before,
            }
        )

        with self.assertRaisesRegex(
            JournalConflictV2,
            r"immutable durable step field changed: 2\.action",
        ):
            self.executor.execute(changed, callbacks=effects.callbacks())

        self.assertEqual([], effects.calls)
        self.assertEqual(
            ["COMPLETED", "PLANNED", "PLANNED"],
            [step["state"] for step in self.store.read()["steps"]],
        )

    def test_resume_rechecks_completed_prefix_with_durable_successor_proof(
        self,
    ) -> None:
        successor_after = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.expected_after.value),
                "inode": 3,
                "treeSha256": "3" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        successor = StepDefinitionV2(
            kind="verify_staged",
            command_id=None,
            action={
                "actionKind": "verify",
                "predicate": "staged",
                "timeoutMs": 1_000,
            },
            before=self.stage.expected_after,
            expected_after=successor_after,
        )
        definition = self._definition(self.stage, successor)
        current = [self.stage.before]
        successor_receipt_durable = [False]
        calls: list[str] = []

        def observe(_definition: StepDefinitionV2) -> ProjectionV2:
            return current[0]

        def apply(step: StepDefinitionV2) -> None:
            calls.append(step.kind)
            current[0] = step.expected_after
            if step.kind == "verify_staged":
                successor_receipt_durable[0] = True

        def completed_current_matches(
            persisted_after: ProjectionV2,
            current_observed: ProjectionV2,
            step: StepDefinitionV2,
        ) -> bool:
            if persisted_after == current_observed:
                return True
            return bool(
                step.kind == "stage"
                and persisted_after == self.stage.expected_after
                and current_observed == successor.expected_after
                and successor_receipt_durable[0]
            )

        callbacks = StepCallbacksV2(
            observe=observe,
            apply=apply,
            completed_current_matches=completed_current_matches,
        )

        def crash_after_successor_effect(
            point: FailurePointV2, kind: str
        ) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "verify_staged"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=callbacks,
                failure_injector=crash_after_successor_effect,
            )

        self.assertEqual(["stage", "verify_staged"], calls)
        resumed = self.executor.execute(definition, callbacks=callbacks)

        self.assertEqual("MUTABLE_COMPLETED", resumed.status)
        self.assertEqual(["stage", "verify_staged"], calls)
        self.assertEqual(
            ["COMPLETED", "COMPLETED", "COMPLETED"],
            [step["state"] for step in self.store.read()["steps"]],
        )

    def test_crash_before_effect_resumes_with_new_attempt_and_no_early_effect(
        self,
    ) -> None:
        definition = self._definition(self.stage, self.verify)
        effects = _Effects(
            {
                "stage": self.stage.before,
                "verify_staged": self.verify.before,
            }
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "stage"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                failure_injector=crash,
            )

        interrupted = self.store.read()
        self.assertEqual([], effects.calls)
        self.assertEqual("INTENT_DURABLE", interrupted["steps"][1]["state"])
        first_attempt = interrupted["attempts"][0]["attemptId"]

        resumed = self.executor.execute(definition, callbacks=effects.callbacks())

        completed = self.store.read()
        self.validate_journal(completed)
        self.assertEqual("MUTABLE_COMPLETED", resumed.status)
        self.assertNotEqual(first_attempt, resumed.attempt_id)
        self.assertEqual(["stage", "verify_staged"], effects.calls)
        self.assertEqual(
            ["COMPLETED", "COMPLETED", "COMPLETED"],
            [step["state"] for step in completed["steps"]],
        )
        self.assertEqual(3, completed["executionPlan"]["firstIncompleteOrdinal"])
        self.assertEqual("FAILED", completed["attempts"][0]["outcome"])
        self.assertEqual("SUCCEEDED", completed["attempts"][1]["outcome"])

        repeated = self.executor.execute(definition, callbacks=effects.callbacks())
        self.assertEqual("MUTABLE_COMPLETED", repeated.status)
        self.assertEqual(["stage", "verify_staged"], effects.calls)

    def test_crash_after_effect_marks_expected_after_without_repeating_effect(
        self,
    ) -> None:
        definition = self._definition(self.stage, self.verify)
        effects = _Effects(
            {
                "stage": self.stage.before,
                "verify_staged": self.verify.before,
            }
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "stage"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                failure_injector=crash,
            )

        self.assertEqual(["stage"], effects.calls)
        self.assertEqual("INTENT_DURABLE", self.store.read()["steps"][1]["state"])

        self.executor.execute(definition, callbacks=effects.callbacks())

        self.assertEqual(["stage", "verify_staged"], effects.calls)
        self.assertEqual(
            self.stage.expected_after.to_document(),
            self.store.read()["steps"][1]["observedAfter"],
        )

    def test_effect_produced_projection_is_persisted_and_replayed_exactly(
        self,
    ) -> None:
        definition = self._definition(self.stage)
        actual_before = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.before.value),
                "treeSha256": "4" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        actual_after = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.expected_after.value),
                "treeSha256": "5" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        effects = _Effects({"stage": actual_before})

        def apply(step: StepDefinitionV2) -> None:
            effects.calls.append(step.kind)
            effects.states[step.kind] = actual_after

        callbacks = StepCallbacksV2(
            observe=effects.observe,
            apply=apply,
            matches_before=lambda observed, _definition: observed == actual_before,
            matches_after=lambda observed, _definition: observed == actual_after,
        )

        result = self.executor.execute(definition, callbacks=callbacks)

        self.assertEqual("MUTABLE_COMPLETED", result.status)
        self.assertEqual(["stage"], effects.calls)
        self.assertEqual(
            actual_after.to_document(),
            self.store.read()["steps"][1]["observedAfter"],
        )

        repeated = self.executor.execute(definition, callbacks=callbacks)
        self.assertEqual("MUTABLE_COMPLETED", repeated.status)
        self.assertEqual(["stage"], effects.calls)

        effects.states["stage"] = _projection(
            "tree-object-v2",
            {
                **dict(actual_after.value),
                "treeSha256": "6" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        with self.assertRaises(RecoveryStateAmbiguousV2):
            self.executor.execute(definition, callbacks=callbacks)

    def test_effect_produced_after_crash_is_completed_without_reapplying(
        self,
    ) -> None:
        definition = self._definition(self.stage)
        actual_after = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.expected_after.value),
                "treeSha256": "7" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        effects = _Effects({"stage": self.stage.before})

        def apply(step: StepDefinitionV2) -> None:
            effects.calls.append(step.kind)
            effects.states[step.kind] = actual_after

        callbacks = StepCallbacksV2(
            observe=effects.observe,
            apply=apply,
            matches_after=lambda observed, _definition: observed == actual_after,
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=callbacks,
                failure_injector=crash,
            )

        self.assertEqual(["stage"], effects.calls)
        self.executor.execute(definition, callbacks=callbacks)
        self.assertEqual(["stage"], effects.calls)
        self.assertEqual(
            actual_after.to_document(),
            self.store.read()["steps"][1]["observedAfter"],
        )

    def test_indistinguishable_verify_replays_only_with_explicit_permission(
        self,
    ) -> None:
        definition = self._definition(self.stage, self.verify)
        effects = _Effects(
            {
                "stage": self.stage.before,
                "verify_staged": self.verify.before,
            }
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "verify_staged"
            ):
                raise InjectedCrashV2(point, kind)

        callbacks = StepCallbacksV2(
            observe=effects.observe,
            apply=effects.apply,
            replay_safe_when_indistinguishable=(
                lambda _observed, step: step.kind == "verify_staged"
            ),
        )
        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=callbacks,
                failure_injector=crash,
            )

        self.assertEqual(["stage"], effects.calls)
        result = self.executor.execute(definition, callbacks=callbacks)

        self.assertEqual("MUTABLE_COMPLETED", result.status)
        self.assertEqual(["stage", "verify_staged"], effects.calls)
        self.assertEqual(
            self.verify.expected_after.to_document(),
            self.store.read()["steps"][2]["observedAfter"],
        )

    def test_third_state_closes_recovery_without_another_effect(self) -> None:
        definition = self._definition(self.stage)
        effects = _Effects({"stage": self.stage.before})

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                failure_injector=crash,
            )
        effects.states["stage"] = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.expected_after.value),
                "treeSha256": "3" * 64,
            },
            "codex-smart/tree-object/v2",
        )

        with self.assertRaises(RecoveryStateAmbiguousV2):
            self.executor.execute(definition, callbacks=effects.callbacks())

        journal = self.store.read()
        self.assertEqual([], effects.calls)
        self.assertEqual("INTENT_DURABLE", journal["steps"][1]["state"])
        self.assertEqual("FAILED", journal["attempts"][-1]["outcome"])

    def test_exact_partial_effect_resumes_only_after_durable_intent(self) -> None:
        definition = self._definition(self.stage)
        effects = _Effects({"stage": self.stage.before})
        partial = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.before.value),
                "treeSha256": "8" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        callbacks = StepCallbacksV2(
            observe=effects.observe,
            apply=effects.apply,
            matches_intent_resume=lambda observed, _step: observed == partial,
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=callbacks,
                failure_injector=crash,
            )
        effects.states["stage"] = partial

        result = self.executor.execute(definition, callbacks=callbacks)

        self.assertEqual("MUTABLE_COMPLETED", result.status)
        self.assertEqual(["stage"], effects.calls)
        self.assertEqual(
            self.stage.expected_after.to_document(),
            self.store.read()["steps"][1]["observedAfter"],
        )

    def test_exact_partial_effect_is_rejected_while_step_is_planned(self) -> None:
        definition = self._definition(self.stage)
        partial = _projection(
            "tree-object-v2",
            {
                **dict(self.stage.before.value),
                "treeSha256": "8" * 64,
            },
            "codex-smart/tree-object/v2",
        )
        effects = _Effects({"stage": partial})
        callbacks = StepCallbacksV2(
            observe=effects.observe,
            apply=effects.apply,
            matches_intent_resume=lambda observed, _step: observed == partial,
        )

        with self.assertRaises(RecoveryStateAmbiguousV2):
            self.executor.execute(definition, callbacks=callbacks)

        self.assertEqual([], effects.calls)
        self.assertEqual("PLANNED", self.store.read()["steps"][1]["state"])

    def test_forward_only_transition_is_durable_before_its_completion_record(
        self,
    ) -> None:
        provisional = ExecutionPlanV2(
            plan_id=PLAN_ID,
            machine_id="apply",
            selected_branch_id="update-matched-active",
            composed_step_kinds=("gate_close", "recovery_forward_only"),
        )
        transition = StepDefinitionV2(
            kind="recovery_forward_only",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "forward-only",
                "journalPath": str(self.journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=_journal_state(
                self.journal_path,
                provisional.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="REVERSIBLE",
                generation=2,
            ),
            expected_after=_journal_state(
                self.journal_path,
                provisional.plan_definition_fingerprint,
                phase="APPLYING",
                recovery_policy="FORWARD_ONLY",
                generation=3,
            ),
        )
        definition = self._definition(transition)
        effects = _Effects({})

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                failure_injector=crash,
            )

        interrupted = self.store.read()
        self.assertEqual("FORWARD_ONLY", interrupted["recoveryPolicy"])
        self.assertEqual("INTENT_DURABLE", interrupted["steps"][1]["state"])
        self.assertEqual([], effects.calls)

        self.executor.execute(definition, callbacks=effects.callbacks())

        completed = self.store.read()
        self.assertEqual("FORWARD_ONLY", completed["recoveryPolicy"])
        self.assertEqual("COMPLETED", completed["steps"][1]["state"])
        self.assertEqual([], effects.calls)

    def test_frozen_terminal_replays_proven_receipt_without_rewriting_journal(
        self,
    ) -> None:
        definition = self._terminal_definition()
        effects = _Effects({"stage": self.stage.before})
        terminal = _TerminalEffects()

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_RECEIPT_BEFORE_JOURNAL_DELETE:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                failure_injector=crash,
            )

        frozen_bytes = self.journal_path.read_bytes()
        frozen = self.store.read()
        self.validate_journal(frozen)
        self.assertEqual("TERMINAL_FROZEN", frozen["phase"])
        self.assertEqual("FORWARD_ONLY", frozen["recoveryPolicy"])
        self.assertEqual(1, terminal.publish_calls)
        terminal_intent = dict(frozen["terminalDeleteIntent"])
        terminal_fingerprint = terminal_intent.pop("terminalStateFingerprint")
        self.assertEqual(
            domain_fingerprint("codex-smart/terminal-state/v2", terminal_intent),
            terminal_fingerprint,
        )
        self.assertEqual(
            [step["stepId"] for step in frozen["steps"]],
            frozen["terminalDeleteIntent"]["completedStepIds"],
        )
        frozen_attempt = frozen["attempts"][-1]["attemptId"]

        with mock.patch(
            "codex_smart_subagents.lifecycle_operation_v2.os.replace",
            wraps=os.replace,
        ) as replace:
            result = self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
            )

        self.assertEqual("COMPLETED", result.status)
        self.assertNotEqual(frozen_attempt, result.attempt_id)
        self.assertEqual(0, replace.call_count)
        self.assertEqual(1, terminal.publish_calls)
        self.assertFalse(self.journal_path.exists())
        self.assertGreaterEqual(terminal.proof_calls, 3)
        self.assertEqual(
            {frozen["journalFingerprint"]}, set(terminal.frozen_fingerprints)
        )
        self.assertNotEqual(b"", frozen_bytes)

    def test_terminal_journal_is_not_closed_until_receipt_is_proven(self) -> None:
        definition = self._terminal_definition()
        effects = _Effects({"stage": self.stage.before})
        terminal = _TerminalEffects(prove_after_publish=False)

        with self.assertRaises(TerminalProofFailedV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
            )

        frozen = self.store.read()
        self.assertEqual("TERMINAL_FROZEN", frozen["phase"])
        self.assertEqual(1, terminal.publish_calls)
        self.assertTrue(self.journal_path.exists())

    def test_uninstall_replays_each_frozen_effect_without_republishing(self) -> None:
        definition = self._uninstall_definition()
        terminal = _UninstallTerminalEffects()
        effects = _Effects({})

        def crash_after_receipt(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_RECEIPT_BEFORE_JOURNAL_DELETE:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                failure_injector=crash_after_receipt,
            )
        frozen_bytes = self.journal_path.read_bytes()
        self.assertEqual(1, terminal.publish_calls)
        self.assertEqual(0, terminal.tombstone_publish_calls)

        def crash_after_tombstone(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_TOMBSTONE_BEFORE_JOURNAL_DELETE:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                failure_injector=crash_after_tombstone,
            )
        self.assertEqual(frozen_bytes, self.journal_path.read_bytes())
        self.assertEqual(1, terminal.publish_calls)
        self.assertEqual(1, terminal.tombstone_publish_calls)

        result = self.executor.execute(
            definition,
            callbacks=effects.callbacks(),
            terminal_callbacks=terminal.callbacks(),
        )

        self.assertEqual("COMPLETED", result.status)
        self.assertEqual(1, terminal.publish_calls)
        self.assertEqual(1, terminal.tombstone_publish_calls)
        self.assertFalse(self.journal_path.exists())

    def test_rollback_uses_the_same_bound_commit_terminal_protocol(self) -> None:
        definition = self._terminal_definition(
            kind="rollback",
            operation="rollback",
            machine_id="rollback",
            selected_branch_id="rollback-matched-active",
        )
        terminal = _TerminalEffects()

        result = self.executor.execute(
            definition,
            callbacks=_Effects({"stage": self.stage.before}).callbacks(),
            terminal_callbacks=terminal.callbacks(),
        )

        self.assertEqual("COMPLETED", result.status)
        self.assertEqual(1, terminal.publish_calls)
        self.assertFalse(self.journal_path.exists())

    def test_terminal_fingerprint_rejects_tamper_after_freeze(self) -> None:
        definition = self._terminal_definition()

        def crash(point: FailurePointV2, kind: str) -> None:
            if point is FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT:
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                definition,
                callbacks=_Effects({"stage": self.stage.before}).callbacks(),
                terminal_callbacks=_TerminalEffects().callbacks(),
                failure_injector=crash,
            )

        tampered = self.store.read()
        tampered["terminalDeleteIntent"]["receiptPath"] = str(
            self.root / "receipts" / "other.json"
        )
        projection = {
            key: value
            for key, value in tampered.items()
            if key != "journalFingerprint"
        }
        tampered["journalFingerprint"] = domain_fingerprint(
            "codex-smart/operation-journal/v2", projection
        )
        self.journal_path.write_bytes(canonical_json_bytes(tampered))

        with self.assertRaisesRegex(
            JournalIntegrityErrorV2, "terminalStateFingerprint mismatch"
        ):
            self.store.read()

    def test_invalid_absence_target_cannot_delete_the_journal(self) -> None:
        definition = self._terminal_definition(
            journal_absence_target=_absence(
                self.journal_path,
                token=30,
                parent_inode_offset=1,
            )
        )
        terminal = _TerminalEffects()

        with self.assertRaisesRegex(
            JournalIntegrityErrorV2, "parent identity changed"
        ):
            self.executor.execute(
                definition,
                callbacks=_Effects({"stage": self.stage.before}).callbacks(),
                terminal_callbacks=terminal.callbacks(),
            )

        self.assertTrue(self.journal_path.exists())

    def test_shared_read_waits_for_another_process_exclusive_lock(self) -> None:
        self.executor.begin(self.definition)
        script = "\n".join(
            (
                "import fcntl, sys",
                "handle = open(sys.argv[1], 'r+b', buffering=0)",
                "fcntl.flock(handle.fileno(), fcntl.LOCK_EX)",
                "print('locked', flush=True)",
                "sys.stdin.readline()",
            )
        )
        holder = subprocess.Popen(
            [sys.executable, "-c", script, str(self.lock_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        reader_finished = threading.Event()
        reader_error: list[BaseException] = []

        def read_journal() -> None:
            try:
                self.store.read()
            except BaseException as error:  # pragma: no cover - отчёт потока
                reader_error.append(error)
            finally:
                reader_finished.set()

        thread = threading.Thread(target=read_journal, daemon=True)
        try:
            assert holder.stdout is not None
            self.assertEqual("locked", holder.stdout.readline().strip())
            thread.start()
            self.assertFalse(reader_finished.wait(0.2))
            assert holder.stdin is not None
            holder.stdin.write("release\n")
            holder.stdin.flush()
            self.assertTrue(reader_finished.wait(2.0))
            self.assertEqual([], reader_error)
        finally:
            if holder.stdin is not None and not holder.stdin.closed:
                holder.stdin.close()
            holder.wait(timeout=2.0)
            if holder.stdout is not None:
                holder.stdout.close()
            if holder.stderr is not None:
                holder.stderr.close()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
