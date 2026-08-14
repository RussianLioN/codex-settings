from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    _LIFECYCLE_SCHEMA_SHA256,
)
from codex_smart_subagents.activation_transition_v2 import (  # noqa: E402
    PreparedManifestCommitV2,
    _manifest_projection as _prepared_manifest_projection,
    _prepared_manifest_fingerprint,
)
from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    capture_directory_binding_v2,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    RollbackEvidenceV2,
)
from codex_smart_subagents.rollback_manifest_preparation_v2 import (  # noqa: E402
    RollbackManifestPreparationReceiptV2,
    rollback_operation_id_v2,
)
from codex_smart_subagents.installer_rollback_composition_v2 import (  # noqa: E402
    ROLLBACK_MATCHED_ACTIVE_STEPS_V2,
    RollbackExternalStepBindingsV2,
    RollbackStepBindingV2,
    build_rollback_external_step_bindings_v2,
    build_rollback_launcher_binding_v2,
    build_rollback_recovery_composition_v2,
    build_rollback_composition_v2,
    read_rollback_external_artifacts_v2,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UpdateStepPortV2,
)
from codex_smart_subagents.installer_update_composition_v2 import (  # noqa: E402
    LauncherBindingV2,
    build_launcher_update_plan_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    FailurePointV2,
    InjectedCrashV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StateBundleV2,
    StepDefinitionV2,
    StoppedControllerLineageV2,
    TransitionSourceReceiptV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)


SCHEMA_SHA256 = _LIFECYCLE_SCHEMA_SHA256
INSTALLATION_ID = "ins2_" + "1" * 32
CURRENT_OPERATION_ID = "op2_" + "2" * 32
PREVIOUS_OPERATION_ID = "op2_" + "3" * 32
PLAN_ID = "pl2_" + "5" * 32
CURRENT_ACTIVATION_ID = "act2_" + "6" * 64
PREVIOUS_ACTIVATION_ID = "act2_" + "7" * 64
CURRENT_DATABASE_ID = "db2_" + "8" * 32
PREVIOUS_DATABASE_ID = "db2_" + "9" * 32
PREPARATION_RECEIPT_FINGERPRINT = "a" * 64


def _projection(
    schema_id: str,
    value: dict[str, object],
    domain: str,
) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": SCHEMA_SHA256,
        "value": copy.deepcopy(value),
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _file_value(path: Path) -> dict[str, object]:
    info = path.lstat()
    payload = path.read_bytes()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{info.st_mode & 0o777:03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _activation(
    root: Path,
    activation_id: str,
    database_id: str,
) -> ProjectionV2:
    directory = root / "activations" / activation_id
    marketplace = directory / "marketplace"
    marketplace.mkdir(parents=True, mode=0o700)
    activation_file = directory / "activation.json"
    activation_file.write_bytes(
        canonical_json_bytes(
            {
                "activationId": activation_id,
                "databaseId": database_id,
            }
        )
    )
    activation_file.chmod(0o600)
    value = {
        "directory": {
            "path": str(directory),
            "device": directory.stat().st_dev,
            "inode": directory.stat().st_ino,
            "ownerUid": os.getuid(),
            "ownerGid": os.getgid(),
            "mode": "0700",
            "entryCount": 2,
            "treeSha256": "b" * 64,
        },
        "activationFile": _file_value(activation_file),
        "activationId": activation_id,
        "activationFingerprint": activation_id.removeprefix("act2_"),
        "generationId": "gen2_" + "c" * 64,
        "release": "0.2.0",
        "databaseId": database_id,
        "databaseIdentityFingerprint": "d" * 64,
        "marketplaceTreeSha256": "e" * 64,
        "generationTreeSha256": "f" * 64,
    }
    return _projection("activation-v2", value, "codex-smart/journal-state/v2")


def _database(path: Path, database_id: str, activation: ProjectionV2) -> ProjectionV2:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(database_id.encode("ascii"))
    path.chmod(0o600)
    binding_file = _file_value(path)
    del binding_file["size"]
    del binding_file["sha256"]
    identity = {
        "databaseId": database_id,
        "activationBindingNonce": "a" * 64,
        "activationId": activation.value["activationId"],
        "activationFingerprint": activation.value["activationFingerprint"],
    }
    return _projection(
        "database-binding-v2",
        {
            **binding_file,
            "databaseId": database_id,
            "databaseIdentity": identity,
            "databaseIdentityFingerprint": domain_fingerprint(
                "codex-smart/database-identity/v2", identity
            ),
            "databaseVersion": "0.2.0",
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": "b" * 64,
            "schemaArtifactSha256": "c" * 64,
            "activationIdentity": {
                "activationId": activation.value["activationId"],
                "activationFingerprint": activation.value["activationFingerprint"],
            },
        },
        "codex-smart/database-binding/v2",
    )


def _manifest_projection(
    path: Path,
    document: dict[str, object],
    *,
    file_value: dict[str, object] | None = None,
) -> ProjectionV2:
    active = document["activeActivation"]
    previous = document["previousActivation"]
    assert isinstance(active, dict)
    assert previous is None or isinstance(previous, dict)
    value = {
        "file": _file_value(path) if file_value is None else copy.deepcopy(file_value),
        "schemaVersion": 2,
        "installationId": INSTALLATION_ID,
        "release": "0.2.0",
        "pluginId": "codex-smart-subagents",
        "stateHome": document["stateHome"],
        "activeActivationId": active["activationId"],
        "previousActivationId": (
            None if previous is None else previous["activationId"]
        ),
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
    return _projection("manifest-v2", value, "codex-smart/journal-state/v2")


def _receipt(
    *,
    operation_id: str,
    manifest: ProjectionV2,
    activation: ProjectionV2,
    database: ProjectionV2,
    manifest_document: dict[str, object],
    transition_lineage: ActivationTransitionLineageV2,
) -> dict[str, object]:
    unsigned = {
        "schemaVersion": 2,
        "receiptKind": "activation-commit",
        "installationId": INSTALLATION_ID,
        "operationId": operation_id,
        "frozenJournalFingerprint": "1" * 64,
        "manifest": manifest.to_document(),
        "manifestDocument": copy.deepcopy(manifest_document),
        "transitionLineage": transition_lineage.to_document(),
        "activation": activation.to_document(),
        "databaseBinding": database.to_document(),
        "journalAbsenceTarget": _projection(
            "absence-proof-v2",
            {"operationId": operation_id},
            "codex-smart/absence-proof-projection/v2",
        ).to_document(),
        "controllerIdentity": "2" * 64,
        "completedStepIds": ["st2_" + "3" * 32],
        "completedAt": "2026-07-19T10:00:00Z",
    }
    return {
        **unsigned,
        "receiptFingerprint": domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", unsigned
        ),
    }


def _empty_bundle(*, activation: ProjectionV2 | None) -> StateBundleV2:
    return StateBundleV2(
        file_objects=(),
        tree_objects=(),
        symlinks=(),
        manifest=None,
        activation=activation,
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


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, 13, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


class _Ids:
    def __init__(self) -> None:
        self.value = 1

    def __call__(self, prefix: str) -> str:
        result = f"{prefix}_{self.value:032x}"
        self.value += 1
        return result


class InstallerRollbackCompositionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rollback-composition-v2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.managed = self.root / "managed"
        self.managed.mkdir(mode=0o700)
        self.current_activation = _activation(
            self.managed, CURRENT_ACTIVATION_ID, CURRENT_DATABASE_ID
        )
        self.previous_activation = _activation(
            self.managed, PREVIOUS_ACTIVATION_ID, PREVIOUS_DATABASE_ID
        )
        self.marketplace_link = self.managed / "marketplace-current"
        os.symlink(
            f"activations/{CURRENT_ACTIVATION_ID}/marketplace",
            self.marketplace_link,
        )
        for name in ("gateway", "admin"):
            for activation_id in (
                CURRENT_ACTIVATION_ID,
                PREVIOUS_ACTIVATION_ID,
            ):
                target = (
                    self.managed / "activations" / activation_id / "marketplace" / name
                )
                target.write_text(f"{activation_id}:{name}", encoding="utf-8")
                target.chmod(0o700)
        self.launcher_root = self.root / "bin"
        self.launcher_root.mkdir(mode=0o700)
        self.launcher_links: list[dict[str, str]] = []
        for name in ("codex-smart", "codex-smart-admin"):
            role = "gateway" if name == "codex-smart" else "admin"
            path = self.launcher_root / name
            target = self.marketplace_link / role
            os.symlink(str(target), path)
            self.launcher_links.append({"path": str(path), "target": str(target)})
        self.manifest_path = self.root / "manifest.json"
        self.current_pointer = self._pointer(self.current_activation)
        self.previous_pointer = self._pointer(self.previous_activation)
        interface_evidence = json.loads(
            (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
                encoding="utf-8"
            )
        )["base"]
        self.manifest_document = {
            "schemaVersion": 2,
            "installationId": INSTALLATION_ID,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "stateHome": str(self.root / "state"),
            "sourceLocator": {
                "lexicalPath": str(self.root / "bin" / "codex"),
                "resolvedPathAtCapture": str(self.root / "bin" / "codex"),
                "argv0Policy": "lexical",
                "sourceObservedSha256": "3" * 64,
            },
            "codexSnapshot": {
                "absolutePath": str(self.root / "snapshots" / "codex"),
                "sha256": "3" * 64,
            },
            "activeActivation": self.current_pointer,
            "previousActivation": self.previous_pointer,
            "interfaceEvidence": interface_evidence,
            "routingPolicyFingerprint": "4" * 64,
            "bundledCatalogFingerprint": "5" * 64,
            "artifacts": [],
            "originalBackup": {
                "type": "absent",
                "path": str(self.root / "original-backup"),
                "parentPath": str(self.root),
                "name": "original-backup",
            },
            "lastCommittedOperation": CURRENT_OPERATION_ID,
            "databaseSchemaVersion": 2,
            "extensions": {},
        }
        self.previous_manifest_source = copy.deepcopy(self.manifest_document)
        self.previous_manifest_source["activeActivation"] = self.previous_pointer
        self.previous_manifest_source["previousActivation"] = None
        self.previous_manifest_source["lastCommittedOperation"] = PREVIOUS_OPERATION_ID
        self.manifest_path.write_bytes(canonical_json_bytes(self.manifest_document))
        self.manifest_path.chmod(0o600)
        current_manifest = _manifest_projection(
            self.manifest_path, self.manifest_document
        )
        current_database = _database(
            self.root / "state" / "current.sqlite3",
            CURRENT_DATABASE_ID,
            self.current_activation,
        )
        previous_database = _database(
            self.root / "state" / "previous.sqlite3",
            PREVIOUS_DATABASE_ID,
            self.previous_activation,
        )
        receipts_root = self.root / "receipts" / INSTALLATION_ID
        receipts_root.mkdir(parents=True, mode=0o700)
        source_path = receipts_root / f"{CURRENT_OPERATION_ID}.preparation.json"
        source_document = {
            "installationId": INSTALLATION_ID,
            "operationId": CURRENT_OPERATION_ID,
            "receiptFingerprint": "a" * 64,
        }
        source_path.write_bytes(canonical_json_bytes(source_document))
        source_path.chmod(0o600)
        current_lineage = ActivationTransitionLineageV2(
            transition_kind="update",
            source_receipt=TransitionSourceReceiptV2(
                receipt_kind="activation-preparation",
                path=source_path,
                raw_sha256=hashlib.sha256(
                    canonical_json_bytes(source_document)
                ).hexdigest(),
                receipt_fingerprint="a" * 64,
            ),
            activation_proof_fingerprint="b" * 64,
            shutdown_command_ids=ControllerShutdownLineageV2(
                maintenance_begin="cc2_" + "1" * 32,
                maintenance_strengthen="cc2_" + "2" * 32,
                shutdown="cc2_" + "3" * 32,
            ),
            stopped_controller=StoppedControllerLineageV2(
                operation_id=CURRENT_OPERATION_ID,
                activation_id=PREVIOUS_ACTIVATION_ID,
                database_id=PREVIOUS_DATABASE_ID,
                controller_identity="2" * 64,
                control_epoch=4,
            ),
        )
        current_receipt = _receipt(
            operation_id=CURRENT_OPERATION_ID,
            manifest=current_manifest,
            activation=self.current_activation,
            database=current_database,
            manifest_document=self.manifest_document,
            transition_lineage=current_lineage,
        )
        previous_file = copy.deepcopy(dict(current_manifest.value["file"]))
        previous_raw = canonical_json_bytes(self.previous_manifest_source)
        previous_file["size"] = len(previous_raw)
        previous_file["sha256"] = hashlib.sha256(previous_raw).hexdigest()
        previous_manifest = _manifest_projection(
            self.manifest_path,
            self.previous_manifest_source,
            file_value=previous_file,
        )
        previous_receipt = _receipt(
            operation_id=PREVIOUS_OPERATION_ID,
            manifest=previous_manifest,
            activation=self.previous_activation,
            database=previous_database,
            manifest_document=self.previous_manifest_source,
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="initial",
                source_receipt=None,
                activation_proof_fingerprint=None,
                shutdown_command_ids=None,
                stopped_controller=None,
            ),
        )
        self.evidence = RollbackEvidenceV2(
            manifest_path=self.manifest_path,
            receipts_root=receipts_root,
            activations_root=self.managed / "activations",
            marketplace_link=self.marketplace_link,
            installation_id=INSTALLATION_ID,
            current_operation_id=CURRENT_OPERATION_ID,
            previous_operation_id=PREVIOUS_OPERATION_ID,
            current_activation_id=CURRENT_ACTIVATION_ID,
            previous_activation_id=PREVIOUS_ACTIVATION_ID,
            current_pointer=self.current_pointer,
            previous_pointer=self.previous_pointer,
            manifest_document=self.manifest_document,
            manifest_file_projection=_file_value(self.manifest_path),
            current_receipt_path=receipts_root / f"{CURRENT_OPERATION_ID}.commit.json",
            previous_receipt_path=receipts_root
            / f"{PREVIOUS_OPERATION_ID}.commit.json",
            current_receipt=current_receipt,
            previous_receipt=previous_receipt,
            current_manifest_projection=current_manifest,
            current_activation_projection=self.current_activation,
            previous_activation_projection=self.previous_activation,
            previous_database_binding=previous_database,
            evidence_fingerprint="6" * 64,
        )
        self.rollback_operation_id = rollback_operation_id_v2(self.evidence)
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        self.execution_plan = LifecyclePlanRegistryV2.from_document(automaton).select(
            machine_id="rollback",
            branch_id="rollback-matched-active",
            plan_id=PLAN_ID,
        )
        self.installer_receipt_path = self.root / "installer-receipt.json"
        self.installer_receipt = {
            "schemaVersion": 2,
            "kind": "codex-smart-installer-receipt/v2",
            "sourceDigest": "7" * 64,
            "installationId": INSTALLATION_ID,
            "activationId": CURRENT_ACTIVATION_ID,
            "codexHome": str(self.root / "codex-home"),
            "codexBinary": str(self.root / "bin" / "codex"),
            "stateHome": str(self.root / "state"),
            "marketplacePath": str(self.marketplace_link),
            "registeredMarketplacePath": str(
                (
                    self.managed / "activations" / CURRENT_ACTIVATION_ID / "marketplace"
                ).resolve(strict=True)
            ),
            "links": self.launcher_links,
            "marketplaceName": "codex-settings-adaptive",
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "extensions": {
                "sourceLineage": {
                    "schemaVersion": 1,
                    "generation": 2,
                    "implementationDigest": "e" * 64,
                }
            },
        }
        self.installer_receipt_path.write_bytes(
            canonical_json_bytes(self.installer_receipt)
        )
        self.installer_receipt_path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _pointer(activation: ProjectionV2) -> dict[str, object]:
        return {
            "activationId": activation.value["activationId"],
            "activationFingerprint": activation.value["activationFingerprint"],
            "symlinkTarget": (
                f"activations/{activation.value['activationId']}/marketplace"
            ),
            "generationId": activation.value["generationId"],
            "databaseId": activation.value["databaseId"],
        }

    def test_prepared_manifest_is_bound_to_swapped_receipt_pointers(self) -> None:
        prepared = self._prepared_manifest()

        self.assertEqual(
            self.previous_pointer, prepared.manifest_document["activeActivation"]
        )
        self.assertEqual(
            self.current_pointer, prepared.manifest_document["previousActivation"]
        )
        self.assertEqual(
            self.rollback_operation_id,
            prepared.manifest_document["lastCommittedOperation"],
        )
        self.assertEqual(
            prepared.prepared_file.value["inode"],
            prepared.expected_after.value["file"]["inode"],
        )
        self.assertEqual(
            str(self.manifest_path),
            prepared.expected_after.value["file"]["path"],
        )

    def test_external_artifacts_bind_current_receipt_to_previous_marketplace(
        self,
    ) -> None:
        artifacts = read_rollback_external_artifacts_v2(
            evidence=self.evidence,
            installer_receipt_path=self.installer_receipt_path,
        )

        self.assertEqual(
            Path(self.installer_receipt["registeredMarketplacePath"]),
            artifacts.current_registered_marketplace,
        )
        self.assertEqual(
            (
                self.managed / "activations" / PREVIOUS_ACTIVATION_ID / "marketplace"
            ).resolve(strict=True),
            artifacts.previous_registered_marketplace,
        )
        self.assertEqual(
            tuple(Path(item["path"]) for item in self.launcher_links),
            tuple(binding.path for binding in artifacts.launchers),
        )

        Path(self.launcher_links[0]["path"]).unlink()
        os.symlink("/tmp/foreign", self.launcher_links[0]["path"])
        with self.assertRaises(Exception):
            read_rollback_external_artifacts_v2(
                evidence=self.evidence,
                installer_receipt_path=self.installer_receipt_path,
            )

    def test_production_launcher_adapter_reproves_stable_lexical_links(self) -> None:
        bindings = []
        for ordinal, item in enumerate(self.launcher_links):
            role = "gateway" if ordinal == 0 else "admin"
            bindings.append(
                LauncherBindingV2(
                    name=Path(item["path"]).name,
                    role=role,
                    path=Path(item["path"]),
                    target=Path(item["target"]),
                    expected_resolved_target=(
                        self.managed
                        / "activations"
                        / PREVIOUS_ACTIVATION_ID
                        / "marketplace"
                        / role
                    ),
                )
            )
        plan = build_launcher_update_plan_v2(
            installation_id=INSTALLATION_ID,
            operation_id=self.rollback_operation_id,
            bindings=tuple(bindings),
        )
        binding = build_rollback_launcher_binding_v2(plan=plan)

        temporary = self.marketplace_link.with_name(".rollback-launcher-test")
        os.symlink(self.previous_pointer["symlinkTarget"], temporary)
        os.replace(temporary, self.marketplace_link)
        observed = binding.port.observe(binding.definition)
        binding.port.apply(binding.definition)

        self.assertEqual(binding.definition.expected_after, observed)
        self.assertEqual(
            tuple(item["target"] for item in self.launcher_links),
            tuple(os.readlink(item["path"]) for item in self.launcher_links),
        )

    def test_composition_keeps_exact_normative_order(self) -> None:
        prepared = self._prepared_manifest()
        external = self._external_bindings()
        artifacts = read_rollback_external_artifacts_v2(
            evidence=self.evidence,
            installer_receipt_path=self.installer_receipt_path,
        )

        composition = build_rollback_composition_v2(
            evidence=self.evidence,
            execution_plan=self.execution_plan,
            operation_id=self.rollback_operation_id,
            journal_path=self.root / "operation.transaction.json",
            prepared_manifest=prepared,
            preparation_receipt=self._preparation_receipt(prepared),
            external_bindings=external,
            external_artifacts=artifacts,
        )

        definition = composition.definition
        actual = (definition.gate_close.kind,) + tuple(
            step.kind for step in definition.mutable_steps
        )
        assert definition.terminal is not None
        actual += (
            definition.terminal.freeze.kind,
            *definition.terminal.post_freeze_action_kinds,
        )
        self.assertEqual(ROLLBACK_MATCHED_ACTIVE_STEPS_V2, actual)
        self.assertEqual(
            self.previous_activation,
            definition.desired.activation if definition.desired else None,
        )
        self.assertEqual(
            self.previous_activation,
            definition.terminal.receipt_payload.activation,
        )
        manifest_restore = next(
            step for step in definition.mutable_steps if step.kind == "manifest_restore"
        )
        self.assertEqual(
            {
                "actionKind": "file-mutation",
                "method": "atomic-prepared-manifest-replace",
                "sourcePath": str(prepared.prepared_path),
                "targetPath": str(self.manifest_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            manifest_restore.action,
        )

    def test_named_external_factory_checks_the_full_control_chain(self) -> None:
        source = self._external_bindings()
        controller_kinds = {
            "maintenance_begin",
            "wait_runtime_quiescent",
            "maintenance_strengthen",
            "controller_shutdown",
            "controller_previous_accept",
            "maintenance_resume",
        }
        assembled = build_rollback_external_step_bindings_v2(
            evidence=self.evidence,
            operation_id=self.rollback_operation_id,
            controller_bindings={
                kind: source.require(kind) for kind in controller_kinds
            },
            shutdown_socket_cleanup=source.require("shutdown_socket_cleanup"),
            registry_restore=source.require("registry_restore"),
            launchers_restore=source.require("launchers_restore"),
            controller_candidate_spawn=source.require("controller_candidate_spawn"),
            verify_candidate=source.require("verify_candidate"),
        )

        self.assertEqual(
            source.require("controller_previous_accept"),
            assembled.require("controller_previous_accept"),
        )

    def test_initial_journal_contains_every_planned_step_and_terminal_snapshot(
        self,
    ) -> None:
        composition, _external = self._composition()
        journal_path = self.root / "operation.transaction.json"
        executor = OperationExecutorV2(
            store=OperationJournalStoreV2(
                journal_path=journal_path,
                lock_path=self.root / "operation.lock",
                validate_document=lambda _document: None,
            ),
            now=_Clock(),
            id_factory=_Ids(),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "maintenance_begin"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            executor.execute(
                composition.definition,
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                failure_injector=crash,
            )

        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual(15, len(journal["steps"]))
        self.assertEqual(
            list(ROLLBACK_MATCHED_ACTIVE_STEPS_V2[:15]),
            [step["kind"] for step in journal["steps"]],
        )
        self.assertEqual("INTENT_DURABLE", journal["steps"][1]["state"])
        self.assertTrue(
            all(step["state"] == "PLANNED" for step in journal["steps"][2:])
        )
        self.assertIsNotNone(journal["terminalDefinitionSnapshot"])

    def test_full_initial_journal_passes_normative_schema(self) -> None:
        composition, _external = self._composition()
        journal_path = self.root / "operation.transaction.json"
        store = OperationJournalStoreV2(
            journal_path=journal_path,
            lock_path=self.root / "operation.lock",
            validate_document=build_operation_journal_validator_v2(
                ROOT / "docs" / "contracts" / "schemas"
            ),
        )
        executor = OperationExecutorV2(
            store=store,
            now=_Clock(),
            id_factory=_Ids(),
        )

        run = executor.begin(composition.definition)
        journal = store.read()

        self.assertEqual("STARTED", run.status)
        self.assertEqual("rollback", journal["kind"])
        self.assertEqual(15, len(journal["steps"]))
        self.assertIsNotNone(journal["terminalDefinitionSnapshot"])

    def test_recovery_after_link_effect_uses_persisted_definition_and_finishes(
        self,
    ) -> None:
        composition, external = self._composition()
        journal_path = self.root / "operation.transaction.json"
        executor = OperationExecutorV2(
            store=OperationJournalStoreV2(
                journal_path=journal_path,
                lock_path=self.root / "operation.lock",
                validate_document=lambda _document: None,
            ),
            now=_Clock(),
            id_factory=_Ids(),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "activation_link_restore"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            executor.execute(
                composition.definition,
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                failure_injector=crash,
            )
        self.assertEqual(
            self.previous_pointer["symlinkTarget"],
            os.readlink(self.marketplace_link),
        )

        recovered = build_rollback_recovery_composition_v2(
            evidence=self.evidence,
            definition=composition.definition,
            prepared_manifest=composition.prepared_manifest,
            preparation_receipt_fingerprint=(
                composition.preparation_receipt_fingerprint
            ),
            external_bindings=external,
            external_artifacts=read_rollback_external_artifacts_v2(
                evidence=self.evidence,
                installer_receipt_path=self.installer_receipt_path,
            ),
        )
        run = executor.execute(
            recovered.definition,
            callbacks=recovered.callbacks,
            terminal_callbacks=recovered.terminal_callbacks,
        )

        self.assertEqual("COMPLETED", run.status)
        self.assertFalse(journal_path.exists())
        self.assertFalse(composition.prepared_manifest.prepared_path.exists())
        restored = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(self.previous_pointer, restored["activeActivation"])
        self.assertEqual(self.current_pointer, restored["previousActivation"])
        self.assertTrue(
            (
                self.evidence.receipts_root
                / f"{self.rollback_operation_id}.commit.json"
            ).exists()
        )

    def test_recovery_after_forward_only_effect_never_reverses_link(self) -> None:
        composition, external = self._composition()
        journal_path = self.root / "operation.transaction.json"
        executor = OperationExecutorV2(
            store=OperationJournalStoreV2(
                journal_path=journal_path,
                lock_path=self.root / "operation.lock",
                validate_document=lambda _document: None,
            ),
            now=_Clock(),
            id_factory=_Ids(),
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "registry_restore"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            executor.execute(
                composition.definition,
                callbacks=composition.callbacks,
                terminal_callbacks=composition.terminal_callbacks,
                failure_injector=crash,
            )

        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        states = {step["kind"]: step["state"] for step in journal["steps"]}
        self.assertEqual("FORWARD_ONLY", journal["recoveryPolicy"])
        self.assertEqual("COMPLETED", states["activation_link_restore"])
        self.assertEqual("COMPLETED", states["recovery_forward_only"])
        self.assertEqual("INTENT_DURABLE", states["registry_restore"])
        self.assertEqual(
            self.previous_pointer["symlinkTarget"],
            os.readlink(self.marketplace_link),
        )

        recovered = build_rollback_recovery_composition_v2(
            evidence=self.evidence,
            definition=composition.definition,
            prepared_manifest=composition.prepared_manifest,
            preparation_receipt_fingerprint=(
                composition.preparation_receipt_fingerprint
            ),
            external_bindings=external,
            external_artifacts=read_rollback_external_artifacts_v2(
                evidence=self.evidence,
                installer_receipt_path=self.installer_receipt_path,
            ),
        )
        run = executor.execute(
            recovered.definition,
            callbacks=recovered.callbacks,
            terminal_callbacks=recovered.terminal_callbacks,
        )

        self.assertEqual("COMPLETED", run.status)
        self.assertFalse(journal_path.exists())
        self.assertEqual(
            self.previous_pointer["symlinkTarget"],
            os.readlink(self.marketplace_link),
        )

    def _composition(
        self,
    ) -> tuple[object, RollbackExternalStepBindingsV2]:
        prepared = self._prepared_manifest()
        external = self._external_bindings()
        artifacts = read_rollback_external_artifacts_v2(
            evidence=self.evidence,
            installer_receipt_path=self.installer_receipt_path,
        )
        composition = build_rollback_composition_v2(
            evidence=self.evidence,
            execution_plan=self.execution_plan,
            operation_id=self.rollback_operation_id,
            journal_path=self.root / "operation.transaction.json",
            prepared_manifest=prepared,
            preparation_receipt=self._preparation_receipt(prepared),
            external_bindings=external,
            external_artifacts=artifacts,
        )
        return composition, external

    def _prepared_manifest(self) -> PreparedManifestCommitV2:
        prepared_root = self.root / "prepared"
        prepared_root.mkdir(mode=0o700, exist_ok=True)
        manifest = copy.deepcopy(self.previous_manifest_source)
        manifest["previousActivation"] = copy.deepcopy(self.current_pointer)
        manifest["lastCommittedOperation"] = self.rollback_operation_id
        raw = canonical_json_bytes(manifest)
        prepared_path = prepared_root / (
            f"{self.rollback_operation_id}.{hashlib.sha256(raw).hexdigest()}"
            ".rollback-manifest.json"
        )
        prepared_path.write_bytes(raw)
        prepared_path.chmod(0o600)
        prepared_file = _projection(
            "file-object-v2",
            _file_value(prepared_path),
            "codex-smart/file-object/v2",
        )
        target_file = copy.deepcopy(dict(prepared_file.value))
        target_file["path"] = str(self.manifest_path)
        expected_after = _prepared_manifest_projection(
            self.manifest_path,
            manifest,
            file_projection=target_file,
        )
        parent = prepared_root.lstat()
        prepared = PreparedManifestCommitV2(
            activation_proof_fingerprint=self.evidence.evidence_fingerprint,
            operation_id=self.rollback_operation_id,
            activation_id=PREVIOUS_ACTIVATION_ID,
            activation_tree_sha256=str(
                self.previous_activation.value["directory"]["treeSha256"]
            ),
            target_path=self.manifest_path,
            prepared_path=prepared_path,
            prepared_parent_device=parent.st_dev,
            prepared_parent_inode=parent.st_ino,
            manifest_document=manifest,
            prepared_raw=raw,
            prepared_file_projection=prepared_file.value,
            prepared_file=prepared_file,
            expected_after=expected_after,
            preparation_fingerprint="0" * 64,
        )
        return replace(
            prepared,
            preparation_fingerprint=_prepared_manifest_fingerprint(prepared),
        )

    def _preparation_receipt(
        self,
        prepared: PreparedManifestCommitV2,
    ) -> RollbackManifestPreparationReceiptV2:
        lineage = ActivationTransitionLineageV2.from_document(
            self.evidence.current_receipt["transitionLineage"]
        )
        source = lineage.source_receipt
        assert source is not None
        receipt = RollbackManifestPreparationReceiptV2(
            installation_id=self.evidence.installation_id,
            operation_id=self.rollback_operation_id,
            current_operation_id=self.evidence.current_operation_id,
            previous_operation_id=self.evidence.previous_operation_id,
            current_activation_id=self.evidence.current_activation_id,
            previous_activation_id=self.evidence.previous_activation_id,
            evidence_fingerprint=self.evidence.evidence_fingerprint,
            preparation_intent_fingerprint="8" * 64,
            current_preparation_receipt_path=source.path,
            current_preparation_receipt_fingerprint=source.receipt_fingerprint,
            current_preparation_receipt_sha256=source.raw_sha256,
            transition_proof_snapshot_fingerprint=lineage.lineage_fingerprint,
            target_path=prepared.target_path,
            prepared_path=prepared.prepared_path,
            prepared_manifest_file=prepared.prepared_file,
            prepared_manifest_parent=capture_directory_binding_v2(
                prepared.prepared_path.parent,
                schema_sha256=SCHEMA_SHA256,
            ),
            manifest_document=prepared.manifest_document,
            manifest_raw_sha256=hashlib.sha256(prepared.prepared_raw).hexdigest(),
            previous_activation_tree_sha256=str(
                self.previous_activation.value["directory"]["treeSha256"]
            ),
            expected_after=prepared.expected_after,
            frozen_journal_fingerprint="9" * 64,
            completed_at=datetime(2026, 7, 19, 12, 30, tzinfo=timezone.utc),
        )
        path = self.evidence.receipts_root / (
            f"{self.rollback_operation_id}.rollback-preparation.json"
        )
        path.write_bytes(canonical_json_bytes(receipt.to_document()))
        path.chmod(0o600)
        return receipt

    def _external_bindings(self) -> RollbackExternalStepBindingsV2:
        missing = {
            "gate_close",
            "activation_link_restore",
            "recovery_forward_only",
            "manifest_restore",
            "terminal_journal_freeze",
            "commit_receipt_publish",
            "gate_open",
        }
        state: dict[str, ProjectionV2] = {}
        bindings: dict[str, RollbackStepBindingV2] = {}
        controller_definitions = self._controller_step_definitions()
        for index, kind in enumerate(
            item for item in ROLLBACK_MATCHED_ACTIVE_STEPS_V2 if item not in missing
        ):
            if kind == "registry_restore":
                before = self._registry_projection(
                    Path(self.installer_receipt["registeredMarketplacePath"])
                )
                after = self._registry_projection(
                    self.managed
                    / "activations"
                    / PREVIOUS_ACTIVATION_ID
                    / "marketplace"
                )
            elif kind == "launchers_restore":
                before = self._launcher_projection(PREVIOUS_ACTIVATION_ID)
                after = before
            else:
                before = controller_definitions[kind].before
                after = controller_definitions[kind].expected_after
            if kind == "registry_restore":
                command_id = "ec2_" + f"{index + 1:032x}"
                action = {
                    "actionKind": "external-command",
                    "commandRole": "codex-registry",
                    "method": "registry-restore",
                    "externalCommandId": command_id,
                    "argvFingerprint": "8" * 64,
                    "timeoutMs": 30_000,
                }
            elif kind == "launchers_restore":
                command_id = None
                operations = []
                launcher_entries = before.value["launchers"]
                for ordinal, (item, entry) in enumerate(
                    zip(self.launcher_links, launcher_entries, strict=True)
                ):
                    role = "gateway" if ordinal == 0 else "admin"
                    fingerprint = domain_fingerprint(
                        "codex-smart/launcher-entry/v2", entry
                    )
                    operations.append(
                        {
                            "name": Path(item["path"]).name,
                            "role": role,
                            "method": "write-replace",
                            "targetPath": item["path"],
                            "beforeFingerprint": fingerprint,
                            "expectedAfterFingerprint": fingerprint,
                        }
                    )
                action = {
                    "actionKind": "launcher-set-mutation",
                    "mode": "RESTORE_PREVIOUS",
                    "operations": operations,
                    "durability": "FSYNC_EACH_FILE_AND_PARENT",
                }
            else:
                definition = controller_definitions[kind]
                command_id = definition.command_id
                action = definition.action
            if kind in {"registry_restore", "launchers_restore"}:
                definition = StepDefinitionV2(
                    kind=kind,
                    command_id=command_id,
                    action=action,
                    before=before,
                    expected_after=after,
                )
            state[kind] = before

            def observe(
                received: StepDefinitionV2,
                *,
                expected: StepDefinitionV2 = definition,
            ) -> ProjectionV2:
                self.assertEqual(expected, received)
                return state[expected.kind]

            def apply(
                received: StepDefinitionV2,
                *,
                expected: StepDefinitionV2 = definition,
            ) -> None:
                self.assertEqual(expected, received)
                state[expected.kind] = expected.expected_after

            bindings[kind] = RollbackStepBindingV2(
                definition=definition,
                port=UpdateStepPortV2(
                    observe=observe,
                    apply=apply,
                    replay_safe_when_indistinguishable=(
                        (lambda observed, received: observed == received.before)
                        if kind in {"launchers_restore", "verify_candidate"}
                        else (lambda _observed, _received: False)
                    ),
                ),
            )
        return RollbackExternalStepBindingsV2(bindings)

    def _controller_step_definitions(self) -> dict[str, StepDefinitionV2]:
        accepting = self._controller_projection(
            state="ACCEPTING",
            epoch=7,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
        )
        draining = self._controller_projection(
            state="DRAINING",
            epoch=8,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            mode="drain",
            operation_id=self.rollback_operation_id,
            accepting=False,
            quiescent=False,
        )
        drain_quiescent = self._controller_projection(
            state="MAINTENANCE",
            epoch=8,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            mode="drain",
            operation_id=self.rollback_operation_id,
            accepting=False,
            quiescent=True,
        )
        frozen = self._controller_projection(
            state="MAINTENANCE",
            epoch=9,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            mode="freeze",
            operation_id=self.rollback_operation_id,
            accepting=False,
            quiescent=True,
        )
        stopped = self._controller_projection(
            state="STOPPED",
            epoch=10,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            mode=None,
            operation_id=None,
            accepting=False,
            quiescent=True,
        )
        shutdown = _projection(
            "shutdown-intent-v2",
            {
                "controllerAfter": stopped.value,
                "operationId": self.rollback_operation_id,
                "commandId": "cc2_" + "3" * 32,
                "requestFingerprint": "1" * 64,
                "commandReceiptFingerprint": "2" * 64,
                "previousControlEpoch": 9,
                "newControlEpoch": 10,
                "targetPid": 4100,
                "targetStartMarker": "darwin:100:1",
                "targetProcessGroupId": 4100,
                "socket": self._socket_identity(),
                "lockPath": str(self.root / "state" / "controller.lock"),
                "processExitProofFingerprint": None,
                "exclusiveLockProofFingerprint": None,
                "status": "EXPECTED_SHUTDOWN_PROOF",
            },
            "codex-smart/shutdown-intent/v2",
        )
        candidate_expected = self._candidate_projection(ready=False)
        accepted = self._controller_projection(
            state="EXPECTED_MAINTENANCE",
            epoch=2,
            activation_id=PREVIOUS_ACTIVATION_ID,
            database_id=PREVIOUS_DATABASE_ID,
            mode="freeze",
            operation_id=self.rollback_operation_id,
            accepting=False,
            quiescent=True,
            expected=True,
        )
        resumed = self._controller_projection(
            state="EXPECTED_ACCEPTING",
            epoch=3,
            activation_id=PREVIOUS_ACTIVATION_ID,
            database_id=PREVIOUS_DATABASE_ID,
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
            expected=True,
        )
        quiescence = _projection(
            "quiescence-proof-v2",
            {
                "proofKind": "runtime-v2",
                "controllerIdentity": "2" * 64,
                "instanceId": "ci2_" + "2" * 32,
                "controlEpoch": 8,
                "workCounts": {
                    "nonterminalRoutes": 0,
                    "nonterminalNodes": 0,
                    "activeAttempts": 0,
                    "activeLeases": 0,
                    "openIntents": 0,
                    "inflightLaunchPermits": 0,
                    "activeRuntimeArtifacts": 0,
                    "pendingCandidatePublications": 0,
                    "activeEvidenceJobs": 0,
                    "queuedEvidenceJobs": 0,
                },
                "databasePredicatesFingerprint": "3" * 64,
                "barrierHeld": True,
                "quiescent": True,
            },
            "codex-smart/quiescence-proof/v2",
        )
        ready_path = self.root / "state" / "candidate.ready.sock"
        controller_socket_path = self.root / "state" / "controller.sock"
        definitions = {
            "maintenance_begin": self._controller_step(
                "maintenance_begin", accepting, draining, 7, "1"
            ),
            "wait_runtime_quiescent": StepDefinitionV2(
                kind="wait_runtime_quiescent",
                command_id=None,
                action={
                    "actionKind": "verify",
                    "predicate": "runtime-quiescent",
                    "timeoutMs": 2_500,
                },
                before=draining,
                expected_after=quiescence,
            ),
            "maintenance_strengthen": self._controller_step(
                "maintenance_strengthen", drain_quiescent, frozen, 8, "2"
            ),
            "controller_shutdown": self._controller_step(
                "controller_shutdown", frozen, shutdown, 9, "3"
            ),
            "shutdown_socket_cleanup": StepDefinitionV2(
                kind="shutdown_socket_cleanup",
                command_id=None,
                action={
                    "actionKind": "socket-cleanup",
                    "method": "unlink-proven-orphan",
                    "proofSource": "CONTROLLER_SHUTDOWN_INTENT",
                    "proofSourceId": "cc2_" + "3" * 32,
                    "socketPath": str(self.root / "state" / "controller.sock"),
                    "socketParentDevice": 1,
                    "socketParentInode": 2,
                    "socketDevice": 3,
                    "socketInode": 4,
                    "socketOwnerUid": os.getuid(),
                    "socketOwnerGid": os.getgid(),
                    "socketMode": "0600",
                    "targetPid": 4100,
                    "targetStartMarker": "darwin:100:1",
                    "targetProcessGroupId": 4100,
                    "lockPath": str(self.root / "state" / "controller.lock"),
                    "durability": "UNLINKAT_FSYNC_PARENT",
                },
                before=shutdown,
                expected_after=self._absence_projection(
                    controller_socket_path, token=11
                ),
            ),
            "controller_candidate_spawn": StepDefinitionV2(
                kind="controller_candidate_spawn",
                command_id=None,
                action={
                    "actionKind": "controller-candidate-spawn",
                    **{
                        key: candidate_expected.value[key]
                        for key in (
                            "candidateId",
                            "controllerIdentity",
                            "controllerStartId",
                            "operationId",
                            "activationId",
                            "activationFingerprint",
                            "databaseId",
                            "argvFingerprint",
                            "snapshotFingerprint",
                            "privateReadyChannelPath",
                            "readinessTokenHash",
                            "readinessWindowMs",
                            "processGroupPolicy",
                        )
                    },
                    "argv": [
                        "/private/runtime/python3",
                        "/private/activation/controller/server.py",
                        "--serve-candidate-v2",
                    ],
                },
                before=self._absence_projection(ready_path, token=12),
                expected_after=candidate_expected,
            ),
            "controller_previous_accept": self._controller_step(
                "controller_previous_accept", candidate_expected, accepted, 1, "4"
            ),
            "verify_candidate": StepDefinitionV2(
                kind="verify_candidate",
                command_id=None,
                action={
                    "actionKind": "verify",
                    "predicate": "candidate",
                    "timeoutMs": 30_000,
                },
                before=self.previous_activation,
                expected_after=self.previous_activation,
            ),
            "maintenance_resume": self._controller_step(
                "maintenance_resume", accepted, resumed, 2, "5"
            ),
        }
        return definitions

    def _controller_step(
        self,
        kind: str,
        before: ProjectionV2,
        after: ProjectionV2,
        epoch: int,
        token: str,
    ) -> StepDefinitionV2:
        methods = {
            "maintenance_begin": "maintenance_begin",
            "maintenance_strengthen": "maintenance_strengthen",
            "controller_shutdown": "shutdown",
            "controller_previous_accept": "controller_accept",
            "maintenance_resume": "maintenance_resume",
        }
        return StepDefinitionV2(
            kind=kind,
            command_id="cc2_" + token * 32,
            action={
                "actionKind": "controller-command",
                "method": methods[kind],
                "operationId": self.rollback_operation_id,
                "expectedControlEpoch": epoch,
            },
            before=before,
            expected_after=after,
        )

    def _socket_identity(self) -> dict[str, object]:
        return {
            "path": str(self.root / "state" / "controller.sock"),
            "device": 3,
            "inode": 4,
            "ownerUid": os.getuid(),
            "ownerGid": os.getgid(),
            "mode": "0600",
        }

    def _controller_projection(
        self,
        *,
        state: str,
        epoch: int,
        activation_id: str,
        database_id: str,
        mode: str | None,
        operation_id: str | None,
        accepting: bool,
        quiescent: bool,
        expected: bool = False,
    ) -> ProjectionV2:
        no_process = expected
        return _projection(
            "controller-state-v2",
            {
                "controllerIdentity": "2" * 64,
                "instanceId": None if no_process else "ci2_" + "2" * 32,
                "controllerStartId": "cs2_" + "3" * 32,
                "pid": None if no_process else 4100,
                "processStartMarker": (None if no_process else "darwin:100:1"),
                "processGroupId": (None if no_process else 4100),
                "controlEpoch": epoch,
                "state": state,
                "maintenanceMode": mode,
                "operationId": operation_id,
                "activationId": activation_id,
                "activationFingerprint": activation_id.removeprefix("act2_"),
                "databaseId": database_id,
                "socket": (
                    None
                    if no_process or state == "STOPPED"
                    else self._socket_identity()
                ),
                "lockHeld": state != "STOPPED",
                "acceptingNewRoutes": accepting,
                "quiescent": quiescent,
            },
            "codex-smart/controller-state/v2",
        )

    def _candidate_projection(self, *, ready: bool) -> ProjectionV2:
        argv = [
            "/private/runtime/python3",
            "/private/activation/controller/server.py",
            "--serve-candidate-v2",
        ]
        return _projection(
            "controller-candidate-v2",
            {
                "candidateId": "cand2_" + "4" * 32,
                "controllerIdentity": "2" * 64,
                "controllerStartId": "cs2_" + "3" * 32,
                "operationId": self.rollback_operation_id,
                "activationId": PREVIOUS_ACTIVATION_ID,
                "activationFingerprint": PREVIOUS_ACTIVATION_ID.removeprefix("act2_"),
                "databaseId": PREVIOUS_DATABASE_ID,
                "argvFingerprint": domain_fingerprint(
                    "codex-smart/controller-candidate-argv/v2", {"argv": argv}
                ),
                "snapshotFingerprint": "5" * 64,
                "privateReadyChannelPath": str(
                    self.root / "state" / "candidate.ready.sock"
                ),
                "privateReadyChannel": (
                    self._candidate_ready_socket_identity() if ready else None
                ),
                "readinessTokenHash": "6" * 64,
                "readinessWindowMs": 30_000,
                "processGroupPolicy": "NEW_PRIVATE_GROUP",
                "pid": 4200 if ready else None,
                "processStartMarker": "darwin:101:1" if ready else None,
                "processGroupId": 4200 if ready else None,
                "registrationFingerprint": "7" * 64 if ready else None,
                "databaseLeaseProofFingerprint": "8" * 64 if ready else None,
                "databaseOpened": ready,
                "workingSocketPublished": False,
                "acceptingNewRoutes": False,
                "status": "REGISTERED_READY" if ready else "EXPECTED_REGISTRATION",
                "exitProofFingerprint": None,
            },
            "codex-smart/controller-candidate/v2",
        )

    def _candidate_ready_socket_identity(self) -> dict[str, object]:
        return {
            "path": str(self.root / "state" / "candidate.ready.sock"),
            "device": 13,
            "inode": 14,
            "ownerUid": os.getuid(),
            "ownerGid": os.getgid(),
            "mode": "0600",
        }

    def _absence_projection(self, path: Path, *, token: int) -> ProjectionV2:
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = {
            "proofId": f"ap2_{token:032x}",
            "installationId": INSTALLATION_ID,
            "operationId": self.rollback_operation_id,
            "entries": [
                {
                    "path": str(path),
                    "basename": path.name,
                    "parentDevice": parent.stat().st_dev,
                    "parentInode": parent.stat().st_ino,
                    "absent": True,
                }
            ],
            "directorySyncCompleted": True,
        }
        value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2", value
        )
        return _projection(
            "absence-proof-v2",
            value,
            "codex-smart/absence-proof-projection/v2",
        )

    def _registry_projection(self, marketplace: Path) -> ProjectionV2:
        marketplace = marketplace.resolve(strict=True)
        config = _file_value(self.installer_receipt_path)
        value = {
            "status": "PLUGIN_ENABLED",
            "marketplaceName": "codex-settings-adaptive",
            "marketplacePath": str(marketplace),
            "marketplaceFingerprint": hashlib.sha256(
                str(marketplace).encode("utf-8")
            ).hexdigest(),
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "pluginEnabled": True,
            "pluginFingerprint": hashlib.sha256(
                (str(marketplace) + "/plugin").encode("utf-8")
            ).hexdigest(),
            "configFile": config,
            "configSemanticFingerprint": "9" * 64,
            "marketplaceListFingerprint": "a" * 64,
            "pluginListFingerprint": "b" * 64,
        }
        return _projection("registry-state-v2", value, "codex-smart/registry-state/v2")

    def _launcher_projection(self, activation_id: str) -> ProjectionV2:
        launchers: list[dict[str, object]] = []
        for ordinal, item in enumerate(self.launcher_links):
            path = Path(item["path"])
            role = "gateway" if ordinal == 0 else "admin"
            target = self.managed / "activations" / activation_id / "marketplace" / role
            file_value = _file_value(target)
            file_value["path"] = str(path)
            launchers.append(
                {
                    "name": path.name,
                    "role": role,
                    "file": file_value,
                }
            )
        value: dict[str, object] = {"launchers": launchers}
        value["setFingerprint"] = domain_fingerprint(
            "codex-smart/launcher-set/v2", value
        )
        return _projection(
            "launcher-set-v2", value, "codex-smart/launcher-set-projection/v2"
        )


if __name__ == "__main__":
    unittest.main()
