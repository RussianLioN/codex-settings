from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    prepared_receipt_to_staged_activation_v2,
)
from codex_smart_subagents.activation_transition_v2 import (  # noqa: E402
    _projection,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    RollbackEvidenceV2,
    read_rollback_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    StoppedControllerLineageV2,
    TransitionSourceReceiptV2,
    ProjectionV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)
from codex_smart_subagents.installer_upgrade_v2 import (  # noqa: E402
    build_upgrade_preparation_v2,
    execute_and_verify_upgrade_preparation_v2,
    prepared_manifest_from_upgrade_receipt_v2,
    prepare_upgrade_database_v2,
)
from tests.smart_subagents import test_activation_transition_v2 as transition_fixtures  # noqa: E402


CURRENT_OPERATION_ID = "op2_" + "9" * 32
SCHEMA_ROOT = ROOT / "docs" / "contracts" / "schemas"


class _MonotonicNanoseconds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


def _schema_validator(name: str) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in SCHEMA_ROOT.glob("*.schema.json")
    }
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()]
    )
    return Draft202012Validator(
        schemas[name], registry=registry, format_checker=FormatChecker()
    )


def _write_private_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)


def _commit_receipt(
    *,
    installation_id: str,
    operation_id: str,
    manifest,
    activation,
    database,
    controller_identity: str,
    manifest_document: dict[str, object],
    transition_lineage: ActivationTransitionLineageV2,
) -> dict[str, object]:
    absence = _projection(
        "absence-proof-v2",
        {"operationId": operation_id},
        "codex-smart/absence-proof-projection/v2",
    )
    activation = _projection(
        "activation-v2",
        activation.value,
        "codex-smart/journal-state/v2",
    )
    unsigned = {
        "schemaVersion": 2,
        "receiptKind": "activation-commit",
        "installationId": installation_id,
        "operationId": operation_id,
        "frozenJournalFingerprint": "a" * 64,
        "manifest": manifest.to_document(),
        "manifestDocument": copy.deepcopy(manifest_document),
        "transitionLineage": transition_lineage.to_document(),
        "activation": activation.to_document(),
        "databaseBinding": database.to_document(),
        "journalAbsenceTarget": absence.to_document(),
        "controllerIdentity": controller_identity,
        "completedStepIds": ["st2_" + "b" * 32],
        "completedAt": "2026-07-19T12:00:00Z",
    }
    return {
        **unsigned,
        "receiptFingerprint": domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", unsigned
        ),
    }


class _PublishedUpgradeFixture:
    def __init__(self) -> None:
        self.base = transition_fixtures.ActivationTransitionV2Tests(
            methodName="runTest"
        )
        self.base.setUp()
        proof = self.base.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=CURRENT_OPERATION_ID,
            source_root=ROOT,
            codex_binary=self.base.codex_binary,
            policy_bundle=self.base.policy,
            snapshotter=self.base.snapshotter,
            interface_executor=self.base.interface_executor,
        )
        self.current_preparation_receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )
        staged = prepared_receipt_to_staged_activation_v2(
            self.current_preparation_receipt
        )
        database = prepare_upgrade_database_v2(self.current_preparation_receipt)
        prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=self.current_preparation_receipt,
        )
        temporary_link = proof.layout.marketplace_link.with_name(
            ".published-upgrade-link"
        )
        os.symlink(
            f"activations/{staged.activation_id}/marketplace",
            temporary_link,
        )
        os.replace(temporary_link, proof.layout.marketplace_link)
        os.replace(prepared.prepared_path, proof.layout.manifest_path)
        previous_receipt = copy.deepcopy(proof.commit_receipt_document)
        previous_receipt["activation"] = _projection(
            "activation-v2",
            previous_receipt["activation"]["value"],
            "codex-smart/journal-state/v2",
        ).to_document()
        previous_unsigned = {
            key: value
            for key, value in previous_receipt.items()
            if key != "receiptFingerprint"
        }
        previous_receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", previous_unsigned
        )
        _write_private_json(proof.commit_receipt_path, previous_receipt)
        current_receipt_path = (
            proof.layout.receipts_root
            / proof.installation_id
            / f"{CURRENT_OPERATION_ID}.commit.json"
        )
        _write_private_json(
            current_receipt_path,
            _commit_receipt(
                installation_id=proof.installation_id,
                operation_id=CURRENT_OPERATION_ID,
                manifest=prepared.expected_after,
                activation=self.current_preparation_receipt.prepared.activation,
                database=database,
                controller_identity=staged.controller_identity,
                manifest_document=prepared.manifest_document,
                transition_lineage=ActivationTransitionLineageV2(
                    transition_kind="update",
                    source_receipt=TransitionSourceReceiptV2(
                        receipt_kind="activation-preparation",
                        path=preparation.definition.receipt_path,
                        raw_sha256=hashlib.sha256(
                            canonical_json_bytes(
                                self.current_preparation_receipt.to_document()
                            )
                        ).hexdigest(),
                        receipt_fingerprint=(
                            self.current_preparation_receipt.receipt_fingerprint
                        ),
                    ),
                    activation_proof_fingerprint=(
                        self.current_preparation_receipt.transition_proof_snapshot.activation_proof_fingerprint
                    ),
                    shutdown_command_ids=ControllerShutdownLineageV2(
                        maintenance_begin="cc2_" + "1" * 32,
                        maintenance_strengthen="cc2_" + "2" * 32,
                        shutdown="cc2_" + "3" * 32,
                    ),
                    stopped_controller=StoppedControllerLineageV2(
                        operation_id=CURRENT_OPERATION_ID,
                        activation_id=proof.active_pointer["activationId"],
                        database_id=proof.active_pointer["databaseId"],
                        controller_identity=proof.controller_identity,
                        control_epoch=int(proof.controller_row["control_epoch"]) + 3,
                    ),
                ),
            ),
        )
        self.evidence = read_rollback_v2(
            manifest_path=proof.layout.manifest_path,
            receipts_root=proof.layout.receipts_root / proof.installation_id,
            activations_root=proof.layout.managed_root / "activations",
            marketplace_link=proof.layout.marketplace_link,
        )
        self.current_preparation_receipt_path = preparation.definition.receipt_path
        self.manifest_root = proof.layout.manifest_root

    def close(self) -> None:
        self.base.tearDown()

    def build_preparation(self, module, suffix: str = ""):
        operation_id = module.rollback_operation_id_v2(self.evidence)
        prefix = "" if not suffix else f"{suffix}-"
        prepared_root = self.manifest_root / "prepared-manifests"
        if suffix:
            prepared_root = prepared_root / suffix
            prepared_root.mkdir(mode=0o700)
        return module.build_rollback_manifest_preparation_v2(
            evidence=self.evidence,
            current_preparation_receipt_path=self.current_preparation_receipt_path,
            journal_path=(
                self.manifest_root
                / f"{prefix}rollback-manifest-preparation.transaction.json"
            ),
            receipt_path=(
                self.evidence.receipts_root
                / f"{prefix}{operation_id}.rollback-preparation.json"
            ),
            lock_path=(
                self.manifest_root / f"{prefix}rollback-manifest-preparation.lock"
            ),
            prepared_root=prepared_root,
        )


class RollbackManifestPreparationV2Tests(unittest.TestCase):
    def test_deadline_after_step_intent_preserves_rollback_preparation_journal(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(module, suffix="deadline")
            monotonic = _MonotonicNanoseconds()
            deadline = OperationDeadlineV2.start(
                operation="rollback",
                timeout_seconds=1,
                timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
                monotonic_ns=monotonic,
            )

            def expire_after_intent(point) -> None:
                if (
                    point
                    is module.RollbackManifestPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT
                ):
                    monotonic.value = 1_000_000_000

            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    module.RollbackManifestPreparationExecutorV2(
                        definition=preparation.definition,
                        failure_injector=expire_after_intent,
                    ).execute()

            journal = json.loads(
                preparation.definition.journal_path.read_text(encoding="utf-8")
            )
            self.assertEqual("PREPARING", journal["phase"])
            self.assertEqual("INTENT_DURABLE", journal["steps"][0]["state"])
            self.assertFalse(
                preparation.definition.activation_intent.prepared_path.exists()
            )
        finally:
            fixture.close()

    def test_public_contract_exports_every_integration_symbol(self) -> None:
        module = importlib.import_module(
            "codex_smart_subagents.rollback_manifest_preparation_v2"
        )
        expected = {
            "InjectedRollbackManifestPreparationCrashV2",
            "ROLLBACK_JOURNAL_KIND_V2",
            "RollbackManifestPreparationDefinitionV2",
            "RollbackManifestPreparationExecutorV2",
            "RollbackManifestPreparationFailurePointV2",
            "RollbackManifestPreparationIntentV2",
            "RollbackManifestPreparationPathsV2",
            "RollbackManifestPreparationReceiptV2",
            "RollbackManifestPreparationV2",
            "RollbackManifestPreparationV2Error",
            "build_rollback_manifest_preparation_v2",
            "prepared_rollback_manifest_from_receipt_v2",
            "rollback_manifest_preparation_paths_v2",
            "rollback_operation_id_v2",
        }

        self.assertTrue(expected.issubset(set(module.__all__)))
        self.assertTrue(all(hasattr(module, name) for name in expected))

    def test_operation_id_is_deterministic_and_bound_to_all_rollback_ids(self) -> None:
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
        except ModuleNotFoundError:
            self.fail("rollback manifest preparation module is missing")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            evidence = RollbackEvidenceV2(
                manifest_path=root / "manifest.json",
                receipts_root=root / "receipts",
                activations_root=root / "activations",
                marketplace_link=root / "marketplace-current",
                installation_id="ins2_" + "1" * 32,
                current_operation_id="op2_" + "2" * 32,
                previous_operation_id="op2_" + "3" * 32,
                current_activation_id="act2_" + "4" * 64,
                previous_activation_id="act2_" + "5" * 64,
                current_pointer={},
                previous_pointer={},
                manifest_document={},
                manifest_file_projection={},
                current_receipt_path=root / "current.commit.json",
                previous_receipt_path=root / "previous.commit.json",
                current_receipt={},
                previous_receipt={},
                current_manifest_projection=None,
                current_activation_projection=None,
                previous_activation_projection=None,
                previous_database_binding=None,
                evidence_fingerprint="6" * 64,
            )

            first = module.rollback_operation_id_v2(evidence)
            second = module.rollback_operation_id_v2(evidence)
            changed = module.rollback_operation_id_v2(
                copy.copy(evidence).__class__(
                    **{
                        **evidence.__dict__,
                        "previous_operation_id": "op2_" + "7" * 32,
                    }
                )
            )

        self.assertRegex(first, r"^op2_[0-9a-f]{32}$")
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_builder_is_pure_and_uses_only_the_previous_manifest_snapshot(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            operation_id = module.rollback_operation_id_v2(fixture.evidence)
            journal_path = (
                fixture.manifest_root / "rollback-manifest-preparation.transaction.json"
            )
            receipt_path = (
                fixture.evidence.receipts_root
                / f"{operation_id}.rollback-preparation.json"
            )
            lock_path = fixture.manifest_root / "rollback-manifest-preparation.lock"
            prepared_root = fixture.manifest_root / "prepared-manifests"
            before_entries = tuple(sorted(fixture.manifest_root.iterdir()))

            preparation = module.build_rollback_manifest_preparation_v2(
                evidence=fixture.evidence,
                current_preparation_receipt_path=(
                    fixture.current_preparation_receipt_path
                ),
                journal_path=journal_path,
                receipt_path=receipt_path,
                lock_path=lock_path,
                prepared_root=prepared_root,
            )

            self.assertEqual(
                before_entries, tuple(sorted(fixture.manifest_root.iterdir()))
            )
            self.assertFalse(journal_path.exists())
            self.assertFalse(receipt_path.exists())
            self.assertFalse(lock_path.exists())
            self.assertFalse(
                preparation.definition.activation_intent.prepared_path.exists()
            )
            source = copy.deepcopy(
                fixture.current_preparation_receipt.transition_proof_snapshot.manifest_document
            )
            expected = copy.deepcopy(source)
            expected["activeActivation"] = copy.deepcopy(
                fixture.evidence.previous_pointer
            )
            expected["previousActivation"] = copy.deepcopy(
                fixture.evidence.current_pointer
            )
            expected["lastCommittedOperation"] = operation_id
            self.assertEqual(
                expected,
                preparation.definition.activation_intent.manifest_document,
            )
            self.assertEqual(
                fixture.evidence.evidence_fingerprint,
                preparation.definition.activation_intent.evidence_fingerprint,
            )
            self.assertEqual(
                fixture.evidence.current_manifest_projection.schema_sha256,
                preparation.definition.activation_intent.projection_schema_sha256,
            )
        finally:
            fixture.close()

    def test_commit_lineage_supports_a_to_b_to_a_to_b_rollbacks(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )

            def publish_rollback(
                evidence: RollbackEvidenceV2,
                *,
                source_path: Path,
                epoch: int,
            ) -> tuple[RollbackEvidenceV2, object]:
                operation_id = module.rollback_operation_id_v2(evidence)
                paths = module.rollback_manifest_preparation_paths_v2(evidence)
                preparation = module.build_rollback_manifest_preparation_v2(
                    evidence=evidence,
                    current_preparation_receipt_path=source_path,
                    journal_path=paths.journal_path,
                    receipt_path=paths.receipt_path,
                    lock_path=paths.lock_path,
                    prepared_root=paths.prepared_root,
                )
                preparation_receipt = module.RollbackManifestPreparationExecutorV2(
                    definition=preparation.definition
                ).execute()
                prepared = module.prepared_rollback_manifest_from_receipt_v2(
                    preparation_receipt,
                    evidence,
                )
                current_database = ProjectionV2.from_document(
                    evidence.current_receipt["databaseBinding"]
                )
                lineage = ActivationTransitionLineageV2(
                    transition_kind="rollback",
                    source_receipt=TransitionSourceReceiptV2(
                        receipt_kind="rollback-manifest-preparation",
                        path=preparation.definition.receipt_path,
                        raw_sha256=hashlib.sha256(
                            canonical_json_bytes(preparation_receipt.to_document())
                        ).hexdigest(),
                        receipt_fingerprint=preparation_receipt.receipt_fingerprint,
                    ),
                    activation_proof_fingerprint=evidence.evidence_fingerprint,
                    shutdown_command_ids=ControllerShutdownLineageV2(
                        maintenance_begin="cc2_" + f"{epoch:032x}",
                        maintenance_strengthen="cc2_" + f"{epoch + 1:032x}",
                        shutdown="cc2_" + f"{epoch + 2:032x}",
                    ),
                    stopped_controller=StoppedControllerLineageV2(
                        operation_id=operation_id,
                        activation_id=evidence.current_activation_id,
                        database_id=str(current_database.value["databaseId"]),
                        controller_identity=str(
                            evidence.current_receipt["controllerIdentity"]
                        ),
                        control_epoch=epoch + 3,
                    ),
                )
                commit_receipt = _commit_receipt(
                    installation_id=evidence.installation_id,
                    operation_id=operation_id,
                    manifest=preparation_receipt.expected_after,
                    activation=evidence.previous_activation_projection,
                    database=evidence.previous_database_binding,
                    controller_identity=str(
                        evidence.previous_receipt["controllerIdentity"]
                    ),
                    manifest_document=dict(preparation_receipt.manifest_document),
                    transition_lineage=lineage,
                )
                temporary_link = evidence.marketplace_link.with_name(
                    f".rollback-{epoch}-link"
                )
                os.symlink(evidence.previous_pointer["symlinkTarget"], temporary_link)
                os.replace(temporary_link, evidence.marketplace_link)
                os.replace(prepared.prepared_path, evidence.manifest_path)
                _write_private_json(
                    evidence.receipts_root / f"{operation_id}.commit.json",
                    commit_receipt,
                )
                return (
                    read_rollback_v2(
                        manifest_path=evidence.manifest_path,
                        receipts_root=evidence.receipts_root,
                        activations_root=evidence.activations_root,
                        marketplace_link=evidence.marketplace_link,
                    ),
                    preparation_receipt,
                )

            evidence_b = fixture.evidence
            evidence_a, first_preparation = publish_rollback(
                evidence_b,
                source_path=fixture.current_preparation_receipt_path,
                epoch=10,
            )
            first_lineage = ActivationTransitionLineageV2.from_document(
                evidence_a.current_receipt["transitionLineage"]
            )
            assert first_lineage.source_receipt is not None
            evidence_b_again, second_preparation = publish_rollback(
                evidence_a,
                source_path=first_lineage.source_receipt.path,
                epoch=20,
            )

            self.assertEqual(
                (evidence_b.current_activation_id, evidence_b.previous_activation_id),
                (
                    evidence_b_again.current_activation_id,
                    evidence_b_again.previous_activation_id,
                ),
            )
            self.assertEqual(
                first_preparation.operation_id,
                evidence_a.current_operation_id,
            )
            self.assertEqual(
                second_preparation.operation_id,
                evidence_b_again.current_operation_id,
            )
            self.assertEqual(
                "rollback-manifest-preparation",
                first_lineage.source_receipt.receipt_kind,
            )
            self.assertNotEqual(
                evidence_b.current_operation_id,
                evidence_b_again.current_operation_id,
            )
        finally:
            fixture.close()

    def test_builder_binds_archived_installer_source_digest_to_restored_manifest(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            paths = module.rollback_manifest_preparation_paths_v2(fixture.evidence)
            previous_source_digest = "8" * 64

            preparation = module.build_rollback_manifest_preparation_v2(
                evidence=fixture.evidence,
                current_preparation_receipt_path=(
                    fixture.current_preparation_receipt_path
                ),
                journal_path=paths.journal_path,
                receipt_path=paths.receipt_path,
                lock_path=paths.lock_path,
                prepared_root=paths.prepared_root,
                installer_source_digest=previous_source_digest,
            )

            self.assertEqual(
                previous_source_digest,
                preparation.definition.activation_intent.manifest_document[
                    "extensions"
                ]["installerSourceDigest"],
            )
            self.assertFalse(paths.journal_path.exists())
            self.assertFalse(paths.receipt_path.exists())
        finally:
            fixture.close()

    def test_normative_paths_and_journal_kind_are_unambiguous(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            operation_id = module.rollback_operation_id_v2(fixture.evidence)

            paths = module.rollback_manifest_preparation_paths_v2(fixture.evidence)

            self.assertEqual(
                fixture.manifest_root
                / "codex-smart-subagents-v2.rollback-manifest-preparation.transaction.json",
                paths.journal_path,
            )
            self.assertEqual(
                fixture.evidence.receipts_root
                / f"{operation_id}.rollback-preparation.json",
                paths.receipt_path,
            )
            self.assertEqual(
                fixture.manifest_root / "rollback-manifest-preparation.lock",
                paths.lock_path,
            )
            self.assertEqual(
                fixture.manifest_root / "prepared-manifests",
                paths.prepared_root,
            )
            self.assertEqual(
                "rollback-manifest-preparation", module.ROLLBACK_JOURNAL_KIND_V2
            )
        finally:
            fixture.close()

    def test_execute_publishes_immutable_receipt_and_existing_commit_type(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(module)
            executor = module.RollbackManifestPreparationExecutorV2(
                definition=preparation.definition
            )

            first = executor.execute()
            second = module.RollbackManifestPreparationExecutorV2(
                definition=preparation.definition
            ).execute()
            prepared = module.prepared_rollback_manifest_from_receipt_v2(
                first, fixture.evidence
            )

            intent = preparation.definition.activation_intent
            self.assertEqual(first.to_document(), second.to_document())
            self.assertFalse(preparation.definition.journal_path.exists())
            self.assertTrue(preparation.definition.receipt_path.is_file())
            self.assertTrue(intent.prepared_path.is_file())
            self.assertEqual("0600", first.prepared_manifest_file.value["mode"])
            self.assertEqual(
                0o600,
                intent.prepared_path.stat().st_mode & 0o777,
            )
            self.assertEqual(1, intent.prepared_path.stat().st_nlink)
            self.assertEqual(
                first.prepared_manifest_file.value["inode"],
                first.expected_after.value["file"]["inode"],
            )
            self.assertEqual(
                str(fixture.evidence.manifest_path),
                first.expected_after.value["file"]["path"],
            )
            self.assertTrue(prepared.complete)
            self.assertEqual(
                fixture.evidence.evidence_fingerprint,
                prepared.activation_proof_fingerprint,
            )
            self.assertEqual(intent.operation_id, prepared.operation_id)
            self.assertEqual(
                fixture.evidence.previous_activation_id, prepared.activation_id
            )
            self.assertEqual(
                first.receipt_fingerprint, first.to_document()["receiptFingerprint"]
            )
        finally:
            fixture.close()

    def test_receipt_rehydrates_after_source_is_atomically_moved_to_target(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(module)
            receipt = module.RollbackManifestPreparationExecutorV2(
                definition=preparation.definition
            ).execute()

            os.replace(receipt.prepared_path, receipt.target_path)
            prepared = module.prepared_rollback_manifest_from_receipt_v2(
                receipt, fixture.evidence
            )

            self.assertFalse(receipt.prepared_path.exists())
            self.assertTrue(prepared.complete)
            self.assertEqual(
                receipt.expected_after.value["file"]["inode"],
                receipt.target_path.stat().st_ino,
            )
            self.assertEqual(
                receipt.manifest_document,
                __import__("json").loads(
                    receipt.target_path.read_text(encoding="utf-8")
                ),
            )
        finally:
            fixture.close()

    def test_repeat_execute_never_recreates_source_consumed_by_main_operation(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(module)
            receipt = module.RollbackManifestPreparationExecutorV2(
                definition=preparation.definition
            ).execute()
            os.replace(receipt.prepared_path, receipt.target_path)

            with self.assertRaises(module.RollbackManifestPreparationV2Error):
                module.RollbackManifestPreparationExecutorV2(
                    definition=preparation.definition
                ).execute()

            self.assertFalse(receipt.prepared_path.exists())
            self.assertEqual(
                receipt.manifest_document,
                json.loads(receipt.target_path.read_text(encoding="utf-8")),
            )
        finally:
            fixture.close()

    def test_recovery_rehydrates_definition_only_from_durable_journal(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(
                module, suffix="rehydrated-definition"
            )

            def crash_after_effect(point) -> None:
                if (
                    point
                    is module.RollbackManifestPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE
                ):
                    raise module.InjectedRollbackManifestPreparationCrashV2(point)

            with self.assertRaises(module.InjectedRollbackManifestPreparationCrashV2):
                module.RollbackManifestPreparationExecutorV2(
                    definition=preparation.definition,
                    failure_injector=crash_after_effect,
                ).execute()
            journal = json.loads(
                preparation.definition.journal_path.read_text(encoding="utf-8")
            )
            rehydrated = module.RollbackManifestPreparationDefinitionV2.from_document(
                journal["definition"]
            )

            receipt = module.RollbackManifestPreparationExecutorV2(
                definition=rehydrated
            ).recover()

            self.assertEqual(preparation.definition, rehydrated)
            self.assertEqual(
                rehydrated.activation_intent.operation_id, receipt.operation_id
            )
            self.assertFalse(rehydrated.journal_path.exists())
        finally:
            fixture.close()

    def test_recovery_converges_after_every_declared_failure_point(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            points = tuple(module.RollbackManifestPreparationFailurePointV2)
            self.assertEqual(7, len(points))
            for index, point in enumerate(points):
                with self.subTest(point=point.value):
                    preparation = fixture.build_preparation(
                        module, suffix=f"crash-{index}"
                    )
                    crashed = False

                    def crash_once(observed_point) -> None:
                        nonlocal crashed
                        if observed_point is point and not crashed:
                            crashed = True
                            raise module.InjectedRollbackManifestPreparationCrashV2(
                                point
                            )

                    with self.assertRaises(
                        module.InjectedRollbackManifestPreparationCrashV2
                    ):
                        module.RollbackManifestPreparationExecutorV2(
                            definition=preparation.definition,
                            failure_injector=crash_once,
                        ).execute()
                    self.assertTrue(crashed)

                    recovered = module.RollbackManifestPreparationExecutorV2(
                        definition=preparation.definition
                    ).recover()
                    repeated = module.RollbackManifestPreparationExecutorV2(
                        definition=preparation.definition
                    ).execute()
                    prepared = module.prepared_rollback_manifest_from_receipt_v2(
                        recovered, fixture.evidence
                    )

                    self.assertEqual(recovered.to_document(), repeated.to_document())
                    self.assertFalse(preparation.definition.journal_path.exists())
                    self.assertTrue(preparation.definition.receipt_path.is_file())
                    self.assertTrue(prepared.complete)
                    self.assertEqual(
                        recovered.prepared_manifest_file.value["inode"],
                        preparation.definition.activation_intent.prepared_path.stat().st_ino,
                    )
        finally:
            fixture.close()

    def test_changed_transition_source_receipt_is_rejected_explicitly(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            document = fixture.current_preparation_receipt.to_document()
            document.pop("transitionProofSnapshot")
            _write_private_json(fixture.current_preparation_receipt_path, document)
            paths = module.rollback_manifest_preparation_paths_v2(fixture.evidence)

            with self.assertRaises(
                module.RollbackManifestPreparationV2Error
            ) as captured:
                module.build_rollback_manifest_preparation_v2(
                    evidence=fixture.evidence,
                    current_preparation_receipt_path=(
                        fixture.current_preparation_receipt_path
                    ),
                    journal_path=paths.journal_path,
                    receipt_path=paths.receipt_path,
                    lock_path=paths.lock_path,
                    prepared_root=paths.prepared_root,
                )

            self.assertEqual(
                "ROLLBACK_PREVIOUS_MANIFEST_SOURCE_MISMATCH",
                captured.exception.code,
            )
            self.assertFalse(paths.journal_path.exists())
            self.assertFalse(paths.receipt_path.exists())
        finally:
            fixture.close()

    def test_orphan_prepared_manifest_without_journal_or_receipt_is_rejected(
        self,
    ) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            preparation = fixture.build_preparation(module, suffix="orphan")
            intent = preparation.definition.activation_intent
            intent.prepared_path.write_bytes(
                canonical_json_bytes(intent.manifest_document)
            )
            intent.prepared_path.chmod(0o600)

            with self.assertRaises(
                module.RollbackManifestPreparationV2Error
            ) as captured:
                module.RollbackManifestPreparationExecutorV2(
                    definition=preparation.definition
                ).execute()

            self.assertEqual(
                "ROLLBACK_PREPARATION_ORPHAN_SOURCE", captured.exception.code
            )
            self.assertFalse(preparation.definition.journal_path.exists())
            self.assertFalse(preparation.definition.receipt_path.exists())
        finally:
            fixture.close()

    def test_frozen_journal_and_receipt_conform_to_tracked_schemas(self) -> None:
        fixture = _PublishedUpgradeFixture()
        try:
            module = importlib.import_module(
                "codex_smart_subagents.rollback_manifest_preparation_v2"
            )
            frozen_preparation = fixture.build_preparation(
                module, suffix="schema-frozen"
            )

            def crash_after_freeze(point) -> None:
                if (
                    point
                    is module.RollbackManifestPreparationFailurePointV2.AFTER_PREPARATION_FREEZE
                ):
                    raise module.InjectedRollbackManifestPreparationCrashV2(point)

            with self.assertRaises(module.InjectedRollbackManifestPreparationCrashV2):
                module.RollbackManifestPreparationExecutorV2(
                    definition=frozen_preparation.definition,
                    failure_injector=crash_after_freeze,
                ).execute()
            journal_document = json.loads(
                frozen_preparation.definition.journal_path.read_text(encoding="utf-8")
            )
            journal_errors = list(
                _schema_validator(
                    "rollback-manifest-preparation-journal-v2.schema.json"
                ).iter_errors(journal_document)
            )
            self.assertEqual(
                [],
                journal_errors,
                journal_errors[0].message if journal_errors else "",
            )

            receipt = module.RollbackManifestPreparationExecutorV2(
                definition=frozen_preparation.definition
            ).recover()
            receipt_errors = list(
                _schema_validator(
                    "rollback-manifest-preparation-receipt-v2.schema.json"
                ).iter_errors(receipt.to_document())
            )
            self.assertEqual(
                [],
                receipt_errors,
                receipt_errors[0].message if receipt_errors else "",
            )
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
