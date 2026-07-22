from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    ActivationPreparationAbortV2,
    ActivationPreparationAmbiguousV2,
    ActivationPreparationCallbacksV2,
    ActivationPreparationDefinitionV2,
    ActivationPreparationExecutorV2,
    ActivationPreparationFailurePointV2,
    ActivationPreparationIntentV2,
    ActivationPreparationIntegrityErrorV2,
    ActivationPreparationReceiptV2,
    PreparedActivationObjectsV2,
    InjectedActivationPreparationCrashV2,
    LogicalPreparationObjectV2,
    capture_file_projection_v2,
    prepared_receipt_to_staged_activation_v2,
    tree_content_sha256_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    StateBundleV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


SCHEMA_SHA256 = "a" * 64
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INSTALLATION_ID = "ins2_1234567890abcdef1234567890abcdef"
OPERATION_ID = "op2_1234567890abcdef1234567890abcdef"
DATABASE_ID = "db2_1234567890abcdef1234567890abcdef"


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _MonotonicNanoseconds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


class _CrashOnce:
    def __init__(
        self,
        point: ActivationPreparationFailurePointV2,
        *,
        step_kind: str | None = None,
    ) -> None:
        self.point = point
        self.step_kind = step_kind
        self.triggered = False

    def __call__(
        self,
        point: ActivationPreparationFailurePointV2,
        step_kind: str | None,
    ) -> None:
        if (
            not self.triggered
            and point is self.point
            and (self.step_kind is None or self.step_kind == step_kind)
        ):
            self.triggered = True
            raise InjectedActivationPreparationCrashV2(point, step_kind)


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


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        self.control = root / "control"
        self.control.mkdir(mode=0o700)
        self.receipts = root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.activations = root / "managed" / "activations"
        self.activations.mkdir(parents=True, mode=0o700)
        os.chmod(self.activations.parent, 0o700)
        self.database_parent = root / "state" / "databases" / DATABASE_ID
        self.database_parent.mkdir(parents=True, mode=0o700)
        os.chmod(root / "state", 0o700)
        os.chmod(root / "state" / "databases", 0o700)
        self.template = root / "template"
        self.template.mkdir(mode=0o700)
        marketplace = self.template / "marketplace"
        marketplace.mkdir(mode=0o700)
        plugin = marketplace / "plugin.txt"
        plugin.write_bytes(b"immutable plugin\n")
        plugin.chmod(0o600)

        self.snapshot = root / "snapshot" / ("6" * 64)
        self.snapshot.parent.mkdir(mode=0o700)
        self.snapshot.write_bytes(b"codex snapshot\n")
        self.snapshot.chmod(0o500)
        self.database_path = self.database_parent / "smart-subagents.sqlite3"
        self.materialize_calls = 0
        snapshot_sha = hashlib.sha256(self.snapshot.read_bytes()).hexdigest()
        bundled_catalog = {
            "models": [{"model": "gpt-test", "reasoningEfforts": ["low", "high"]}]
        }
        bundled_catalog_fingerprint = domain_fingerprint(
            "codex-smart/bundled-catalog/v1", bundled_catalog
        )
        catalog_file = marketplace / "bundled-catalog-v1.json"
        catalog_file.write_bytes(canonical_json_bytes(bundled_catalog))
        catalog_file.chmod(0o600)
        identity = {
            "schemaVersion": 2,
            "generationId": "gen2_" + "c" * 64,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "database": {
                "databaseId": DATABASE_ID,
                "absolutePath": str(self.database_path),
                "schemaVersion": 2,
                "schemaFingerprint": "d" * 64,
                "schemaArtifactSha256": "e" * 64,
                "activationBindingNonce": "f" * 64,
            },
            "codexSnapshot": {
                "absolutePath": str(self.snapshot),
                "sha256": snapshot_sha,
            },
            "compatibilityFingerprint": "1" * 64,
            "routingPolicyFingerprint": "2" * 64,
            "bundledCatalogFingerprint": bundled_catalog_fingerprint,
            "minimumGatewayVersion": "0.2.0",
            "marketplaceTreeSha256": "4" * 64,
            "generationTreeSha256": "5" * 64,
        }
        activation_fingerprint = domain_fingerprint(
            "codex-smart/activation/v2", identity
        )
        activation_id = "act2_" + activation_fingerprint
        self.activation_dir = self.activations / activation_id
        self.activation_document = {
            "schemaVersion": 2,
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "identity": identity,
        }
        activation_file = self.template / "activation.json"
        activation_file.write_bytes(canonical_json_bytes(self.activation_document))
        activation_file.chmod(0o600)

        controller_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2",
            {
                "protocolVersion": 2,
                "release": "0.2.0",
                "namespace": "codex-smart-subagents-v2",
                "codexHomeHash": hashlib.sha256(
                    str((root / "codex-home").resolve()).encode("utf-8")
                ).hexdigest(),
                "stateHome": str(root / "state"),
                "activationFingerprint": activation_fingerprint,
                "compatibilityFingerprint": "1" * 64,
                "routingPolicyFingerprint": "2" * 64,
                "bundledCatalogFingerprint": bundled_catalog_fingerprint,
                "databaseId": DATABASE_ID,
                "databaseSchemaVersion": 2,
            },
        )

        completed_at = datetime(2026, 7, 19, 11, 59, tzinfo=timezone.utc)
        self.intent = ActivationPreparationIntentV2(
            source_root=root / "source",
            codex_home=root / "codex-home",
            codex_binary=root / "bin" / "codex",
            state_home=root / "state",
            socket_path=root / "state" / "controller.sock",
            controller_lock_path=root / "state" / "controller.lock",
            installation_id=INSTALLATION_ID,
            operation_id=OPERATION_ID,
            database_id=DATABASE_ID,
            activation_binding_nonce="f" * 64,
            activation_id=activation_id,
            activation_fingerprint=activation_fingerprint,
            controller_identity=controller_identity,
            compatibility_fingerprint="1" * 64,
            routing_policy_fingerprint="2" * 64,
            bundled_catalog_fingerprint=bundled_catalog_fingerprint,
            schema_fingerprint="d" * 64,
            schema_artifact_sha256="e" * 64,
            activation_dir=self.activation_dir,
            snapshot_path=self.snapshot,
            database_path=self.database_path,
            bundled_catalog_path=(
                self.activation_dir / "marketplace" / "bundled-catalog-v1.json"
            ),
            identity=self.activation_document["identity"],
            activation_document=self.activation_document,
            source_locator={
                "lexicalPath": str(root / "bin" / "codex"),
                "resolvedPathAtCapture": str(root / "bin" / "codex"),
                "argv0Policy": "lexical",
                "sourceObservedSha256": "8" * 64,
            },
            snapshot_locator={
                "absolutePath": str(self.snapshot),
                "sha256": snapshot_sha,
            },
            bundled_catalog=bundled_catalog,
            interface_evidence={
                "schemaVersion": 1,
                "compatibilityFingerprint": "1" * 64,
            },
            completed_at=completed_at,
        )
        activation_sha = hashlib.sha256(
            canonical_json_bytes(self.activation_document)
        ).hexdigest()
        self.definition = ActivationPreparationDefinitionV2(
            journal_path=self.control / "activation-preparation-v2.json",
            receipt_path=self.receipts / f"{OPERATION_ID}.json",
            lock_path=self.control / "installation.lock",
            activation_intent=self.intent,
            desired_seed=_empty_bundle(),
            snapshot_file=capture_file_projection_v2(
                self.snapshot, schema_sha256=SCHEMA_SHA256
            ),
            activation_tree_logical=LogicalPreparationObjectV2(
                path=self.activation_dir,
                object_type="directory",
                mode="0700",
                content_sha256=tree_content_sha256_v2(self.template),
            ),
            activation_file_logical=LogicalPreparationObjectV2(
                path=self.activation_dir / "activation.json",
                object_type="regular-file",
                mode="0600",
                content_sha256=activation_sha,
            ),
            database_empty_file_logical=LogicalPreparationObjectV2(
                path=self.database_path,
                object_type="regular-file",
                mode="0600",
                content_sha256=EMPTY_SHA256,
            ),
        )

    def materialize(self, intent: ActivationPreparationIntentV2) -> None:
        self.materialize_calls += 1
        self.assert_same_intent(intent)
        shutil.copytree(self.template, self.activation_dir)
        for directory, _, filenames in os.walk(self.activation_dir):
            Path(directory).chmod(0o700)
            for filename in filenames:
                (Path(directory) / filename).chmod(0o600)

    def build_desired(
        self,
        prepared: PreparedActivationObjectsV2,
        seed: StateBundleV2,
    ) -> StateBundleV2:
        if seed.to_document() != _empty_bundle().to_document():
            raise AssertionError("unexpected desired seed")
        return StateBundleV2(
            file_objects=(prepared.snapshot_file,),
            tree_objects=(),
            symlinks=(),
            manifest=None,
            activation=prepared.activation,
            database=prepared.database_binding_target,
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

    def assert_same_intent(self, intent: ActivationPreparationIntentV2) -> None:
        if intent.to_document() != self.intent.to_document():
            raise AssertionError("materializer received a changed intent")

    def executor(
        self,
        *,
        failure_injector=None,
        materialize=None,
    ) -> ActivationPreparationExecutorV2:
        callbacks = ActivationPreparationCallbacksV2(
            materialize_activation_tree=(materialize or self.materialize),
            build_desired=self.build_desired,
        )
        return ActivationPreparationExecutorV2(
            definition=self.definition,
            callbacks=callbacks,
            clock=_Clock(),
            failure_injector=failure_injector,
        )


class ActivationPreparationV2Tests(unittest.TestCase):
    def test_deadline_after_step_intent_preserves_preparation_journal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            monotonic = _MonotonicNanoseconds()
            deadline = OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
                monotonic_ns=monotonic,
            )

            def expire_after_intent(
                point: ActivationPreparationFailurePointV2,
                step_kind: str | None,
            ) -> None:
                if (
                    point
                    is ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT
                    and step_kind == "activation_tree"
                ):
                    monotonic.value = 1_000_000_000

            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    fixture.executor(failure_injector=expire_after_intent).execute()

            journal = json.loads(
                fixture.definition.journal_path.read_text(encoding="utf-8")
            )
            self.assertEqual(0, fixture.materialize_calls)
            self.assertEqual("PREPARING", journal["phase"])
            self.assertEqual("INTENT_DURABLE", journal["steps"][0]["state"])

    def test_abort_before_first_effect_only_closes_an_empty_intent(self) -> None:
        for point in (
            ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT,
            ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT,
        ):
            with self.subTest(point=point):
                with tempfile.TemporaryDirectory() as raw:
                    fixture = _Fixture(Path(raw))
                    crash = _CrashOnce(
                        point,
                        step_kind=(
                            "activation_tree"
                            if point
                            is ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT
                            else None
                        ),
                    )
                    with self.assertRaises(InjectedActivationPreparationCrashV2):
                        fixture.executor(failure_injector=crash).execute()

                    aborted = fixture.executor(
                        materialize=lambda _intent: self.fail(
                            "abort must not read or materialize the source tree"
                        )
                    ).abort_before_first_effect()
                    repeated = fixture.executor(
                        materialize=lambda _intent: self.fail(
                            "idempotent abort must not materialize the source tree"
                        )
                    ).abort_before_first_effect()

                    self.assertIsInstance(aborted, ActivationPreparationAbortV2)
                    self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
                    self.assertEqual(aborted, repeated)
                    self.assertFalse(fixture.definition.journal_path.exists())
                    self.assertFalse(fixture.definition.receipt_path.exists())
                    self.assertFalse(fixture.activation_dir.exists())
                    self.assertFalse(fixture.database_path.exists())

    def test_abort_before_first_effect_refuses_an_existing_candidate_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            crash = _CrashOnce(
                ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE,
                step_kind="activation_tree",
            )
            with self.assertRaises(InjectedActivationPreparationCrashV2):
                fixture.executor(failure_injector=crash).execute()

            with self.assertRaises(ActivationPreparationAmbiguousV2):
                fixture.executor().abort_before_first_effect()

            receipt = fixture.executor().execute()
            self.assertEqual(fixture.intent.operation_id, receipt.operation_id)

    def test_execute_publishes_complete_receipt_then_deletes_journal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))

            receipt = fixture.executor().execute()

            self.assertFalse(fixture.definition.journal_path.exists())
            self.assertTrue(fixture.definition.receipt_path.exists())
            self.assertEqual(fixture.materialize_calls, 1)
            self.assertEqual(receipt.activation_intent, fixture.intent)
            self.assertIn(receipt.snapshot_file, receipt.desired.file_objects)
            self.assertEqual(receipt.desired.activation, receipt.prepared.activation)
            self.assertEqual(
                receipt.desired.activation.value["directory"],
                receipt.activation_tree.value,
            )
            self.assertEqual(
                receipt.desired.activation.value["activationFile"],
                receipt.activation_file.value,
            )
            self.assertEqual(
                receipt.desired.database,
                receipt.database_binding_target,
            )
            self.assertEqual(receipt.snapshot_file, fixture.definition.snapshot_file)
            self.assertEqual(
                receipt.database_empty_file.value["device"],
                receipt.database_binding_target.value["device"],
            )
            self.assertEqual(
                receipt.database_empty_file.value["inode"],
                receipt.database_binding_target.value["inode"],
            )
            self.assertEqual(
                receipt.activation_tree.value["path"], str(fixture.activation_dir)
            )
            self.assertEqual(
                receipt.activation_file.value["sha256"],
                fixture.definition.activation_file_logical.content_sha256,
            )
            staged = prepared_receipt_to_staged_activation_v2(receipt)
            self.assertEqual(staged.activation_id, fixture.intent.activation_id)
            self.assertEqual(staged.database_id, DATABASE_ID)
            self.assertEqual(staged.database_path, fixture.database_path)
            self.assertEqual(
                staged.interface_evidence, fixture.intent.interface_evidence
            )

    def test_all_declared_crash_windows_converge(self) -> None:
        cases = (
            (ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT, None),
            (
                ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT,
                "activation_tree",
            ),
            (
                ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE,
                "activation_tree",
            ),
            (
                ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT,
                "database_empty_file",
            ),
            (
                ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE,
                "database_empty_file",
            ),
            (ActivationPreparationFailurePointV2.BEFORE_PREPARATION_FREEZE, None),
            (ActivationPreparationFailurePointV2.AFTER_PREPARATION_FREEZE, None),
            (ActivationPreparationFailurePointV2.BEFORE_RECEIPT_PUBLISH, None),
            (ActivationPreparationFailurePointV2.AFTER_RECEIPT_PUBLISH, None),
        )
        for index, (point, step_kind) in enumerate(cases):
            with self.subTest(point=point, step_kind=step_kind):
                with tempfile.TemporaryDirectory() as raw:
                    fixture = _Fixture(Path(raw) / str(index))
                    crash = _CrashOnce(point, step_kind=step_kind)
                    with self.assertRaises(InjectedActivationPreparationCrashV2):
                        fixture.executor(failure_injector=crash).execute()

                    receipt = fixture.executor().execute()

                    self.assertEqual(
                        receipt.activation_intent.activation_id,
                        fixture.intent.activation_id,
                    )
                    self.assertEqual(receipt.activation_intent.database_id, DATABASE_ID)
                    self.assertFalse(fixture.definition.journal_path.exists())
                    self.assertTrue(fixture.definition.receipt_path.exists())
                    self.assertEqual(fixture.materialize_calls, 1)

    def test_exact_receipt_is_the_only_source_on_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            first = fixture.executor().execute()

            def forbidden(_: ActivationPreparationIntentV2) -> None:
                raise AssertionError("completed preparation must not rematerialize")

            second = fixture.executor(materialize=forbidden).execute()

            self.assertEqual(first.to_document(), second.to_document())
            self.assertEqual(fixture.materialize_calls, 1)

    def test_existing_target_without_journal_or_receipt_is_ambiguous(self) -> None:
        for target_kind in ("activation", "database"):
            with self.subTest(target_kind=target_kind):
                with tempfile.TemporaryDirectory() as raw:
                    fixture = _Fixture(Path(raw))
                    if target_kind == "activation":
                        fixture.materialize(fixture.intent)
                    else:
                        fixture.database_path.write_bytes(b"")
                        fixture.database_path.chmod(0o600)

                    with self.assertRaises(ActivationPreparationAmbiguousV2):
                        fixture.executor().execute()

    def test_recovery_blocks_a_third_logical_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            crash = _CrashOnce(
                ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT,
                step_kind="activation_tree",
            )
            with self.assertRaises(InjectedActivationPreparationCrashV2):
                fixture.executor(failure_injector=crash).execute()
            fixture.activation_dir.mkdir(mode=0o700)
            foreign = fixture.activation_dir / "foreign"
            foreign.write_bytes(b"not the planned tree")
            foreign.chmod(0o600)

            with self.assertRaises(ActivationPreparationAmbiguousV2):
                fixture.executor().execute()

    def test_frozen_journal_and_receipt_presence_matrix_closes_journal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            crash = _CrashOnce(
                ActivationPreparationFailurePointV2.AFTER_RECEIPT_PUBLISH
            )
            with self.assertRaises(InjectedActivationPreparationCrashV2):
                fixture.executor(failure_injector=crash).execute()
            frozen_bytes = fixture.definition.journal_path.read_bytes()
            self.assertTrue(fixture.definition.receipt_path.exists())

            receipt = fixture.executor().execute()

            self.assertFalse(fixture.definition.journal_path.exists())
            self.assertEqual(
                receipt.frozen_journal_fingerprint,
                ActivationPreparationReceiptV2.from_path(
                    fixture.definition.receipt_path
                ).frozen_journal_fingerprint,
            )
            self.assertTrue(frozen_bytes)

    def test_tampered_receipt_is_rejected_even_if_fingerprint_is_recomputed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            receipt = fixture.executor().execute().to_document()
            receipt["databaseBindingTarget"]["value"]["inode"] += 1
            binding = receipt["databaseBindingTarget"]
            envelope = {
                key: value
                for key, value in binding.items()
                if key != "valueFingerprint"
            }
            binding["valueFingerprint"] = domain_fingerprint(
                "codex-smart/database-binding-target/v2", envelope
            )
            receipt_without_fingerprint = {
                key: value
                for key, value in receipt.items()
                if key != "receiptFingerprint"
            }
            receipt["receiptFingerprint"] = domain_fingerprint(
                "codex-smart/activation-preparation-receipt/v2",
                receipt_without_fingerprint,
            )

            with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                ActivationPreparationReceiptV2.from_document(receipt)

    def test_definition_rejects_non_absolute_paths_and_wrong_activation_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                replace(fixture.definition, journal_path=Path("relative.json"))
            with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                replace(
                    fixture.definition,
                    activation_file_logical=replace(
                        fixture.definition.activation_file_logical,
                        path=fixture.activation_dir / "other.json",
                    ),
                )

    def test_transition_proof_snapshot_and_prepared_manifest_are_paired(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            prepared_manifest = LogicalPreparationObjectV2(
                path=fixture.control / "prepared-manifests" / "manifest.json",
                object_type="regular-file",
                mode="0600",
                content_sha256="b" * 64,
            )

            with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                replace(
                    fixture.definition,
                    prepared_manifest_logical=prepared_manifest,
                )

    def test_receipt_json_has_exact_top_level_object_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            document = fixture.executor().execute().to_document()

            self.assertEqual(
                set(document),
                {
                    "schemaVersion",
                    "receiptKind",
                    "installationId",
                    "operationId",
                    "activationIntent",
                    "snapshotFile",
                    "activationTree",
                    "activationFile",
                    "databaseEmptyFile",
                    "databaseBindingTarget",
                    "desired",
                    "frozenJournalFingerprint",
                    "completedAt",
                    "receiptFingerprint",
                },
            )
            mode = stat.S_IMODE(fixture.definition.receipt_path.lstat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_valid_looking_but_changed_step_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            crash = _CrashOnce(
                ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT
            )
            with self.assertRaises(InjectedActivationPreparationCrashV2):
                fixture.executor(failure_injector=crash).execute()
            document = __import__("json").loads(
                fixture.definition.journal_path.read_text(encoding="utf-8")
            )
            step = document["steps"][0]
            step["stepId"] = "pst2_ffffffffffffffffffffffffffffffff"
            step_projection = {
                key: value for key, value in step.items() if key != "stepFingerprint"
            }
            step["stepFingerprint"] = domain_fingerprint(
                "codex-smart/activation-preparation-step/v2", step_projection
            )
            journal_projection = {
                key: value
                for key, value in document.items()
                if key != "journalFingerprint"
            }
            document["journalFingerprint"] = domain_fingerprint(
                "codex-smart/activation-preparation-journal/v2",
                journal_projection,
            )
            fixture.definition.journal_path.write_bytes(canonical_json_bytes(document))

            with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                fixture.executor().execute()

    def test_intent_rejects_rebound_outer_fingerprint_with_broken_inner_link(
        self,
    ) -> None:
        def change_interface(document: dict[str, object]) -> None:
            document["interfaceEvidence"]["compatibilityFingerprint"] = "9" * 64

        def change_identity_compatibility(document: dict[str, object]) -> None:
            document["identity"]["compatibilityFingerprint"] = "9" * 64
            document["activationDocument"]["identity"] = copy.deepcopy(
                document["identity"]
            )

        def change_identity_routing(document: dict[str, object]) -> None:
            document["identity"]["routingPolicyFingerprint"] = "9" * 64
            document["activationDocument"]["identity"] = copy.deepcopy(
                document["identity"]
            )

        def change_identity_catalog(document: dict[str, object]) -> None:
            document["identity"]["bundledCatalogFingerprint"] = "9" * 64
            document["activationDocument"]["identity"] = copy.deepcopy(
                document["identity"]
            )

        def change_snapshot_path(document: dict[str, object]) -> None:
            document["identity"]["codexSnapshot"]["absolutePath"] = str(
                Path(document["snapshotPath"]).with_name("foreign")
            )
            document["activationDocument"]["identity"] = copy.deepcopy(
                document["identity"]
            )

        def change_snapshot_sha(document: dict[str, object]) -> None:
            document["identity"]["codexSnapshot"]["sha256"] = "9" * 64
            document["activationDocument"]["identity"] = copy.deepcopy(
                document["identity"]
            )

        def change_bundled_catalog(document: dict[str, object]) -> None:
            document["bundledCatalog"]["models"][0]["model"] = "other-model"

        def change_controller_identity(document: dict[str, object]) -> None:
            document["controllerIdentity"] = "9" * 64

        cases = (
            change_interface,
            change_identity_compatibility,
            change_identity_routing,
            change_identity_catalog,
            change_snapshot_path,
            change_snapshot_sha,
            change_bundled_catalog,
            change_controller_identity,
        )
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            for mutate in cases:
                with self.subTest(mutate=mutate.__name__):
                    document = fixture.intent.to_document()
                    mutate(document)
                    projection = {
                        key: value
                        for key, value in document.items()
                        if key != "activationIntentFingerprint"
                    }
                    document["activationIntentFingerprint"] = domain_fingerprint(
                        "codex-smart/activation-preparation-intent/v2",
                        projection,
                    )
                    with self.assertRaises(ActivationPreparationIntegrityErrorV2):
                        ActivationPreparationIntentV2.from_document(document)


if __name__ == "__main__":
    unittest.main()
