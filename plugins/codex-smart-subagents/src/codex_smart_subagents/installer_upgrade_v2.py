"""Производственная подготовка кандидата для обновления установки версии 2."""

from __future__ import annotations

import copy
import hashlib
import os
import secrets
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .activation_gateway_v2 import (
    GatewayLayout,
    _LIFECYCLE_SCHEMA_SHA256,
    _tree_sha256,
)
from .activation_materializer_v2 import (
    _EXCLUDED_TREE_NAMES,
    _CONFIG_CONTRACT_VECTOR_FILES,
    StagedActivationV2,
    _RUNTIME_SCHEMA_FILES,
    _RUNTIME_VECTOR_FILES,
    _PLUGIN_NAME,
    _RELEASE,
    _atomic_write_json,
    _controller_identity,
    _ensure_lock_file,
    _ensure_private_directory,
    _fsync_directory,
    _materialize_marketplace,
    _make_activation_tree_removable_v2,
    _read_json,
    _required_sha256,
    _sha256_file,
    _validate_snapshot_subject,
    normalize_state_home_v2,
    seal_activation_tree_v2,
)
from .activation_preparation_v2 import (
    ActivationPreparationAbortV2,
    ActivationPreparationExecutorV2,
    ActivationPreparationCallbacksV2,
    ActivationPreparationDefinitionV2,
    ActivationPreparationIntentV2,
    ActivationPreparationReceiptV2,
    LogicalPreparationObjectV2,
    PreparedActivationObjectsV2,
    capture_file_projection_v2,
    capture_tree_projection_v2,
    prepared_receipt_to_staged_activation_v2,
    tree_content_sha256_v2,
    _read_canonical_private_json,
)
from .activation_transition_v2 import (
    ActivationTransitionProofV2,
    PreparedManifestCommitV2,
    PreparedManifestPlanV2,
    _build_prepared_manifest_plan_from_verified_proof_v2,
    _validate_installer_source_lineage_v2,
    build_prepared_manifest_plan_v2,
    materialize_prepared_manifest_plan_v2,
    prepared_manifest_commit_from_receipt_v2,
    reverify_activation_transition_proof_v2,
    verify_prepared_manifest_file_v2,
)
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2
from .activation_transition_rehydration_v2 import (
    ActivationTransitionProofSnapshotV2,
    rehydrate_activation_transition_proof_v2,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .codex_binary_snapshot import CodexBinarySnapshotter, SnapshotCommandExecutor
from .interface_probe_v1 import probe_codex_interface_v1
from .lifecycle_operation_v2 import ProjectionV2, StateBundleV2
from .policy_bundle_v2 import PolicyBundleV2
from .prepared_database_v2 import (
    PreparedDatabaseServiceIdentityV2,
    PreparedDatabaseStateV2,
    observe_prepared_database_v2,
    prepare_database_v2,
)
from .schema_projection import APPLICATION_ID, read_schema_artifact


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SOURCE_LINEAGE_KIND = "codex-smart-source-lineage/v2"


def _installer_source_lineage_from_plugin_root_v2(
    plugin_root: Path,
    *,
    required: bool,
) -> dict[str, Any] | None:
    path = plugin_root / "config" / "source-lineage-v2.json"
    if not os.path.lexists(path):
        if required:
            raise ValueError("candidate source lineage is missing")
        return None
    document = _read_json(path)
    if (
        set(document)
        != {"schemaVersion", "kind", "generation", "implementationDigest"}
        or document.get("kind") != _SOURCE_LINEAGE_KIND
    ):
        raise ValueError("candidate source lineage has an invalid shape")
    return _validate_installer_source_lineage_v2(
        {
            key: document[key]
            for key in ("schemaVersion", "generation", "implementationDigest")
        }
    )


def _installer_source_lineage_from_source_root_v2(
    source_root: Path,
) -> dict[str, Any]:
    value = _installer_source_lineage_from_plugin_root_v2(
        source_root / "plugins" / _PLUGIN_NAME,
        required=True,
    )
    assert value is not None
    return value


def _installer_source_lineage_from_activation_v2(
    definition: ActivationPreparationDefinitionV2,
) -> dict[str, Any] | None:
    return _installer_source_lineage_from_plugin_root_v2(
        definition.activation_intent.activation_dir
        / "marketplace"
        / "plugins"
        / _PLUGIN_NAME,
        required=False,
    )


@dataclass(frozen=True)
class UpgradePreparationV2:
    definition: ActivationPreparationDefinitionV2
    callbacks: ActivationPreparationCallbacksV2
    prepared_manifest_plan: PreparedManifestPlanV2


@dataclass(frozen=True)
class InitialActivationPreparationV2:
    """Долговечная подготовка самой первой активации."""

    definition: ActivationPreparationDefinitionV2
    callbacks: ActivationPreparationCallbacksV2


def build_initial_activation_preparation_v2(
    *,
    source_root: Path,
    codex_home: Path,
    state_home: Path,
    codex_binary: Path,
    policy_bundle: PolicyBundleV2,
    installation_id: str,
    operation_id: str,
    snapshotter: Any | None = None,
    interface_executor: SnapshotCommandExecutor | None = None,
    completed_at: datetime | None = None,
) -> InitialActivationPreparationV2:
    """Построить или восстановить первое подготовительное намерение."""

    if (
        len(installation_id) != len("ins2_") + 32
        or not installation_id.startswith("ins2_")
        or any(character not in "0123456789abcdef" for character in installation_id[5:])
        or len(operation_id) != len("op2_") + 32
        or not operation_id.startswith("op2_")
        or any(character not in "0123456789abcdef" for character in operation_id[4:])
    ):
        raise ValueError("initial preparation identities are invalid")
    source_root = source_root.expanduser().resolve()
    codex_home = codex_home.expanduser().absolute()
    state_home = normalize_state_home_v2(state_home)
    codex_binary = codex_binary.expanduser().absolute()
    layout = GatewayLayout.for_codex_home(codex_home)
    control_path = (
        layout.manifest_root
        / "codex-smart-subagents-v2.activation-preparation.transaction.json"
    )
    receipt_path = (
        layout.receipts_root
        / installation_id
        / f"{operation_id}.preparation.json"
    )
    lock_path = layout.lock_path
    for directory in (
        layout.manifest_root,
        layout.receipts_root,
        receipt_path.parent,
        layout.managed_root,
        layout.managed_root / "activations",
        layout.managed_root / "codex-snapshots",
        state_home,
        state_home / "databases",
        state_home / "backups",
        state_home / "quarantine",
    ):
        _ensure_private_directory(directory)
    _ensure_lock_file(lock_path)

    persisted = _load_persisted_definition(
        control_path=control_path,
        receipt_path=receipt_path,
    )
    if persisted is not None:
        intent = persisted.activation_intent
        if (
            intent.installation_id != installation_id
            or intent.operation_id != operation_id
            or intent.source_root != source_root
            or intent.codex_home != codex_home
            or intent.state_home != state_home
            or intent.codex_binary != codex_binary
            or persisted.desired_seed != _empty_bundle()
            or persisted.prepared_manifest_logical is not None
            or persisted.transition_proof_snapshot is not None
        ):
            raise ValueError("persisted initial preparation differs from request")
        return InitialActivationPreparationV2(
            definition=persisted,
            callbacks=_initial_callbacks_for_intent_v2(
                intent,
                expected_activation_tree_sha256=(
                    persisted.activation_tree_logical.content_sha256
                ),
            ),
        )

    snapshotter = snapshotter or CodexBinarySnapshotter(
        snapshot_root=layout.managed_root / "codex-snapshots"
    )
    subject = snapshotter.materialize(str(codex_binary))
    snapshot_path = _validate_snapshot_subject(
        subject,
        expected_root=layout.managed_root / "codex-snapshots",
        codex_binary=codex_binary,
    )
    observation = probe_codex_interface_v1(
        subject=subject,
        contract_root=source_root / "docs" / "contracts",
        policy_bundle=policy_bundle,
        executor=interface_executor,
    )
    captured_at = _aware(completed_at or datetime.now(timezone.utc))
    database_seed = domain_fingerprint(
        "codex-smart/initial-database-id/v2",
        {
            "installationId": installation_id,
            "operationId": operation_id,
            "snapshotSha256": subject["snapshotSha256"],
        },
    )
    database_id = "db2_" + database_seed[:32]
    activation_nonce = domain_fingerprint(
        "codex-smart/initial-activation-binding/v2",
        {
            "installationId": installation_id,
            "operationId": operation_id,
            "databaseId": database_id,
            "snapshotSha256": subject["snapshotSha256"],
        },
    )
    database_path = state_home / "databases" / database_id / "smart-subagents.sqlite3"
    _ensure_private_directory(database_path.parent)
    source_locator = {
        "lexicalPath": str(codex_binary),
        "resolvedPathAtCapture": str(codex_binary.resolve(strict=True)),
        "argv0Policy": "lexical",
        "sourceObservedSha256": str(subject["sourceObservedSha256"]),
    }
    snapshot_locator = {
        "absolutePath": str(snapshot_path),
        "sha256": str(subject["snapshotSha256"]),
    }
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="cs-initial-tree-") as raw:
        template = Path(raw).resolve()
        template.chmod(0o700)
        marketplace = template / "marketplace"
        plugin_root = marketplace / "plugins" / _PLUGIN_NAME
        _materialize_marketplace(
            source_root=source_root,
            marketplace=marketplace,
            plugin_root=plugin_root,
            bundled_catalog=observation.bundled_catalog.projection,
        )
        marketplace_sha = _tree_sha256(marketplace)
        generation_sha = _tree_sha256(plugin_root)
        schema_manifest = _read_json(
            plugin_root
            / "src"
            / "codex_smart_subagents"
            / "schema"
            / "state-v2.manifest.json"
        )
        schema_artifact = (
            plugin_root
            / "src"
            / "codex_smart_subagents"
            / "schema"
            / "state-v2.sql"
        )
        schema_fingerprint = _required_sha256(
            schema_manifest.get("schemaFingerprint"), "schemaFingerprint"
        )
        schema_artifact_sha256 = _required_sha256(
            schema_manifest.get("stateSqlSha256"), "stateSqlSha256"
        )
        if _sha256_file(schema_artifact) != schema_artifact_sha256:
            raise ValueError("candidate schema artifact differs from its manifest")
        compatibility = str(
            observation.interface_evidence["compatibilityFingerprint"]
        )
        identity = {
            "schemaVersion": 2,
            "generationId": "gen2_" + generation_sha,
            "release": _RELEASE,
            "pluginId": _PLUGIN_NAME,
            "marketplaceTreeSha256": marketplace_sha,
            "generationTreeSha256": generation_sha,
            "database": {
                "databaseId": database_id,
                "absolutePath": str(database_path),
                "schemaVersion": 2,
                "schemaFingerprint": schema_fingerprint,
                "schemaArtifactSha256": schema_artifact_sha256,
                "activationBindingNonce": activation_nonce,
            },
            "codexSnapshot": {
                "absolutePath": str(snapshot_path),
                "sha256": str(subject["snapshotSha256"]),
            },
            "compatibilityFingerprint": compatibility,
            "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
            "bundledCatalogFingerprint": observation.bundled_catalog.fingerprint,
            "minimumGatewayVersion": _RELEASE,
        }
        activation_fingerprint = domain_fingerprint(
            "codex-smart/activation/v2", identity
        )
        activation_id = "act2_" + activation_fingerprint
        activation_dir = layout.managed_root / "activations" / activation_id
        activation_document = {
            "schemaVersion": 2,
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "identity": identity,
        }
        _atomic_write_json(template / "activation.json", activation_document)
        seal_activation_tree_v2(template)
        activation_tree_sha256 = tree_content_sha256_v2(template)
        _make_activation_tree_removable_v2(template)
    intent = ActivationPreparationIntentV2(
        source_root=source_root,
        codex_home=codex_home,
        codex_binary=codex_binary,
        state_home=state_home,
        socket_path=state_home / "controller.sock",
        controller_lock_path=state_home / "controller.lock",
        installation_id=installation_id,
        operation_id=operation_id,
        database_id=database_id,
        activation_binding_nonce=activation_nonce,
        activation_id=activation_id,
        activation_fingerprint=activation_fingerprint,
        controller_identity=_controller_identity(
            codex_home=codex_home,
            state_home=state_home,
            activation_fingerprint=activation_fingerprint,
            compatibility_fingerprint=compatibility,
            routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
            bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
            database_id=database_id,
        ),
        compatibility_fingerprint=compatibility,
        routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
        bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
        schema_fingerprint=schema_fingerprint,
        schema_artifact_sha256=schema_artifact_sha256,
        activation_dir=activation_dir,
        snapshot_path=snapshot_path,
        database_path=database_path,
        bundled_catalog_path=(
            activation_dir
            / "marketplace"
            / "plugins"
            / _PLUGIN_NAME
            / "config"
            / "bundled-catalog-v1.json"
        ),
        identity=identity,
        activation_document=activation_document,
        source_locator=source_locator,
        snapshot_locator=snapshot_locator,
        bundled_catalog=copy.deepcopy(observation.bundled_catalog.projection),
        interface_evidence=copy.deepcopy(observation.interface_evidence),
        completed_at=captured_at,
    )
    definition = ActivationPreparationDefinitionV2(
        journal_path=control_path,
        receipt_path=receipt_path,
        lock_path=lock_path,
        activation_intent=intent,
        desired_seed=_empty_bundle(),
        snapshot_file=capture_file_projection_v2(
            snapshot_path, schema_sha256=_LIFECYCLE_SCHEMA_SHA256
        ),
        activation_tree_logical=LogicalPreparationObjectV2(
            path=activation_dir,
            object_type="directory",
            mode="0500",
            content_sha256=activation_tree_sha256,
        ),
        activation_file_logical=LogicalPreparationObjectV2(
            path=activation_dir / "activation.json",
            object_type="regular-file",
            mode="0400",
            content_sha256=hashlib.sha256(
                canonical_json_bytes(activation_document)
            ).hexdigest(),
        ),
        database_empty_file_logical=LogicalPreparationObjectV2(
            path=database_path,
            object_type="regular-file",
            mode="0600",
            content_sha256=_EMPTY_SHA256,
        ),
    )
    return InitialActivationPreparationV2(
        definition=definition,
        callbacks=_initial_callbacks_for_intent_v2(
            intent,
            expected_activation_tree_sha256=activation_tree_sha256,
        ),
    )


def execute_initial_activation_preparation_v2(
    preparation: InitialActivationPreparationV2,
) -> StagedActivationV2:
    """Завершить подготовку и вернуть staged только из проверенной квитанции."""

    if not isinstance(preparation, InitialActivationPreparationV2):
        raise TypeError("preparation must be InitialActivationPreparationV2")
    executor = ActivationPreparationExecutorV2(
        definition=preparation.definition,
        callbacks=preparation.callbacks,
    )
    database_path = preparation.definition.activation_intent.database_path
    receipt_path = preparation.definition.receipt_path
    initialized_database = False
    if os.path.lexists(database_path):
        database_info = database_path.lstat()
        initialized_database = (
            stat.S_ISREG(database_info.st_mode)
            and not stat.S_ISLNK(database_info.st_mode)
            and database_info.st_size > 0
        )
    if initialized_database and os.path.lexists(receipt_path):
        if os.path.lexists(preparation.definition.journal_path):
            raise ValueError(
                "initialized initial database coexists with preparation journal"
            )
        published = ActivationPreparationReceiptV2.from_path(receipt_path)
        executor._verify_receipt_matches_definition(published)
        executor._verify_live_receipt(
            published,
            database_may_be_initialized=True,
        )
        verified = published
    else:
        executor.execute()
        published = ActivationPreparationReceiptV2.from_path(receipt_path)
        verified = executor.execute()
    if published.to_document() != verified.to_document():
        raise ValueError("initial preparation receipt changed during verification")
    _remove_published_stage_owner_v2(verified.activation_intent)
    return prepared_receipt_to_staged_activation_v2(verified)


def _initial_callbacks_for_intent_v2(
    intent: ActivationPreparationIntentV2,
    *,
    expected_activation_tree_sha256: str,
) -> ActivationPreparationCallbacksV2:
    def materialize(received: ActivationPreparationIntentV2) -> None:
        if received.to_document() != intent.to_document():
            raise ValueError("initial activation preparation intent changed")
        if os.path.lexists(received.activation_dir):
            raise ValueError("initial activation path is already occupied")
        _remove_incomplete_activation_stage_v2(received)
        stage = _activation_tree_stage_path_v2(received)
        previous_umask = os.umask(0o077)
        try:
            published = False
            try:
                _create_activation_stage_owner_v2(received)
                stage.mkdir(mode=0o700)
                marketplace = stage / "marketplace"
                plugin_root = marketplace / "plugins" / _PLUGIN_NAME
                _materialize_marketplace(
                    source_root=received.source_root,
                    marketplace=marketplace,
                    plugin_root=plugin_root,
                    bundled_catalog=received.bundled_catalog,
                )
                _atomic_write_json(
                    stage / "activation.json", received.activation_document
                )
                os.replace(stage, received.activation_dir)
                published = True
                seal_activation_tree_v2(received.activation_dir)
                if (
                    tree_content_sha256_v2(received.activation_dir)
                    != expected_activation_tree_sha256
                ):
                    raise ValueError(
                        "materialized initial activation differs from intent"
                    )
                _fsync_materialized_tree_v2(received.activation_dir)
                _fsync_directory(received.activation_dir.parent)
                _remove_published_stage_owner_v2(received)
            except BaseException:
                if published:
                    _remove_published_activation_tree_v2(received)
                else:
                    _remove_incomplete_activation_stage_v2(received)
                raise
        finally:
            os.umask(previous_umask)

    def build_desired(
        prepared: PreparedActivationObjectsV2,
        seed: StateBundleV2,
    ) -> StateBundleV2:
        if seed != _empty_bundle():
            raise ValueError("initial preparation seed changed")
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

    return ActivationPreparationCallbacksV2(
        materialize_activation_tree=materialize,
        build_desired=build_desired,
    )


@dataclass(frozen=True)
class _BoundPythonRuntimeV2:
    path: Path
    identity: tuple[int, int, int, int, int, int, int, int, int]
    portable_shebang: bytes


class PersistedUpgradePreparationRecoveryV2(ActivationPreparationExecutorV2):
    """Точное prep-recovery без повторного чтения source_root и Codex."""

    def __init__(self, definition: ActivationPreparationDefinitionV2) -> None:
        self.prepared_manifest_plan: PreparedManifestPlanV2 | None = None
        super().__init__(
            definition=definition,
            callbacks=_source_independent_recovery_callbacks_v2(
                definition=definition,
                prepared_manifest_plan=None,
            ),
        )

    def recover(
        self,
    ) -> ActivationPreparationReceiptV2 | ActivationPreparationAbortV2:
        intent = self.definition.activation_intent
        if not os.path.lexists(intent.activation_dir):
            _remove_incomplete_activation_stage_v2(intent)
            return self.abort_before_first_effect()

        observed_tree = capture_tree_projection_v2(
            intent.activation_dir,
            schema_sha256=self.definition.snapshot_file.schema_sha256,
        )
        if (
            observed_tree.value.get("treeSha256")
            != self.definition.activation_tree_logical.content_sha256
        ):
            raise ValueError(
                "persisted activation tree differs from preparation intent"
            )
        _remove_published_stage_owner_v2(intent)
        snapshot = self.definition.transition_proof_snapshot
        if snapshot is None:
            raise ValueError("persisted upgrade preparation has no transition proof")
        proof = rehydrate_activation_transition_proof_v2(snapshot)
        staged = _staged_from_intent(intent)
        plan = build_prepared_manifest_plan_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=(
                self.definition.activation_tree_logical.content_sha256
            ),
        )
        if self.definition.prepared_manifest_logical != _prepared_manifest_logical(
            plan
        ):
            source_digest = _installer_source_digest_from_activation_v2(self.definition)
            plan = build_prepared_manifest_plan_v2(
                proof=proof,
                staged=staged,
                activation_tree_sha256=(
                    self.definition.activation_tree_logical.content_sha256
                ),
                installer_source_digest=source_digest,
                installer_source_lineage=(
                    _installer_source_lineage_from_activation_v2(self.definition)
                ),
            )
            if self.definition.prepared_manifest_logical != _prepared_manifest_logical(
                plan
            ):
                raise ValueError(
                    "persisted prepared manifest differs from immutable candidate"
                )
        self.prepared_manifest_plan = plan
        return ActivationPreparationExecutorV2(
            definition=self.definition,
            callbacks=_source_independent_recovery_callbacks_v2(
                definition=self.definition,
                prepared_manifest_plan=plan,
            ),
        ).recover()


def build_persisted_upgrade_preparation_recovery_v2(
    *,
    journal_path: Path,
) -> PersistedUpgradePreparationRecoveryV2:
    """Восстановить исполнитель только из полного определения prep-журнала."""

    journal_path = journal_path.expanduser().absolute()
    document = _read_private_canonical_object(journal_path)
    definition_document = document.get("definition")
    if type(definition_document) is not dict:
        raise ValueError("preparation journal has no complete definition")
    definition = _definition_from_document(definition_document)
    if definition.journal_path != journal_path:
        raise ValueError("preparation journal path differs from its definition")
    recovery = PersistedUpgradePreparationRecoveryV2(definition)
    if recovery._read_journal() != document:
        raise ValueError("preparation journal changed during recovery binding")
    return recovery


def _recover_upgrade_preparation_from_main_journal_v2(
    *,
    preparation_receipt_path: Path,
    journal: Mapping[str, Any],
) -> UpgradePreparationV2:
    """Восстановить подготовку только из main journal и prep receipt."""

    if (
        not isinstance(preparation_receipt_path, Path)
        or not preparation_receipt_path.is_absolute()
    ):
        raise TypeError("preparation_receipt_path must be an absolute Path")
    receipt = ActivationPreparationReceiptV2.from_path(preparation_receipt_path)
    snapshot = receipt.transition_proof_snapshot
    if snapshot is None:
        raise ValueError("preparation receipt has no transition proof snapshot")
    proof = rehydrate_activation_transition_proof_v2(snapshot, journal=journal)
    control_path = (
        proof.layout.manifest_root
        / "codex-smart-subagents-v2.activation-preparation.transaction.json"
    )
    expected_receipt_path = (
        proof.layout.receipts_root
        / receipt.installation_id
        / f"{receipt.operation_id}.preparation.json"
    )
    if preparation_receipt_path != expected_receipt_path:
        raise ValueError("preparation receipt path differs from transition proof")
    persisted = _load_persisted_definition(
        control_path=control_path,
        receipt_path=preparation_receipt_path,
    )
    expected = _definition_from_preparation_receipt_v2(
        receipt,
        control_path=control_path,
        receipt_path=preparation_receipt_path,
    )
    if persisted is None or persisted != expected:
        raise ValueError("persisted upgrade preparation differs from receipt")

    staged = _staged_from_intent(persisted.activation_intent)
    plan = _build_prepared_manifest_plan_from_verified_proof_v2(
        proof=proof,
        staged=staged,
        activation_tree_sha256=persisted.activation_tree_logical.content_sha256,
    )
    if persisted.prepared_manifest_logical != _prepared_manifest_logical(plan):
        plan = _build_prepared_manifest_plan_from_verified_proof_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=(
                persisted.activation_tree_logical.content_sha256
            ),
            installer_source_digest=(
                _installer_source_digest_from_activation_v2(persisted)
            ),
            installer_source_lineage=(
                _installer_source_lineage_from_activation_v2(persisted)
            ),
        )
    if persisted.prepared_manifest_logical != _prepared_manifest_logical(plan):
        raise ValueError("persisted prepared manifest differs from receipt")

    preparation = UpgradePreparationV2(
        definition=persisted,
        callbacks=_source_independent_recovery_callbacks_v2(
            definition=persisted,
            prepared_manifest_plan=plan,
        ),
        prepared_manifest_plan=plan,
    )
    prepared_manifest_from_upgrade_receipt_v2(
        proof=proof,
        preparation=preparation,
        receipt=receipt,
    )
    return preparation


def build_upgrade_preparation_v2(
    *,
    proof: Any,
    operation_id: str,
    source_root: Path,
    codex_binary: Path,
    policy_bundle: PolicyBundleV2,
    snapshotter: Any | None = None,
    interface_executor: SnapshotCommandExecutor | None = None,
    completed_at: datetime | None = None,
    source_digest: str | None = None,
) -> UpgradePreparationV2:
    """Построить или восстановить определение неактивного кандидата.

    Идентификаторы выводятся из уже случайного ``operationId`` и аттестованного
    снимка. Повтор одного operationId поэтому не создаёт новую идентичность, а
    существующий журнал или квитанция остаются единственным источником истины.
    """

    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if os.path.lexists(proof.layout.journal_path):
        reverify_activation_transition_proof_v2(
            proof,
            operation_id=operation_id,
            require_journal=True,
        )
    else:
        reverify_activation_transition_proof_v2(proof)
    transition_proof_snapshot = ActivationTransitionProofSnapshotV2.from_proof(
        proof,
        operation_id=operation_id,
    )
    layout = proof.layout
    state_home = normalize_state_home_v2(Path(proof.state_home))
    source_root = source_root.expanduser().resolve()
    source_lineage = (
        _installer_source_lineage_from_source_root_v2(source_root)
        if source_digest is not None
        else None
    )
    codex_binary = codex_binary.expanduser().absolute()
    control_path = (
        layout.manifest_root
        / "codex-smart-subagents-v2.activation-preparation.transaction.json"
    )
    receipt_path = (
        layout.receipts_root
        / str(proof.installation_id)
        / f"{operation_id}.preparation.json"
    )
    lock_path = layout.manifest_root / "activation-preparation.lock"
    _ensure_private_directory(layout.manifest_root)
    _ensure_private_directory(layout.receipts_root)
    _ensure_private_directory(receipt_path.parent)
    _ensure_lock_file(lock_path)

    persisted = _load_persisted_definition(
        control_path=control_path,
        receipt_path=receipt_path,
    )
    if persisted is not None:
        intent = persisted.activation_intent
        if (
            intent.operation_id != operation_id
            or intent.installation_id != proof.installation_id
            or intent.source_root != source_root
            or intent.codex_binary != codex_binary
            or intent.codex_home != proof.codex_home
            or intent.state_home != state_home
            or persisted.transition_proof_snapshot != transition_proof_snapshot
        ):
            raise ValueError("persisted upgrade preparation differs from request")
        staged = _staged_from_intent(intent)
        prepared_manifest_plan = build_prepared_manifest_plan_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=(persisted.activation_tree_logical.content_sha256),
            installer_source_digest=source_digest,
            installer_source_lineage=source_lineage,
        )
        prepared_logical = _prepared_manifest_logical(prepared_manifest_plan)
        if (
            persisted.desired_seed != _empty_bundle()
            or persisted.prepared_manifest_logical != prepared_logical
        ):
            raise ValueError(
                "persisted upgrade preparation omits the prepared manifest"
            )
        return UpgradePreparationV2(
            definition=persisted,
            callbacks=_callbacks_for_intent(
                intent,
                _empty_bundle(),
                prepared_manifest_plan,
                control_path,
                expected_activation_tree_sha256=(
                    persisted.activation_tree_logical.content_sha256
                ),
            ),
            prepared_manifest_plan=prepared_manifest_plan,
        )

    _ensure_private_directory(layout.managed_root / "activations")
    _ensure_private_directory(layout.managed_root / "codex-snapshots")
    _ensure_private_directory(state_home)
    _ensure_private_directory(state_home / "databases")
    snapshotter = snapshotter or CodexBinarySnapshotter(
        snapshot_root=layout.managed_root / "codex-snapshots"
    )
    subject = snapshotter.materialize(str(codex_binary))
    snapshot_path = _validate_snapshot_subject(
        subject,
        expected_root=layout.managed_root / "codex-snapshots",
        codex_binary=codex_binary,
    )
    observation = probe_codex_interface_v1(
        subject=subject,
        contract_root=source_root / "docs" / "contracts",
        policy_bundle=policy_bundle,
        executor=interface_executor,
    )
    captured_at = _aware(completed_at or datetime.now(timezone.utc))
    database_seed = domain_fingerprint(
        "codex-smart/upgrade-database-id/v2",
        {
            "installationId": proof.installation_id,
            "operationId": operation_id,
            "snapshotSha256": subject["snapshotSha256"],
        },
    )
    database_id = "db2_" + database_seed[:32]
    activation_nonce = domain_fingerprint(
        "codex-smart/upgrade-activation-binding/v2",
        {
            "installationId": proof.installation_id,
            "operationId": operation_id,
            "databaseId": database_id,
            "snapshotSha256": subject["snapshotSha256"],
        },
    )
    database_path = state_home / "databases" / database_id / "smart-subagents.sqlite3"
    _ensure_private_directory(database_path.parent)
    source_locator = {
        "lexicalPath": str(codex_binary),
        "resolvedPathAtCapture": str(codex_binary.resolve(strict=True)),
        "argv0Policy": "lexical",
        "sourceObservedSha256": str(subject["sourceObservedSha256"]),
    }
    snapshot_locator = {
        "absolutePath": str(snapshot_path),
        "sha256": str(subject["snapshotSha256"]),
    }

    with tempfile.TemporaryDirectory(dir="/tmp", prefix="cs-upgrade-tree-") as raw:
        template = Path(raw).resolve()
        template.chmod(0o700)
        marketplace = template / "marketplace"
        plugin_root = marketplace / "plugins" / _PLUGIN_NAME
        _materialize_marketplace(
            source_root=source_root,
            marketplace=marketplace,
            plugin_root=plugin_root,
            bundled_catalog=observation.bundled_catalog.projection,
        )
        marketplace_sha = _tree_sha256(marketplace)
        generation_sha = _tree_sha256(plugin_root)
        schema_manifest = _read_json(
            plugin_root
            / "src"
            / "codex_smart_subagents"
            / "schema"
            / "state-v2.manifest.json"
        )
        schema_artifact = (
            plugin_root / "src" / "codex_smart_subagents" / "schema" / "state-v2.sql"
        )
        schema_fingerprint = _required_sha256(
            schema_manifest.get("schemaFingerprint"), "schemaFingerprint"
        )
        schema_artifact_sha256 = _required_sha256(
            schema_manifest.get("stateSqlSha256"), "stateSqlSha256"
        )
        if _sha256_file(schema_artifact) != schema_artifact_sha256:
            raise ValueError("candidate schema artifact differs from its manifest")
        compatibility = str(observation.interface_evidence["compatibilityFingerprint"])
        identity = {
            "schemaVersion": 2,
            "generationId": "gen2_" + generation_sha,
            "release": _RELEASE,
            "pluginId": _PLUGIN_NAME,
            "marketplaceTreeSha256": marketplace_sha,
            "generationTreeSha256": generation_sha,
            "database": {
                "databaseId": database_id,
                "absolutePath": str(database_path),
                "schemaVersion": 2,
                "schemaFingerprint": schema_fingerprint,
                "schemaArtifactSha256": schema_artifact_sha256,
                "activationBindingNonce": activation_nonce,
            },
            "codexSnapshot": {
                "absolutePath": str(snapshot_path),
                "sha256": str(subject["snapshotSha256"]),
            },
            "compatibilityFingerprint": compatibility,
            "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
            "bundledCatalogFingerprint": observation.bundled_catalog.fingerprint,
            "minimumGatewayVersion": _RELEASE,
        }
        activation_fingerprint = domain_fingerprint(
            "codex-smart/activation/v2", identity
        )
        activation_id = "act2_" + activation_fingerprint
        activation_dir = layout.managed_root / "activations" / activation_id
        activation_document = {
            "schemaVersion": 2,
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "identity": identity,
        }
        _atomic_write_json(template / "activation.json", activation_document)
        seal_activation_tree_v2(template)
        if source_digest is not None:
            materialized_source_digest = (
                installer_source_digest_from_materialized_activation_v2(
                    activation_dir=template,
                    codex_binary=codex_binary,
                    source_locator=source_locator,
                    snapshot_locator=snapshot_locator,
                    snapshot_path=snapshot_path,
                )
            )
            if materialized_source_digest != source_digest:
                raise ValueError(
                    "sourceDigest differs from immutable candidate"
                )
        activation_tree_sha256 = tree_content_sha256_v2(template)
        _make_activation_tree_removable_v2(template)
    controller_identity = _controller_identity(
        codex_home=proof.codex_home,
        state_home=state_home,
        activation_fingerprint=activation_fingerprint,
        compatibility_fingerprint=compatibility,
        routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
        bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
        database_id=database_id,
    )
    intent = ActivationPreparationIntentV2(
        source_root=source_root,
        codex_home=proof.codex_home,
        codex_binary=codex_binary,
        state_home=state_home,
        socket_path=state_home / "controller.sock",
        controller_lock_path=state_home / "controller.lock",
        installation_id=str(proof.installation_id),
        operation_id=operation_id,
        database_id=database_id,
        activation_binding_nonce=activation_nonce,
        activation_id=activation_id,
        activation_fingerprint=activation_fingerprint,
        controller_identity=controller_identity,
        compatibility_fingerprint=compatibility,
        routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
        bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
        schema_fingerprint=schema_fingerprint,
        schema_artifact_sha256=schema_artifact_sha256,
        activation_dir=activation_dir,
        snapshot_path=snapshot_path,
        database_path=database_path,
        bundled_catalog_path=(
            activation_dir
            / "marketplace"
            / "plugins"
            / _PLUGIN_NAME
            / "config"
            / "bundled-catalog-v1.json"
        ),
        identity=identity,
        activation_document=activation_document,
        source_locator=source_locator,
        snapshot_locator=snapshot_locator,
        bundled_catalog=copy.deepcopy(observation.bundled_catalog.projection),
        interface_evidence=copy.deepcopy(observation.interface_evidence),
        completed_at=captured_at,
    )
    staged = _staged_from_intent(intent)
    prepared_manifest_plan = build_prepared_manifest_plan_v2(
        proof=proof,
        staged=staged,
        activation_tree_sha256=activation_tree_sha256,
        installer_source_digest=source_digest,
        installer_source_lineage=source_lineage,
    )
    desired_seed = _empty_bundle()
    definition = ActivationPreparationDefinitionV2(
        journal_path=control_path,
        receipt_path=receipt_path,
        lock_path=lock_path,
        activation_intent=intent,
        desired_seed=desired_seed,
        snapshot_file=capture_file_projection_v2(
            snapshot_path,
            schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
        ),
        activation_tree_logical=LogicalPreparationObjectV2(
            path=activation_dir,
            object_type="directory",
            mode="0500",
            content_sha256=activation_tree_sha256,
        ),
        activation_file_logical=LogicalPreparationObjectV2(
            path=activation_dir / "activation.json",
            object_type="regular-file",
            mode="0400",
            content_sha256=hashlib.sha256(
                canonical_json_bytes(activation_document)
            ).hexdigest(),
        ),
        database_empty_file_logical=LogicalPreparationObjectV2(
            path=database_path,
            object_type="regular-file",
            mode="0600",
            content_sha256=_EMPTY_SHA256,
        ),
        prepared_manifest_logical=_prepared_manifest_logical(prepared_manifest_plan),
        transition_proof_snapshot=transition_proof_snapshot,
    )
    return UpgradePreparationV2(
        definition=definition,
        callbacks=_callbacks_for_intent(
            intent,
            desired_seed,
            prepared_manifest_plan,
            control_path,
            expected_activation_tree_sha256=activation_tree_sha256,
        ),
        prepared_manifest_plan=prepared_manifest_plan,
    )


def execute_and_verify_upgrade_preparation_v2(
    *,
    proof: ActivationTransitionProofV2,
    preparation: UpgradePreparationV2,
) -> ActivationPreparationReceiptV2:
    """Подготовить кандидата с закрытой маской создаваемых объектов."""

    previous_umask = os.umask(0o077)
    try:
        return _execute_and_verify_upgrade_preparation_private_v2(
            proof=proof,
            preparation=preparation,
        )
    finally:
        os.umask(previous_umask)


def _execute_and_verify_upgrade_preparation_private_v2(
    *,
    proof: ActivationTransitionProofV2,
    preparation: UpgradePreparationV2,
) -> ActivationPreparationReceiptV2:
    """Подготовить кандидата и закрыть границу перед основным журналом.

    Возвращаемая квитанция заново прочитана с диска и её физические объекты
    повторно проверены штатным исполнителем. На всём переходе основной журнал
    обязан отсутствовать; следующий вызывающий код может атомарно создать его
    только после успешного возврата этой функции.
    """

    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if not isinstance(preparation, UpgradePreparationV2):
        raise TypeError("preparation must be UpgradePreparationV2")
    if (
        preparation.definition.activation_intent.installation_id
        != proof.installation_id
    ):
        raise ValueError("upgrade preparation belongs to another installation")
    reverify_activation_transition_proof_v2(proof)
    if os.path.lexists(proof.layout.journal_path):
        raise ValueError("main operation journal exists before preparation handoff")

    executor = ActivationPreparationExecutorV2(
        definition=preparation.definition,
        callbacks=preparation.callbacks,
    )
    executor.execute()
    published = ActivationPreparationReceiptV2.from_path(
        preparation.definition.receipt_path
    )
    verified = executor.execute()
    if published.to_document() != verified.to_document():
        raise ValueError("preparation receipt changed during live verification")

    staged = prepared_receipt_to_staged_activation_v2(verified)
    prepared_manifest = prepared_manifest_from_upgrade_receipt_v2(
        proof=proof,
        preparation=preparation,
        receipt=verified,
    )
    verify_prepared_manifest_file_v2(
        proof=proof,
        staged=staged,
        prepared=prepared_manifest,
    )
    extensions = prepared_manifest.manifest_document.get("extensions")
    expected_source_digest = (
        extensions.get("installerSourceDigest")
        if isinstance(extensions, Mapping)
        else None
    )
    if expected_source_digest is not None:
        observed_source_digest = _installer_source_digest_from_activation_v2(
            preparation.definition
        )
        if observed_source_digest != expected_source_digest:
            raise ValueError(
                "sourceDigest differs from immutable candidate"
            )

    reverify_activation_transition_proof_v2(proof)
    if os.path.lexists(proof.layout.journal_path):
        raise ValueError("main operation journal appeared during preparation handoff")
    return verified


def prepared_manifest_from_upgrade_receipt_v2(
    *,
    proof: ActivationTransitionProofV2,
    preparation: UpgradePreparationV2,
    receipt: ActivationPreparationReceiptV2,
) -> PreparedManifestCommitV2:
    """Восстановить физический manifest source только из prep receipt."""

    if receipt.operation_id != preparation.definition.activation_intent.operation_id:
        raise ValueError("preparation receipt belongs to another operation")
    if (
        receipt.prepared_manifest_file is None
        or receipt.prepared_manifest_parent is None
    ):
        raise ValueError("preparation receipt omits manifest source binding")
    prepared = prepared_manifest_commit_from_receipt_v2(
        plan=preparation.prepared_manifest_plan,
        prepared_file=receipt.prepared_manifest_file,
        prepared_parent=receipt.prepared_manifest_parent,
    )
    if prepared.prepared_file not in receipt.desired.file_objects:
        raise ValueError("preparation receipt omits the prepared manifest")
    staged = prepared_receipt_to_staged_activation_v2(receipt)
    if os.path.lexists(prepared.prepared_path):
        verify_prepared_manifest_file_v2(
            proof=proof,
            staged=staged,
            prepared=prepared,
        )
    return prepared


def prepare_upgrade_database_v2(
    receipt: ActivationPreparationReceiptV2,
) -> ProjectionV2:
    """Инициализировать закреплённый файл базы кандидата или доказать повтор.

    Схема берётся только из уже подготовленного дерева кандидата и сверяется с
    неизменяемым намерением. Сам ``prepare_database_v2`` удерживает доказанный
    inode и после вызова проверяет полную привязку базы и служебных строк.
    """

    intent = receipt.activation_intent
    database_binding = build_upgrade_database_binding_v2(receipt)
    schema_path = (
        intent.activation_dir
        / "marketplace"
        / "plugins"
        / _PLUGIN_NAME
        / "src"
        / "codex_smart_subagents"
        / "schema"
        / "state-v2.sql"
    )
    if _sha256_file(schema_path) != intent.schema_artifact_sha256:
        raise ValueError("prepared schema artifact differs from activation intent")
    schema_sql = read_schema_artifact(schema_path)
    completed_at = _timestamp(intent.completed_at)

    def initialize(path: Path) -> None:
        connection = connect_sqlite_with_deadline_v2(
            path,
            isolation_level=None,
            timeout=5.0,
        )
        try:
            connection.execute("pragma foreign_keys=ON")
            connection.execute("pragma trusted_schema=OFF")
            connection.execute("pragma synchronous=FULL")
            connection.execute("pragma secure_delete=FAST")
            journal_mode_row = connection.execute(
                "pragma journal_mode=WAL"
            ).fetchone()
            if (
                journal_mode_row is None
                or str(journal_mode_row[0]).lower() != "wal"
            ):
                raise RuntimeError("prepared database journal mode is not WAL")
            connection.executescript("BEGIN IMMEDIATE;\n" + schema_sql)
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
            connection.execute(
                "insert into database_identity "
                "(singleton,database_id,schema_version,schema_fingerprint,"
                "schema_artifact_sha256,activation_binding_nonce,activation_id,"
                "activation_fingerprint,source_shape,source_schema_fingerprint,"
                "source_backup_sha256,created_operation_id,created_at) "
                "values(1,?,?,?,?,?,?,?,'fresh-v2',null,null,?,?)",
                (
                    intent.database_id,
                    2,
                    intent.schema_fingerprint,
                    intent.schema_artifact_sha256,
                    intent.activation_binding_nonce,
                    intent.activation_id,
                    intent.activation_fingerprint,
                    intent.operation_id,
                    completed_at,
                ),
            )
            connection.execute(
                "insert into controller_state "
                "(singleton,database_id,protocol_version,release,controller_identity,"
                "instance_id,controller_start_id,controller_pid,"
                "controller_process_start_marker,controller_process_group_id,"
                "control_epoch,state,maintenance_mode,reason_code,operation_id,"
                "activation_id,activation_fingerprint,compatibility_fingerprint,"
                "routing_policy_fingerprint,bundled_catalog_fingerprint,socket_path,"
                "socket_device,socket_inode,socket_owner_uid,socket_owner_gid,"
                "socket_mode,lock_held,accepting_new_routes,quiescent,updated_at) "
                "values(1,?,2,'0.2.0',?,null,null,null,null,null,1,'MAINTENANCE',"
                "'FREEZE','AWAITING_CONTROLLER_ACCEPT',?,?,?,?,?,?,null,null,null,"
                "null,null,null,0,0,1,?)",
                (
                    intent.database_id,
                    intent.controller_identity,
                    intent.operation_id,
                    intent.activation_id,
                    intent.activation_fingerprint,
                    intent.compatibility_fingerprint,
                    intent.routing_policy_fingerprint,
                    intent.bundled_catalog_fingerprint,
                    completed_at,
                ),
            )
            connection.execute("COMMIT")
            checkpoint = connection.execute(
                "pragma wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if (
                checkpoint is None
                or len(checkpoint) != 3
                or int(checkpoint[0]) != 0
                or int(checkpoint[1]) != int(checkpoint[2])
            ):
                raise RuntimeError("prepared database WAL checkpoint did not finish")
        except BaseException as primary:
            if connection.in_transaction:
                try:
                    connection.rollback_for_cleanup_v2()
                except BaseException as cleanup_error:
                    primary.add_note(
                        "SQLite upgrade cleanup rollback also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            raise
        finally:
            connection.close()

    return prepare_database_v2(
        database_path=intent.database_path,
        database_empty_file=receipt.database_empty_file,
        database_binding_target=database_binding,
        expected_service_identity=PreparedDatabaseServiceIdentityV2(
            operation_id=intent.operation_id,
            controller_identity=intent.controller_identity,
            compatibility_fingerprint=intent.compatibility_fingerprint,
            routing_policy_fingerprint=intent.routing_policy_fingerprint,
            bundled_catalog_fingerprint=intent.bundled_catalog_fingerprint,
        ),
        initializer=initialize,
        recover_interrupted=True,
    )


def observe_upgrade_database_v2(
    receipt: ActivationPreparationReceiptV2,
) -> tuple[PreparedDatabaseStateV2, ProjectionV2]:
    """Без эффекта различить EMPTY и PREPARED для database_prepare."""

    intent = receipt.activation_intent
    return observe_prepared_database_v2(
        database_path=intent.database_path,
        database_empty_file=receipt.database_empty_file,
        database_binding_target=build_upgrade_database_binding_v2(receipt),
        expected_service_identity=PreparedDatabaseServiceIdentityV2(
            operation_id=intent.operation_id,
            controller_identity=intent.controller_identity,
            compatibility_fingerprint=intent.compatibility_fingerprint,
            routing_policy_fingerprint=intent.routing_policy_fingerprint,
            bundled_catalog_fingerprint=intent.bundled_catalog_fingerprint,
        ),
    )


def build_upgrade_database_binding_v2(
    receipt: ActivationPreparationReceiptV2,
) -> ProjectionV2:
    """Чисто построить точную полную привязку подготовленной базы."""

    intent = receipt.activation_intent
    target = receipt.database_binding_target.value
    identity = {
        "databaseId": intent.database_id,
        "activationBindingNonce": intent.activation_binding_nonce,
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
    }
    value = {
        **{
            name: target[name]
            for name in (
                "path",
                "device",
                "inode",
                "ownerUid",
                "ownerGid",
                "mode",
                "linkCount",
            )
        },
        "databaseId": intent.database_id,
        "databaseIdentity": identity,
        "databaseIdentityFingerprint": domain_fingerprint(
            "codex-smart/database-identity/v2", identity
        ),
        "activationIdentity": {
            "activationId": intent.activation_id,
            "activationFingerprint": intent.activation_fingerprint,
        },
        "databaseVersion": "0.2.0",
        "schemaVersion": 2,
        "userVersion": 2,
        "schemaFingerprint": intent.schema_fingerprint,
        "schemaArtifactSha256": intent.schema_artifact_sha256,
    }
    envelope = {
        "schemaId": "database-binding-v2",
        "schemaSha256": receipt.database_binding_target.schema_sha256,
        "value": value,
    }
    return ProjectionV2(
        schema_id="database-binding-v2",
        schema_sha256=receipt.database_binding_target.schema_sha256,
        value=value,
        value_fingerprint=domain_fingerprint(
            "codex-smart/database-binding/v2", envelope
        ),
    )


def _callbacks_for_intent(
    intent: ActivationPreparationIntentV2,
    desired_seed: StateBundleV2,
    prepared_manifest_plan: PreparedManifestPlanV2,
    preparation_journal_path: Path,
    *,
    expected_activation_tree_sha256: str,
) -> ActivationPreparationCallbacksV2:
    extensions = prepared_manifest_plan.manifest_document.get("extensions")
    expected_source_digest = (
        extensions.get("installerSourceDigest")
        if isinstance(extensions, Mapping)
        else None
    )

    def materialize(received: ActivationPreparationIntentV2) -> None:
        if received.to_document() != intent.to_document():
            raise ValueError("activation preparation intent changed")
        stage = _activation_tree_stage_path_v2(received)
        marker = _activation_tree_stage_owner_path_v2(received)
        if (
            os.path.lexists(received.activation_dir)
            or os.path.lexists(stage)
            or os.path.lexists(marker)
        ):
            raise ValueError("activation preparation tree path is already occupied")
        previous_umask = os.umask(0o077)
        try:
            published = False
            try:
                _create_activation_stage_owner_v2(received)
                stage.mkdir(mode=0o700)
                stage.chmod(0o700)
                marketplace = stage / "marketplace"
                plugin_root = marketplace / "plugins" / _PLUGIN_NAME
                _materialize_marketplace(
                    source_root=received.source_root,
                    marketplace=marketplace,
                    plugin_root=plugin_root,
                    bundled_catalog=received.bundled_catalog,
                )
                _atomic_write_json(
                    stage / "activation.json",
                    received.activation_document,
                )
                os.replace(stage, received.activation_dir)
                published = True
                seal_activation_tree_v2(received.activation_dir)
                if expected_source_digest is not None:
                    observed_source_digest = (
                        installer_source_digest_from_materialized_activation_v2(
                            activation_dir=received.activation_dir,
                            codex_binary=received.codex_binary,
                            source_locator=received.source_locator,
                            snapshot_locator=received.snapshot_locator,
                            snapshot_path=received.snapshot_path,
                        )
                    )
                    if observed_source_digest != expected_source_digest:
                        raise ValueError(
                            "sourceDigest differs from immutable candidate"
                        )
                if (
                    tree_content_sha256_v2(received.activation_dir)
                    != expected_activation_tree_sha256
                ):
                    raise ValueError(
                        "materialized activation tree differs from preparation intent"
                    )
                _fsync_materialized_tree_v2(received.activation_dir)
                _fsync_directory(received.activation_dir.parent)
                _remove_published_stage_owner_v2(received)
            except BaseException:
                if published:
                    _remove_published_activation_tree_v2(received)
                else:
                    _remove_incomplete_activation_stage_v2(received)
                raise
        finally:
            os.umask(previous_umask)

    def materialize_prepared_manifest(
        received: ActivationPreparationIntentV2,
        expected: LogicalPreparationObjectV2,
    ) -> None:
        if (
            received.to_document() != intent.to_document()
            or expected != _prepared_manifest_logical(prepared_manifest_plan)
        ):
            raise ValueError("prepared manifest intent changed")
        materialize_prepared_manifest_plan_v2(
            plan=prepared_manifest_plan,
            preparation_journal_path=preparation_journal_path,
        )

    def build_desired(
        prepared: PreparedActivationObjectsV2,
        seed: StateBundleV2,
    ) -> StateBundleV2:
        return _build_preparation_desired_v2(
            prepared=prepared,
            seed=seed,
            desired_seed=desired_seed,
        )

    return ActivationPreparationCallbacksV2(
        materialize_activation_tree=materialize,
        build_desired=build_desired,
        materialize_prepared_manifest=materialize_prepared_manifest,
    )


def _activation_tree_stage_path_v2(intent: ActivationPreparationIntentV2) -> Path:
    return (
        intent.activation_dir.parent
        / f".{intent.activation_id}.{intent.operation_id}.preparing"
    )


def _activation_tree_stage_owner_path_v2(
    intent: ActivationPreparationIntentV2,
) -> Path:
    stage = _activation_tree_stage_path_v2(intent)
    return stage.with_name(stage.name + ".owner.json")


def _activation_tree_stage_owner_document_v2(
    intent: ActivationPreparationIntentV2,
) -> dict[str, Any]:
    value = {
        "schemaVersion": 1,
        "kind": "activation-preparation-stage-owner/v1",
        "installationId": intent.installation_id,
        "operationId": intent.operation_id,
        "activationId": intent.activation_id,
        "activationBindingNonce": intent.activation_binding_nonce,
        "stagePath": str(_activation_tree_stage_path_v2(intent)),
    }
    return {
        **value,
        "ownerFingerprint": domain_fingerprint(
            "codex-smart/activation-preparation-stage-owner/v1",
            value,
        ),
    }


def _stage_owner_raw_v2(intent: ActivationPreparationIntentV2) -> bytes:
    return canonical_json_bytes(_activation_tree_stage_owner_document_v2(intent)) + b"\n"


def _create_activation_stage_owner_v2(
    intent: ActivationPreparationIntentV2,
) -> None:
    marker = _activation_tree_stage_owner_path_v2(intent)
    temporary = marker.with_name(
        f".{marker.name}.publish-{secrets.token_hex(16)}"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            payload = _stage_owner_raw_v2(intent)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("activation stage owner write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, marker, follow_symlinks=False)
        _fsync_directory(marker.parent)
        temporary.unlink()
        _fsync_directory(marker.parent)
        _validate_activation_stage_owner_v2(intent)
    except BaseException:
        if os.path.lexists(temporary):
            temporary.unlink()
            _fsync_directory(marker.parent)
        raise


def _validate_activation_stage_owner_v2(
    intent: ActivationPreparationIntentV2,
) -> os.stat_result:
    marker = _activation_tree_stage_owner_path_v2(intent)
    descriptor = os.open(
        marker,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(descriptor)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink < 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or b"".join(chunks) != _stage_owner_raw_v2(intent)
    ):
        raise ValueError("activation preparation stage ownership is invalid")
    if info.st_nlink != 1:
        prefix = f".{marker.name}.publish-"
        for candidate in marker.parent.iterdir():
            if candidate == marker or not candidate.name.startswith(prefix):
                continue
            candidate_info = os.lstat(candidate)
            if (
                stat.S_ISREG(candidate_info.st_mode)
                and not stat.S_ISLNK(candidate_info.st_mode)
                and candidate_info.st_dev == info.st_dev
                and candidate_info.st_ino == info.st_ino
            ):
                candidate.unlink()
        _fsync_directory(marker.parent)
        info = os.lstat(marker)
        if info.st_nlink != 1:
            raise ValueError("activation preparation stage owner has foreign links")
    return info


def _unlink_activation_stage_owner_v2(
    intent: ActivationPreparationIntentV2,
) -> None:
    marker = _activation_tree_stage_owner_path_v2(intent)
    expected = _validate_activation_stage_owner_v2(intent)
    observed = os.lstat(marker)
    if observed.st_dev != expected.st_dev or observed.st_ino != expected.st_ino:
        raise ValueError("activation preparation stage owner changed")
    marker.unlink()
    _fsync_directory(marker.parent)


def _validate_owned_stage_tree_v2(
    root: Path,
    *,
    normalized: bool,
) -> None:
    normalized_root_mode = None
    if normalized:
        normalized_root_mode = stat.S_IMODE(os.lstat(root).st_mode)
        if normalized_root_mode not in {0o500, 0o700}:
            raise ValueError("activation preparation stage root mode changed")
    pending = [root]
    while pending:
        path = pending.pop()
        info = os.lstat(path)
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
            raise ValueError("activation preparation stage is not owned")
        if stat.S_ISDIR(info.st_mode):
            if normalized and mode != normalized_root_mode:
                raise ValueError("activation preparation stage directory mode changed")
            if not normalized:
                if (mode & 0o7000) != 0:
                    raise ValueError(
                        "activation preparation stage directory mode changed"
                    )
                if mode != 0o700:
                    path.chmod(0o700)
                    changed = os.lstat(path)
                    if (
                        not stat.S_ISDIR(changed.st_mode)
                        or stat.S_ISLNK(changed.st_mode)
                        or changed.st_uid != info.st_uid
                        or changed.st_dev != info.st_dev
                        or changed.st_ino != info.st_ino
                        or stat.S_IMODE(changed.st_mode) != 0o700
                    ):
                        raise ValueError(
                            "activation preparation stage directory changed"
                        )
            children = sorted(
                path.iterdir(),
                key=lambda item: item.name.encode("utf-8"),
                reverse=True,
            )
            pending.extend(children)
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (
                mode
                not in (
                    {0o400, 0o500}
                    if normalized_root_mode == 0o500
                    else {0o500, 0o600}
                )
                if normalized
                else (mode & 0o7000) != 0
            )
        ):
            raise ValueError("activation preparation stage contains an unsafe object")


def _remove_incomplete_activation_stage_v2(
    intent: ActivationPreparationIntentV2,
) -> None:
    stage = _activation_tree_stage_path_v2(intent)
    marker = _activation_tree_stage_owner_path_v2(intent)
    if not os.path.lexists(stage) and not os.path.lexists(marker):
        return
    if not os.path.lexists(marker):
        raise ValueError("activation preparation stage has no ownership marker")
    _validate_activation_stage_owner_v2(intent)
    if os.path.lexists(stage):
        _validate_owned_stage_tree_v2(stage, normalized=False)
        shutil.rmtree(stage)
        _fsync_directory(stage.parent)
    _unlink_activation_stage_owner_v2(intent)


def _remove_published_stage_owner_v2(
    intent: ActivationPreparationIntentV2,
) -> None:
    stage = _activation_tree_stage_path_v2(intent)
    marker = _activation_tree_stage_owner_path_v2(intent)
    if os.path.lexists(stage):
        raise ValueError("published activation retained its preparation stage")
    if os.path.lexists(marker):
        _unlink_activation_stage_owner_v2(intent)


def _remove_published_activation_tree_v2(
    intent: ActivationPreparationIntentV2,
) -> None:
    activation_dir = intent.activation_dir
    marker = _activation_tree_stage_owner_path_v2(intent)
    if os.path.lexists(activation_dir):
        _validate_owned_stage_tree_v2(activation_dir, normalized=False)
        shutil.rmtree(activation_dir)
        _fsync_directory(activation_dir.parent)
    if os.path.lexists(marker):
        _unlink_activation_stage_owner_v2(intent)


def _fsync_materialized_tree_v2(root: Path) -> None:
    _validate_owned_stage_tree_v2(root, normalized=True)
    paths = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    for path in paths:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            continue
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            observed = os.fstat(descriptor)
            if observed.st_dev != info.st_dev or observed.st_ino != info.st_ino:
                raise ValueError("activation preparation file changed during fsync")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = [path for path in paths if path.is_dir()]
    for path in sorted(
        directories,
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        _fsync_directory(path)
    _fsync_directory(root)


def _source_independent_recovery_callbacks_v2(
    *,
    definition: ActivationPreparationDefinitionV2,
    prepared_manifest_plan: PreparedManifestPlanV2 | None,
) -> ActivationPreparationCallbacksV2:
    def forbid_activation_materialization(
        _intent: ActivationPreparationIntentV2,
    ) -> None:
        raise ValueError(
            "persisted recovery cannot materialize a missing activation tree"
        )

    def materialize_prepared_manifest(
        received: ActivationPreparationIntentV2,
        expected: LogicalPreparationObjectV2,
    ) -> None:
        if (
            prepared_manifest_plan is None
            or received != definition.activation_intent
            or expected != _prepared_manifest_logical(prepared_manifest_plan)
        ):
            raise ValueError("persisted prepared manifest intent changed")
        materialize_prepared_manifest_plan_v2(
            plan=prepared_manifest_plan,
            preparation_journal_path=definition.journal_path,
        )

    return ActivationPreparationCallbacksV2(
        materialize_activation_tree=forbid_activation_materialization,
        build_desired=lambda prepared, seed: _build_preparation_desired_v2(
            prepared=prepared,
            seed=seed,
            desired_seed=definition.desired_seed,
        ),
        materialize_prepared_manifest=(
            materialize_prepared_manifest
            if definition.prepared_manifest_logical is not None
            else None
        ),
    )


def _build_preparation_desired_v2(
    *,
    prepared: PreparedActivationObjectsV2,
    seed: StateBundleV2,
    desired_seed: StateBundleV2,
) -> StateBundleV2:
    if seed != desired_seed:
        raise ValueError("unexpected upgrade preparation seed")
    if prepared.prepared_manifest_file is None:
        raise ValueError("prepared manifest physical projection is missing")
    return StateBundleV2(
        file_objects=(prepared.prepared_manifest_file, prepared.snapshot_file),
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


def _installer_source_digest_from_activation_v2(
    definition: ActivationPreparationDefinitionV2,
) -> str:
    """Воспроизвести installer sourceDigest из неизменяемой активации."""

    intent = definition.activation_intent
    return installer_source_digest_from_materialized_activation_v2(
        activation_dir=intent.activation_dir,
        codex_binary=intent.codex_binary,
        source_locator=intent.source_locator,
        snapshot_locator=intent.snapshot_locator,
        snapshot_path=intent.snapshot_path,
    )


def installer_source_digest_from_materialized_activation_v2(
    *,
    activation_dir: Path,
    codex_binary: Path,
    source_locator: Mapping[str, Any],
    snapshot_locator: Mapping[str, Any],
    snapshot_path: Path,
) -> str:
    """Воспроизвести sourceDigest только из принятого неизменяемого дерева."""

    marketplace = activation_dir / "marketplace"
    plugin_root = marketplace / "plugins" / _PLUGIN_NAME
    files: dict[str, tuple[Path, bool]] = {}
    for path in _iter_recovery_plugin_files_v2(plugin_root):
        plugin_relative = path.relative_to(plugin_root)
        if plugin_relative == Path(
            "config/bundled-catalog-v1.json"
        ) or plugin_relative.is_relative_to(
            Path("config/contracts")
        ) or plugin_relative.is_relative_to(Path("config/runtime-schemas")):
            continue
        source_relative = Path("plugins") / _PLUGIN_NAME / plugin_relative
        files[source_relative.as_posix()] = (
            path,
            plugin_relative.parent == Path("bin"),
        )

    extras = {
        ".agents/plugins/marketplace.json": (
            marketplace / ".agents" / "plugins" / "marketplace.json"
        ),
        ".claude-plugin/marketplace.json": (
            marketplace / ".claude-plugin" / "marketplace.json"
        ),
        ".codex/adaptive-subagents.toml": (
            marketplace / ".codex" / "adaptive-subagents.toml"
        ),
        "scripts/install_adaptive_subagents.py": (
            marketplace / "scripts" / "install_adaptive_subagents.py"
        ),
        **{
            f"docs/contracts/vectors/{name}": (
                plugin_root / "config" / "contracts" / name
            )
            for name in _CONFIG_CONTRACT_VECTOR_FILES
        },
        **{
            f"docs/contracts/schemas/{name}": (
                marketplace / "docs" / "contracts" / "schemas" / name
            )
            for name in _RUNTIME_SCHEMA_FILES
        },
        **{
            f"docs/contracts/vectors/{name}": (
                marketplace / "docs" / "contracts" / "vectors" / name
            )
            for name in _RUNTIME_VECTOR_FILES
        },
    }
    for relative, path in extras.items():
        files[relative] = (path, False)

    digest = hashlib.sha256()
    digest.update(b"codex-smart/source-digest/v2\0")
    bound_python_runtime: _BoundPythonRuntimeV2 | None = None
    for relative, (path, restore_portable_shebang) in sorted(
        files.items(), key=lambda item: item[0].encode("utf-8")
    ):
        payload, executable, entrypoint_runtime = _recovery_source_file_v2(
            path,
            restore_portable_shebang=restore_portable_shebang,
        )
        if entrypoint_runtime is not None:
            if bound_python_runtime is None:
                bound_python_runtime = entrypoint_runtime
            elif (
                entrypoint_runtime.path != bound_python_runtime.path
                or entrypoint_runtime.identity != bound_python_runtime.identity
            ):
                raise ValueError(
                    "persisted Python entrypoints bind different runtimes"
                )
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0x\0" if executable else b"\0f\0")
        digest.update(hashlib.sha256(payload).digest())

    source_sha256 = str(source_locator["sourceObservedSha256"])
    snapshot_sha256 = str(snapshot_locator["sha256"])
    if source_sha256 != snapshot_sha256:
        raise ValueError("persisted Codex source and snapshot digests differ")
    snapshot_payload, snapshot_executable, snapshot_runtime = _recovery_source_file_v2(
        snapshot_path,
        restore_portable_shebang=False,
    )
    if (
        not snapshot_executable
        or hashlib.sha256(snapshot_payload).hexdigest() != source_sha256
    ):
        raise ValueError("persisted Codex snapshot changed")
    if snapshot_runtime is not None:
        raise ValueError("Codex snapshot unexpectedly binds a Python runtime")
    digest.update(b"\0codex-binary-v1\0")
    digest.update(str(codex_binary).encode("utf-8"))
    digest.update(b"\0")
    digest.update(bytes.fromhex(source_sha256))
    if bound_python_runtime is None:
        raise ValueError("persisted Python entrypoints are absent")
    runtime_sha256 = _stable_python_runtime_sha256_v2(bound_python_runtime)
    digest.update(b"\0python-runtime-v1\0")
    digest.update(str(bound_python_runtime.path).encode("utf-8"))
    digest.update(b"\0")
    digest.update(bytes.fromhex(runtime_sha256))
    return digest.hexdigest()


def _iter_recovery_plugin_files_v2(root: Path):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("persisted plugin tree is unavailable")
    for child in sorted(root.iterdir(), key=lambda item: item.name.encode("utf-8")):
        if child.name in _EXCLUDED_TREE_NAMES or child.suffix == ".pyc":
            continue
        info = child.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            yield from _iter_recovery_plugin_files_v2(child)
        elif stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            yield child
        else:
            raise ValueError(f"unsafe persisted plugin object: {child}")


def _recovery_source_file_v2(
    path: Path,
    *,
    restore_portable_shebang: bool,
) -> tuple[bytes, bool, _BoundPythonRuntimeV2 | None]:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or mode not in {0o400, 0o500, 0o600}
    ):
        raise ValueError(f"unsafe persisted source file: {path}")
    payload = path.read_bytes()
    executable = mode == 0o500
    bound_runtime = None
    if restore_portable_shebang and executable:
        bound_runtime = _bound_python_runtime_from_shebang_v2(path, payload)
        line_end = payload.find(b"\n")
        payload = bound_runtime.portable_shebang + payload[line_end + 1 :]
    return payload, executable, bound_runtime


def _bound_python_runtime_from_shebang_v2(
    entrypoint: Path,
    payload: bytes,
) -> _BoundPythonRuntimeV2:
    line_end = payload.find(b"\n")
    line = payload[: line_end + 1] if line_end >= 0 else b""
    suffixes = (
        (b" -S -B\n", b"#!/usr/bin/env -S python3 -S\n"),
        (b" -B\n", b"#!/usr/bin/env python3\n"),
    )
    suffix_and_portable = next(
        (candidate for candidate in suffixes if line.endswith(candidate[0])), None
    )
    if not line.startswith(b"#!") or suffix_and_portable is None:
        raise ValueError(
            f"persisted Python entrypoint has no exact bound shebang: {entrypoint}"
        )
    suffix, portable_shebang = suffix_and_portable
    raw_path = line[2 : -len(suffix)]
    try:
        runtime = Path(raw_path.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"persisted Python entrypoint has an invalid runtime path: {entrypoint}"
        ) from exc
    if (
        not raw_path
        or b"\0" in raw_path
        or b" " in raw_path
        or b"\t" in raw_path
        or b"\r" in raw_path
        or not runtime.is_absolute()
        or len(line) > 120
    ):
        raise ValueError(
            f"persisted Python entrypoint has an invalid runtime path: {entrypoint}"
        )
    try:
        resolved = runtime.resolve(strict=True)
        info = os.lstat(runtime)
    except OSError as exc:
        raise ValueError(
            f"persisted Python runtime is unavailable: {runtime}"
        ) from exc
    if (
        runtime != resolved
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not os.access(runtime, os.X_OK)
    ):
        raise ValueError(f"persisted Python runtime is unsafe: {runtime}")
    return _BoundPythonRuntimeV2(
        path=runtime,
        identity=_runtime_file_identity_v2(info),
        portable_shebang=portable_shebang,
    )


def _stable_python_runtime_sha256_v2(
    runtime: _BoundPythonRuntimeV2,
) -> str:
    try:
        before = os.lstat(runtime.path)
        resolved_before = runtime.path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"persisted Python runtime is unavailable: {runtime.path}"
        ) from exc
    if (
        resolved_before != runtime.path
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or not os.access(runtime.path, os.X_OK)
        or _runtime_file_identity_v2(before) != runtime.identity
    ):
        raise ValueError(f"persisted Python runtime changed: {runtime.path}")
    runtime_sha256 = _sha256_file(runtime.path)
    try:
        after = os.lstat(runtime.path)
        resolved_after = runtime.path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"persisted Python runtime changed: {runtime.path}"
        ) from exc
    if (
        resolved_after != runtime.path
        or _runtime_file_identity_v2(after) != runtime.identity
    ):
        raise ValueError(f"persisted Python runtime changed: {runtime.path}")
    return runtime_sha256


def _runtime_file_identity_v2(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _staged_from_intent(intent: ActivationPreparationIntentV2) -> StagedActivationV2:
    return StagedActivationV2(
        status="IDENTITY_STAGED",
        readiness="AWAITING_CONTROLLER_BIND",
        source_root=intent.source_root,
        codex_home=intent.codex_home,
        codex_binary=intent.codex_binary,
        state_home=intent.state_home,
        socket_path=intent.socket_path,
        controller_lock_path=intent.controller_lock_path,
        installation_id=intent.installation_id,
        operation_id=intent.operation_id,
        database_id=intent.database_id,
        activation_binding_nonce=intent.activation_binding_nonce,
        activation_id=intent.activation_id,
        activation_fingerprint=intent.activation_fingerprint,
        controller_identity=intent.controller_identity,
        compatibility_fingerprint=intent.compatibility_fingerprint,
        routing_policy_fingerprint=intent.routing_policy_fingerprint,
        bundled_catalog_fingerprint=intent.bundled_catalog_fingerprint,
        schema_fingerprint=intent.schema_fingerprint,
        schema_artifact_sha256=intent.schema_artifact_sha256,
        activation_dir=intent.activation_dir,
        snapshot_path=intent.snapshot_path,
        database_path=intent.database_path,
        bundled_catalog_path=intent.bundled_catalog_path,
        identity=copy.deepcopy(dict(intent.identity)),
        activation_document=copy.deepcopy(dict(intent.activation_document)),
        source_locator=copy.deepcopy(dict(intent.source_locator)),
        snapshot_locator=copy.deepcopy(dict(intent.snapshot_locator)),
        bundled_catalog=copy.deepcopy(dict(intent.bundled_catalog)),
        interface_evidence=copy.deepcopy(dict(intent.interface_evidence)),
        completed_at=intent.completed_at,
    )


def _prepared_manifest_logical(
    plan: PreparedManifestPlanV2,
) -> LogicalPreparationObjectV2:
    if not isinstance(plan, PreparedManifestPlanV2) or not plan.complete:
        raise ValueError("prepared manifest plan is incomplete")
    return LogicalPreparationObjectV2(
        path=plan.prepared_path,
        object_type="regular-file",
        mode="0600",
        content_sha256=hashlib.sha256(plan.prepared_raw).hexdigest(),
    )


def _prepared_manifest_logical_from_receipt(
    receipt: ActivationPreparationReceiptV2,
    *,
    manifest_root: Path,
) -> LogicalPreparationObjectV2:
    prepared_file = receipt.prepared_manifest_file
    prepared_parent = receipt.prepared_manifest_parent
    if prepared_file is None or prepared_parent is None:
        raise ValueError("preparation receipt has no prepared manifest binding")
    expected_parent = manifest_root / "prepared-manifests"
    prepared_path = Path(str(prepared_file.value.get("path")))
    if (
        prepared_path.parent != expected_parent
        or prepared_parent.value.get("path") != str(expected_parent)
        or not prepared_path.name.startswith(
            receipt.activation_intent.operation_id + "."
        )
        or receipt.desired.tree_objects
        or receipt.desired.symlinks
        or receipt.desired.controller_candidates
        or receipt.desired.watchdogs
        or receipt.desired.external_commands
        or receipt.desired.receipts
        or receipt.desired.absence_proofs
        or receipt.desired.manifest is not None
        or receipt.desired.controller is not None
        or receipt.desired.registry is not None
        or receipt.desired.launchers is not None
        or receipt.desired.legacy_processes is not None
        or receipt.desired.quiescence is not None
    ):
        raise ValueError("preparation receipt contains an unexpected desired seed")
    return LogicalPreparationObjectV2(
        path=prepared_path,
        object_type="regular-file",
        mode="0600",
        content_sha256=str(prepared_file.value["sha256"]),
    )


def _load_persisted_definition(
    *,
    control_path: Path,
    receipt_path: Path,
) -> ActivationPreparationDefinitionV2 | None:
    if os.path.lexists(control_path):
        document = _read_private_canonical_object(control_path)
        definition = document.get("definition")
        if type(definition) is not dict:
            raise ValueError("preparation journal has no complete definition")
        return _definition_from_document(definition)
    if os.path.lexists(receipt_path):
        receipt = ActivationPreparationReceiptV2.from_path(receipt_path)
        return _definition_from_preparation_receipt_v2(
            receipt,
            control_path=control_path,
            receipt_path=receipt_path,
        )
    return None


def _definition_from_preparation_receipt_v2(
    receipt: ActivationPreparationReceiptV2,
    *,
    control_path: Path,
    receipt_path: Path,
) -> ActivationPreparationDefinitionV2:
    intent = receipt.activation_intent
    return ActivationPreparationDefinitionV2(
        journal_path=control_path,
        receipt_path=receipt_path,
        lock_path=control_path.parent / "activation-preparation.lock",
        activation_intent=intent,
        desired_seed=_empty_bundle(),
        snapshot_file=receipt.snapshot_file,
        activation_tree_logical=LogicalPreparationObjectV2(
            path=intent.activation_dir,
            object_type="directory",
            mode=str(receipt.activation_tree.value["mode"]),
            content_sha256=str(receipt.activation_tree.value["treeSha256"]),
        ),
        activation_file_logical=LogicalPreparationObjectV2(
            path=intent.activation_file_path,
            object_type="regular-file",
            mode=str(receipt.activation_file.value["mode"]),
            content_sha256=str(receipt.activation_file.value["sha256"]),
        ),
        database_empty_file_logical=LogicalPreparationObjectV2(
            path=intent.database_path,
            object_type="regular-file",
            mode="0600",
            content_sha256=_EMPTY_SHA256,
        ),
        prepared_manifest_logical=(
            None
            if (
                receipt.prepared_manifest_file is None
                and receipt.prepared_manifest_parent is None
            )
            else _prepared_manifest_logical_from_receipt(
                receipt,
                manifest_root=control_path.parent,
            )
        ),
        transition_proof_snapshot=receipt.transition_proof_snapshot,
    )


def _definition_from_document(
    document: Mapping[str, Any],
) -> ActivationPreparationDefinitionV2:
    return ActivationPreparationDefinitionV2(
        journal_path=Path(str(document["journalPath"])),
        receipt_path=Path(str(document["receiptPath"])),
        lock_path=Path(str(document["lockPath"])),
        activation_intent=ActivationPreparationIntentV2.from_document(
            document["activationIntent"]
        ),
        desired_seed=StateBundleV2.from_document(document["desiredSeed"]),
        snapshot_file=ProjectionV2.from_document(document["snapshotFile"]),
        activation_tree_logical=LogicalPreparationObjectV2.from_document(
            document["activationTreeLogical"]
        ),
        activation_file_logical=LogicalPreparationObjectV2.from_document(
            document["activationFileLogical"]
        ),
        database_empty_file_logical=LogicalPreparationObjectV2.from_document(
            document["databaseEmptyFileLogical"]
        ),
        prepared_manifest_logical=(
            None
            if "preparedManifestLogical" not in document
            else LogicalPreparationObjectV2.from_document(
                document["preparedManifestLogical"]
            )
        ),
        transition_proof_snapshot=(
            None
            if "transitionProofSnapshot" not in document
            else ActivationTransitionProofSnapshotV2.from_document(
                document["transitionProofSnapshot"]
            )
        ),
    )


def _read_private_canonical_object(path: Path) -> dict[str, Any]:
    return _read_canonical_private_json(path, "preparation journal")


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


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("completed_at must contain timezone")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _aware(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "UpgradePreparationV2",
    "build_upgrade_database_binding_v2",
    "build_upgrade_preparation_v2",
    "execute_and_verify_upgrade_preparation_v2",
    "observe_upgrade_database_v2",
    "prepared_manifest_from_upgrade_receipt_v2",
    "prepare_upgrade_database_v2",
]
