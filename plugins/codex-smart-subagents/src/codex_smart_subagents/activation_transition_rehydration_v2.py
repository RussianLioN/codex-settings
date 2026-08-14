"""Долговечный снимок и восстановление доказательства перехода активации v2."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from .activation_gateway_v2 import GatewayLayout, _file_projection, _tree_projection
from .activation_transition_v2 import (
    ActivationTransitionProofV2,
    _durable_filesystem_projection_matches,
    _durable_manifest_projection_matches,
    _manifest_projection,
    _observe_link,
    _projection,
    _read_private_json_bytes,
    _validate_database_file_identity,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .lifecycle_operation_v2 import ProjectionV2
from .operation_deadline_v2 import OperationDeadlineExceededV2
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2


_SNAPSHOT_DOMAIN = "codex-smart/activation-transition-proof-snapshot/v2"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_PLAN_ID = re.compile(r"^pl2_[0-9a-f]{32}$")
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")


class ActivationTransitionRehydrationV2Error(RuntimeError):
    """Закрытый отказ разбора либо повторной проверки снимка."""


@dataclass(frozen=True)
class ActivationTransitionProofSnapshotV2:
    """Самодостаточная статическая часть доказательства старой активации."""

    operation_id: str
    codex_home: Path
    manifest_path: Path
    marketplace_link_path: Path
    installation_id: str
    activation_id: str
    activation_fingerprint: str
    current_operation_id: str
    state_home: Path
    database_path: Path
    activation_dir: Path
    manifest_raw_sha256: str
    manifest_document: Mapping[str, Any]
    manifest_file_projection: Mapping[str, Any]
    manifest_projection: ProjectionV2
    active_pointer: Mapping[str, Any]
    link_target: str
    link_device: int
    link_inode: int
    link_projection: ProjectionV2
    activation_raw_sha256: str
    activation_document: Mapping[str, Any]
    activation_tree_projection: ProjectionV2
    activation_projection: ProjectionV2
    commit_receipt_path: Path
    commit_receipt_raw_sha256: str
    commit_receipt_document: Mapping[str, Any]
    commit_receipt_file_projection: Mapping[str, Any]
    commit_receipt_projection: ProjectionV2
    database_binding: ProjectionV2
    database_identity_row: Mapping[str, Any]
    controller_row: Mapping[str, Any]
    controller_identity: str
    installer_receipt_path: Path
    installer_receipt_raw_sha256: str
    installer_receipt_document: Mapping[str, Any]
    installer_receipt_file_projection: Mapping[str, Any]
    installer_receipt_projection: ProjectionV2
    activation_proof_fingerprint: str
    snapshot_fingerprint: str

    def __post_init__(self) -> None:
        for name in (
            "codex_home",
            "manifest_path",
            "marketplace_link_path",
            "state_home",
            "database_path",
            "activation_dir",
            "commit_receipt_path",
            "installer_receipt_path",
        ):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                _fail(f"{name} must be an absolute Path")
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            _fail("operationId is invalid")
        if _OPERATION_ID.fullmatch(self.current_operation_id) is None:
            _fail("currentOperationId is invalid")
        if _INSTALLATION_ID.fullmatch(self.installation_id) is None:
            _fail("installationId is invalid")
        if (
            _ACTIVATION_ID.fullmatch(self.activation_id) is None
            or self.activation_id != "act2_" + self.activation_fingerprint
        ):
            _fail("activation identity is invalid")
        for name in (
            "activation_fingerprint",
            "manifest_raw_sha256",
            "activation_raw_sha256",
            "commit_receipt_raw_sha256",
            "controller_identity",
            "installer_receipt_raw_sha256",
            "activation_proof_fingerprint",
            "snapshot_fingerprint",
        ):
            if _SHA256.fullmatch(str(getattr(self, name))) is None:
                _fail(f"{name} is not sha256")
        for name in (
            "manifest_document",
            "manifest_file_projection",
            "active_pointer",
            "activation_document",
            "commit_receipt_document",
            "commit_receipt_file_projection",
            "database_identity_row",
            "controller_row",
            "installer_receipt_document",
            "installer_receipt_file_projection",
        ):
            value = getattr(self, name)
            if type(value) is not dict:
                _fail(f"{name} must be an object")
            object.__setattr__(self, name, copy.deepcopy(dict(value)))
        for name in (
            "manifest_projection",
            "link_projection",
            "activation_tree_projection",
            "activation_projection",
            "commit_receipt_projection",
            "database_binding",
            "installer_receipt_projection",
        ):
            if not isinstance(getattr(self, name), ProjectionV2):
                _fail(f"{name} must be ProjectionV2")
        if (
            type(self.link_device) is not int
            or self.link_device < 0
            or type(self.link_inode) is not int
            or self.link_inode < 0
            or not isinstance(self.link_target, str)
            or self.link_target.startswith("/")
        ):
            _fail("link identity is invalid")
        layout = GatewayLayout.for_codex_home(self.codex_home)
        if (
            self.manifest_path != layout.manifest_path
            or self.marketplace_link_path != layout.marketplace_link
            or self.activation_dir
            != layout.managed_root / "activations" / self.activation_id
            or self.commit_receipt_path
            != layout.receipts_root
            / self.installation_id
            / f"{self.current_operation_id}.commit.json"
        ):
            _fail("snapshot paths do not match GatewayLayout")
        if self.manifest_projection.schema_id != "manifest-v2":
            _fail("manifest projection type is invalid")
        if self.link_projection.schema_id != "symlink-object-v2":
            _fail("link projection type is invalid")
        if self.activation_tree_projection.schema_id != "tree-object-v2":
            _fail("activation tree projection type is invalid")
        if self.activation_projection.schema_id != "activation-v2":
            _fail("activation projection type is invalid")
        if self.commit_receipt_projection.schema_id != "receipt-object-v2":
            _fail("commit receipt projection type is invalid")
        if self.database_binding.schema_id != "database-binding-v2":
            _fail("database binding projection type is invalid")
        if self.installer_receipt_projection.schema_id != "file-object-v2":
            _fail("installer receipt projection type is invalid")

    @classmethod
    def from_proof(
        cls,
        proof: ActivationTransitionProofV2,
        *,
        operation_id: str,
    ) -> "ActivationTransitionProofSnapshotV2":
        if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
            _fail("activation transition proof is incomplete")
        snapshot = cls(
            operation_id=operation_id,
            codex_home=proof.codex_home,
            manifest_path=proof.layout.manifest_path,
            marketplace_link_path=proof.layout.marketplace_link,
            installation_id=proof.installation_id,
            activation_id=proof.activation_id,
            activation_fingerprint=proof.activation_fingerprint,
            current_operation_id=proof.current_operation_id,
            state_home=proof.state_home,
            database_path=proof.database_path,
            activation_dir=proof.activation_dir,
            manifest_raw_sha256=hashlib.sha256(proof.manifest_raw).hexdigest(),
            manifest_document=proof.manifest_document,
            manifest_file_projection=proof.manifest_file_projection,
            manifest_projection=proof.manifest_projection,
            active_pointer=proof.active_pointer,
            link_target=proof.link_target,
            link_device=proof.link_device,
            link_inode=proof.link_inode,
            link_projection=proof.link_projection,
            activation_raw_sha256=hashlib.sha256(proof.activation_raw).hexdigest(),
            activation_document=proof.activation_document,
            activation_tree_projection=proof.activation_tree_projection,
            activation_projection=proof.activation_projection,
            commit_receipt_path=proof.commit_receipt_path,
            commit_receipt_raw_sha256=hashlib.sha256(
                proof.commit_receipt_raw
            ).hexdigest(),
            commit_receipt_document=proof.commit_receipt_document,
            commit_receipt_file_projection=proof.commit_receipt_file_projection,
            commit_receipt_projection=proof.commit_receipt_projection,
            database_binding=proof.database_binding,
            database_identity_row=proof.database_identity_row,
            controller_row=proof.controller_row,
            controller_identity=proof.controller_identity,
            installer_receipt_path=proof.installer_receipt_path,
            installer_receipt_raw_sha256=hashlib.sha256(
                proof.installer_receipt_raw
            ).hexdigest(),
            installer_receipt_document=proof.installer_receipt_document,
            installer_receipt_file_projection=proof.installer_receipt_file_projection,
            installer_receipt_projection=proof.installer_receipt_projection,
            activation_proof_fingerprint=proof.proof_fingerprint,
            snapshot_fingerprint="0" * 64,
        )
        return replace(
            snapshot,
            snapshot_fingerprint=domain_fingerprint(
                _SNAPSHOT_DOMAIN,
                snapshot._projection(),
            ),
        )

    @property
    def complete(self) -> bool:
        return self.snapshot_fingerprint == domain_fingerprint(
            _SNAPSHOT_DOMAIN,
            self._projection(),
        )

    def _projection(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "snapshotKind": "activation-transition-proof",
            "operationId": self.operation_id,
            "codexHome": str(self.codex_home),
            "manifestPath": str(self.manifest_path),
            "marketplaceLinkPath": str(self.marketplace_link_path),
            "installationId": self.installation_id,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "currentOperationId": self.current_operation_id,
            "stateHome": str(self.state_home),
            "databasePath": str(self.database_path),
            "activationDir": str(self.activation_dir),
            "manifestRawSha256": self.manifest_raw_sha256,
            "manifestDocument": copy.deepcopy(dict(self.manifest_document)),
            "manifestFileProjection": copy.deepcopy(
                dict(self.manifest_file_projection)
            ),
            "manifestProjection": self.manifest_projection.to_document(),
            "activePointer": copy.deepcopy(dict(self.active_pointer)),
            "linkTarget": self.link_target,
            "linkDevice": self.link_device,
            "linkInode": self.link_inode,
            "linkProjection": self.link_projection.to_document(),
            "activationRawSha256": self.activation_raw_sha256,
            "activationDocument": copy.deepcopy(dict(self.activation_document)),
            "activationTreeProjection": (
                self.activation_tree_projection.to_document()
            ),
            "activationProjection": self.activation_projection.to_document(),
            "commitReceiptPath": str(self.commit_receipt_path),
            "commitReceiptRawSha256": self.commit_receipt_raw_sha256,
            "commitReceiptDocument": copy.deepcopy(
                dict(self.commit_receipt_document)
            ),
            "commitReceiptFileProjection": copy.deepcopy(
                dict(self.commit_receipt_file_projection)
            ),
            "commitReceiptProjection": (
                self.commit_receipt_projection.to_document()
            ),
            "databaseBinding": self.database_binding.to_document(),
            "databaseIdentityRow": copy.deepcopy(dict(self.database_identity_row)),
            "controllerRow": copy.deepcopy(dict(self.controller_row)),
            "controllerIdentity": self.controller_identity,
            "installerReceiptPath": str(self.installer_receipt_path),
            "installerReceiptRawSha256": self.installer_receipt_raw_sha256,
            "installerReceiptDocument": copy.deepcopy(
                dict(self.installer_receipt_document)
            ),
            "installerReceiptFileProjection": copy.deepcopy(
                dict(self.installer_receipt_file_projection)
            ),
            "installerReceiptProjection": (
                self.installer_receipt_projection.to_document()
            ),
            "activationProofFingerprint": self.activation_proof_fingerprint,
        }

    def to_document(self) -> dict[str, Any]:
        return {
            **self._projection(),
            "snapshotFingerprint": self.snapshot_fingerprint,
        }

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
    ) -> "ActivationTransitionProofSnapshotV2":
        expected = {
            "schemaVersion", "snapshotKind", "operationId", "codexHome",
            "manifestPath", "marketplaceLinkPath", "installationId",
            "activationId", "activationFingerprint", "currentOperationId",
            "stateHome", "databasePath", "activationDir", "manifestRawSha256",
            "manifestDocument", "manifestFileProjection", "manifestProjection",
            "activePointer", "linkTarget", "linkDevice", "linkInode",
            "linkProjection", "activationRawSha256", "activationDocument",
            "activationTreeProjection", "activationProjection",
            "commitReceiptPath", "commitReceiptRawSha256",
            "commitReceiptDocument", "commitReceiptFileProjection",
            "commitReceiptProjection", "databaseBinding", "databaseIdentityRow",
            "controllerRow", "controllerIdentity", "installerReceiptPath",
            "installerReceiptRawSha256", "installerReceiptDocument",
            "installerReceiptFileProjection", "installerReceiptProjection",
            "activationProofFingerprint", "snapshotFingerprint",
        }
        if type(document) is not dict or set(document) != expected:
            _fail("transition proof snapshot has unexpected fields")
        if (
            document["schemaVersion"] != 2
            or document["snapshotKind"] != "activation-transition-proof"
        ):
            _fail("transition proof snapshot header is invalid")
        result = cls(
            operation_id=_string(document["operationId"], "operationId"),
            codex_home=Path(_string(document["codexHome"], "codexHome")),
            manifest_path=Path(_string(document["manifestPath"], "manifestPath")),
            marketplace_link_path=Path(
                _string(document["marketplaceLinkPath"], "marketplaceLinkPath")
            ),
            installation_id=_string(document["installationId"], "installationId"),
            activation_id=_string(document["activationId"], "activationId"),
            activation_fingerprint=_string(
                document["activationFingerprint"], "activationFingerprint"
            ),
            current_operation_id=_string(
                document["currentOperationId"], "currentOperationId"
            ),
            state_home=Path(_string(document["stateHome"], "stateHome")),
            database_path=Path(_string(document["databasePath"], "databasePath")),
            activation_dir=Path(_string(document["activationDir"], "activationDir")),
            manifest_raw_sha256=_string(
                document["manifestRawSha256"], "manifestRawSha256"
            ),
            manifest_document=_object(document["manifestDocument"], "manifestDocument"),
            manifest_file_projection=_object(
                document["manifestFileProjection"], "manifestFileProjection"
            ),
            manifest_projection=ProjectionV2.from_document(
                _object(document["manifestProjection"], "manifestProjection")
            ),
            active_pointer=_object(document["activePointer"], "activePointer"),
            link_target=_string(document["linkTarget"], "linkTarget"),
            link_device=_integer(document["linkDevice"], "linkDevice"),
            link_inode=_integer(document["linkInode"], "linkInode"),
            link_projection=ProjectionV2.from_document(
                _object(document["linkProjection"], "linkProjection")
            ),
            activation_raw_sha256=_string(
                document["activationRawSha256"], "activationRawSha256"
            ),
            activation_document=_object(
                document["activationDocument"], "activationDocument"
            ),
            activation_tree_projection=ProjectionV2.from_document(
                _object(
                    document["activationTreeProjection"],
                    "activationTreeProjection",
                )
            ),
            activation_projection=ProjectionV2.from_document(
                _object(document["activationProjection"], "activationProjection")
            ),
            commit_receipt_path=Path(
                _string(document["commitReceiptPath"], "commitReceiptPath")
            ),
            commit_receipt_raw_sha256=_string(
                document["commitReceiptRawSha256"], "commitReceiptRawSha256"
            ),
            commit_receipt_document=_object(
                document["commitReceiptDocument"], "commitReceiptDocument"
            ),
            commit_receipt_file_projection=_object(
                document["commitReceiptFileProjection"],
                "commitReceiptFileProjection",
            ),
            commit_receipt_projection=ProjectionV2.from_document(
                _object(
                    document["commitReceiptProjection"],
                    "commitReceiptProjection",
                )
            ),
            database_binding=ProjectionV2.from_document(
                _object(document["databaseBinding"], "databaseBinding")
            ),
            database_identity_row=_object(
                document["databaseIdentityRow"], "databaseIdentityRow"
            ),
            controller_row=_object(document["controllerRow"], "controllerRow"),
            controller_identity=_string(
                document["controllerIdentity"], "controllerIdentity"
            ),
            installer_receipt_path=Path(
                _string(document["installerReceiptPath"], "installerReceiptPath")
            ),
            installer_receipt_raw_sha256=_string(
                document["installerReceiptRawSha256"],
                "installerReceiptRawSha256",
            ),
            installer_receipt_document=_object(
                document["installerReceiptDocument"], "installerReceiptDocument"
            ),
            installer_receipt_file_projection=_object(
                document["installerReceiptFileProjection"],
                "installerReceiptFileProjection",
            ),
            installer_receipt_projection=ProjectionV2.from_document(
                _object(
                    document["installerReceiptProjection"],
                    "installerReceiptProjection",
                )
            ),
            activation_proof_fingerprint=_string(
                document["activationProofFingerprint"],
                "activationProofFingerprint",
            ),
            snapshot_fingerprint=_string(
                document["snapshotFingerprint"], "snapshotFingerprint"
            ),
        )
        if not result.complete:
            _fail("transition proof snapshot fingerprint mismatch")
        return result


def rehydrate_activation_transition_proof_v2(
    snapshot: ActivationTransitionProofSnapshotV2 | Mapping[str, Any],
    *,
    journal: Mapping[str, Any] | None = None,
) -> ActivationTransitionProofV2:
    """Восстановить proof, допуская только persisted before/after переходов.

    Переданный ``journal`` обязан быть тем же документом, который уже прочитан
    через ``OperationJournalStoreV2.read`` и строго разобран посредством
    ``operation_definition_from_journal_v2``. Здесь дополнительно проверяется
    необходимая для перехода связь порядка, плана и носителей его шагов.
    """

    try:
        return _rehydrate_activation_transition_proof_v2(
            snapshot,
            journal=journal,
        )
    except ActivationTransitionRehydrationV2Error:
        raise
    except OperationDeadlineExceededV2:
        raise
    except Exception as exc:
        raise ActivationTransitionRehydrationV2Error(str(exc)) from exc


def _rehydrate_activation_transition_proof_v2(
    snapshot: ActivationTransitionProofSnapshotV2 | Mapping[str, Any],
    *,
    journal: Mapping[str, Any] | None,
) -> ActivationTransitionProofV2:

    if not isinstance(snapshot, ActivationTransitionProofSnapshotV2):
        snapshot = ActivationTransitionProofSnapshotV2.from_document(snapshot)
    if not snapshot.complete:
        _fail("transition proof snapshot is incomplete")
    if journal is not None:
        _validate_main_journal_binding(snapshot, journal)
    manifest_raw, manifest = _read_private_json_bytes(
        snapshot.manifest_path,
        code="MANIFEST_TRANSITION_AMBIGUOUS",
        require_canonical=True,
    )
    manifest_observed = _manifest_projection(snapshot.manifest_path, manifest)
    link_observed, link_info, link_target = _observe_link(
        snapshot.marketplace_link_path
    )
    _verify_transition_state(
        journal,
        kind="activation_link",
        captured_before=snapshot.link_projection,
        current=link_observed,
        before_identity=(snapshot.link_device, snapshot.link_inode),
        current_identity=(link_info.st_dev, link_info.st_ino),
    )
    _verify_transition_state(
        journal,
        kind="manifest_commit",
        captured_before=snapshot.manifest_projection,
        current=manifest_observed,
    )
    _verify_stable_artifacts(snapshot)
    installer_raw, installer = _read_private_json_bytes(
        snapshot.installer_receipt_path,
        code="INSTALLER_RECEIPT_CHANGED",
        require_canonical=False,
    )
    proof = ActivationTransitionProofV2(
        codex_home=snapshot.codex_home,
        layout=GatewayLayout.for_codex_home(snapshot.codex_home),
        installation_id=snapshot.installation_id,
        activation_id=snapshot.activation_id,
        activation_fingerprint=snapshot.activation_fingerprint,
        current_operation_id=snapshot.current_operation_id,
        state_home=snapshot.state_home,
        database_path=snapshot.database_path,
        activation_dir=snapshot.activation_dir,
        manifest_raw=canonical_json_bytes(snapshot.manifest_document),
        manifest_document=snapshot.manifest_document,
        manifest_file_projection=snapshot.manifest_file_projection,
        manifest_projection=snapshot.manifest_projection,
        active_pointer=snapshot.active_pointer,
        link_target=snapshot.link_target,
        link_device=snapshot.link_device,
        link_inode=snapshot.link_inode,
        link_projection=snapshot.link_projection,
        activation_raw=canonical_json_bytes(snapshot.activation_document),
        activation_document=snapshot.activation_document,
        activation_tree_projection=snapshot.activation_tree_projection,
        activation_projection=snapshot.activation_projection,
        commit_receipt_path=snapshot.commit_receipt_path,
        commit_receipt_raw=canonical_json_bytes(snapshot.commit_receipt_document),
        commit_receipt_document=snapshot.commit_receipt_document,
        commit_receipt_file_projection=snapshot.commit_receipt_file_projection,
        commit_receipt_projection=snapshot.commit_receipt_projection,
        database_binding=snapshot.database_binding,
        database_identity_row=snapshot.database_identity_row,
        controller_row=snapshot.controller_row,
        controller_identity=snapshot.controller_identity,
        installer_receipt_path=snapshot.installer_receipt_path,
        installer_receipt_raw=installer_raw,
        installer_receipt_document=installer,
        installer_receipt_file_projection=(
            snapshot.installer_receipt_file_projection
        ),
        installer_receipt_projection=snapshot.installer_receipt_projection,
        proof_fingerprint=snapshot.activation_proof_fingerprint,
    )
    if not proof.complete:
        _fail("rehydrated activation proof fingerprint mismatch")
    if link_observed == snapshot.link_projection and link_target != snapshot.link_target:
        _fail("captured link target changed")
    if manifest_observed == snapshot.manifest_projection and (
        hashlib.sha256(manifest_raw).hexdigest() != snapshot.manifest_raw_sha256
    ):
        _fail("captured manifest raw bytes changed")
    return proof


def _validate_main_journal_binding(
    snapshot: ActivationTransitionProofSnapshotV2,
    journal: Mapping[str, Any],
) -> None:
    if (
        journal.get("operationId") != snapshot.operation_id
        or journal.get("installationId") != snapshot.installation_id
    ):
        _fail("main journal belongs to another transition snapshot")
    plan = journal.get("executionPlan")
    steps = journal.get("steps")
    if not isinstance(plan, Mapping) or type(steps) is not list or not steps:
        _fail("main journal plan or steps are missing")
    cursor = plan.get("firstIncompleteOrdinal")
    plan_id = plan.get("planId")
    if (
        type(cursor) is not int
        or cursor < 1
        or type(plan_id) is not str
        or _PLAN_ID.fullmatch(plan_id) is None
    ):
        _fail("main journal cursor is invalid")
    ordered = list(steps)
    if (
        not ordered
        or not all(isinstance(step, Mapping) for step in ordered)
        or ordered[0].get("kind") != "gate_close"
        or ordered[0].get("planOrdinal") != 0
        or ordered[0].get("state") != "COMPLETED"
        or [step.get("planOrdinal") for step in ordered]
        != list(range(len(ordered)))
    ):
        _fail("main journal steps are not one ordered durable prefix")
    for ordinal, step in enumerate(ordered):
        expected_carrier = (
            "JOURNAL_ATOMIC_BOUNDARY"
            if step.get("kind") in {"gate_close", "terminal_journal_freeze"}
            else "JOURNAL_MUTABLE"
        )
        if (
            step.get("planId") != plan_id
            or step.get("recordCarrier") != expected_carrier
        ):
            _fail("main journal step is not bound to its execution plan")
        if ordinal == 0:
            continue
        ordinal = int(step["planOrdinal"])
        state = step.get("state")
        if ordinal < cursor and state != "COMPLETED":
            _fail("main journal has an incomplete step before its cursor")
        if ordinal == cursor and state not in {"PLANNED", "INTENT_DURABLE"}:
            _fail("main journal cursor step has an invalid state")
        if ordinal > cursor and state != "PLANNED":
            _fail("main journal has a non-planned future step")
    if cursor > len(ordered):
        _fail("main journal cursor exceeds its persisted durable prefix")


def _verify_stable_artifacts(snapshot: ActivationTransitionProofSnapshotV2) -> None:
    activation_root_mode = stat.S_IMODE(os.lstat(snapshot.activation_dir).st_mode)
    if activation_root_mode not in {0o500, 0o700}:
        raise ActivationTransitionRehydrationV2Error(
            "ACTIVE_TREE_CHANGED: activation directory mode changed"
        )
    activation_raw, activation = _read_private_json_bytes(
        snapshot.activation_dir / "activation.json",
        code="ACTIVE_TREE_CHANGED",
        require_canonical=True,
        expected_modes=frozenset(
            {0o400 if activation_root_mode == 0o500 else 0o600}
        ),
    )
    activation_tree = _projection(
        "tree-object-v2",
        _tree_projection(snapshot.activation_dir),
        "codex-smart/tree-object/v2",
    )
    if (
        hashlib.sha256(activation_raw).hexdigest()
        != snapshot.activation_raw_sha256
        or activation != dict(snapshot.activation_document)
        or not _durable_tree_projection_matches(
            snapshot.activation_tree_projection,
            activation_tree,
        )
    ):
        _fail("stable activation tree changed")
    commit_raw, commit = _read_private_json_bytes(
        snapshot.commit_receipt_path,
        code="COMMIT_RECEIPT_CHANGED",
        require_canonical=True,
    )
    commit_file = _file_projection(snapshot.commit_receipt_path)
    commit_projection = _projection(
        "receipt-object-v2",
        {
            "file": commit_file,
            "receiptKind": commit["receiptKind"],
            "installationId": commit["installationId"],
            "operationId": commit["operationId"],
            "receiptFingerprint": commit["receiptFingerprint"],
        },
        "codex-smart/receipt-object/v2",
    )
    if (
        hashlib.sha256(commit_raw).hexdigest()
        != snapshot.commit_receipt_raw_sha256
        or commit != dict(snapshot.commit_receipt_document)
        or not _durable_filesystem_projection_matches(
            snapshot.commit_receipt_file_projection,
            commit_file,
        )
        or not _durable_receipt_projection_matches(
            snapshot.commit_receipt_projection,
            commit_projection,
        )
    ):
        _fail("stable commit receipt changed")
    installer_raw, installer = _read_private_json_bytes(
        snapshot.installer_receipt_path,
        code="INSTALLER_RECEIPT_CHANGED",
        require_canonical=False,
    )
    installer_file = _file_projection(snapshot.installer_receipt_path)
    installer_projection = _projection(
        "file-object-v2",
        installer_file,
        "codex-smart/file-object/v2",
    )
    if (
        hashlib.sha256(installer_raw).hexdigest()
        != snapshot.installer_receipt_raw_sha256
        or installer != dict(snapshot.installer_receipt_document)
        or not _durable_filesystem_projection_matches(
            snapshot.installer_receipt_file_projection,
            installer_file,
        )
        or not _durable_file_projection_matches(
            snapshot.installer_receipt_projection,
            installer_projection,
        )
    ):
        _fail("stable installer receipt changed")
    _validate_database_file_identity(snapshot.database_binding)
    uri = f"file:{snapshot.database_path}?mode=ro"
    try:
        connection = connect_sqlite_with_deadline_v2(uri, uri=True)
        connection.row_factory = sqlite3.Row
        rows = connection.execute("select * from database_identity").fetchall()
    except sqlite3.Error as exc:
        _fail(f"database identity cannot be read: {exc}")
    finally:
        if "connection" in locals():
            connection.close()
    if len(rows) != 1 or dict(rows[0]) != dict(snapshot.database_identity_row):
        _fail("stable database identity changed")


def _verify_transition_state(
    journal: Mapping[str, Any] | None,
    *,
    kind: str,
    captured_before: ProjectionV2,
    current: ProjectionV2,
    before_identity: tuple[int, int] | None = None,
    current_identity: tuple[int, int] | None = None,
) -> None:
    def matches_current(expected: ProjectionV2) -> bool:
        if kind == "activation_link":
            return _durable_symlink_projection_matches(expected, current)
        if kind == "manifest_commit":
            return _durable_manifest_projection_matches(expected, current)
        return current == expected

    def before_identity_matches() -> bool:
        if before_identity is None:
            return True
        if current_identity is None:
            return False
        if kind == "activation_link":
            before_device, before_inode = before_identity
            current_device, current_inode = current_identity
            return (
                _captured_device_is_valid(before_device)
                and _captured_device_is_valid(current_device)
                and current_inode == before_inode
            )
        return current_identity == before_identity

    if journal is None:
        if not matches_current(captured_before) or not before_identity_matches():
            _fail(f"{kind} changed without a durable journal")
        return
    steps = journal.get("steps")
    if type(steps) is not list:
        _fail("main journal has no steps")
    matching_steps = [
        step
        for step in steps
        if isinstance(step, Mapping) and step.get("kind") == kind
    ]
    if len(matching_steps) != 1:
        _fail(f"main journal must contain exactly one {kind} step")
    step = matching_steps[0]
    before = ProjectionV2.from_document(_object(step.get("before"), f"{kind}.before"))
    expected_after = ProjectionV2.from_document(
        _object(step.get("expectedAfter"), f"{kind}.expectedAfter")
    )
    if before != captured_before:
        _fail(f"{kind}.before differs from transition snapshot")
    state = step.get("state")
    current_is_before = matches_current(before)
    current_is_after = matches_current(expected_after)
    if state == "PLANNED":
        accepted = current_is_before
        if before_identity is not None:
            accepted = accepted and before_identity_matches()
    elif state == "INTENT_DURABLE":
        accepted = current_is_before or current_is_after
        if current_is_before and before_identity is not None:
            accepted = accepted and before_identity_matches()
    elif state == "COMPLETED":
        observed_after = ProjectionV2.from_document(
            _object(step.get("observedAfter"), f"{kind}.observedAfter")
        )
        accepted = observed_after == expected_after and matches_current(observed_after)
    else:
        _fail(f"{kind} has an unknown durable state")
    if not accepted:
        _fail(f"{kind} live state is neither its permitted before nor after")
    if kind == "manifest_commit":
        _verify_prepared_manifest_pair(
            step,
            current=current,
            before=before,
            expected_after=expected_after,
        )


def _verify_prepared_manifest_pair(
    step: Mapping[str, Any],
    *,
    current: ProjectionV2,
    before: ProjectionV2,
    expected_after: ProjectionV2,
) -> None:
    action = _object(step.get("action"), "manifest_commit.action")
    source = Path(_string(action.get("sourcePath"), "manifest sourcePath"))
    target = Path(_string(action.get("targetPath"), "manifest targetPath"))
    if not source.is_absolute() or not target.is_absolute():
        _fail("manifest transition paths must be absolute")
    try:
        source_projection = _file_projection(source)
    except FileNotFoundError:
        source_projection = None
    expected_file = expected_after.value.get("file")
    if type(expected_file) is not dict:
        _fail("manifest expectedAfter has no file projection")
    current_is_before = _durable_manifest_projection_matches(before, current)
    current_is_after = _durable_manifest_projection_matches(expected_after, current)
    if current_is_before:
        if source_projection is None:
            _fail("manifest target is before but prepared source is absent")
        normalized = copy.deepcopy(source_projection)
        normalized["path"] = str(target)
        if not _durable_filesystem_projection_matches(expected_file, normalized):
            _fail("prepared manifest source differs from expectedAfter inode")
    elif current_is_after and source_projection is not None:
        _fail("manifest target is after but prepared source still exists")


def _durable_tree_projection_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
) -> bool:
    return (
        _durable_projection_header_matches(
            captured,
            observed,
            "codex-smart/tree-object/v2",
        )
        and _durable_filesystem_projection_matches(captured.value, observed.value)
    )


def _durable_file_projection_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
) -> bool:
    return (
        _durable_projection_header_matches(
            captured,
            observed,
            "codex-smart/file-object/v2",
        )
        and _durable_filesystem_projection_matches(captured.value, observed.value)
    )


def _durable_receipt_projection_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
) -> bool:
    if not _durable_projection_header_matches(
        captured,
        observed,
        "codex-smart/receipt-object/v2",
    ):
        return False
    captured_file = captured.value.get("file")
    observed_file = observed.value.get("file")
    if not isinstance(observed_file, Mapping):
        return False
    if not _durable_filesystem_projection_matches(captured_file, observed_file):
        return False
    return all(
        key == "file" or captured.value[key] == observed.value[key]
        for key in observed.value
    )


def _durable_symlink_projection_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
) -> bool:
    if not _durable_projection_header_matches(
        captured,
        observed,
        "codex-smart/symlink-object/v2",
    ):
        return False
    parent_device = captured.value.get("parentDevice")
    if not _captured_device_is_valid(parent_device):
        return False
    return all(
        key == "parentDevice" or captured.value[key] == observed.value[key]
        for key in observed.value
    )


def _captured_device_is_valid(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _durable_projection_header_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
    domain: str,
) -> bool:
    return (
        captured.schema_id == observed.schema_id
        and captured.schema_sha256 == observed.schema_sha256
        and set(captured.value) == set(observed.value)
        and _projection_value_fingerprint_matches(captured, domain)
    )


def _projection_value_fingerprint_matches(
    projection: ProjectionV2,
    domain: str,
) -> bool:
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    return projection.value_fingerprint == domain_fingerprint(domain, envelope)


def _object(value: object, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{name} must be an object")
    return copy.deepcopy(value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{name} must be a non-empty string")
    return value


def _integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{name} must be a non-negative integer")
    return value


def _fail(message: str) -> None:
    raise ActivationTransitionRehydrationV2Error(message)


__all__ = [
    "ActivationTransitionProofSnapshotV2",
    "ActivationTransitionRehydrationV2Error",
    "rehydrate_activation_transition_proof_v2",
]
