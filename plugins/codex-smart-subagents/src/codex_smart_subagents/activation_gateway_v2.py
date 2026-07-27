"""Permanent activation gateway for adaptive subagents protocol version 2.

The launcher-facing part of this module is deliberately independent from an
activation's Python tree.  A failed proof therefore selects ordinary Codex;
it never imports or repairs the candidate activation.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol, Sequence
from urllib.parse import quote

from .canonical_json import CanonicalJsonError, canonical_json_bytes, domain_fingerprint
from .catalog import Catalog, CatalogError
from .codex_binary_snapshot import CODE_SIGNATURE_REQUIREMENT
from .evidence import EvidenceError, verify_interface_evidence
from .launcher import (
    apply_coordinator_defaults,
    clean_ordinary_environment,
    parse_managed_invocation,
)
from .mcp_runtime_proof_v2 import (
    MCP_SESSION_NONCE_ENV_V2,
    USER_MCP_POLICY_PROOF_ENV_V2,
    build_user_mcp_policy_proof_v2,
    require_bundled_mcp_manifest_v2,
)
from . import operation_deadline_v2
from . import operation_process_group_supervisor_v2
from . import supervised_subprocess_v2
from .schema_projection import (
    APPLICATION_ID,
    SchemaProjectionError,
    database_schema_fingerprint,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_JSON_BYTES = 4 * 1024 * 1024
_ADAPTIVE_DISABLED_FEATURE_ARGUMENTS = (
    "--disable",
    "multi_agent",
    "--disable",
    "multi_agent_v2",
    "--disable",
    "enable_fanout",
)
_ADAPTIVE_DIRECT_TOOL_ARGUMENTS = (
    "-c",
    'code_mode.direct_only_tool_namespaces=["mcp__codex_smart_subagents"]',
)
_RELEASE = "0.2.0"
_NAMESPACE = "codex-smart-subagents-v2"
_LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)
_MANIFEST_KEYS = {
    "schemaVersion",
    "installationId",
    "release",
    "pluginId",
    "marketplaceName",
    "stateHome",
    "sourceLocator",
    "codexSnapshot",
    "activeActivation",
    "previousActivation",
    "interfaceEvidence",
    "routingPolicyFingerprint",
    "bundledCatalogFingerprint",
    "artifacts",
    "originalBackup",
    "lastCommittedOperation",
    "databaseSchemaVersion",
    "extensions",
}


@dataclass
class GatewayUnavailable(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class ManagedLaunchUnavailable(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class GatewayLayout:
    codex_home: Path
    managed_root: Path
    manifest_root: Path
    manifest_path: Path
    lock_path: Path
    journal_path: Path
    receipts_root: Path
    fallback_path: Path
    marketplace_link: Path

    @classmethod
    def for_codex_home(cls, codex_home: Path) -> "GatewayLayout":
        root = codex_home.expanduser().absolute()
        if not root.is_absolute():
            raise ValueError("CODEX_HOME must be absolute")
        manifests = root / "install-manifests"
        managed = root / "codex-smart-subagents-v2"
        name = "codex-smart-subagents-v2"
        return cls(
            codex_home=root,
            managed_root=managed,
            manifest_root=manifests,
            manifest_path=manifests / f"{name}.json",
            lock_path=manifests / f"{name}.lock",
            journal_path=manifests / f"{name}.transaction.json",
            receipts_root=manifests / f"{name}.receipts",
            fallback_path=manifests / f"{name}.fallback.json",
            marketplace_link=managed / "marketplace-current",
        )


class _ProofError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class GatewayState(str, Enum):
    READY = "READY"
    ORDINARY = "ORDINARY"


@dataclass(frozen=True)
class GatewayRuntimeBindingV2:
    """Fresh runtime facts retained only after the complete READY proof."""

    activation_id: str
    activation_fingerprint: str
    compatibility_fingerprint: str
    control_epoch: int
    state_home: Path
    marketplace_path: Path
    database_path: Path
    database_identity_row: Mapping[str, object]
    controller_row: Mapping[str, object]
    interface_evidence: Mapping[str, object]
    activation_identity: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.activation_id != "act2_" + self.activation_fingerprint:
            raise ValueError("runtime activation identity diverges")
        for value, name in (
            (self.activation_fingerprint, "activation fingerprint"),
            (self.compatibility_fingerprint, "compatibility fingerprint"),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"runtime {name} is invalid")
        if type(self.control_epoch) is not int or self.control_epoch < 1:
            raise ValueError("runtime control epoch is invalid")
        for value, name in (
            (self.state_home, "state home"),
            (self.marketplace_path, "marketplace path"),
            (self.database_path, "database path"),
        ):
            if not value.is_absolute():
                raise ValueError(f"runtime {name} must be absolute")
        if (
            self.database_identity_row.get("activation_id") != self.activation_id
            or self.database_identity_row.get("activation_fingerprint")
            != self.activation_fingerprint
            or self.controller_row.get("activation_id") != self.activation_id
            or self.controller_row.get("activation_fingerprint")
            != self.activation_fingerprint
            or self.controller_row.get("compatibility_fingerprint")
            != self.compatibility_fingerprint
            or self.controller_row.get("control_epoch") != self.control_epoch
        ):
            raise ValueError("runtime database or controller binding diverges")


@dataclass(frozen=True)
class GatewayDecision:
    state: GatewayState
    reason_code: str
    executable: Path
    coordinator: Mapping[str, str] | None = None
    activation_id: str | None = None
    gate_fingerprint: str | None = None
    activation_gate: Mapping[str, object] | None = None
    catalog_path: Path | None = None
    runtime_binding: GatewayRuntimeBindingV2 | None = None

    def __post_init__(self) -> None:
        if not self.executable.is_absolute():
            raise ValueError("gateway executable must be absolute")
        if self.state is GatewayState.READY:
            if (
                self.coordinator is None
                or self.activation_id is None
                or self.gate_fingerprint is None
                or self.activation_gate is None
                or self.catalog_path is None
            ):
                raise ValueError("READY gateway decision is incomplete")
            if self.activation_gate.get("gateFingerprint") != self.gate_fingerprint:
                raise ValueError("READY activation gate fingerprint diverges")
        elif any(
            value is not None
            for value in (
                self.coordinator,
                self.activation_id,
                self.gate_fingerprint,
                self.activation_gate,
                self.catalog_path,
                self.runtime_binding,
            )
        ):
            raise ValueError("ordinary gateway decision carries adaptive state")


class GatewayResolver(Protocol):
    def resolve(self) -> GatewayDecision: ...


def v2_gateway_state_present(layout: GatewayLayout) -> bool:
    """Не позволяет частичной версии 2 незаметно уйти в старый загрузчик."""

    return any(
        os.path.lexists(path)
        for path in (
            layout.manifest_path,
            layout.fallback_path,
            layout.journal_path,
            layout.managed_root,
        )
    )


class ActivationResolver:
    """Prove one immutable activation or return an independent ordinary path."""

    def __init__(
        self,
        *,
        layout: GatewayLayout,
        wrapper: Path,
        snapshot_verifier=None,
        controller_probe=None,
    ) -> None:
        self.layout = layout
        self.wrapper = wrapper.expanduser().absolute()
        self.snapshot_verifier = snapshot_verifier
        self.controller_probe = controller_probe

    def resolve(self) -> GatewayDecision:
        ordinary = self._resolve_fallback()
        try:
            if not self.layout.manifest_path.exists():
                raise _ProofError(
                    "MANIFEST_UNAVAILABLE",
                    "activation manifest is absent",
                )
            return self._resolve_ready()
        except operation_deadline_v2.OperationDeadlineExceededV2:
            raise
        except _ProofError as exc:
            return GatewayDecision(
                state=GatewayState.ORDINARY,
                reason_code=exc.code,
                executable=ordinary,
            )
        except (
            CanonicalJsonError,
            EvidenceError,
            KeyError,
            IndexError,
            OSError,
            SchemaProjectionError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ):
            return GatewayDecision(
                state=GatewayState.ORDINARY,
                reason_code="ACTIVATION_PROOF_INVALID",
                executable=ordinary,
            )
        raise AssertionError("gateway resolution did not return a decision")

    def resolve_persisted_activation(self) -> GatewayDecision:
        """Доказывает принятую активацию без требования живого контроллера."""

        return self._resolve_ready(require_live_controller=False)

    def _resolve_ready(
        self,
        *,
        require_live_controller: bool = True,
    ) -> GatewayDecision:
        try:
            with _shared_installation_lock(self.layout.lock_path):
                _verify_directory(self.layout.codex_home, private=False, code="ROOT_INVALID")
                _verify_directory(self.layout.manifest_root, private=True, code="ROOT_INVALID")
                _verify_directory(self.layout.managed_root, private=True, code="ROOT_INVALID")
                if _path_exists_no_follow(self.layout.journal_path):
                    raise _ProofError(
                        "JOURNAL_PRESENT",
                        "the main installation journal is present",
                    )

                manifest = _read_owned_json(
                    self.layout.manifest_path,
                    expected_mode=0o600,
                    code="MANIFEST_INVALID",
                )
                self._validate_manifest(manifest)
                state_home = _absolute_path(manifest["stateHome"], "MANIFEST_INVALID")
                _verify_directory(state_home, private=True, code="STATE_HOME_INVALID")

                source_locator, fallback_snapshot = self._fallback_records()
                if manifest["sourceLocator"] != source_locator:
                    raise _ProofError(
                        "MANIFEST_BINDING_MISMATCH",
                        "manifest source locator differs from fallback capsule",
                    )
                if manifest["codexSnapshot"] != fallback_snapshot:
                    raise _ProofError(
                        "MANIFEST_BINDING_MISMATCH",
                        "manifest snapshot differs from fallback capsule",
                    )
                executable = self._verify_ready_source(source_locator)

                active = manifest["activeActivation"]
                activation_id = active["activationId"]
                activations_root = self.layout.managed_root / "activations"
                _verify_directory(
                    activations_root,
                    private=True,
                    code="ACTIVATION_TREE_MISMATCH",
                )
                target = f"activations/{activation_id}/marketplace"
                link_info = os.lstat(self.layout.marketplace_link)
                if (
                    not stat.S_ISLNK(link_info.st_mode)
                    or os.readlink(self.layout.marketplace_link) != target
                    or active["symlinkTarget"] != target
                ):
                    raise _ProofError(
                        "ACTIVATION_LINK_MISMATCH",
                        "marketplace-current is not the direct active target",
                    )
                activation_dir = self.layout.managed_root / "activations" / activation_id
                marketplace = activation_dir / "marketplace"
                if self.layout.marketplace_link.resolve(strict=True) != marketplace.resolve(
                    strict=True
                ):
                    raise _ProofError(
                        "ACTIVATION_LINK_MISMATCH",
                        "marketplace-current resolves outside the active activation",
                    )
                activation = _read_owned_json(
                    activation_dir / "activation.json",
                    expected_mode=0o600,
                    code="ACTIVATION_INVALID",
                )
                identity = self._validate_activation(
                    activation,
                    activation_dir=activation_dir,
                    marketplace=marketplace,
                    manifest=manifest,
                )

                interface = self._validate_interface(
                    manifest["interfaceEvidence"],
                    identity=identity,
                    manifest=manifest,
                )
                catalog_path = (
                    marketplace
                    / "plugins"
                    / "codex-smart-subagents"
                    / "config"
                    / "adaptive-subagents.toml"
                )
                try:
                    catalog = Catalog.load(catalog_path)
                except (CatalogError, OSError) as exc:
                    raise _ProofError("CATALOG_INVALID", str(exc)) from exc

                receipt_path = (
                    self.layout.receipts_root
                    / manifest["installationId"]
                    / f"{manifest['lastCommittedOperation']}.commit.json"
                )
                _verify_directory(
                    self.layout.receipts_root,
                    private=True,
                    code="RECEIPT_INVALID",
                )
                _verify_directory(
                    receipt_path.parent,
                    private=True,
                    code="RECEIPT_INVALID",
                )
                receipt = _read_owned_json(
                    receipt_path,
                    expected_mode=0o600,
                    code="RECEIPT_INVALID",
                )
                self._validate_receipt_envelope(receipt, manifest=manifest)

                database_binding, database_identity_row, controller_row = (
                    self._validate_database(
                    receipt["databaseBinding"],
                    identity=identity,
                    interface=interface,
                    state_home=state_home,
                    marketplace=marketplace,
                    )
                )
                self._validate_receipt_projections(
                    receipt,
                    manifest=manifest,
                    activation=activation,
                    activation_dir=activation_dir,
                    database_binding=database_binding,
                )
                absence = _refresh_absence_proof(
                    receipt["journalAbsenceTarget"],
                    expected_journal=self.layout.journal_path,
                )
                controller_identity = self._validate_controller(
                    controller_row,
                    receipt=receipt,
                    identity=identity,
                    interface=interface,
                    state_home=state_home,
                    absence=absence,
                    require_live_controller=require_live_controller,
                )
                if controller_identity != receipt["controllerIdentity"]:
                    raise _ProofError(
                        "CONTROLLER_BINDING_MISMATCH",
                        "controller identity differs from commit receipt",
                    )

                manifest_semantic = receipt["manifest"]["value"][
                    "semanticFingerprint"
                ]
                gate_projection = {
                    "manifestSemanticFingerprint": manifest_semantic,
                    "activationReceiptFingerprint": receipt["receiptFingerprint"],
                    "journalAbsenceProof": absence,
                }
                gate_fingerprint = domain_fingerprint(
                    "codex-smart/activation-gate/v2", gate_projection
                )
                activation_gate = dict(gate_projection)
                activation_gate["gateFingerprint"] = gate_fingerprint
                return GatewayDecision(
                    state=GatewayState.READY,
                    reason_code="READY",
                    executable=executable,
                    coordinator=dict(catalog.coordinator),
                    activation_id=activation_id,
                    gate_fingerprint=gate_fingerprint,
                    activation_gate=activation_gate,
                    catalog_path=catalog_path,
                    runtime_binding=GatewayRuntimeBindingV2(
                        activation_id=activation_id,
                        activation_fingerprint=activation["activationFingerprint"],
                        compatibility_fingerprint=interface[
                            "compatibilityFingerprint"
                        ],
                        control_epoch=int(controller_row["control_epoch"]),
                        state_home=state_home,
                        marketplace_path=marketplace,
                        database_path=Path(
                            str(identity["database"]["absolutePath"])
                        ),
                        database_identity_row=dict(database_identity_row),
                        controller_row=dict(controller_row),
                        interface_evidence=dict(interface),
                        activation_identity=dict(identity),
                    ),
                )
        except operation_deadline_v2.OperationDeadlineExceededV2:
            raise
        except _ProofError:
            raise
        except (OSError, sqlite3.Error, EvidenceError, SchemaProjectionError) as exc:
            raise _ProofError("ACTIVATION_PROOF_FAILED", str(exc)) from exc

    def _fallback_records(self) -> tuple[dict[str, object], dict[str, object]]:
        capsule = _read_owned_json(
            self.layout.fallback_path,
            expected_mode=0o600,
            code="FALLBACK_INVALID",
        )
        _exact_keys(
            capsule,
            {"schemaVersion", "sourceLocator", "backupSnapshot", "extensions"},
            "FALLBACK_INVALID",
        )
        if capsule["schemaVersion"] != 2 or capsule["extensions"] != {}:
            raise _ProofError("FALLBACK_INVALID", "fallback capsule is invalid")
        source = capsule["sourceLocator"]
        backup = capsule["backupSnapshot"]
        _validate_source_locator(source, "FALLBACK_INVALID")
        _validate_snapshot_locator(backup, "FALLBACK_INVALID")
        return source, backup

    def _validate_manifest(self, manifest: dict[str, object]) -> None:
        _exact_keys(manifest, _MANIFEST_KEYS, "MANIFEST_INVALID")
        constants = {
            "schemaVersion": 2,
            "release": _RELEASE,
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "databaseSchemaVersion": 2,
        }
        for name, expected in constants.items():
            if manifest[name] != expected:
                raise _ProofError("MANIFEST_INVALID", f"manifest {name} is invalid")
        _identifier(manifest["installationId"], "ins2_", 32, "MANIFEST_INVALID")
        _identifier(
            manifest["lastCommittedOperation"], "op2_", 32, "MANIFEST_INVALID"
        )
        _absolute_path(manifest["stateHome"], "MANIFEST_INVALID")
        _validate_source_locator(manifest["sourceLocator"], "MANIFEST_INVALID")
        _validate_snapshot_locator(manifest["codexSnapshot"], "MANIFEST_INVALID")
        _validate_activation_pointer(manifest["activeActivation"], "MANIFEST_INVALID")
        previous = manifest["previousActivation"]
        if previous is not None:
            _validate_activation_pointer(previous, "MANIFEST_INVALID")
        _sha256(manifest["routingPolicyFingerprint"], "MANIFEST_INVALID")
        _sha256(manifest["bundledCatalogFingerprint"], "MANIFEST_INVALID")
        _validate_artifacts(manifest["artifacts"], self.layout.codex_home)
        _validate_original_backup(manifest["originalBackup"], "MANIFEST_INVALID")
        if type(manifest["extensions"]) is not dict:
            raise _ProofError("MANIFEST_INVALID", "manifest extensions are invalid")

    def _verify_ready_source(self, source: dict[str, object]) -> Path:
        lexical = _absolute_path(source["lexicalPath"], "SOURCE_CHANGED")
        captured = _absolute_path(
            source["resolvedPathAtCapture"], "SOURCE_CHANGED"
        )
        try:
            resolved = lexical.resolve(strict=True)
            if resolved != captured.resolve(strict=True):
                raise _ProofError("SOURCE_CHANGED", "source target changed")
            if _hash_file(resolved) != source["sourceObservedSha256"]:
                raise _ProofError("SOURCE_CHANGED", "source bytes changed")
            if not os.access(resolved, os.X_OK) or resolved == self.wrapper.resolve():
                raise _ProofError("SOURCE_CHANGED", "source is not executable")
            return lexical
        except OSError as exc:
            raise _ProofError("SOURCE_CHANGED", str(exc)) from exc

    def _validate_activation(
        self,
        activation: dict[str, object],
        *,
        activation_dir: Path,
        marketplace: Path,
        manifest: dict[str, object],
    ) -> dict[str, object]:
        _exact_keys(
            activation,
            {"schemaVersion", "activationId", "activationFingerprint", "identity"},
            "ACTIVATION_INVALID",
        )
        if activation["schemaVersion"] != 2:
            raise _ProofError("ACTIVATION_INVALID", "activation version is invalid")
        identity = activation["identity"]
        _exact_keys(
            identity,
            {
                "schemaVersion",
                "generationId",
                "release",
                "pluginId",
                "marketplaceTreeSha256",
                "generationTreeSha256",
                "database",
                "codexSnapshot",
                "compatibilityFingerprint",
                "routingPolicyFingerprint",
                "bundledCatalogFingerprint",
                "minimumGatewayVersion",
            },
            "ACTIVATION_INVALID",
        )
        if (
            identity["schemaVersion"] != 2
            or identity["release"] != _RELEASE
            or identity["pluginId"] != "codex-smart-subagents"
            or identity["minimumGatewayVersion"] != _RELEASE
        ):
            raise _ProofError("ACTIVATION_INVALID", "activation identity is invalid")
        fingerprint = domain_fingerprint("codex-smart/activation/v2", identity)
        activation_id = "act2_" + fingerprint
        if (
            activation["activationFingerprint"] != fingerprint
            or activation["activationId"] != activation_id
            or manifest["activeActivation"]["activationId"] != activation_id
            or manifest["activeActivation"]["activationFingerprint"] != fingerprint
            or activation_dir.name != activation_id
        ):
            raise _ProofError("ACTIVATION_INVALID", "activation fingerprint diverges")
        marketplace_sha = _tree_sha256(marketplace)
        generation_root = marketplace / "plugins" / "codex-smart-subagents"
        generation_sha = _tree_sha256(generation_root)
        if (
            identity["marketplaceTreeSha256"] != marketplace_sha
            or identity["generationTreeSha256"] != generation_sha
            or identity["generationId"] != "gen2_" + generation_sha
            or manifest["activeActivation"]["generationId"]
            != identity["generationId"]
        ):
            raise _ProofError("ACTIVATION_TREE_MISMATCH", "activation tree changed")
        _validate_snapshot_locator(identity["codexSnapshot"], "ACTIVATION_INVALID")
        database = identity["database"]
        _exact_keys(
            database,
            {
                "databaseId",
                "absolutePath",
                "schemaVersion",
                "schemaFingerprint",
                "schemaArtifactSha256",
                "activationBindingNonce",
            },
            "ACTIVATION_INVALID",
        )
        _identifier(database["databaseId"], "db2_", 32, "ACTIVATION_INVALID")
        _absolute_path(database["absolutePath"], "ACTIVATION_INVALID")
        for name in (
            "schemaFingerprint",
            "schemaArtifactSha256",
            "activationBindingNonce",
        ):
            _sha256(database[name], "ACTIVATION_INVALID")
        if (
            database["schemaVersion"] != 2
            or manifest["activeActivation"]["databaseId"] != database["databaseId"]
        ):
            raise _ProofError("ACTIVATION_INVALID", "activation database is invalid")
        return identity

    def _validate_interface(
        self,
        value: object,
        *,
        identity: dict[str, object],
        manifest: dict[str, object],
    ) -> dict[str, object]:
        interface = verify_interface_evidence(value)
        subject = interface["subject"]
        semantic = interface["semantic"]
        if (
            subject["snapshotPath"] != identity["codexSnapshot"]["absolutePath"]
            or subject["snapshotSha256"] != identity["codexSnapshot"]["sha256"]
            or subject["sourceLocator"] != manifest["sourceLocator"]["lexicalPath"]
            or subject["sourceObservedSha256"]
            != manifest["sourceLocator"]["sourceObservedSha256"]
            or interface["compatibilityFingerprint"]
            != identity["compatibilityFingerprint"]
            or semantic["routingPolicyFingerprint"]
            != identity["routingPolicyFingerprint"]
            or semantic["bundledCatalogFingerprint"]
            != identity["bundledCatalogFingerprint"]
            or manifest["routingPolicyFingerprint"]
            != identity["routingPolicyFingerprint"]
            or manifest["bundledCatalogFingerprint"]
            != identity["bundledCatalogFingerprint"]
        ):
            raise _ProofError("INTERFACE_BINDING_MISMATCH", "interface evidence diverges")
        snapshot = _absolute_path(subject["snapshotPath"], "SNAPSHOT_MISMATCH")
        expected_snapshot = (
            self.layout.managed_root
            / "codex-snapshots"
            / subject["snapshotSha256"]
            / "codex"
        )
        if snapshot != expected_snapshot:
            raise _ProofError(
                "SNAPSHOT_MISMATCH",
                "snapshot is outside the managed content-addressed snapshot path",
            )
        _verify_directory(
            expected_snapshot.parent.parent,
            private=True,
            code="SNAPSHOT_MISMATCH",
        )
        _verify_directory(
            expected_snapshot.parent,
            private=True,
            code="SNAPSHOT_MISMATCH",
        )
        info = _verify_private_file(
            snapshot,
            expected_mode=0o500,
            expected_sha256=subject["snapshotSha256"],
            code="SNAPSHOT_MISMATCH",
        )
        observed = {
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "inode": info.st_ino,
            "mtimeNs": str(info.st_mtime_ns),
        }
        if any(subject[name] != expected for name, expected in observed.items()):
            raise _ProofError("SNAPSHOT_MISMATCH", "snapshot subject metadata changed")
        verifier = self.snapshot_verifier or _default_snapshot_verifier
        try:
            verifier(subject)
        except operation_deadline_v2.OperationDeadlineExceededV2:
            raise
        except _ProofError:
            raise
        except Exception as exc:
            raise _ProofError("SNAPSHOT_MISMATCH", str(exc)) from exc
        return interface

    def _validate_receipt_envelope(
        self,
        receipt: dict[str, object],
        *,
        manifest: dict[str, object],
    ) -> None:
        _exact_keys(
            receipt,
            {
                "schemaVersion",
                "receiptKind",
                "installationId",
                "operationId",
                "frozenJournalFingerprint",
                "manifest",
                "manifestDocument",
                "transitionLineage",
                "activation",
                "databaseBinding",
                "journalAbsenceTarget",
                "controllerIdentity",
                "completedStepIds",
                "receiptFingerprint",
                "completedAt",
            },
            "RECEIPT_INVALID",
        )
        if (
            receipt["schemaVersion"] != 2
            or receipt["receiptKind"] != "activation-commit"
            or receipt["installationId"] != manifest["installationId"]
            or receipt["operationId"] != manifest["lastCommittedOperation"]
        ):
            raise _ProofError("RECEIPT_INVALID", "receipt identity diverges")
        for name in (
            "frozenJournalFingerprint",
            "controllerIdentity",
            "receiptFingerprint",
        ):
            _sha256(receipt[name], "RECEIPT_INVALID")
        steps = receipt["completedStepIds"]
        if (
            type(steps) is not list
            or not steps
            or len(steps) != len(set(steps))
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"st2_[0-9a-f]{32}", item) is None
                for item in steps
            )
        ):
            raise _ProofError("RECEIPT_INVALID", "receipt step identities are invalid")
        if type(receipt["completedAt"]) is not str or not receipt["completedAt"]:
            raise _ProofError("RECEIPT_INVALID", "receipt completion time is invalid")
        projection = {
            key: value for key, value in receipt.items() if key != "receiptFingerprint"
        }
        expected = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", projection
        )
        if receipt["receiptFingerprint"] != expected:
            raise _ProofError("RECEIPT_INVALID", "receipt fingerprint mismatches")
        _validate_typed_projection(
            receipt["manifest"],
            schema_id="manifest-v2",
            domain="codex-smart/journal-state/v2",
            code="RECEIPT_INVALID",
        )
        _validate_typed_projection(
            receipt["activation"],
            schema_id="activation-v2",
            domain="codex-smart/journal-state/v2",
            code="RECEIPT_INVALID",
        )
        _validate_typed_projection(
            receipt["databaseBinding"],
            schema_id="database-binding-v2",
            domain="codex-smart/database-binding/v2",
            code="RECEIPT_INVALID",
        )
        _validate_absence_projection(receipt["journalAbsenceTarget"])

    def _validate_database(
        self,
        claimed_binding: dict[str, object],
        *,
        identity: dict[str, object],
        interface: dict[str, object],
        state_home: Path,
        marketplace: Path,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        claimed_binding_value = claimed_binding.get("value")
        if type(claimed_binding_value) is not dict:
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH",
                "database binding value is invalid",
            )
        captured_device = _safe_integer(
            claimed_binding_value.get("device"),
            "DATABASE_BINDING_MISMATCH",
        )
        database_identity = identity["database"]
        database_path = _absolute_path(
            database_identity["absolutePath"], "DATABASE_BINDING_MISMATCH"
        )
        expected_database_path = (
            state_home
            / "databases"
            / database_identity["databaseId"]
            / "smart-subagents.sqlite3"
        )
        if database_path != expected_database_path:
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH",
                "database does not use the canonical database path",
            )
        _verify_directory(
            expected_database_path.parent.parent,
            private=True,
            code="DATABASE_BINDING_MISMATCH",
        )
        _verify_directory(
            expected_database_path.parent,
            private=True,
            code="DATABASE_BINDING_MISMATCH",
        )
        before = os.lstat(database_path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH", "database file metadata is invalid"
            )
        operation_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )
        sqlite_timeout = 1.0
        if operation_deadline is not None:
            operation_deadline.checkpoint()
            sqlite_timeout = operation_deadline.bounded_timeout_seconds(
                local_cap_seconds=sqlite_timeout
            )
        connection = sqlite3.connect(
            f"file:{quote(str(database_path))}?mode=ro",
            uri=True,
            timeout=sqlite_timeout,
        )
        connection.row_factory = sqlite3.Row
        if operation_deadline is not None:
            busy_timeout_ms = operation_deadline.bounded_timeout_ms(
                local_cap_ms=1000
            )
            connection.execute(f"pragma busy_timeout={busy_timeout_ms}")
            connection.set_progress_handler(
                lambda: int(
                    operation_deadline.remaining_nanoseconds() <= 0
                ),
                1000,
            )
        try:
            connection.execute("pragma query_only=on")
            if int(connection.execute("pragma application_id").fetchone()[0]) != APPLICATION_ID:
                raise _ProofError(
                    "DATABASE_BINDING_MISMATCH", "database application id differs"
                )
            if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
                raise _ProofError(
                    "DATABASE_BINDING_MISMATCH", "database user version differs"
                )
            check = connection.execute("pragma quick_check").fetchall()
            if [tuple(row) for row in check] != [("ok",)]:
                raise _ProofError(
                    "DATABASE_BINDING_MISMATCH", "database quick check failed"
                )
            if connection.execute("pragma foreign_key_check").fetchone() is not None:
                raise _ProofError(
                    "DATABASE_BINDING_MISMATCH", "database foreign key check failed"
                )
            schema = database_schema_fingerprint(connection, version=2)
            rows = connection.execute("select * from database_identity").fetchall()
            controllers = connection.execute("select * from controller_state").fetchall()
            if len(rows) != 1 or len(controllers) != 1:
                raise _ProofError(
                    "DATABASE_BINDING_MISMATCH", "database singleton rows differ"
                )
            row = dict(rows[0])
            controller = dict(controllers[0])
        except sqlite3.OperationalError:
            if operation_deadline is not None:
                operation_deadline.checkpoint()
            raise
        finally:
            if operation_deadline is not None:
                connection.set_progress_handler(None, 0)
            connection.close()
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        after = os.lstat(database_path)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH", "database file changed during proof"
            )

        expected_row = {
            "database_id": database_identity["databaseId"],
            "schema_version": 2,
            "schema_fingerprint": database_identity["schemaFingerprint"],
            "schema_artifact_sha256": database_identity["schemaArtifactSha256"],
            "activation_binding_nonce": database_identity["activationBindingNonce"],
            "activation_id": "act2_" + domain_fingerprint(
                "codex-smart/activation/v2", identity
            ),
            "activation_fingerprint": domain_fingerprint(
                "codex-smart/activation/v2", identity
            ),
        }
        if any(row[name] != value for name, value in expected_row.items()):
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH", "database identity row diverges"
            )
        installed_schema = (
            marketplace
            / "plugins/codex-smart-subagents/src/codex_smart_subagents/schema/state-v2.sql"
        )
        if (
            schema.fingerprint != database_identity["schemaFingerprint"]
            or _hash_file(installed_schema)
            != database_identity["schemaArtifactSha256"]
        ):
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH", "database schema proof diverges"
            )
        identity_value = {
            "databaseId": row["database_id"],
            "activationBindingNonce": row["activation_binding_nonce"],
            "activationId": row["activation_id"],
            "activationFingerprint": row["activation_fingerprint"],
        }
        identity_fingerprint = domain_fingerprint(
            "codex-smart/database-identity/v2", identity_value
        )
        binding_value = {
            "path": str(database_path),
            "device": captured_device,
            "inode": after.st_ino,
            "ownerUid": after.st_uid,
            "ownerGid": after.st_gid,
            "mode": f"0{stat.S_IMODE(after.st_mode):03o}",
            "linkCount": after.st_nlink,
            "databaseId": row["database_id"],
            "databaseIdentity": identity_value,
            "databaseIdentityFingerprint": identity_fingerprint,
            "activationIdentity": {
                "activationId": row["activation_id"],
                "activationFingerprint": row["activation_fingerprint"],
            },
            "databaseVersion": _RELEASE,
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": row["schema_fingerprint"],
            "schemaArtifactSha256": row["schema_artifact_sha256"],
        }
        binding = {
            "schemaId": "database-binding-v2",
            "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
            "value": binding_value,
        }
        binding["valueFingerprint"] = domain_fingerprint(
            "codex-smart/database-binding/v2", binding
        )
        if binding != claimed_binding:
            raise _ProofError(
                "DATABASE_BINDING_MISMATCH", "live database differs from receipt"
            )
        if (
            controller["compatibility_fingerprint"]
            != interface["compatibilityFingerprint"]
        ):
            raise _ProofError(
                "CONTROLLER_BINDING_MISMATCH", "controller compatibility differs"
            )
        return binding, row, controller

    def _validate_receipt_projections(
        self,
        receipt: dict[str, object],
        *,
        manifest: dict[str, object],
        activation: dict[str, object],
        activation_dir: Path,
        database_binding: dict[str, object],
    ) -> None:
        active = manifest["activeActivation"]
        source_locator = manifest["sourceLocator"]
        claimed_manifest_value = receipt["manifest"].get("value")
        if type(claimed_manifest_value) is not dict:
            raise _ProofError(
                "MANIFEST_BINDING_MISMATCH",
                "receipt manifest projection is invalid",
            )
        claimed_manifest_file = claimed_manifest_value.get("file")
        if type(claimed_manifest_file) is not dict:
            raise _ProofError(
                "MANIFEST_BINDING_MISMATCH",
                "receipt manifest file projection is invalid",
            )
        manifest_file = _file_projection(self.layout.manifest_path)
        manifest_file["device"] = _safe_integer(
            claimed_manifest_file.get("device"),
            "MANIFEST_BINDING_MISMATCH",
        )
        manifest_semantic = _sha256(
            claimed_manifest_value.get("semanticFingerprint"),
            "MANIFEST_BINDING_MISMATCH",
        )
        actual_manifest_semantic = domain_fingerprint(
            "codex-smart/manifest-semantic/v2",
            {
                key: value
                for key, value in manifest.items()
                if key != "extensions"
            },
        )
        if manifest_semantic != actual_manifest_semantic:
            raise _ProofError(
                "MANIFEST_BINDING_MISMATCH",
                "receipt semantic fingerprint differs from the live manifest",
            )
        manifest_value = {
            "file": manifest_file,
            "schemaVersion": 2,
            "installationId": manifest["installationId"],
            "release": _RELEASE,
            "pluginId": manifest["pluginId"],
            "stateHome": manifest["stateHome"],
            "activeActivationId": active["activationId"],
            "previousActivationId": (
                None
                if manifest["previousActivation"] is None
                else manifest["previousActivation"]["activationId"]
            ),
            "lastCommittedOperation": manifest["lastCommittedOperation"],
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(source_locator)
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes(manifest["artifacts"])
            ).hexdigest(),
            "semanticFingerprint": manifest_semantic,
        }
        expected_manifest = _journal_projection("manifest-v2", manifest_value)
        database_fingerprint = database_binding["value"][
            "databaseIdentityFingerprint"
        ]
        identity = activation["identity"]
        claimed_activation_value = receipt["activation"].get("value")
        if type(claimed_activation_value) is not dict:
            raise _ProofError(
                "ACTIVATION_BINDING_MISMATCH",
                "receipt activation projection is invalid",
            )
        claimed_directory = claimed_activation_value.get("directory")
        claimed_activation_file = claimed_activation_value.get("activationFile")
        if type(claimed_directory) is not dict or type(claimed_activation_file) is not dict:
            raise _ProofError(
                "ACTIVATION_BINDING_MISMATCH",
                "receipt activation filesystem projection is invalid",
            )
        activation_directory = _tree_projection(activation_dir)
        activation_directory["device"] = _safe_integer(
            claimed_directory.get("device"),
            "ACTIVATION_BINDING_MISMATCH",
        )
        activation_file = _file_projection(activation_dir / "activation.json")
        activation_file["device"] = _safe_integer(
            claimed_activation_file.get("device"),
            "ACTIVATION_BINDING_MISMATCH",
        )
        activation_value = {
            "directory": activation_directory,
            "activationFile": activation_file,
            "activationId": activation["activationId"],
            "activationFingerprint": activation["activationFingerprint"],
            "generationId": identity["generationId"],
            "release": identity["release"],
            "databaseId": identity["database"]["databaseId"],
            "databaseIdentityFingerprint": database_fingerprint,
            "marketplaceTreeSha256": identity["marketplaceTreeSha256"],
            "generationTreeSha256": identity["generationTreeSha256"],
        }
        expected_activation = _journal_projection(
            "activation-v2", activation_value
        )
        if receipt["manifest"] != expected_manifest:
            raise _ProofError(
                "MANIFEST_BINDING_MISMATCH", "receipt manifest projection differs"
            )
        if receipt["activation"] != expected_activation:
            raise _ProofError(
                "ACTIVATION_BINDING_MISMATCH", "receipt activation projection differs"
            )

    def _validate_controller(
        self,
        row: dict[str, object],
        *,
        receipt: dict[str, object],
        identity: dict[str, object],
        interface: dict[str, object],
        state_home: Path,
        absence: dict[str, object],
        require_live_controller: bool,
    ) -> str:
        del absence
        codex_home_hash = hashlib.sha256(
            str(self.layout.codex_home.resolve()).encode("utf-8")
        ).hexdigest()
        controller_projection = {
            "protocolVersion": 2,
            "release": _RELEASE,
            "namespace": _NAMESPACE,
            "codexHomeHash": codex_home_hash,
            "stateHome": str(state_home),
            "activationFingerprint": receipt["activation"]["value"][
                "activationFingerprint"
            ],
            "compatibilityFingerprint": interface["compatibilityFingerprint"],
            "routingPolicyFingerprint": identity["routingPolicyFingerprint"],
            "bundledCatalogFingerprint": identity["bundledCatalogFingerprint"],
            "databaseId": identity["database"]["databaseId"],
            "databaseSchemaVersion": 2,
        }
        expected_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2", controller_projection
        )
        expected_row = {
            "protocol_version": 2,
            "release": _RELEASE,
            "controller_identity": expected_identity,
            "database_id": identity["database"]["databaseId"],
            "state": "ACCEPTING",
            "maintenance_mode": "NONE",
            "reason_code": "NONE",
            "operation_id": None,
            "activation_id": receipt["activation"]["value"]["activationId"],
            "activation_fingerprint": receipt["activation"]["value"][
                "activationFingerprint"
            ],
            "compatibility_fingerprint": interface["compatibilityFingerprint"],
            "routing_policy_fingerprint": identity["routingPolicyFingerprint"],
            "bundled_catalog_fingerprint": identity["bundledCatalogFingerprint"],
            "lock_held": 1,
            "accepting_new_routes": 1,
        }
        if any(row[name] != value for name, value in expected_row.items()):
            raise _ProofError(
                "CONTROLLER_BINDING_MISMATCH", "controller database row diverges"
            )
        if not require_live_controller:
            return expected_identity
        socket_path = _absolute_path(
            row["socket_path"], "CONTROLLER_BINDING_MISMATCH"
        )
        socket_info = os.lstat(socket_path)
        socket_expected = (
            row["socket_device"],
            row["socket_inode"],
            row["socket_owner_uid"],
            row["socket_owner_gid"],
            row["socket_mode"],
        )
        socket_observed = (
            socket_info.st_dev,
            socket_info.st_ino,
            socket_info.st_uid,
            socket_info.st_gid,
            f"0{stat.S_IMODE(socket_info.st_mode):03o}",
        )
        if not stat.S_ISSOCK(socket_info.st_mode) or socket_expected != socket_observed:
            raise _ProofError(
                "CONTROLLER_BINDING_MISMATCH", "controller socket identity diverges"
            )
        request_projection = {
            "messageType": "request",
            "protocolVersion": 2,
            "release": _RELEASE,
            "codexHomeHash": codex_home_hash,
            "shellSessionId": "gateway-v2",
            "controllerIdentity": None,
            "instanceId": None,
            "controllerStartId": None,
            "commandId": None,
            "expectedControlEpoch": None,
            "operationId": None,
            "method": "health",
            "params": {},
        }
        request = dict(request_projection)
        request["requestFingerprint"] = domain_fingerprint(
            "codex-smart/controller-request/v2", request_projection
        )
        request["extensions"] = {}
        probe = self.controller_probe or _unix_controller_probe
        try:
            response = probe(socket_path, request)
        except operation_deadline_v2.OperationDeadlineExceededV2:
            raise
        except _ProofError:
            raise
        except Exception as exc:
            raise _ProofError("CONTROLLER_UNAVAILABLE", str(exc)) from exc
        _validate_health_response(response, request=request)
        if response["controlEpoch"] != row["control_epoch"]:
            raise _ProofError(
                "CONTROLLER_BINDING_MISMATCH",
                "health control epoch differs from the database",
            )
        payload = response["payload"]
        health_expected = {
            "namespace": _NAMESPACE,
            "controllerIdentity": row["controller_identity"],
            "instanceId": row["instance_id"],
            "controllerStartId": row["controller_start_id"],
            "pid": row["controller_pid"],
            "processStartMarker": row["controller_process_start_marker"],
            "processGroupId": row["controller_process_group_id"],
            "state": "ACCEPTING",
            "maintenanceMode": None,
            "operationId": None,
            "acceptingNewRoutes": True,
            "quiescent": bool(row["quiescent"]),
            "activationFingerprint": row["activation_fingerprint"],
            "compatibilityFingerprint": row["compatibility_fingerprint"],
            "routingPolicyFingerprint": row["routing_policy_fingerprint"],
            "bundledCatalogFingerprint": row["bundled_catalog_fingerprint"],
            "databaseId": row["database_id"],
            "databaseSchemaVersion": 2,
        }
        for name, expected in health_expected.items():
            if payload[name] != expected:
                raise _ProofError(
                    "CONTROLLER_BINDING_MISMATCH", f"health {name} diverges"
                )
        return expected_identity

    def _resolve_fallback(self) -> Path:
        try:
            _verify_directory(
                self.layout.codex_home,
                private=False,
                code="FALLBACK_INVALID",
            )
            _verify_directory(
                self.layout.manifest_root,
                private=True,
                code="FALLBACK_INVALID",
            )
            capsule = _read_owned_json(
                self.layout.fallback_path,
                expected_mode=0o600,
                code="FALLBACK_INVALID",
            )
            _exact_keys(
                capsule,
                {
                    "schemaVersion",
                    "sourceLocator",
                    "backupSnapshot",
                    "extensions",
                },
                "FALLBACK_INVALID",
            )
            if capsule["schemaVersion"] != 2 or capsule["extensions"] != {}:
                raise _ProofError(
                    "FALLBACK_INVALID",
                    "fallback capsule version or extensions are invalid",
                )
            source = capsule["sourceLocator"]
            backup = capsule["backupSnapshot"]
            _exact_keys(
                source,
                {
                    "lexicalPath",
                    "resolvedPathAtCapture",
                    "argv0Policy",
                    "sourceObservedSha256",
                },
                "FALLBACK_INVALID",
            )
            _exact_keys(
                backup,
                {"absolutePath", "sha256"},
                "FALLBACK_INVALID",
            )
            if source["argv0Policy"] != "lexical":
                raise _ProofError(
                    "FALLBACK_INVALID",
                    "fallback argv0 policy is invalid",
                )
            lexical = _absolute_path(source["lexicalPath"], "FALLBACK_INVALID")
            _absolute_path(source["resolvedPathAtCapture"], "FALLBACK_INVALID")
            _sha256(source["sourceObservedSha256"], "FALLBACK_INVALID")
            backup_path = _absolute_path(backup["absolutePath"], "FALLBACK_INVALID")
            backup_sha = _sha256(backup["sha256"], "FALLBACK_INVALID")
        except (OSError, _ProofError, ValueError) as exc:
            raise GatewayUnavailable(
                "FALLBACK_UNAVAILABLE",
                f"cannot read independent fallback capsule: {exc}",
            ) from exc

        selected = _ordinary_source(lexical, self.wrapper)
        if selected is not None:
            return selected
        try:
            _verify_private_file(
                backup_path,
                expected_mode=0o500,
                expected_sha256=backup_sha,
                code="FALLBACK_SNAPSHOT_INVALID",
            )
            if backup_path.resolve() == self.wrapper.resolve():
                raise _ProofError(
                    "FALLBACK_SNAPSHOT_INVALID",
                    "fallback snapshot points to the gateway",
                )
            return backup_path
        except (OSError, _ProofError) as exc:
            raise GatewayUnavailable(
                "FALLBACK_UNAVAILABLE",
                f"ordinary source and fallback snapshot are unavailable: {exc}",
            ) from exc


def _normalize_failure_code(code: object, default: str) -> str:
    if (
        not isinstance(code, str)
        or not code
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
            for character in code
        )
    ):
        return default
    return code


def _managed_failure_code(error: Exception, default: str) -> str:
    return _normalize_failure_code(getattr(error, "code", default), default)


def run_permanent_gateway(
    arguments: Sequence[str],
    *,
    resolver: GatewayResolver,
    wrapper: Path,
    environment: Mapping[str, str] | None = None,
    managed_required: bool = False,
    execve=os.execve,
) -> int:
    """Resolve once and replace the permanent wrapper with selected Codex."""

    source_environment = dict(os.environ if environment is None else environment)
    parsed_invocation = parse_managed_invocation(arguments)
    invocation = parsed_invocation.decision
    try:
        decision = resolver.resolve()
    except Exception as exc:
        if managed_required and invocation.adaptive:
            raise ManagedLaunchUnavailable(
                _managed_failure_code(exc, "MANAGED_RESOLUTION_FAILED"),
                "managed activation resolution failed",
            ) from exc
        raise
    executable = decision.executable
    if executable.resolve() == wrapper.expanduser().resolve():
        raise RuntimeError("LAUNCHER_RECURSION: selected Codex is the gateway")

    if decision.state is GatewayState.ORDINARY or not invocation.adaptive:
        if managed_required and invocation.adaptive:
            raise ManagedLaunchUnavailable(
                _normalize_failure_code(
                    decision.reason_code,
                    "MANAGED_ACTIVATION_UNAVAILABLE",
                ),
                "managed activation is unavailable",
            )
        ordinary_environment = clean_ordinary_environment(source_environment)
        execve(
            str(executable),
            [str(executable), *arguments],
            ordinary_environment,
        )
        raise AssertionError("execve unexpectedly returned")

    try:
        require_bundled_mcp_manifest_v2(Path(__file__).resolve().parents[2])
        policy_proof = build_user_mcp_policy_proof_v2(
            Path(source_environment.get("CODEX_HOME", ""))
        )
    except Exception as exc:
        if managed_required:
            raise ManagedLaunchUnavailable(
                _managed_failure_code(
                    exc,
                    "MANAGED_POLICY_PROOF_UNAVAILABLE",
                ),
                "managed policy proof is unavailable",
            ) from exc
        ordinary_environment = clean_ordinary_environment(source_environment)
        execve(
            str(executable),
            [str(executable), *arguments],
            ordinary_environment,
        )
        raise AssertionError("execve unexpectedly returned")

    adaptive_environment = clean_ordinary_environment(source_environment)
    adaptive_environment["CODEX_ADAPTIVE_SESSION_ID"] = (
        "cas2_" + secrets.token_urlsafe(32)
    )
    adaptive_environment["CODEX_SMART_LAUNCHER_ACTIVE"] = "1"
    adaptive_environment[MCP_SESSION_NONCE_ENV_V2] = (
        "mcpn2_" + secrets.token_hex(32)
    )
    adaptive_environment[USER_MCP_POLICY_PROOF_ENV_V2] = policy_proof
    adaptive_environment["CODEX_SMART_GATEWAY_PATH"] = str(
        wrapper.expanduser().absolute()
    )
    adaptive_environment["CODEX_SMART_ACTIVATION_ID"] = str(
        decision.activation_id
    )
    adaptive_environment["CODEX_SMART_GATE_FINGERPRINT"] = str(
        decision.gate_fingerprint
    )
    adaptive_environment["CODEX_SMART_ACTIVATION_GATE"] = canonical_json_bytes(
        dict(decision.activation_gate or {})
    ).decode("utf-8")
    adaptive_environment["CODEX_ADAPTIVE_CATALOG"] = str(
        decision.catalog_path
    )
    if decision.runtime_binding is not None:
        adaptive_environment["CODEX_SMART_STATE_HOME"] = str(
            decision.runtime_binding.state_home
        )
    separator_index = parsed_invocation.separator_index
    root_end = len(arguments) if separator_index is None else separator_index
    rewritten_root = list(arguments[:root_end])
    if not parsed_invocation.coordinator_control:
        rewritten_root = apply_coordinator_defaults(
            rewritten_root,
            dict(decision.coordinator or {}),
        )
    # Codex 0.145.0 откладывает MCP-команды, но координатор Terra не получает
    # средство их поиска. Оставляем напрямую видимым только проверенное
    # пространство четырёх команд управляемого маршрута.
    rewritten_root.extend(_ADAPTIVE_DIRECT_TOOL_ARGUMENTS)
    # Эти параметры намеренно завершают argv: пользовательский ``--enable``
    # не должен открыть параллельный путь субагентов мимо доказуемого
    # контроллера выбранной пары модели и уровня рассуждения.
    rewritten_root.extend(_ADAPTIVE_DISABLED_FEATURE_ARGUMENTS)
    rewritten = [
        *rewritten_root,
        *arguments[root_end:],
    ]
    execve(
        str(executable),
        [str(executable), *rewritten],
        adaptive_environment,
    )
    raise AssertionError("execve unexpectedly returned")


def _read_owned_json(
    path: Path,
    *,
    expected_mode: int,
    code: str,
) -> dict[str, object]:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != expected_mode
        or before.st_nlink != 1
        or before.st_size > _MAX_JSON_BYTES
    ):
        raise _ProofError(code, f"unsafe JSON file metadata: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _ProofError(code, f"JSON file changed before open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, _MAX_JSON_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_JSON_BYTES:
                raise _ProofError(code, f"JSON file exceeds size limit: {path}")
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise _ProofError(code, f"JSON file changed during read: {path}")
    finally:
        os.close(descriptor)
    try:
        raw = b"".join(chunks)
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: (_raise_json("floating values are forbidden")),
            parse_constant=lambda _value: (_raise_json("non-finite values are forbidden")),
        )
        canonical_json_bytes(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        CanonicalJsonError,
        ValueError,
    ) as exc:
        raise _ProofError(code, f"invalid strict JSON: {path}: {exc}") from exc
    if type(value) is not dict:
        raise _ProofError(code, f"JSON root must be an object: {path}")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _raise_json(message: str):
    raise ValueError(message)


def _exact_keys(value, expected: set[str], code: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise _ProofError(code, "object fields do not match the closed contract")


def _absolute_path(value, code: str) -> Path:
    if type(value) is not str or not value or "\0" in value or len(value.encode()) > 4096:
        raise _ProofError(code, "path is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise _ProofError(code, "path must be absolute")
    return path


def _sha256(value, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _ProofError(code, "SHA-256 value is invalid")
    return value


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _verify_private_file(
    path: Path,
    *,
    expected_mode: int,
    expected_sha256: str,
    code: str,
) -> os.stat_result:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != expected_mode
        or before.st_nlink != 1
    ):
        raise _ProofError(code, f"unsafe private file metadata: {path}")
    actual_sha = _hash_file(path)
    after = os.lstat(path)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or actual_sha != expected_sha256:
        raise _ProofError(code, f"private file content changed or mismatched: {path}")
    return after


def _ordinary_source(path: Path, wrapper: Path) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not os.access(resolved, os.X_OK)
            or resolved == wrapper.resolve()
        ):
            return None
        return path
    except (OSError, RuntimeError):
        return None


@contextmanager
def _shared_installation_lock(path: Path):
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise _ProofError("LOCK_INVALID", "installation lock is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _ProofError("LOCK_BUSY", "installation lock is exclusive") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _verify_directory(path: Path, *, private: bool, code: str) -> os.stat_result:
    info = os.lstat(path)
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or (private and mode != 0o700)
        or (not private and mode & 0o022)
    ):
        raise _ProofError(code, f"directory metadata is invalid: {path}")
    return info


def _path_exists_no_follow(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def _identifier(value, prefix: str, hexadecimal: int, code: str) -> str:
    if (
        type(value) is not str
        or not value.startswith(prefix)
        or len(value) != len(prefix) + hexadecimal
        or re.fullmatch(r"[0-9a-f]+", value[len(prefix) :]) is None
    ):
        raise _ProofError(code, f"identifier with prefix {prefix} is invalid")
    return value


def _validate_source_locator(value, code: str) -> None:
    _exact_keys(
        value,
        {
            "lexicalPath",
            "resolvedPathAtCapture",
            "argv0Policy",
            "sourceObservedSha256",
        },
        code,
    )
    _absolute_path(value["lexicalPath"], code)
    _absolute_path(value["resolvedPathAtCapture"], code)
    _sha256(value["sourceObservedSha256"], code)
    if value["argv0Policy"] != "lexical":
        raise _ProofError(code, "source argv0 policy is invalid")


def _validate_snapshot_locator(value, code: str) -> None:
    _exact_keys(value, {"absolutePath", "sha256"}, code)
    _absolute_path(value["absolutePath"], code)
    _sha256(value["sha256"], code)


def _validate_activation_pointer(value, code: str) -> None:
    _exact_keys(
        value,
        {
            "activationId",
            "activationFingerprint",
            "symlinkTarget",
            "generationId",
            "databaseId",
        },
        code,
    )
    _identifier(value["activationId"], "act2_", 64, code)
    _sha256(value["activationFingerprint"], code)
    _identifier(value["generationId"], "gen2_", 64, code)
    _identifier(value["databaseId"], "db2_", 32, code)
    target = value["symlinkTarget"]
    if (
        type(target) is not str
        or target.startswith("/")
        or ".." in Path(target).parts
        or "\0" in target
    ):
        raise _ProofError(code, "activation symlink target is invalid")


def _validate_artifacts(value, codex_home: Path) -> None:
    if type(value) is not list or len(value) > 4096:
        raise _ProofError("MANIFEST_INVALID", "manifest artifacts are invalid")
    seen: set[str] = set()
    for item in value:
        if type(item) is not dict or item.get("type") not in {
            "regular",
            "directory",
            "symlink",
            "absent",
        }:
            raise _ProofError("MANIFEST_INVALID", "artifact variant is invalid")
        kind = item["type"]
        expected = {
            "regular": {"type", "relativePath", "mode", "size", "sha256"},
            "directory": {"type", "relativePath", "mode", "treeSha256"},
            "symlink": {"type", "relativePath", "target"},
            "absent": {"type", "relativePath", "parentRelativePath", "name"},
        }[kind]
        _exact_keys(item, expected, "MANIFEST_INVALID")
        relative = item["relativePath"]
        if (
            type(relative) is not str
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in seen
        ):
            raise _ProofError("MANIFEST_INVALID", "artifact path is invalid")
        seen.add(relative)
        path = codex_home / relative
        if kind == "regular":
            _sha256(item["sha256"], "MANIFEST_INVALID")
            expected_mode = _mode_integer(item["mode"], "MANIFEST_INVALID")
            info = _verify_private_file(
                path,
                expected_mode=expected_mode,
                expected_sha256=item["sha256"],
                code="MANIFEST_ARTIFACT_MISMATCH",
            )
            if info.st_size != item["size"]:
                raise _ProofError(
                    "MANIFEST_ARTIFACT_MISMATCH", "artifact size differs"
                )
        elif kind == "directory":
            _sha256(item["treeSha256"], "MANIFEST_INVALID")
            info = _verify_directory(path, private=True, code="MANIFEST_ARTIFACT_MISMATCH")
            if stat.S_IMODE(info.st_mode) != _mode_integer(
                item["mode"], "MANIFEST_INVALID"
            ) or _tree_sha256(path) != item["treeSha256"]:
                raise _ProofError(
                    "MANIFEST_ARTIFACT_MISMATCH", "artifact tree differs"
                )
        elif kind == "symlink":
            info = os.lstat(path)
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != item["target"]:
                raise _ProofError(
                    "MANIFEST_ARTIFACT_MISMATCH", "artifact symlink differs"
                )
        else:
            if _path_exists_no_follow(path):
                raise _ProofError(
                    "MANIFEST_ARTIFACT_MISMATCH", "absent artifact exists"
                )


def _validate_original_backup(value, code: str) -> None:
    if type(value) is not dict or value.get("type") not in {
        "regular",
        "directory",
        "symlink",
        "absent",
    }:
        raise _ProofError(code, "original backup variant is invalid")
    kind = value["type"]
    keys = {
        "regular": {
            "type",
            "path",
            "device",
            "inode",
            "ownerUid",
            "ownerGid",
            "mode",
            "linkCount",
            "size",
            "sha256",
        },
        "directory": {
            "type",
            "path",
            "device",
            "inode",
            "ownerUid",
            "ownerGid",
            "mode",
            "entryCount",
            "treeSha256",
        },
        "symlink": {
            "type",
            "path",
            "parentDevice",
            "parentInode",
            "ownerUid",
            "ownerGid",
            "mode",
            "target",
            "targetFingerprint",
        },
        "absent": {"type", "path", "parentPath", "name"},
    }[kind]
    _exact_keys(value, keys, code)
    path = _absolute_path(value["path"], code)

    if kind == "absent":
        parent = _absolute_path(value["parentPath"], code)
        if (
            type(value["name"]) is not str
            or not value["name"]
            or "/" in value["name"]
            or path.parent != parent
            or path.name != value["name"]
            or _path_exists_no_follow(path)
        ):
            raise _ProofError(code, "original backup absence path diverges")
        _verify_directory(parent, private=False, code=code)
        return

    info = os.lstat(path)
    numeric_names = {
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
    }
    if kind == "regular":
        numeric_names.update({"linkCount", "size"})
    elif kind == "directory":
        numeric_names.add("entryCount")
    else:
        numeric_names = {
            "parentDevice",
            "parentInode",
            "ownerUid",
            "ownerGid",
        }
    for name in numeric_names:
        _safe_integer(value[name], code)
    expected_mode = _mode_integer(value["mode"], code)

    if kind == "regular":
        _sha256(value["sha256"], code)
        observed = (
            info.st_ino,
            info.st_uid,
            info.st_gid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
            info.st_size,
            _hash_file(path),
        )
        expected = (
            value["inode"],
            value["ownerUid"],
            value["ownerGid"],
            expected_mode,
            value["linkCount"],
            value["size"],
            value["sha256"],
        )
        if not stat.S_ISREG(info.st_mode) or observed != expected:
            raise _ProofError(code, "regular original backup diverges")
        return

    if kind == "directory":
        _sha256(value["treeSha256"], code)
        observed = (
            info.st_ino,
            info.st_uid,
            info.st_gid,
            stat.S_IMODE(info.st_mode),
            sum(1 for item in path.rglob("*") if not item.is_symlink()),
            _tree_sha256(path),
        )
        expected = (
            value["inode"],
            value["ownerUid"],
            value["ownerGid"],
            expected_mode,
            value["entryCount"],
            value["treeSha256"],
        )
        if not stat.S_ISDIR(info.st_mode) or observed != expected:
            raise _ProofError(code, "directory original backup diverges")
        return

    target = value["target"]
    _sha256(value["targetFingerprint"], code)
    if (
        type(target) is not str
        or not target
        or len(target.encode("utf-8")) > 4096
        or Path(target).is_absolute()
    ):
        raise _ProofError(code, "original backup symlink target is invalid")
    parent_info = os.lstat(path.parent)
    observed = (
        parent_info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        os.readlink(path) if stat.S_ISLNK(info.st_mode) else None,
    )
    expected = (
        value["parentInode"],
        value["ownerUid"],
        value["ownerGid"],
        expected_mode,
        target,
    )
    if not stat.S_ISLNK(info.st_mode) or observed != expected:
        raise _ProofError(code, "symlink original backup diverges")


def _safe_integer(value, code: str) -> int:
    if type(value) is not int or not 0 <= value <= 9_007_199_254_740_991:
        raise _ProofError(code, "safe integer is invalid")
    return value


def _mode_integer(value, code: str) -> int:
    if type(value) is int and 0 <= value <= 0o7777:
        return value
    if type(value) is str and re.fullmatch(r"0[0-7]{3}", value):
        return int(value, 8)
    raise _ProofError(code, "file mode is invalid")


def _tree_sha256(root: Path) -> str:
    _verify_directory(root, private=True, code="ACTIVATION_TREE_MISMATCH")
    entries: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        children = sorted(
            directory.iterdir(),
            key=lambda path: path.name.encode("utf-8"),
            reverse=True,
        )
        for child in children:
            info = os.lstat(child)
            relative = child.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": stat.S_IMODE(info.st_mode),
                        "target": os.readlink(child),
                    }
                )
            elif stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _ProofError(
                        "ACTIVATION_TREE_MISMATCH", "tree directory is not private"
                    )
                entries.append(
                    {
                        "path": relative,
                        "type": "directory",
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise _ProofError(
                        "ACTIVATION_TREE_MISMATCH", "tree file metadata is unsafe"
                    )
                entries.append(
                    {
                        "path": relative,
                        "type": "regular",
                        "mode": stat.S_IMODE(info.st_mode),
                        "size": info.st_size,
                        "sha256": _hash_file(child),
                    }
                )
            else:
                raise _ProofError(
                    "ACTIVATION_TREE_MISMATCH", "unsupported object in activation tree"
                )
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def _file_projection(path: Path) -> dict[str, object]:
    info = os.lstat(path)
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _hash_file(path),
    }


def _tree_projection(path: Path) -> dict[str, object]:
    info = os.lstat(path)
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "entryCount": sum(1 for item in path.rglob("*") if not item.is_symlink()),
        "treeSha256": _tree_sha256(path),
    }


def _journal_projection(
    schema_id: str, value: dict[str, object]
) -> dict[str, object]:
    projection = {
        "schemaId": schema_id,
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    projection["valueFingerprint"] = domain_fingerprint(
        "codex-smart/journal-state/v2", projection
    )
    return projection


def _validate_typed_projection(value, *, schema_id: str, domain: str, code: str) -> None:
    _exact_keys(
        value,
        {"schemaId", "schemaSha256", "value", "valueFingerprint"},
        code,
    )
    if value["schemaId"] != schema_id or value["schemaSha256"] != _LIFECYCLE_SCHEMA_SHA256:
        raise _ProofError(code, "typed projection identity differs")
    _sha256(value["valueFingerprint"], code)
    projection = {key: value[key] for key in ("schemaId", "schemaSha256", "value")}
    if value["valueFingerprint"] != domain_fingerprint(domain, projection):
        raise _ProofError(code, "typed projection fingerprint differs")


def _validate_absence_projection(value) -> None:
    _validate_typed_projection(
        value,
        schema_id="absence-proof-v2",
        domain="codex-smart/absence-proof-projection/v2",
        code="ABSENCE_PROOF_MISMATCH",
    )
    proof = value["value"]
    _exact_keys(
        proof,
        {
            "proofId",
            "installationId",
            "operationId",
            "entries",
            "directorySyncCompleted",
            "proofFingerprint",
        },
        "ABSENCE_PROOF_MISMATCH",
    )
    _identifier(proof["proofId"], "ap2_", 32, "ABSENCE_PROOF_MISMATCH")
    _identifier(
        proof["installationId"], "ins2_", 32, "ABSENCE_PROOF_MISMATCH"
    )
    _identifier(proof["operationId"], "op2_", 32, "ABSENCE_PROOF_MISMATCH")
    if proof["directorySyncCompleted"] is not True:
        raise _ProofError(
            "ABSENCE_PROOF_MISMATCH", "absence proof is not synchronized"
        )
    entries = proof["entries"]
    if type(entries) is not list or not entries:
        raise _ProofError("ABSENCE_PROOF_MISMATCH", "absence entries are empty")
    for entry in entries:
        _exact_keys(
            entry,
            {"path", "basename", "parentDevice", "parentInode", "absent"},
            "ABSENCE_PROOF_MISMATCH",
        )
        if entry["absent"] is not True:
            raise _ProofError("ABSENCE_PROOF_MISMATCH", "absence flag differs")
    projection = {key: proof[key] for key in proof if key != "proofFingerprint"}
    if proof["proofFingerprint"] != domain_fingerprint(
        "codex-smart/absence-proof/v2", projection
    ):
        raise _ProofError(
            "ABSENCE_PROOF_MISMATCH", "absence proof fingerprint differs"
        )


def _refresh_absence_proof(value, *, expected_journal: Path) -> dict[str, object]:
    _validate_absence_projection(value)
    proof = value["value"]
    entries = proof["entries"]
    if len(entries) != 1 or entries[0]["path"] != str(expected_journal):
        raise _ProofError(
            "ABSENCE_PROOF_MISMATCH", "absence target is not the main journal"
        )
    entry = entries[0]
    if entry["basename"] != expected_journal.name:
        raise _ProofError("ABSENCE_PROOF_MISMATCH", "absence basename differs")
    parent = expected_journal.parent
    descriptor = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        info = os.fstat(descriptor)
        _safe_integer(entry["parentDevice"], "ABSENCE_PROOF_MISMATCH")
        if info.st_ino != entry["parentInode"]:
            raise _ProofError(
                "ABSENCE_PROOF_MISMATCH", "absence parent identity differs"
            )
        _require_absent_at(descriptor, entry["basename"])
        os.fsync(descriptor)
        _require_absent_at(descriptor, entry["basename"])
    finally:
        os.close(descriptor)
    return value


def refresh_activation_journal_absence_v2(
    value: Mapping[str, object],
    *,
    expected_journal: Path,
) -> dict[str, object]:
    """Повторно проверяет доказанное отсутствие главного журнала установки."""

    return _refresh_absence_proof(
        dict(value),
        expected_journal=expected_journal,
    )


def require_pinned_controller_health_v2(
    *,
    codex_home: Path,
    state_home: Path,
    activation_id: str,
    controller_probe=None,
) -> None:
    """Быстро подтверждает живой принимающий контроллер заданной активации.

    Полное доказательство дерева активации остаётся обязанностью шлюза перед
    запуском Codex и поставщика контроллера перед каждой командой. Этот проход
    проверяет только неизменяемую привязку запуска и локальный ответ ``health``,
    чтобы короткий обработчик запроса не хешировал весь снимок Codex повторно.
    """

    code = "PINNED_CONTROLLER_INVALID"
    codex_root = Path(codex_home).expanduser().absolute()
    state_root = Path(state_home).expanduser().absolute()
    _verify_directory(codex_root, private=False, code=code)
    _verify_directory(state_root, private=True, code=code)
    pinned_activation_id = _identifier(activation_id, "act2_", 64, code)
    pinned_fingerprint = pinned_activation_id.removeprefix("act2_")

    socket_path = state_root / "controller.sock"
    socket_info = os.lstat(socket_path)
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != os.getuid()
        or stat.S_IMODE(socket_info.st_mode) != 0o600
        or socket_info.st_nlink != 1
    ):
        raise _ProofError(code, "pinned controller socket is not private")

    codex_home_hash = hashlib.sha256(
        str(codex_root.resolve()).encode("utf-8")
    ).hexdigest()
    request_projection = {
        "messageType": "request",
        "protocolVersion": 2,
        "release": _RELEASE,
        "codexHomeHash": codex_home_hash,
        "shellSessionId": "user-prompt-v2",
        "controllerIdentity": None,
        "instanceId": None,
        "controllerStartId": None,
        "commandId": None,
        "expectedControlEpoch": None,
        "operationId": None,
        "method": "health",
        "params": {},
    }
    request = dict(request_projection)
    request["requestFingerprint"] = domain_fingerprint(
        "codex-smart/controller-request/v2",
        request_projection,
    )
    request["extensions"] = {}
    probe = controller_probe or _unix_controller_probe
    try:
        response = probe(socket_path, request)
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except _ProofError:
        raise
    except Exception as exc:
        raise _ProofError(code, "pinned controller did not answer") from exc

    _validate_health_response(response, request=request)
    payload = response["payload"]
    expected_runtime = {
        "namespace": _NAMESPACE,
        "state": "ACCEPTING",
        "maintenanceMode": None,
        "operationId": None,
        "acceptingNewRoutes": True,
        "activationFingerprint": pinned_fingerprint,
        "databaseSchemaVersion": 2,
    }
    if any(payload[name] != expected for name, expected in expected_runtime.items()):
        raise _ProofError(code, "pinned controller is not accepting this activation")

    _identifier(payload["instanceId"], "ci2_", 32, code)
    _identifier(payload["controllerStartId"], "cs2_", 32, code)
    _identifier(payload["databaseId"], "db2_", 32, code)
    for name in (
        "controllerIdentity",
        "compatibilityFingerprint",
        "routingPolicyFingerprint",
        "bundledCatalogFingerprint",
    ):
        _sha256(payload[name], code)
    if (
        type(payload["pid"]) is not int
        or payload["pid"] <= 0
        or type(payload["processGroupId"]) is not int
        or payload["processGroupId"] <= 0
        or type(payload["processStartMarker"]) is not str
        or not payload["processStartMarker"]
    ):
        raise _ProofError(code, "pinned controller process identity is invalid")

    controller_projection = {
        "protocolVersion": 2,
        "release": _RELEASE,
        "namespace": _NAMESPACE,
        "codexHomeHash": codex_home_hash,
        "stateHome": str(state_root),
        "activationFingerprint": pinned_fingerprint,
        "compatibilityFingerprint": payload["compatibilityFingerprint"],
        "routingPolicyFingerprint": payload["routingPolicyFingerprint"],
        "bundledCatalogFingerprint": payload["bundledCatalogFingerprint"],
        "databaseId": payload["databaseId"],
        "databaseSchemaVersion": 2,
    }
    expected_identity = domain_fingerprint(
        "codex-smart/controller-identity/v2",
        controller_projection,
    )
    if payload["controllerIdentity"] != expected_identity:
        raise _ProofError(code, "pinned controller identity differs")


def _require_absent_at(directory_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise _ProofError("ABSENCE_PROOF_MISMATCH", "main journal exists")


def _validate_health_response(value, *, request: dict[str, object]) -> None:
    try:
        canonical_json_bytes(value)
    except CanonicalJsonError as exc:
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH",
            f"health response is outside canonical JSON: {exc}",
        ) from exc
    _exact_keys(
        value,
        {
            "messageType",
            "protocolVersion",
            "release",
            "method",
            "responseKind",
            "commandId",
            "requestFingerprint",
            "controlEpoch",
            "payload",
            "responseFingerprint",
            "extensions",
        },
        "CONTROLLER_BINDING_MISMATCH",
    )
    constants = {
        "messageType": "response",
        "protocolVersion": 2,
        "release": _RELEASE,
        "method": "health",
        "responseKind": "HEALTH",
        "commandId": None,
    }
    if any(value[name] != expected for name, expected in constants.items()):
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health response envelope differs"
        )
    if value["requestFingerprint"] != request["requestFingerprint"]:
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health request fingerprint differs"
        )
    if type(value["controlEpoch"]) is not int or value["controlEpoch"] < 1:
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health control epoch is invalid"
        )
    if type(value["extensions"]) is not dict or len(value["extensions"]) > 128:
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health extensions are invalid"
        )
    _sha256(value["responseFingerprint"], "CONTROLLER_BINDING_MISMATCH")
    response_projection = {
        key: item
        for key, item in value.items()
        if key not in {"responseFingerprint", "extensions"}
    }
    if value["responseFingerprint"] != domain_fingerprint(
        "codex-smart/controller-response/v2", response_projection
    ):
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health response fingerprint differs"
        )
    payload = value["payload"]
    _exact_keys(
        payload,
        {
            "namespace",
            "controllerIdentity",
            "instanceId",
            "controllerStartId",
            "pid",
            "processStartMarker",
            "processGroupId",
            "state",
            "maintenanceMode",
            "operationId",
            "acceptingNewRoutes",
            "quiescent",
            "activationFingerprint",
            "compatibilityFingerprint",
            "routingPolicyFingerprint",
            "bundledCatalogFingerprint",
            "databaseId",
            "databaseSchemaVersion",
            "workCounts",
        },
        "CONTROLLER_BINDING_MISMATCH",
    )
    counts = payload["workCounts"]
    expected_counts = {
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
    if (
        type(counts) is not dict
        or set(counts) != expected_counts
        or any(
            type(item) is not int or not 0 <= item <= 9_007_199_254_740_991
            for item in counts.values()
        )
        or type(payload["acceptingNewRoutes"]) is not bool
        or type(payload["quiescent"]) is not bool
        or (payload["quiescent"] is True and any(counts.values()))
    ):
        raise _ProofError(
            "CONTROLLER_BINDING_MISMATCH", "health work counts are invalid"
        )


def _unix_controller_probe(
    socket_path: Path, request: dict[str, object]
) -> dict[str, object]:
    encoded = canonical_json_bytes(request) + b"\n"
    if len(encoded) > 1024 * 1024:
        raise _ProofError("CONTROLLER_UNAVAILABLE", "health request is too large")
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    timeout_seconds = 1.0
    if operation_deadline is not None:
        operation_deadline.checkpoint()
        call_deadline = operation_deadline.child(
            phase="activation-controller-health-probe",
            max_seconds=timeout_seconds,
            timeout_code="CONTROLLER_HEALTH_PROBE_TIMEOUT",
        )
    else:
        call_deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="activation-controller-health-probe",
            timeout_seconds=timeout_seconds,
            timeout_code="CONTROLLER_HEALTH_PROBE_TIMEOUT",
        )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            _set_controller_probe_timeout(
                connection,
                deadline=call_deadline,
                local_cap_seconds=timeout_seconds,
            )
            connection.connect(str(socket_path))
            _set_controller_probe_timeout(
                connection,
                deadline=call_deadline,
                local_cap_seconds=timeout_seconds,
            )
            connection.sendall(encoded)
            chunks: list[bytes] = []
            total = 0
            while True:
                _set_controller_probe_timeout(
                    connection,
                    deadline=call_deadline,
                    local_cap_seconds=timeout_seconds,
                )
                chunk = connection.recv(65536)
                call_deadline.checkpoint()
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 1024 * 1024:
                    raise _ProofError(
                        "CONTROLLER_UNAVAILABLE", "health response is too large"
                    )
                if b"\n" in chunk:
                    break
    except operation_deadline_v2.OperationDeadlineExceededV2 as exc:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        raise TimeoutError("controller health probe timed out") from exc
    except TimeoutError:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        raise
    raw = b"".join(chunks).split(b"\n", 1)[0]
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: _raise_json("floating values are forbidden"),
            parse_constant=lambda _value: _raise_json("non-finite values are forbidden"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _ProofError("CONTROLLER_UNAVAILABLE", str(exc)) from exc
    if type(value) is not dict:
        raise _ProofError("CONTROLLER_UNAVAILABLE", "health response is not an object")
    return value


def _set_controller_probe_timeout(
    connection: socket.socket,
    *,
    deadline: operation_deadline_v2.OperationDeadlineV2,
    local_cap_seconds: float,
) -> None:
    deadline.checkpoint()
    connection.settimeout(
        deadline.bounded_timeout_seconds(
            local_cap_seconds=local_cap_seconds,
        )
    )


def _default_snapshot_verifier(subject: Mapping[str, object]) -> None:
    path = str(subject["snapshotPath"])
    commands = (
        ["/usr/bin/lipo", "-archs", path],
        ["/usr/bin/codesign", "-v", "--strict", "--all-architectures", path],
        [
            "/usr/bin/codesign",
            "-v",
            "--strict",
            "--all-architectures",
            "-R",
            CODE_SIGNATURE_REQUIREMENT,
            path,
        ],
    )
    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is None:
        deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="snapshot-verification",
            timeout_seconds=31,
            timeout_code="SNAPSHOT_VERIFICATION_DEADLINE_TIMEOUT",
        )
    supervisor = (
        operation_process_group_supervisor_v2.
        current_process_group_supervisor_v2()
    )
    if supervisor is None:
        supervisor = (
            operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2()
        )
    for command in commands:
        result = supervised_subprocess_v2.run_supervised_command_v2(
            argv=command,
            label="snapshot-verification",
            stdin=b"",
            local_timeout_seconds=10,
            cleanup_wait_seconds=0.5,
            max_output_bytes=1024 * 1024,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
            deadline=deadline,
            supervisor=supervisor,
        )
        if result.returncode != 0:
            raise _ProofError(
                "SNAPSHOT_MISMATCH",
                result.stderr.decode("utf-8", "replace")[:1000]
                or "snapshot verification failed",
            )
        if command[0] == "/usr/bin/lipo" and result.stdout.strip() != b"arm64":
            raise _ProofError("SNAPSHOT_MISMATCH", "snapshot architecture differs")
