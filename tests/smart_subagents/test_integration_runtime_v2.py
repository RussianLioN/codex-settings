from __future__ import annotations

import copy
import hashlib
import json
import importlib.util
import os
import runpy
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from typing import Mapping
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN / "scripts"))
sys.path.insert(0, str(PLUGIN / "src"))
LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)

from integration_runtime_v2 import (  # noqa: E402
    FreshActivationProviderV2,
    HookTurnContextV2,
    IntegrationConfigV2,
    IntegrationV2Error,
    PinnedResumeBindingV2,
    TurnContextStoreV2,
)
from integration_runtime import _git_identity  # noqa: E402
from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayDecision,
    GatewayRuntimeBindingV2,
    GatewayState,
    SourceDriftV1,
)
from codex_smart_subagents import activation_gateway_v2 as gateway_module  # noqa: E402
from codex_smart_subagents.supervised_subprocess_v2 import (  # noqa: E402
    SupervisedCommandOutputLimitExceededV2,
)
from codex_smart_subagents import operation_deadline_v2  # noqa: E402
from codex_smart_subagents.mcp_contracts_v2 import (  # noqa: E402
    get_tool_definitions_v2,
)
from codex_smart_subagents.mcp_runtime_proof_v2 import (  # noqa: E402
    MCPRuntimeAttestationPublisherV2,
    MCP_SESSION_NONCE_ENV_V2,
    USER_MCP_POLICY_PROOF_ENV_V2,
    build_user_mcp_policy_proof_v2,
)
from codex_smart_subagents.mcp_server_v2 import (  # noqa: E402
    MCP_PROTOCOL,
    SERVER_NAME,
    SERVER_VERSION,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    ResumeCandidateV2,
    ResumeSessionV2Error,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
)
from codex_smart_subagents.schema_projection import (  # noqa: E402
    APPLICATION_ID,
    database_schema_fingerprint,
)


def deferred_reason(response: dict[str, object]) -> str:
    prefix = "SMART_HOOK_DEFERRED: "
    system_message = response.get("systemMessage")
    if not isinstance(system_message, str) or not system_message.startswith(prefix):
        raise AssertionError(response)
    return system_message[len(prefix) :]


class _Resolver:
    def __init__(self, decision: GatewayDecision) -> None:
        self.decision = decision

    def resolve(self) -> GatewayDecision:
        return self.decision


class IntegrationRuntimeV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csir2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.user_config = self.codex_home / "config.toml"
        self.user_config.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = true\n",
            encoding="utf-8",
        )
        self.user_config.chmod(0o600)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.gateway = self.root / "codex-smart"
        self.gateway.write_bytes(b"#!/bin/sh\n")
        self.gateway.chmod(0o500)
        self.catalog = self.root / "adaptive-subagents.toml"
        self.catalog.write_text("schema_version = 1\n", encoding="utf-8")
        self.activation_fingerprint = "a" * 64
        self.compatibility_fingerprint = "b" * 64
        self.routing_fingerprint = "6" * 64
        self.catalog_fingerprint = "7" * 64
        self.schema_fingerprint = "8" * 64
        self.schema_artifact_sha256 = "9" * 64
        self.activation_binding_nonce = "0" * 64
        self.installation_id = "ins2_" + "3" * 32
        self.operation_id = "op2_" + "9" * 32
        self.generation_id = "gen2_" + "4" * 64
        self.receipt_fingerprint = "5" * 64
        self.gate_fingerprint = "c" * 64
        self.activation_id = "act2_" + self.activation_fingerprint
        self.config = IntegrationConfigV2.from_environ(self._environment())
        self.record = HookTurnContextV2(
            shell_session_id="cas2_" + "s" * 32,
            session_id="session-1",
            turn_id="turn-1",
            codex_home=str(self.codex_home),
            repo_root=str(self.root),
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _environment(self) -> dict[str, str]:
        return {
            "CODEX_SMART_LAUNCHER_ACTIVE": "1",
            "CODEX_ADAPTIVE_SESSION_ID": "cas2_" + "s" * 32,
            "CODEX_HOME": str(self.codex_home),
            "CODEX_SMART_STATE_HOME": str(self.state_home),
            "CODEX_SMART_GATEWAY_PATH": str(self.gateway),
            "CODEX_SMART_ACTIVATION_ID": self.activation_id,
            "CODEX_SMART_GATE_FINGERPRINT": self.gate_fingerprint,
            "CODEX_ADAPTIVE_CATALOG": str(self.catalog),
        }

    def _controller_binding(
        self,
        _config: IntegrationConfigV2,
        _environ: Mapping[str, str],
        *,
        deadline: float,
    ) -> PinnedResumeBindingV2:
        self.assertGreater(deadline, time.monotonic())
        return PinnedResumeBindingV2(
            self.state_home / "controller.sqlite3",
            self.compatibility_fingerprint,
        )

    def _launch_gate(self) -> dict[str, object]:
        absence_value = {
            "proofId": "ap2_" + "a" * 32,
            "installationId": "ins2_" + "b" * 32,
            "operationId": "op2_" + "c" * 32,
            "entries": [
                {
                    "path": str(
                        self.codex_home
                        / "install-manifests"
                        / "codex-smart-subagents-v2.transaction.json"
                    ),
                    "basename": "codex-smart-subagents-v2.transaction.json",
                    "parentDevice": 1,
                    "parentInode": 2,
                    "absent": True,
                }
            ],
            "directorySyncCompleted": True,
        }
        absence_value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2",
            dict(absence_value),
        )
        proof = {
            "schemaId": "absence-proof-v2",
            "schemaSha256": LIFECYCLE_SCHEMA_SHA256,
            "value": absence_value,
        }
        proof["valueFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof-projection/v2",
            proof,
        )
        projection = {
            "manifestSemanticFingerprint": getattr(
                self,
                "manifest_semantic_fingerprint",
                "4" * 64,
            ),
            "activationReceiptFingerprint": self.receipt_fingerprint,
            "journalAbsenceProof": proof,
        }
        return {
            **projection,
            "gateFingerprint": domain_fingerprint(
                "codex-smart/activation-gate/v2",
                projection,
            ),
        }

    def _decision(self) -> GatewayDecision:
        database = self.state_home / "databases" / ("db2_" + "f" * 32)
        database.mkdir(parents=True, mode=0o700)
        database_path = database / "smart-subagents.sqlite3"
        marketplace = self.root / "marketplace"
        marketplace.mkdir(exist_ok=True, mode=0o700)
        database_row = {
            "activation_id": self.activation_id,
            "activation_fingerprint": self.activation_fingerprint,
        }
        controller_row = {
            "activation_id": self.activation_id,
            "activation_fingerprint": self.activation_fingerprint,
            "compatibility_fingerprint": self.compatibility_fingerprint,
            "control_epoch": 7,
        }
        binding = GatewayRuntimeBindingV2(
            activation_id=self.activation_id,
            activation_fingerprint=self.activation_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
            control_epoch=7,
            state_home=self.state_home,
            marketplace_path=marketplace,
            database_path=database_path,
            database_identity_row=database_row,
            controller_row=controller_row,
            interface_evidence={"compatibilityFingerprint": self.compatibility_fingerprint},
            activation_identity={"codexSnapshot": {"absolutePath": str(self.gateway)}},
        )
        return GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.gateway,
            coordinator={"model": "coordinator", "reasoning_effort": "medium"},
            activation_id=self.activation_id,
            gate_fingerprint=self.gate_fingerprint,
            activation_gate={
                "manifestSemanticFingerprint": "1" * 64,
                "activationReceiptFingerprint": "2" * 64,
                "journalAbsenceProof": {},
                "gateFingerprint": self.gate_fingerprint,
            },
            catalog_path=self.catalog,
            runtime_binding=binding,
        )

    def _proven_environment(
        self,
    ) -> tuple[dict[str, str], MCPRuntimeAttestationPublisherV2]:
        environment = self._environment()
        environment[MCP_SESSION_NONCE_ENV_V2] = "mcpn2_" + "f" * 64
        environment[USER_MCP_POLICY_PROOF_ENV_V2] = (
            build_user_mcp_policy_proof_v2(self.codex_home)
        )
        publisher = MCPRuntimeAttestationPublisherV2.from_environ(environment)
        publisher.publish(
            get_tool_definitions_v2(),
            server_name=SERVER_NAME,
            server_version=SERVER_VERSION,
            protocol_version=MCP_PROTOCOL,
        )
        return environment, publisher

    def _publish_launch_gate(self, environment: dict[str, str]) -> dict[str, object]:
        gate = self._launch_gate()
        environment["CODEX_SMART_GATE_FINGERPRINT"] = str(gate["gateFingerprint"])
        environment["CODEX_SMART_ACTIVATION_GATE"] = canonical_json_bytes(
            gate
        ).decode("utf-8")
        return gate

    def _write_minimal_active_manifest(self, database_id: str) -> None:
        manifest_root = self.codex_home / "install-manifests"
        manifest_root.mkdir(mode=0o700)
        manifest = {
            "stateHome": str(self.state_home),
            "activeActivation": {
                "activationId": self.activation_id,
                "activationFingerprint": self.activation_fingerprint,
                "databaseId": database_id,
            },
            "interfaceEvidence": {
                "compatibilityFingerprint": self.compatibility_fingerprint,
            },
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "lastCommittedOperation": self.operation_id,
        }
        path = manifest_root / "codex-smart-subagents-v2.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        path.chmod(0o600)

    def _write_active_manifest(
        self,
        database_id: str,
        *,
        full_receipt: bool = True,
    ) -> None:
        manifest_root = self.codex_home / "install-manifests"
        manifest_root.mkdir(mode=0o700)
        source_locator = {
            "lexicalPath": str(self.gateway),
            "resolvedPathAtCapture": str(self.gateway),
            "sourceObservedSha256": "a" * 64,
        }
        manifest = {
            "schemaVersion": 2,
            "installationId": self.installation_id,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "stateHome": str(self.state_home),
            "sourceLocator": source_locator,
            "codexSnapshot": {
                "absolutePath": str(self.gateway),
                "sha256": "a" * 64,
            },
            "activeActivation": {
                "activationId": self.activation_id,
                "activationFingerprint": self.activation_fingerprint,
                "symlinkTarget": f"activations/{self.activation_id}/marketplace",
                "generationId": self.generation_id,
                "databaseId": database_id,
            },
            "previousActivation": None,
            "interfaceEvidence": {
                "compatibilityFingerprint": self.compatibility_fingerprint,
            },
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "artifacts": [],
            "originalBackup": {
                "type": "absent",
                "path": str(self.codex_home / "original-codex-backup"),
                "parentPath": str(self.codex_home),
                "name": "original-codex-backup",
            },
            "lastCommittedOperation": self.operation_id,
            "databaseSchemaVersion": 2,
            "extensions": {},
        }
        self.manifest_semantic_fingerprint = domain_fingerprint(
            "codex-smart/manifest-semantic/v2",
            {key: value for key, value in manifest.items() if key != "extensions"},
        )
        path = manifest_root / "codex-smart-subagents-v2.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        path.chmod(0o600)
        receipt_root = manifest_root / "codex-smart-subagents-v2.receipts"
        receipt_dir = receipt_root / self.installation_id
        receipt_dir.mkdir(parents=True, mode=0o700)
        if full_receipt:
            receipt = self._activation_commit_receipt(manifest, path)
        else:
            receipt = {
                "schemaVersion": 2,
                "receiptKind": "activation-commit",
                "receiptFingerprint": self.receipt_fingerprint,
            }
        receipt_path = receipt_dir / f"{self.operation_id}.commit.json"
        receipt_path.write_bytes(canonical_json_bytes(receipt))
        receipt_path.chmod(0o600)

    def _write_minimal_routes_database(
        self,
        database_id: str,
        *,
        disposition: str = "delegate",
        state: str = "PLANNED",
        include_route: bool = False,
    ) -> Path:
        database_path = (
            self.state_home / "databases" / database_id / "smart-subagents.sqlite3"
        )
        database_path.parent.mkdir(parents=True, mode=0o700)
        socket_info = self._controller_socket_info()
        controller_identity = self._controller_identity(database_id)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "create table database_identity ("
                "database_id text not null,"
                "schema_version integer not null,"
                "schema_fingerprint text not null,"
                "schema_artifact_sha256 text not null,"
                "activation_binding_nonce text not null,"
                "activation_id text not null,"
                "activation_fingerprint text not null,"
                "source_shape text not null)"
            )
            connection.execute(
                "insert into database_identity values (?,?,?,?,?,?,?,?)",
                (
                    database_id,
                    2,
                    self.schema_fingerprint,
                    self.schema_artifact_sha256,
                    self.activation_binding_nonce,
                    self.activation_id,
                    self.activation_fingerprint,
                    "fresh-v2",
                ),
            )
            connection.execute(
                "create table controller_state ("
                "database_id text not null,"
                "protocol_version integer not null,"
                "release text not null,"
                "controller_identity text not null,"
                "instance_id text not null,"
                "controller_start_id text not null,"
                "controller_pid integer not null,"
                "controller_process_start_marker text not null,"
                "controller_process_group_id integer not null,"
                "activation_id text not null,"
                "activation_fingerprint text not null,"
                "compatibility_fingerprint text not null,"
                "routing_policy_fingerprint text not null,"
                "bundled_catalog_fingerprint text not null,"
                "control_epoch integer not null,"
                "state text not null,"
                "maintenance_mode text not null,"
                "reason_code text not null,"
                "operation_id text,"
                "socket_path text not null,"
                "socket_device integer not null,"
                "socket_inode integer not null,"
                "socket_owner_uid integer not null,"
                "socket_owner_gid integer not null,"
                "socket_mode text not null,"
                "lock_held integer not null,"
                "accepting_new_routes integer not null,"
                "quiescent integer not null)"
            )
            connection.execute(
                "insert into controller_state values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    database_id,
                    2,
                    "0.2.0",
                    controller_identity,
                    "ci2_" + "1" * 32,
                    "cs2_" + "2" * 32,
                    os.getpid(),
                    "test-controller-start",
                    os.getpgrp(),
                    self.activation_id,
                    self.activation_fingerprint,
                    self.compatibility_fingerprint,
                    self.routing_fingerprint,
                    self.catalog_fingerprint,
                    7,
                    "ACCEPTING",
                    "NONE",
                    "NONE",
                    None,
                    str(self.state_home / "controller.sock"),
                    socket_info.st_dev,
                    socket_info.st_ino,
                    socket_info.st_uid,
                    socket_info.st_gid,
                    "0" + oct(stat.S_IMODE(socket_info.st_mode))[2:],
                    1,
                    1,
                    0,
                ),
            )
            connection.execute(
                "create table routes ("
                "shell_session_id text not null,"
                "session_id text not null,"
                "turn_id text not null,"
                "disposition text not null,"
                "state text not null)"
            )
            if include_route:
                connection.execute(
                    "insert into routes values (?,?,?,?,?)",
                    (
                        self.record.shell_session_id,
                        self.record.session_id,
                        self.record.turn_id,
                        disposition,
                        state,
                    ),
                )
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)
        return database_path

    def _activation_commit_receipt(
        self,
        manifest: dict[str, object],
        manifest_path: Path,
    ) -> dict[str, object]:
        database_binding = self.database_binding
        manifest_value = {
            "file": self._file_projection(manifest_path),
            "schemaVersion": 2,
            "installationId": manifest["installationId"],
            "release": "0.2.0",
            "pluginId": manifest["pluginId"],
            "stateHome": manifest["stateHome"],
            "activeActivationId": self.activation_id,
            "previousActivationId": None,
            "lastCommittedOperation": self.operation_id,
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(manifest["sourceLocator"])
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes(manifest["artifacts"])
            ).hexdigest(),
            "semanticFingerprint": self.manifest_semantic_fingerprint,
        }
        activation_value = {
            "directory": {
                "path": str(self.state_home),
                "device": 1,
                "inode": 2,
                "ownerUid": os.getuid(),
                "ownerGid": os.getgid(),
                "mode": "0700",
                "entryCount": 0,
                "treeSha256": "a" * 64,
            },
            "activationFile": {
                "path": str(self.state_home / "activation.json"),
                "device": 1,
                "inode": 3,
                "ownerUid": os.getuid(),
                "ownerGid": os.getgid(),
                "mode": "0600",
                "linkCount": 1,
                "size": 2,
                "sha256": "b" * 64,
            },
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "generationId": self.generation_id,
            "release": "0.2.0",
            "databaseId": database_binding["value"]["databaseId"],
            "databaseIdentityFingerprint": database_binding["value"][
                "databaseIdentityFingerprint"
            ],
            "marketplaceTreeSha256": "c" * 64,
            "generationTreeSha256": "d" * 64,
        }
        lineage = {
            "transitionKind": "initial",
            "sourceReceipt": None,
            "activationProofFingerprint": None,
            "shutdownCommandIds": None,
            "stoppedController": None,
        }
        lineage["lineageFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            dict(lineage),
        )
        receipt = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "frozenJournalFingerprint": domain_fingerprint(
                "codex-smart/materialization-intent/v2",
                {
                    "installationId": self.installation_id,
                    "operationId": self.operation_id,
                    "activationId": self.activation_id,
                },
            ),
            "manifest": self._journal_projection("manifest-v2", manifest_value),
            "manifestDocument": copy.deepcopy(manifest),
            "transitionLineage": lineage,
            "activation": self._journal_projection("activation-v2", activation_value),
            "databaseBinding": database_binding,
            "journalAbsenceTarget": self._launch_gate()["journalAbsenceProof"],
            "controllerIdentity": self._controller_identity(
                database_binding["value"]["databaseId"]
            ),
            "completedStepIds": ["st2_" + "e" * 32],
            "completedAt": "2026-07-26T00:00:00.000000Z",
        }
        self.receipt_fingerprint = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2",
            receipt,
        )
        receipt["receiptFingerprint"] = self.receipt_fingerprint
        return receipt

    def _write_schema_routes_database(
        self,
        database_id: str,
        *,
        disposition: str = "delegate",
        state: str = "PLANNED",
        include_route: bool = False,
    ) -> Path:
        database_path = (
            self.state_home / "databases" / database_id / "smart-subagents.sqlite3"
        )
        database_path.parent.mkdir(parents=True, mode=0o700)
        schema_path = (
            PLUGIN
            / "src"
            / "codex_smart_subagents"
            / "schema"
            / "state-v2.sql"
        )
        socket_info = self._controller_socket_info()
        controller_identity = self._controller_identity(database_id)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.executescript(schema_path.read_text(encoding="utf-8"))
            connection.execute("pragma user_version=2")
            schema = database_schema_fingerprint(connection, version=2)
            self.schema_fingerprint = schema.fingerprint
            connection.execute(
                """
                insert into database_identity(
                  singleton,database_id,schema_version,schema_fingerprint,
                  schema_artifact_sha256,activation_binding_nonce,activation_id,
                  activation_fingerprint,source_shape,source_schema_fingerprint,
                  source_backup_sha256,created_operation_id,created_at
                ) values(1,?,?,?,?,?,?,?,'fresh-v2',null,null,?,?)
                """,
                (
                    database_id,
                    2,
                    self.schema_fingerprint,
                    self.schema_artifact_sha256,
                    self.activation_binding_nonce,
                    self.activation_id,
                    self.activation_fingerprint,
                    self.operation_id,
                    "2026-07-26T00:00:00.000000Z",
                ),
            )
            connection.execute(
                """
                insert into controller_state(
                  singleton,database_id,protocol_version,release,
                  controller_identity,instance_id,controller_start_id,
                  controller_pid,controller_process_start_marker,
                  controller_process_group_id,control_epoch,state,
                  maintenance_mode,reason_code,operation_id,activation_id,
                  activation_fingerprint,compatibility_fingerprint,
                  routing_policy_fingerprint,bundled_catalog_fingerprint,
                  socket_path,socket_device,socket_inode,socket_owner_uid,
                  socket_owner_gid,socket_mode,lock_held,accepting_new_routes,
                  quiescent,updated_at
                ) values(1,?,?,?,?,?,?,?,?,?,7,'ACCEPTING','NONE','NONE',null,
                         ?,?,?,?,?,?,?,?,?,?,'0600',1,1,0,?)
                """,
                (
                    database_id,
                    2,
                    "0.2.0",
                    controller_identity,
                    "ci2_" + "1" * 32,
                    "cs2_" + "2" * 32,
                    os.getpid(),
                    "test-controller-start",
                    os.getpgrp(),
                    self.activation_id,
                    self.activation_fingerprint,
                    self.compatibility_fingerprint,
                    self.routing_fingerprint,
                    self.catalog_fingerprint,
                    str(self.state_home / "controller.sock"),
                    socket_info.st_dev,
                    socket_info.st_ino,
                    socket_info.st_uid,
                    socket_info.st_gid,
                    "2026-07-26T00:00:00.000000Z",
                ),
            )
            if include_route:
                self._insert_route(connection, disposition=disposition, state=state)
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)
        self.database_binding = self._database_binding_projection(
            database_path,
            database_id,
        )
        return database_path

    def _insert_route(
        self,
        connection: sqlite3.Connection,
        *,
        disposition: str,
        state: str,
    ) -> None:
        startable = 0 if state in {"DIRECT", "CLARIFY"} else 1
        context = self.record.value_without_fingerprint()
        context_hash = domain_fingerprint("test/stop-context", context)
        connection.execute(
            """
            insert into routes(
              route_id,request_key,request_hash,context_hash,context_json,
              shell_session_id,session_id,turn_id,codex_home_hash,repo_root_hash,
              base_sha,worktree_fingerprint,catalog_generation,algorithm_version,
              disposition,startable,state,expires_at,run_id,cancel_reason,
              plan_output_json,terminal_result_json,created_at,updated_at,
              activation_fingerprint,compatibility_fingerprint
            ) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,null,null,?,null,?,?,?,?)
            """,
            (
                "route2_" + "1" * 32,
                "request-key",
                "2" * 64,
                context_hash,
                json.dumps(context),
                self.record.shell_session_id,
                self.record.session_id,
                self.record.turn_id,
                "3" * 64,
                "4" * 64,
                self.record.base_sha,
                self.record.worktree_fingerprint,
                "generation-test",
                "algorithm-test",
                disposition,
                startable,
                state,
                "2026-07-27T00:00:00.000000Z",
                "{}",
                "2026-07-26T00:00:00.000000Z",
                "2026-07-26T00:00:00.000000Z",
                self.activation_fingerprint,
                self.compatibility_fingerprint,
            ),
        )

    def _database_binding_projection(
        self,
        database_path: Path,
        database_id: str,
    ) -> dict[str, object]:
        info = database_path.lstat()
        identity_value = {
            "databaseId": database_id,
            "activationBindingNonce": self.activation_binding_nonce,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
        }
        identity_fingerprint = domain_fingerprint(
            "codex-smart/database-identity/v2",
            identity_value,
        )
        binding_value = {
            "path": str(database_path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
            "linkCount": info.st_nlink,
            "databaseId": database_id,
            "databaseIdentity": identity_value,
            "databaseIdentityFingerprint": identity_fingerprint,
            "activationIdentity": {
                "activationId": self.activation_id,
                "activationFingerprint": self.activation_fingerprint,
            },
            "databaseVersion": "0.2.0",
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": self.schema_fingerprint,
            "schemaArtifactSha256": self.schema_artifact_sha256,
        }
        binding = {
            "schemaId": "database-binding-v2",
            "schemaSha256": (
                LIFECYCLE_SCHEMA_SHA256
            ),
            "value": binding_value,
        }
        binding["valueFingerprint"] = domain_fingerprint(
            "codex-smart/database-binding/v2",
            binding,
        )
        return binding

    def _file_projection(self, path: Path) -> dict[str, object]:
        info = path.lstat()
        return {
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
            "linkCount": info.st_nlink,
            "size": info.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def _journal_projection(
        self,
        schema_id: str,
        value: dict[str, object],
    ) -> dict[str, object]:
        projection = {
            "schemaId": schema_id,
            "schemaSha256": (
                LIFECYCLE_SCHEMA_SHA256
            ),
            "value": value,
        }
        projection["valueFingerprint"] = domain_fingerprint(
            "codex-smart/journal-state/v2",
            projection,
        )
        return projection

    def _controller_socket_info(self) -> os.stat_result:
        controller_socket = getattr(self, "_controller_socket", None)
        socket_path = self.state_home / "controller.sock"
        if controller_socket is None:
            controller_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            controller_socket.bind(str(socket_path))
            socket_path.chmod(0o600)
            self._controller_socket = controller_socket
            self.addCleanup(controller_socket.close)
        return socket_path.lstat()

    def _controller_identity(self, database_id: str) -> str:
        projection = {
            "protocolVersion": 2,
            "release": "0.2.0",
            "namespace": "codex-smart-subagents-v2",
            "codexHomeHash": hashlib.sha256(
                str(self.codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "stateHome": str(self.state_home),
            "activationFingerprint": self.activation_fingerprint,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "routingPolicyFingerprint": self.routing_fingerprint,
            "bundledCatalogFingerprint": self.catalog_fingerprint,
            "databaseId": database_id,
            "databaseSchemaVersion": 2,
        }
        return domain_fingerprint(
            "codex-smart/controller-identity/v2",
            projection,
        )

    def test_private_turn_record_round_trips_and_rejects_tampering(self) -> None:
        store = TurnContextStoreV2(self.config)
        store.save(self.record)

        self.assertEqual(self.record, store.load())
        self.assertEqual(0o600, stat.S_IMODE(store.path.stat().st_mode))
        encoded = json.loads(store.path.read_text(encoding="utf-8"))
        encoded["turnId"] = "other-turn"
        store.path.write_text(json.dumps(encoded), encoding="utf-8")
        store.path.chmod(0o600)

        with self.assertRaisesRegex(IntegrationV2Error, "отпечаток"):
            store.load()

    def test_required_mcp_contract_is_closed_and_uses_effective_approve(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        plugin_root = self.root / "plugin"
        plugin_root.mkdir()
        config = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))
        (plugin_root / ".mcp.json").write_text(
            json.dumps(config),
            encoding="utf-8",
        )
        runtime.require_mcp_contract_v2(plugin_root)

        def server(value: dict[str, object]) -> dict[str, object]:
            return value["mcpServers"]["codex-smart-subagents"]

        cases: list[tuple[str, object]] = [
            ("required-false", lambda value: server(value).__setitem__("required", False)),
            ("required-int", lambda value: server(value).__setitem__("required", 1)),
            (
                "approval-auto",
                lambda value: server(value).__setitem__(
                    "default_tools_approval_mode", "auto"
                ),
            ),
            (
                "env-extra",
                lambda value: server(value)["env_vars"].append("UNEXPECTED"),
            ),
            (
                "disabled-tool",
                lambda value: server(value).__setitem__(
                    "disabled_tools", ["smart_plan"]
                ),
            ),
            ("server-disabled", lambda value: server(value).__setitem__("enabled", False)),
            (
                "tool-auto",
                lambda value: server(value).__setitem__(
                    "tools", {"smart_plan": {"approval_mode": "auto"}}
                ),
            ),
            ("unknown", lambda value: server(value).__setitem__("unexpected", True)),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                invalid = copy.deepcopy(config)
                mutate(invalid)
                (plugin_root / ".mcp.json").write_text(
                    json.dumps(invalid),
                    encoding="utf-8",
                )
                with self.assertRaises(IntegrationV2Error):
                    runtime.require_mcp_contract_v2(plugin_root)

    def test_provider_combines_hook_identity_with_fresh_gateway_binding(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        decision = self._decision()
        provider = FreshActivationProviderV2(
            self.config,
            resolver_factory=lambda _config: _Resolver(decision),
        )

        context = provider.request_context()

        self.assertEqual(self.record.turn_id, context.turn_id)
        self.assertEqual(self.activation_fingerprint, context.activation_fingerprint)
        self.assertEqual(self.compatibility_fingerprint, context.compatibility_fingerprint)
        self.assertEqual(7, context.issued_control_epoch)
        self.assertEqual(decision.activation_gate, provider.activation_gate())
        self.assertEqual(decision.runtime_binding, provider.runtime_binding())

    def test_provider_runtime_binding_scopes_shared_deadline_for_resolver(self) -> None:
        observed_deadlines = []
        decision = self._decision()

        class ObservingResolver:
            def resolve(self) -> GatewayDecision:
                observed_deadlines.append(
                    operation_deadline_v2.current_operation_deadline_v2()
                )
                return decision

        provider = FreshActivationProviderV2(
            self.config,
            resolver_factory=lambda _config: ObservingResolver(),
        )

        self.assertEqual(
            decision.runtime_binding,
            provider.runtime_binding(deadline=time.monotonic() + 1.0),
        )
        self.assertEqual(1, len(observed_deadlines))
        self.assertIsNotNone(observed_deadlines[0])

    def test_provider_rejects_activation_changed_after_root_session_launch(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        decision = self._decision()
        decision = GatewayDecision(
            **{
                **decision.__dict__,
                "gate_fingerprint": "9" * 64,
                "activation_gate": {
                    **dict(decision.activation_gate or {}),
                    "gateFingerprint": "9" * 64,
                },
            }
        )
        provider = FreshActivationProviderV2(
            self.config,
            resolver_factory=lambda _config: _Resolver(decision),
        )

        with self.assertRaisesRegex(IntegrationV2Error, "после запуска"):
            provider.request_context()

    def test_live_controller_check_uses_the_bounded_launch_proof_not_full_resolution(
        self,
    ) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=False,
        )
        self._write_active_manifest(database_id)
        environment = self._environment()
        gate = self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)
        observed: list[tuple[str, object]] = []

        def absence_checker(
            value: object,
            *,
            expected_journal: Path,
            deadline: float | None = None,
        ) -> object:
            observed.append(("absence", expected_journal))
            self.assertIsNotNone(deadline)
            self.assertEqual(gate["journalAbsenceProof"], value)
            return value

        def health_checker(**kwargs: object) -> None:
            observed.append(
                (
                    "health",
                    operation_deadline_v2.current_operation_deadline_v2(),
                )
            )
            self.assertEqual(self.codex_home, kwargs["codex_home"])
            self.assertEqual(self.state_home, kwargs["state_home"])
            self.assertEqual(self.activation_id, kwargs["activation_id"])

        binding = runtime.require_live_controller_v2(
            config,
            environment,
            deadline=time.monotonic() + 1,
            absence_checker=absence_checker,
            health_checker=health_checker,
        )

        self.assertEqual(["absence", "health"], [item[0] for item in observed])
        self.assertEqual(database_path, binding.database_path)
        self.assertEqual(
            self.compatibility_fingerprint,
            binding.compatibility_fingerprint,
        )
        self.assertIsNotNone(observed[1][1])
        self.assertIsNone(operation_deadline_v2.current_operation_deadline_v2())

        damaged = dict(environment)
        damaged["CODEX_SMART_ACTIVATION_GATE"] += " "
        with self.assertRaisesRegex(IntegrationV2Error, "контроллер"):
            runtime.require_live_controller_v2(
                config,
                damaged,
                deadline=time.monotonic() + 1,
                absence_checker=absence_checker,
                health_checker=health_checker,
            )

    def test_config_rejects_relative_or_incomplete_adaptive_environment(self) -> None:
        environment = self._environment()
        environment["CODEX_SMART_STATE_HOME"] = "relative"
        with self.assertRaises(IntegrationV2Error):
            IntegrationConfigV2.from_environ(environment)

    def test_durable_turn_state_is_read_from_the_proven_turn_database(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        self.assertTrue(
            hasattr(runtime, "durable_smart_turn_state_v2"),
            "нужен проверяемый читатель полного состояния умного хода",
        )
        decision = self._decision()
        database_path = decision.runtime_binding.database_path
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "create table routes ("
                "shell_session_id text not null,"
                "session_id text not null,"
                "turn_id text not null,"
                "disposition text not null,"
                "state text not null)"
            )
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)
        observed_deadlines: list[object] = []

        class ObservingResolver(_Resolver):
            def resolve(self) -> GatewayDecision:
                observed_deadlines.append(
                    operation_deadline_v2.current_operation_deadline_v2()
                )
                return super().resolve()

        resolver = lambda _config: ObservingResolver(decision)

        self.assertEqual(
            "MISSING",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            )
        )
        self.assertIsNotNone(observed_deadlines[-1])
        self.assertIsNone(operation_deadline_v2.current_operation_deadline_v2())

        connection = sqlite3.connect(database_path)
        try:
            cursor = connection.execute(
                "insert into routes values (?,?,?,?,?)",
                (
                    self.record.shell_session_id,
                    self.record.session_id,
                    self.record.turn_id,
                    "delegate",
                    "PLANNED",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(
            "DELEGATE_PENDING",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )
        self.assertTrue(
            runtime.durable_smart_plan_exists_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            )
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set state='SUCCEEDED' where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "DELEGATE_TERMINAL",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set disposition='direct',state='DIRECT' "
                "where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "DIRECT",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update routes set disposition='clarify',state='CLARIFY' "
                "where rowid=?",
                (cursor.lastrowid,),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            "CLARIFY",
            runtime.durable_smart_turn_state_v2(
                self.config,
                self.record,
                resolver_factory=resolver,
                deadline=time.monotonic() + 1,
            ),
        )

    def test_stop_reads_pinned_database_without_full_activation_resolution(
        self,
    ) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        self._write_schema_routes_database(database_id, include_route=False)
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        gate = self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)
        TurnContextStoreV2(config).save(self.record)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_fast_path_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        with (
            mock.patch.object(
                runtime,
                "ActivationResolver",
                side_effect=AssertionError("Stop не должен запускать resolve"),
            ),
            mock.patch.object(
                runtime,
                "refresh_activation_journal_absence_v2",
                return_value=gate["journalAbsenceProof"],
            ),
            mock.patch.object(
                runtime,
                "require_pinned_controller_health_v2",
                return_value=None,
            ),
        ):
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
            )

        self.assertIn("decision", response)
        self.assertEqual("block", response["decision"])
        self.assertIn("smart_plan", response["reason"])
        self.assertEqual(1, TurnContextStoreV2(config).load().continuation_count)

    def test_stop_rejects_synthetic_minimal_manifest_and_database(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        self._write_minimal_routes_database(database_id, include_route=False)
        self._write_minimal_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)

        with self.assertRaisesRegex(IntegrationV2Error, "закреплённая база"):
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=time.monotonic() + 1,
                absence_checker=lambda *_args, **_kwargs: None,
                health_checker=lambda **_kwargs: None,
            )

    def test_stop_rejects_database_with_wrong_application_id(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=False,
        )
        self._write_active_manifest(database_id)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("pragma application_id=0")
            connection.commit()
        finally:
            connection.close()
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)

        with self.assertRaisesRegex(IntegrationV2Error, "закреплённая база"):
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=time.monotonic() + 1,
                absence_checker=lambda *_args, **_kwargs: None,
                health_checker=lambda **_kwargs: None,
            )

    def test_stop_database_verification_honors_deadline_while_database_is_locked(
        self,
    ) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=False,
        )
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)

        locking_connection = sqlite3.connect(database_path)
        try:
            locking_connection.execute("begin exclusive")
            started = time.monotonic()
            with self.assertRaisesRegex(IntegrationV2Error, "закреплённая база"):
                runtime.durable_stop_smart_turn_state_v2(
                    config,
                    self.record,
                    environ=environment,
                    deadline=started + 0.005,
                    absence_checker=lambda *_args, **_kwargs: None,
                    health_checker=lambda **_kwargs: None,
                )
            elapsed = time.monotonic() - started
        finally:
            locking_connection.rollback()
            locking_connection.close()

        self.assertLess(elapsed, 0.04)

    def test_stop_rejects_minimal_commit_receipt_document(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        self._write_schema_routes_database(database_id, include_route=False)
        self._write_active_manifest(database_id, full_receipt=False)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)

        with self.assertRaisesRegex(IntegrationV2Error, "закреплённая база"):
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=time.monotonic() + 1,
                absence_checker=lambda *_args, **_kwargs: None,
                health_checker=lambda **_kwargs: None,
            )

    def test_stop_rejects_controller_catalog_binding_mismatch(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=False,
        )
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "update controller_state set bundled_catalog_fingerprint=?",
                ("5" * 64,),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(IntegrationV2Error, "закреплённая база"):
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=time.monotonic() + 1,
                absence_checker=lambda *_args, **_kwargs: None,
                health_checker=lambda **_kwargs: None,
            )

    def test_stop_rechecks_absence_and_health_after_database_read(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        self._write_schema_routes_database(database_id, include_route=False)
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        gate = self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)
        calls: list[str] = []

        def absence_checker(
            value: object,
            *,
            expected_journal: Path,
            deadline: float | None = None,
        ) -> object:
            calls.append("absence")
            self.assertIsNotNone(deadline)
            self.assertEqual(gate["journalAbsenceProof"], value)
            self.assertEqual(
                self.codex_home
                / "install-manifests"
                / "codex-smart-subagents-v2.transaction.json",
                expected_journal,
            )
            return value

        def health_checker(**kwargs: object) -> None:
            calls.append("health")
            self.assertIsNotNone(kwargs["deadline"])
            self.assertEqual(self.codex_home, kwargs["codex_home"])
            self.assertEqual(self.state_home, kwargs["state_home"])
            self.assertEqual(self.activation_id, kwargs["activation_id"])

        self.assertEqual(
            "MISSING",
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=time.monotonic() + 1,
                absence_checker=absence_checker,
                health_checker=health_checker,
            ),
        )

        self.assertEqual(["absence", "health", "absence", "health"], calls)

    def test_stop_rechecks_absence_and_health_with_one_absolute_deadline(self) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        self._write_schema_routes_database(database_id, include_route=False)
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)
        deadline = time.monotonic() + 0.75
        observed_deadlines: list[float | None] = []
        observed_operation_deadlines: list[object | None] = []
        health_remaining_budgets: list[int | None] = []

        def absence_checker(
            _value: object,
            *,
            expected_journal: Path,
            deadline: float | None = None,
        ) -> object:
            self.assertEqual(
                self.codex_home
                / "install-manifests"
                / "codex-smart-subagents-v2.transaction.json",
                expected_journal,
            )
            observed_deadlines.append(deadline)
            observed_operation_deadlines.append(
                runtime.operation_deadline_v2.current_operation_deadline_v2()
            )
            return _value

        def health_checker(
            *,
            codex_home: Path,
            state_home: Path,
            activation_id: str,
            deadline: float | None = None,
        ) -> None:
            self.assertEqual(self.codex_home, codex_home)
            self.assertEqual(self.state_home, state_home)
            self.assertEqual(self.activation_id, activation_id)
            observed_deadlines.append(deadline)
            observed_operation_deadlines.append(
                runtime.operation_deadline_v2.current_operation_deadline_v2()
            )
            current = runtime.operation_deadline_v2.current_operation_deadline_v2()
            health_remaining_budgets.append(
                None if current is None else current.remaining_nanoseconds()
            )

        self.assertEqual(
            "MISSING",
            runtime.durable_stop_smart_turn_state_v2(
                config,
                self.record,
                environ=environment,
                deadline=deadline,
                absence_checker=absence_checker,
                health_checker=health_checker,
            ),
        )

        self.assertEqual([deadline, deadline, deadline, deadline], observed_deadlines)
        self.assertTrue(all(item is not None for item in observed_operation_deadlines))
        self.assertEqual(2, len(health_remaining_budgets))
        self.assertTrue(
            all(
                remaining is not None and 0 < remaining <= 750_000_000
                for remaining in health_remaining_budgets
            )
        )

    def test_resume_binding_uses_pinned_database_without_waiting_for_controller(
        self,
    ) -> None:
        runtime = sys.modules["integration_runtime_v2"]
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=False,
        )
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        config = IntegrationConfigV2.from_environ(environment)

        with (
            mock.patch.object(
                runtime,
                "refresh_activation_journal_absence_v2",
                return_value=None,
            ),
            mock.patch.object(
                runtime,
                "require_pinned_controller_health_v2",
                side_effect=AssertionError(
                    "SessionStart не должен ждать живой контроллер; "
                    "UserPromptSubmit проверит его перед первым запросом"
                ),
            ),
            mock.patch.object(
                runtime,
                "ActivationResolver",
                side_effect=AssertionError("SessionStart не должен запускать resolve"),
            ),
        ):
            binding = runtime.pinned_resume_binding_v2(
                config,
                environment,
                deadline=time.monotonic() + 1,
            )

        self.assertEqual(database_path, binding.database_path)
        self.assertEqual(
            self.compatibility_fingerprint,
            binding.compatibility_fingerprint,
        )

    def test_user_prompt_falls_back_when_required_mcp_contract_is_unproved(
        self,
    ) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_unproved_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }

        def unproved(_plugin_root: Path) -> None:
            raise IntegrationV2Error("обязательные инструменты не доказаны")

        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        response = module.handle(
            payload,
            environment,
            v2_mcp_contract_checker=unproved,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        with self.assertRaises(IntegrationV2Error):
            TurnContextStoreV2(self.config).load()

    def test_user_prompt_requires_live_controller_before_writing_turn(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_dead_controller_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)

        def dead_controller(
            _config: IntegrationConfigV2,
            _environ: Mapping[str, str],
            *,
            deadline: float,
        ) -> None:
            self.assertGreater(deadline, time.monotonic())
            raise IntegrationV2Error("контроллер завершился после tools/list")

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-from-hook",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=dead_controller,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        self.assertFalse(TurnContextStoreV2(self.config).path.exists())

    def test_missing_compatibility_proof_has_no_smart_instruction(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_missing_compatibility_proof_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-no-compatibility-proof",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertNotIn("hookSpecificOutput", response)
        self.assertFalse(TurnContextStoreV2(self.config).path.exists())

    def test_thread_capacity_exhaustion_disables_smart_turn_not_root_request(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_thread_capacity_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-capacity-exhausted",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                IntegrationV2Error("MAX_THREADS_EXHAUSTED")
            ),
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertNotIn("hookSpecificOutput", response)

    def test_resume_user_prompt_classifies_runtime_errors_without_exception_details(
        self,
    ) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_resume_runtime_error_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"

        def damaged_contract(_plugin_root: Path) -> None:
            raise IntegrationV2Error("контракт повреждён: /tmp/private/path")

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-from-hook",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=damaged_contract,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertNotIn("/tmp/private/path", json.dumps(response))
        self.assertNotIn("IntegrationV2Error", json.dumps(response))

    def test_second_resumed_prompt_without_attachment_is_a_fresh_smart_turn(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_resume_without_attachment_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"

        response = module.handle(
            {
                "session_id": "session-from-hook",
                "turn_id": "turn-second",
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=self._controller_binding,
        )

        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertIn("hookSpecificOutput", response)
        self.assertIn(
            "Умный режим версии 2 активен",
            response["hookSpecificOutput"]["additionalContext"],
        )
        self.assertEqual("turn-second", TurnContextStoreV2(self.config).load().turn_id)

    def test_resume_lease_lock_failure_is_fail_open_without_stop_reason(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_resume_lease_busy_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)

        with mock.patch.object(
            module.RootSessionLeaseStoreV2,
            "load",
            side_effect=RuntimeError("RESUME_LEASE_BUSY"),
        ):
            response = module.handle(
                {
                    "session_id": "session-from-hook",
                    "turn_id": "turn-lock-busy",
                    "cwd": str(ROOT),
                    "hook_event_name": "UserPromptSubmit",
                },
                environment,
                v2_mcp_contract_checker=lambda _plugin_root: None,
                v2_controller_checker=lambda _config, _environ, *, deadline: (
                    PinnedResumeBindingV2(
                        self.state_home / "owner.sqlite3",
                        self.compatibility_fingerprint,
                    )
                ),
            )

        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())

    def test_other_live_owner_keeps_old_lease_and_current_root_gets_fresh_turn(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_other_live_owner_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "current-root"
        old_project = ProjectIdentityV2(
            repo_root=str(ROOT),
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
            compatibility_fingerprint=self.compatibility_fingerprint,
        )
        fake_store = mock.Mock()
        fake_store.load.return_value = SimpleNamespace(
            project=old_project,
            attachment=None,
        )
        fake_store.begin_resume_claim.side_effect = ResumeSessionV2Error(
            "RESUME_ATTACHMENT_CHANGED",
            "SESSION_OWNER_ACTIVE",
        )

        with mock.patch.object(
            module,
            "RootSessionLeaseStoreV2",
            return_value=fake_store,
        ):
            response = module.handle(
                {
                    "session_id": "session-from-hook",
                    "turn_id": "turn-current-root",
                    "cwd": str(ROOT),
                    "hook_event_name": "UserPromptSubmit",
                },
                environment,
                v2_mcp_contract_checker=lambda _plugin_root: None,
                v2_controller_checker=lambda _config, _environ, *, deadline: (
                    PinnedResumeBindingV2(
                        self.state_home / "owner.sqlite3",
                        self.compatibility_fingerprint,
                    )
                ),
            )

        self.assertIn("hookSpecificOutput", response)
        self.assertIn(
            "Умный режим версии 2 активен",
            response["hookSpecificOutput"]["additionalContext"],
        )
        fake_store.begin_resume_claim.assert_called_once()
        fake_store.finalize_resume_claim.assert_not_called()

    def test_user_prompt_requires_current_policy_before_mcp_attestation(
        self,
    ) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_proofs_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }
        store = TurnContextStoreV2(self.config)

        valid = self._environment()
        valid[MCP_SESSION_NONCE_ENV_V2] = "mcpn2_" + "f" * 64
        valid[USER_MCP_POLICY_PROOF_ENV_V2] = (
            build_user_mcp_policy_proof_v2(self.codex_home)
        )
        response = module.handle(
            payload,
            valid,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=self._controller_binding,
        )
        self.assertIn("hookSpecificOutput", response)
        self.assertEqual("turn-from-hook", store.load().turn_id)
        store.path.unlink()

        missing_proof = dict(valid)
        missing_proof.pop(USER_MCP_POLICY_PROOF_ENV_V2)
        response = module.handle(
            payload,
            missing_proof,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        self.assertFalse(store.path.exists())

        damaged_proof = dict(valid)
        damaged_proof[USER_MCP_POLICY_PROOF_ENV_V2] = "damaged"
        response = module.handle(
            payload,
            damaged_proof,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)
        self.assertFalse(store.path.exists())

    def test_stop_uses_current_policy_before_mcp_attestation(self) -> None:
        environment = self._environment()
        environment[MCP_SESSION_NONCE_ENV_V2] = "mcpn2_" + "f" * 64
        environment[USER_MCP_POLICY_PROOF_ENV_V2] = (
            build_user_mcp_policy_proof_v2(self.codex_home)
        )
        TurnContextStoreV2(self.config).save(self.record)
        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_pre_attestation_test",
            stop_path,
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)

        response = stop_module.handle(
            {
                "session_id": self.record.session_id,
                "turn_id": self.record.turn_id,
                "hook_event_name": "Stop",
            },
            environment,
            v2_plan_state_provider=(
                lambda _config, _record, *, environ, deadline: "MISSING"
            ),
        )

        self.assertEqual("block", response["decision"])
        self.assertIn("smart_plan", response["reason"])
        self.assertEqual(
            1,
            TurnContextStoreV2(self.config).load().continuation_count,
        )

    def test_unrelated_config_rewrite_keeps_user_prompt_active(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self.user_config.write_bytes(
            self.user_config.read_bytes()
            + (
                b'\n[hooks.state."managed-hook"]\n'
                b'trusted_hash = "sha256:' + b"a" * 64 + b'"\n'
            )
        )
        self.user_config.chmod(0o600)
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_unrelated_rewrite_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)
        response = prompt_module.handle(
            {
                "session_id": self.record.session_id,
                "turn_id": self.record.turn_id,
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=self._controller_binding,
        )
        self.assertIn("hookSpecificOutput", response)
        self.assertEqual(
            self.record.turn_id,
            TurnContextStoreV2(self.config).load().turn_id,
        )

    def test_target_policy_change_and_missing_proof_never_enter_stop_cycle(
        self,
    ) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self.user_config.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = false\n",
            encoding="utf-8",
        )
        self.user_config.chmod(0o600)
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_changed_policy_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)
        response = prompt_module.handle(
            {
                "session_id": self.record.session_id,
                "turn_id": self.record.turn_id,
                "cwd": str(ROOT),
                "hook_event_name": "UserPromptSubmit",
            },
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=lambda _config, _environ, *, deadline: None,
        )
        self.assertNotIn("hookSpecificOutput", response)

        TurnContextStoreV2(self.config).save(self.record)
        environment.pop(USER_MCP_POLICY_PROOF_ENV_V2)
        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_missing_proof_test",
            stop_path,
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)

        self.assertIsNone(
            stop_module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=lambda *_args, **_kwargs: self.fail(
                    "Stop не должен читать план без proof"
                ),
            )
        )
        self.assertEqual(0, TurnContextStoreV2(self.config).load().continuation_count)

    def test_bounded_resumed_route_hands_off_to_next_user_prompt(self) -> None:
        database_id = "db2_" + "f" * 32
        database_path = self._write_schema_routes_database(
            database_id,
            include_route=True,
            state="RUNNING",
        )
        self._write_active_manifest(database_id)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        repo_root, base_sha, worktree_fingerprint = _git_identity(
            str(ROOT),
            deadline=time.monotonic() + 2,
        )
        current = HookTurnContextV2(
            shell_session_id=self.config.shell_session_id,
            session_id="session-from-hook",
            turn_id="turn-from-hook",
            codex_home=str(self.codex_home),
            repo_root=repo_root,
            base_sha=base_sha,
            worktree_fingerprint=worktree_fingerprint,
        )
        project = ProjectIdentityV2(
            repo_root=repo_root,
            base_sha=base_sha,
            worktree_fingerprint=worktree_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
        )
        root = RootIdentityV2(
            pid=os.getpid(),
            process_start_marker="test-root-start",
        )
        store = RootSessionLeaseStoreV2(
            self.state_home,
            process_marker_reader=(
                lambda pid: "test-root-start" if pid == os.getpid() else None
            ),
        )
        original_root = RootIdentityV2(
            pid=999999,
            process_start_marker="old-root-start",
        )
        store.register_startup(
            session_id=current.session_id,
            shell_session_id=self.config.shell_session_id,
            root=original_root,
            project=project,
        )
        candidate = ResumeCandidateV2(
            route_id="route2_" + "1" * 32,
            original_shell_session_id=self.config.shell_session_id,
            original_session_id=current.session_id,
            original_turn_id="turn-original",
            route_state="RUNNING",
            start_request_id="sr2_" + "2" * 32,
            node_id="node2_" + "3" * 32,
            terminal_result_unacknowledged=False,
        )
        self.assertEqual(
            "RESUME_PREPARED",
            store.prepare_resume(
                session_id=current.session_id,
                shell_session_id=self.config.shell_session_id,
                root=root,
                project=project,
                candidate=candidate,
            ).status,
        )
        store.bind_resume(
            session_id=current.session_id,
            shell_session_id=self.config.shell_session_id,
            turn_id=current.turn_id,
            root=root,
            project=project,
        )
        TurnContextStoreV2(self.config).save(current)
        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_resume_handoff_test",
            stop_path,
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)

        with mock.patch.object(
            stop_module,
            "system_process_marker_reader_v2",
            side_effect=lambda pid: "test-root-start" if pid == os.getpid() else None,
        ):
            for _attempt in range(2):
                self.assertEqual(
                    "block",
                    stop_module.handle(
                        {
                            "session_id": current.session_id,
                            "turn_id": current.turn_id,
                            "hook_event_name": "Stop",
                        },
                        environment,
                        v2_plan_state_provider=(
                            lambda _config, _record, *, environ, deadline: (
                                "DELEGATE_PENDING"
                            )
                        ),
                    )["decision"],
                )
            bounded = stop_module.handle(
                {
                    "session_id": current.session_id,
                    "turn_id": current.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: (
                        "DELEGATE_PENDING"
                    )
                ),
            )

        self.assertTrue(bounded["continue"])
        self.assertEqual(
            "PENDING_NEXT_TURN",
            store.load(current.session_id).attachment.state,
        )
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_resume_handoff_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)

        with mock.patch.object(
            prompt_module,
            "system_process_marker_reader_v2",
            side_effect=lambda pid: "test-root-start" if pid == os.getpid() else None,
        ):
            response = prompt_module.handle(
                {
                    "session_id": current.session_id,
                    "turn_id": "turn-next",
                    "cwd": repo_root,
                    "hook_event_name": "UserPromptSubmit",
                },
                environment,
                v2_mcp_contract_checker=lambda _plugin_root: None,
                v2_controller_checker=lambda _config, _environ, *, deadline: (
                    PinnedResumeBindingV2(
                        database_path,
                        self.compatibility_fingerprint,
                    )
                ),
            )

        self.assertIn("hookSpecificOutput", response)
        self.assertIn(
            "Возобновлён умный маршрут предыдущего хода",
            response["hookSpecificOutput"]["additionalContext"],
        )
        self.assertIn(
            "smart_wait",
            response["hookSpecificOutput"]["additionalContext"],
        )
        rebound = store.load(current.session_id)
        self.assertEqual("BOUND", rebound.attachment.state)
        self.assertEqual("turn-next", rebound.attachment.bound_turn_id)

    def test_live_compatibility_mismatch_detaches_instead_of_binding_old_route(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        repo_root, base_sha, worktree_fingerprint = _git_identity(
            str(ROOT), deadline=time.monotonic() + 2
        )
        old_compatibility = "a" * 64
        live_compatibility = "b" * 64
        project = ProjectIdentityV2(
            repo_root=repo_root,
            base_sha=base_sha,
            worktree_fingerprint=worktree_fingerprint,
            compatibility_fingerprint=old_compatibility,
        )
        root = RootIdentityV2(os.getpid(), "test-root-start")
        store = RootSessionLeaseStoreV2(
            self.state_home,
            process_marker_reader=(
                lambda pid: "test-root-start" if pid == os.getpid() else None
            ),
        )
        store.register_startup(
            session_id="session-from-hook",
            shell_session_id=self.config.shell_session_id,
            root=RootIdentityV2(999999, "old-root-start"),
            project=project,
        )
        candidate = ResumeCandidateV2(
            route_id="route2_" + "1" * 32,
            original_shell_session_id=self.config.shell_session_id,
            original_session_id="session-from-hook",
            original_turn_id="turn-original",
            route_state="RUNNING",
            start_request_id="sr2_" + "2" * 32,
            node_id="node2_" + "3" * 32,
            terminal_result_unacknowledged=False,
        )
        store.prepare_resume(
            session_id="session-from-hook",
            shell_session_id=self.config.shell_session_id,
            root=root,
            project=project,
            candidate=candidate,
        )
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_live_compatibility_mismatch_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)

        with mock.patch.object(
            prompt_module,
            "system_process_marker_reader_v2",
            side_effect=lambda pid: (
                "test-root-start" if pid == os.getpid() else None
            ),
        ):
            response = prompt_module.handle(
                {
                    "session_id": "session-from-hook",
                    "turn_id": "turn-live-compatibility",
                    "cwd": repo_root,
                    "hook_event_name": "UserPromptSubmit",
                },
                environment,
                v2_mcp_contract_checker=lambda _plugin_root: None,
                v2_controller_checker=lambda _config, _environ, *, deadline: (
                    PinnedResumeBindingV2(
                        self.state_home / "live.sqlite3",
                        live_compatibility,
                    )
                ),
            )

        self.assertIn("hookSpecificOutput", response)
        context = response["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Умный режим версии 2 активен", context)
        self.assertNotIn(candidate.route_id, context)
        self.assertNotIn(candidate.start_request_id, context)
        lease = store.load("session-from-hook")
        self.assertEqual("DETACHED", lease.attachment.state)
        self.assertEqual(live_compatibility, lease.project.compatibility_fingerprint)

    def test_next_prompt_recovers_claim_after_context_write_before_finalize(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        repo_root, base_sha, worktree_fingerprint = _git_identity(
            str(ROOT), deadline=time.monotonic() + 2
        )
        project = ProjectIdentityV2(
            repo_root=repo_root,
            base_sha=base_sha,
            worktree_fingerprint=worktree_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
        )
        root = RootIdentityV2(os.getpid(), "test-root-start")
        store = RootSessionLeaseStoreV2(
            self.state_home,
            process_marker_reader=(
                lambda pid: "test-root-start" if pid == os.getpid() else None
            ),
        )
        store.register_startup(
            session_id="session-from-hook",
            shell_session_id=self.config.shell_session_id,
            root=RootIdentityV2(999999, "old-root-start"),
            project=project,
        )
        candidate = ResumeCandidateV2(
            route_id="route2_" + "1" * 32,
            original_shell_session_id=self.config.shell_session_id,
            original_session_id="session-from-hook",
            original_turn_id="turn-original",
            route_state="RUNNING",
            start_request_id=None,
            node_id="node2_" + "3" * 32,
            terminal_result_unacknowledged=False,
        )
        store.prepare_resume(
            session_id="session-from-hook",
            shell_session_id=self.config.shell_session_id,
            root=root,
            project=project,
            candidate=candidate,
        )
        interrupted = store.begin_resume_claim(
            session_id="session-from-hook",
            shell_session_id=self.config.shell_session_id,
            turn_id="turn-interrupted",
            root=root,
            project=project,
        )
        TurnContextStoreV2(self.config).save(
            HookTurnContextV2(
                shell_session_id=self.config.shell_session_id,
                session_id="session-from-hook",
                turn_id="turn-interrupted",
                codex_home=str(self.codex_home),
                repo_root=repo_root,
                base_sha=base_sha,
                worktree_fingerprint=worktree_fingerprint,
                resume_claim_nonce=interrupted.claim_nonce,
            )
        )
        prompt_path = PLUGIN / "hooks" / "user_prompt_submit.py"
        prompt_spec = importlib.util.spec_from_file_location(
            "smart_prompt_claim_recovery_test",
            prompt_path,
        )
        assert prompt_spec is not None and prompt_spec.loader is not None
        prompt_module = importlib.util.module_from_spec(prompt_spec)
        sys.modules[prompt_spec.name] = prompt_module
        prompt_spec.loader.exec_module(prompt_module)

        with mock.patch.object(
            prompt_module,
            "system_process_marker_reader_v2",
            side_effect=lambda pid: (
                "test-root-start" if pid == os.getpid() else None
            ),
        ):
            response = prompt_module.handle(
                {
                    "session_id": "session-from-hook",
                    "turn_id": "turn-after-recovery",
                    "cwd": repo_root,
                    "hook_event_name": "UserPromptSubmit",
                },
                environment,
                v2_mcp_contract_checker=lambda _plugin_root: None,
                v2_controller_checker=lambda _config, _environ, *, deadline: (
                    PinnedResumeBindingV2(
                        self.state_home / "recovery.sqlite3",
                        self.compatibility_fingerprint,
                    )
                ),
            )

        self.assertIn("hookSpecificOutput", response)
        self.assertIn(
            "route_start",
            response["hookSpecificOutput"]["additionalContext"],
        )
        recovered = store.load("session-from-hook")
        self.assertEqual("BOUND", recovered.attachment.state)
        self.assertEqual("turn-after-recovery", recovered.attachment.bound_turn_id)
        current_context = TurnContextStoreV2(self.config).load()
        self.assertEqual("turn-after-recovery", current_context.turn_id)
        self.assertNotEqual(interrupted.claim_nonce, current_context.resume_claim_nonce)

    def test_user_prompt_hook_writes_v2_turn_and_names_only_v2_tools(self) -> None:
        path = PLUGIN / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location("smart_prompt_hook_v2_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "cwd": str(ROOT),
            "hook_event_name": "UserPromptSubmit",
        }

        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        response = module.handle(
            payload,
            environment,
            v2_mcp_contract_checker=lambda _plugin_root: None,
            v2_controller_checker=self._controller_binding,
        )

        self.assertTrue(response["continue"])
        context = response["hookSpecificOutput"]["additionalContext"]
        self.assertIn("route_start", context)
        self.assertNotIn("smart_start", context)
        self.assertIn("using-smart-subagents", context)
        self.assertIn("до вызова smart_plan", context.lower())
        self.assertIn("прямое имя", context)
        self.assertNotIn("ALL_TOOLS", context)
        saved = TurnContextStoreV2(self.config).load()
        self.assertEqual("session-from-hook", saved.session_id)
        self.assertEqual("turn-from-hook", saved.turn_id)

        stop_path = PLUGIN / "hooks" / "stop.py"
        stop_spec = importlib.util.spec_from_file_location(
            "smart_stop_hook_v2_test", stop_path
        )
        assert stop_spec is not None and stop_spec.loader is not None
        stop_module = importlib.util.module_from_spec(stop_spec)
        sys.modules[stop_spec.name] = stop_module
        stop_spec.loader.exec_module(stop_module)
        stop_payload = {
            "session_id": "session-from-hook",
            "turn_id": "turn-from-hook",
            "hook_event_name": "Stop",
        }
        for expected_count in (1, 2):
            continuation = stop_module.handle(
                stop_payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "MISSING"
                ),
            )
            self.assertEqual("block", continuation["decision"])
            self.assertIn("smart_plan", continuation["reason"])
            self.assertNotIn("continue", continuation)
            self.assertNotIn("hookSpecificOutput", continuation)
            self.assertEqual(
                expected_count,
                TurnContextStoreV2(self.config).load().continuation_count,
            )

        bounded = stop_module.handle(
            stop_payload,
            environment,
            v2_plan_state_provider=(
                lambda _config, _record, *, environ, deadline: "MISSING"
            ),
        )
        self.assertTrue(bounded["continue"])
        self.assertIn("двух попыток", bounded["systemMessage"].lower())
        self.assertEqual(2, TurnContextStoreV2(self.config).load().continuation_count)

        self.assertIsNone(
            stop_module.handle(
                stop_payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "DIRECT"
                ),
            )
        )
        environment = self._environment()
        del environment["CODEX_SMART_GATE_FINGERPRINT"]
        with self.assertRaises(IntegrationV2Error):
            IntegrationConfigV2.from_environ(environment)

    def test_v2_stop_uses_one_bounded_turn_lock_acquisition(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location("smart_stop_one_lock_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        runtime = sys.modules["integration_runtime_v2"]
        original = runtime.finite_file_lock_v2.acquire_flock_v2

        with mock.patch.object(
            runtime.finite_file_lock_v2,
            "acquire_flock_v2",
            wraps=original,
        ) as acquire:
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "MISSING"
                ),
            )

        self.assertEqual("block", response["decision"])
        self.assertEqual(1, acquire.call_count)
        self.assertLessEqual(
            acquire.call_args.kwargs["timeout_seconds"],
            runtime.HOOK_TOTAL_BUDGET_SECONDS,
        )

    def test_v2_stop_direct_without_resume_attachment_skips_full_resolve(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_direct_without_resume_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        with mock.patch.object(
            module,
            "FreshActivationProviderV2",
            side_effect=AssertionError("Stop не должен запускать полный resolve"),
            create=True,
        ):
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "DIRECT"
                ),
            )

        self.assertIsNone(response)

    def test_v2_stop_acknowledges_resume_through_pinned_deadline(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_pinned_acknowledgement_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        route_id = "route2_" + "1" * 32
        lease = SimpleNamespace(
            attachment=SimpleNamespace(
                candidate=SimpleNamespace(route_id=route_id),
            ),
        )
        lease_store = mock.Mock()
        lease_store.load.return_value = lease
        lease_store.authorize_route.return_value = True
        binding = PinnedResumeBindingV2(
            database_path=self.state_home / "smart-subagents.sqlite3",
            compatibility_fingerprint=self.compatibility_fingerprint,
        )
        deadline = time.monotonic() + 1.0

        with (
            mock.patch.object(
                module,
                "FreshActivationProviderV2",
                side_effect=AssertionError("Stop не должен запускать полный resolve"),
                create=True,
            ),
            mock.patch.object(
                module,
                "RootSessionLeaseStoreV2",
                return_value=lease_store,
            ),
            mock.patch.object(module, "route_is_terminal_v2", return_value=True),
            mock.patch.object(
                module,
                "pinned_resume_binding_v2",
                return_value=binding,
                create=True,
            ) as pinned_binding,
        ):
            module._acknowledge_resume_result_v2(
                self.config,
                self.record,
                environment,
                deadline=deadline,
            )

        pinned_binding.assert_called_once_with(
            self.config,
            environment,
            deadline=deadline,
        )
        lease_store.acknowledge_result.assert_called_once()

    def test_v2_stop_expired_deadline_skips_resume_lease_operations(self) -> None:
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_expired_resume_deadline_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        expired = time.monotonic() - 1.0

        with mock.patch.object(module, "RootSessionLeaseStoreV2") as lease_store:
            module._acknowledge_resume_result_v2(
                self.config,
                self.record,
                environment,
                deadline=expired,
            )
            module._defer_resume_to_next_turn_v2(
                self.config,
                self.record,
                environment,
                deadline=expired,
            )

        lease_store.assert_not_called()

    def test_v2_stop_shares_one_absolute_deadline_with_plan_check(self) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location("smart_stop_deadline_test", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        runtime = sys.modules["integration_runtime_v2"]
        original = runtime.finite_file_lock_v2.acquire_flock_v2
        lock_timeouts: list[float] = []
        provider_remaining: list[float] = []

        def delayed_lock(descriptor: int, **kwargs: object) -> None:
            timeout_seconds = float(kwargs["timeout_seconds"])
            lock_timeouts.append(timeout_seconds)
            time.sleep(0.12)
            original(
                descriptor,
                exclusive=bool(kwargs["exclusive"]),
                timeout_seconds=max(0.001, timeout_seconds - 0.12),
                timeout_code=str(kwargs["timeout_code"]),
            )

        def delayed_plan_check(
            _config: IntegrationConfigV2,
            _record: HookTurnContextV2,
            *,
            environ: Mapping[str, str],
            deadline: float,
        ) -> str:
            provider_remaining.append(deadline - time.monotonic())
            time.sleep(0.02)
            return "MISSING"

        started = time.monotonic()
        with (
            mock.patch.object(
                module,
                "HOOK_TOTAL_BUDGET_SECONDS_V2",
                0.20,
                create=True,
            ),
            mock.patch.object(
                runtime.finite_file_lock_v2,
                "acquire_flock_v2",
                side_effect=delayed_lock,
            ),
        ):
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=delayed_plan_check,
            )
        elapsed = time.monotonic() - started

        self.assertEqual("block", response["decision"])
        self.assertEqual(1, len(lock_timeouts))
        self.assertLessEqual(lock_timeouts[0], 0.20)
        self.assertEqual(1, len(provider_remaining))
        self.assertGreater(provider_remaining[0], 0)
        self.assertLess(provider_remaining[0], 0.10)
        self.assertLess(elapsed, 0.30)

    def test_v2_stop_skips_resume_acknowledgement_after_shared_deadline(
        self,
    ) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_resume_ack_deadline_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        def terminal_after_deadline(
            _config: IntegrationConfigV2,
            _record: HookTurnContextV2,
            *,
            environ: Mapping[str, str],
            deadline: float,
        ) -> str:
            time.sleep(0.08)
            return "DIRECT"

        with (
            mock.patch.object(
                module,
                "HOOK_TOTAL_BUDGET_SECONDS_V2",
                0.05,
                create=True,
            ),
            mock.patch.object(
                module,
                "_acknowledge_resume_result_v2",
                side_effect=AssertionError("ack must not run after deadline"),
            ) as acknowledge,
        ):
            response = module.handle(
                {
                    "session_id": self.record.session_id,
                    "turn_id": self.record.turn_id,
                    "hook_event_name": "Stop",
                },
                environment,
                v2_plan_state_provider=terminal_after_deadline,
            )

        self.assertEqual({"continue", "systemMessage"}, set(response))
        self.assertTrue(response["continue"])
        deferred_reason(response)
        acknowledge.assert_not_called()

    def test_v2_stop_resume_acknowledgement_error_is_fail_open_and_repeatable(
        self,
    ) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_resume_ack_error_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": self.record.session_id,
            "turn_id": self.record.turn_id,
            "hook_event_name": "Stop",
        }

        with mock.patch.object(
            module,
            "_acknowledge_resume_result_v2",
            side_effect=RuntimeError("ack failed"),
        ):
            first = module.handle(
                payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "DIRECT"
                ),
            )
            second = module.handle(
                payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "DIRECT"
                ),
            )

        for response in (first, second):
            self.assertEqual({"continue", "systemMessage"}, set(response))
            self.assertTrue(response["continue"])
            self.assertIn("resume", deferred_reason(response))

    def test_stop_parent_supervises_slow_resume_lease_route_worker(self) -> None:
        database_id = "db2_" + "f" * 32
        self._write_schema_routes_database(
            database_id,
            include_route=True,
            state="SUCCEEDED",
        )
        self._write_active_manifest(database_id)
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        self._publish_launch_gate(environment)
        environment["CODEX_SMART_LAUNCH_KIND"] = "resume"
        environment["CODEX_SMART_ROOT_PID"] = str(os.getpid())
        environment["CODEX_SMART_ROOT_START_MARKER"] = "test-root-start"
        project = ProjectIdentityV2(
            repo_root=self.record.repo_root,
            base_sha=self.record.base_sha,
            worktree_fingerprint=self.record.worktree_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
        )
        root = RootIdentityV2(
            pid=os.getpid(),
            process_start_marker="test-root-start",
        )
        lease_store = RootSessionLeaseStoreV2(
            self.state_home,
            process_marker_reader=(
                lambda pid: "test-root-start" if pid == os.getpid() else None
            ),
        )
        lease_store.register_startup(
            session_id=self.record.session_id,
            shell_session_id=self.config.shell_session_id,
            root=root,
            project=project,
        )
        candidate = ResumeCandidateV2(
            route_id="route2_" + "1" * 32,
            original_shell_session_id=self.config.shell_session_id,
            original_session_id=self.record.session_id,
            original_turn_id=self.record.turn_id,
            route_state="SUCCEEDED",
            start_request_id="sr2_" + "2" * 32,
            node_id="node2_" + "3" * 32,
            terminal_result_unacknowledged=True,
        )
        lease_store.prepare_resume(
            session_id=self.record.session_id,
            shell_session_id=self.config.shell_session_id,
            root=root,
            project=project,
            candidate=candidate,
        )
        lease_store.bind_resume(
            session_id=self.record.session_id,
            shell_session_id=self.config.shell_session_id,
            turn_id=self.record.turn_id,
            root=root,
            project=project,
        )
        marker_value: str | None = None
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "sitecustomize.py").write_text(
                "\n".join(
                    [
                        "import builtins",
                        "import os",
                        "import time",
                        "from pathlib import Path",
                        "_original_import = builtins.__import__",
                        "def _patched_import(name, globals=None, locals=None, fromlist=(), level=0):",
                        "    module = _original_import(name, globals, locals, fromlist, level)",
                        "    if name == 'integration_runtime_v2':",
                        "        module.durable_stop_smart_turn_state_v2 = lambda *args, **kwargs: 'DELEGATE_TERMINAL'",
                        "        class _Binding:",
                        "            database_path = Path(os.getenv(\"SMART_TEST_DATABASE_PATH\"))",
                        "            compatibility_fingerprint = os.getenv(\"SMART_TEST_COMPATIBILITY_FINGERPRINT\")",
                        "        module.FreshActivationProviderV2.runtime_binding = lambda self, *, deadline: _Binding()",
                        "    if name == 'codex_smart_subagents.resume_session_v2':",
                        "        module.system_process_marker_reader_v2 = lambda pid: 'test-root-start'",
                        "        original_load = module.RootSessionLeaseStoreV2.load",
                        "        def slow_load(self, session_id, *, deadline=None):",
                        "            if deadline is None:",
                        "                raise AssertionError(\"deadline was not passed to resume load\")",
                        "            marker = os.getenv(\"SMART_TEST_SLOW_LOAD_MARKER\")",
                        "            if marker:",
                        "                Path(marker).write_text(str(deadline), encoding=\"utf-8\")",
                        "            time.sleep(2.2)",
                        "            return original_load(self, session_id, deadline=deadline)",
                        "        module.RootSessionLeaseStoreV2.load = slow_load",
                        "    return module",
                        "builtins.__import__ = _patched_import",
                    ]
                ),
                encoding="utf-8",
            )
            execution_env = dict(getattr(os, "environ"))
            execution_env.update(environment)
            execution_env["PYTHONPATH"] = tmp
            marker = Path(tmp) / "slow-load-marker.txt"
            execution_env["SMART_TEST_SLOW_LOAD_MARKER"] = str(marker)
            execution_env["SMART_TEST_DATABASE_PATH"] = str(
                self.state_home
                / "databases"
                / database_id
                / "smart-subagents.sqlite3"
            )
            execution_env["SMART_TEST_COMPATIBILITY_FINGERPRINT"] = (
                self.compatibility_fingerprint
            )
            started = time.monotonic()
            result = subprocess.run(
                [str(PLUGIN / "bin" / "codex-smart-subagents-hook"), "stop"],
                input=json.dumps(
                    {
                        "session_id": self.record.session_id,
                        "turn_id": self.record.turn_id,
                        "hook_event_name": "Stop",
                    }
                ).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=execution_env,
                check=False,
                timeout=2.0,
            )
            elapsed = time.monotonic() - started
            if marker.exists():
                marker_value = marker.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
        response = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual({"continue", "systemMessage"}, set(response))
        deferred_reason(response)
        self.assertLess(elapsed, 1.75)
        self.assertIsNotNone(marker_value)
        self.assertGreater(float(marker_value or "0"), started)

    def test_v2_stop_blocks_unfinished_delegate_and_allows_terminal_route(
        self,
    ) -> None:
        TurnContextStoreV2(self.config).save(self.record)
        environment, publisher = self._proven_environment()
        self.addCleanup(publisher.cleanup)
        path = PLUGIN / "hooks" / "stop.py"
        spec = importlib.util.spec_from_file_location(
            "smart_stop_delegate_state_test",
            path,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        payload = {
            "session_id": self.record.session_id,
            "turn_id": self.record.turn_id,
            "hook_event_name": "Stop",
        }

        pending = module.handle(
            payload,
            environment,
            v2_plan_state_provider=(
                lambda _config, _record, *, environ, deadline: "DELEGATE_PENDING"
            ),
        )

        self.assertEqual("block", pending["decision"])
        self.assertIn("route_start", pending["reason"])
        self.assertIn("smart_wait", pending["reason"])
        self.assertIsNone(
            module.handle(
                payload,
                environment,
                v2_plan_state_provider=(
                    lambda _config, _record, *, environ, deadline: "DELEGATE_TERMINAL"
                ),
            )
        )

    def test_source_reconciliation_process_uses_real_supervised_group(self) -> None:
        python = str(Path(sys.executable).resolve(strict=True))
        result = gateway_module._run_source_reconciliation_process_v1(
            (python, "-c", "import sys; sys.stdout.write('accepted')"),
            timeout_seconds=180.0,
            max_output_bytes=1024 * 1024,
            environment={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": "",
                "PYTHONNOUSERSITE": "1",
            },
        )

        self.assertEqual(0, result.returncode)
        self.assertEqual(b"accepted", result.stdout)
        self.assertEqual(b"", result.stderr)

    def test_source_reconciliation_output_overflow_is_cleaned_before_return(
        self,
    ) -> None:
        python = str(Path(sys.executable).resolve(strict=True))
        with self.assertRaises(SupervisedCommandOutputLimitExceededV2):
            gateway_module._run_source_reconciliation_process_v1(
                (
                    python,
                    "-c",
                    "import os; os.write(1, b'x' * (1024 * 1024 + 1))",
                ),
                timeout_seconds=180.0,
                max_output_bytes=1024 * 1024,
                environment={
                    "PATH": "/usr/bin:/bin",
                    "PYTHONPATH": "",
                    "PYTHONNOUSERSITE": "1",
                },
            )

    def test_launch_reconciliation_failure_keeps_exact_snapshot(self) -> None:
        wrapper = PLUGIN / "bin" / "codex-smart"
        module = runpy.run_path(
            str(wrapper),
            run_name="codex_smart_failure_integration_test",
        )
        globals_ = module["main"].__globals__
        live = self.root / "live-codex"
        live.write_bytes(b"new")
        live.chmod(0o500)
        snapshot = self.root / "snapshot-codex"
        snapshot.write_bytes(b"old")
        snapshot.chmod(0o500)
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=snapshot,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.catalog,
            source_drift=SourceDriftV1(
                lexical_path=live,
                resolved_path=live,
                observed_sha256="c" * 64,
                expected_sha256="d" * 64,
            ),
        )
        for failure in ("exception", "retry-after"):
            with self.subTest(failure=failure):
                gateway_decisions: list[GatewayDecision] = []
                error = StringIO()

                def reconcile(**_kwargs):
                    if failure == "exception":
                        raise OSError("private failure")
                    return (
                        SimpleNamespace(outcome="RETRY_AFTER", restart=False),
                        self.root / "bin/codex-smart",
                    )

                def gateway(_arguments, **kwargs):
                    gateway_decisions.append(kwargs["resolver"].resolve())
                    return 17

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                        clear=True,
                    ),
                    mock.patch.object(sys, "argv", [str(wrapper), "задача"]),
                    mock.patch.dict(
                        globals_,
                        {
                            "v2_gateway_state_present": lambda _layout: True,
                            "_prepare_v2_decision": lambda **_kwargs: decision,
                            "_reconcile_source_drift": reconcile,
                            "run_permanent_gateway": gateway,
                        },
                    ),
                    redirect_stderr(error),
                ):
                    self.assertEqual(17, globals_["main"]())

                self.assertEqual([decision], gateway_decisions)
                self.assertEqual(1, error.getvalue().count("SOURCE_UPDATE_"))
                self.assertIn("SOURCE_UPDATE_RETRY_AFTER", error.getvalue())


if __name__ == "__main__":
    unittest.main()
