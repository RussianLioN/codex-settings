from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    capture_file_projection_v2,
    capture_tree_projection_v2,
)
from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayLayout,
)
from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    CandidateReadyReconnectV2,
    CandidateSpawnActionV2,
    create_candidate_dispatch_intent_receipt_v2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.installer_rollback_composition_v2 import (  # noqa: E402
    ROLLBACK_MATCHED_ACTIVE_STEPS_V2,
    InstallerRollbackCompositionV2Error,
    RollbackExternalStepBindingsV2,
    _absence_projection,
    _activation_link_restore_binding,
    _forward_only_definition,
    _journal_action,
    _journal_projection,
    _manifest_restore_binding,
    build_rollback_composition_v2,
    read_rollback_external_artifacts_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    FailurePointV2,
    InjectedCrashV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    StoppedControllerLineageV2,
    TerminalDefinitionV2,
    TransitionSourceReceiptV2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UpdateStepPortV2,
)
from codex_smart_subagents.installer_update_composition_v2 import (  # noqa: E402
    CandidateSpawnAuthorizationStoreV2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.rollback_manifest_preparation_v2 import (  # noqa: E402
    RollbackManifestPreparationExecutorV2,
    prepared_rollback_manifest_from_receipt_v2,
)
from codex_smart_subagents.rollback_runtime_bindings_v2 import (  # noqa: E402
    _recover_candidate_authorization,
    _rehydrate_predecessor_shutdown_lineage_v2,
    _wrap_candidate_authorization_port,
    build_rollback_runtime_external_bindings_v2,
    recover_rollback_runtime_external_bindings_v2,
    rehydrate_rollback_evidence_v2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    SmartStoreV2,
)
from tests.smart_subagents import (  # noqa: E402
    test_installer_rollback_composition_v2 as rollback_fixture,
    test_rollback_manifest_preparation_v2 as preparation_fixture,
)


class _RegistryRunner:
    def __init__(
        self,
        *,
        current_marketplace: Path,
        previous_marketplace: Path,
        plugin_relative: Path,
    ) -> None:
        self.current_marketplace = current_marketplace
        self.previous_marketplace = previous_marketplace
        self.plugin_relative = plugin_relative
        self.marketplace: Path | None = current_marketplace
        self.plugin_enabled = True
        self.calls: list[tuple[str, ...]] = []

    def write_config(self, codex_home: Path) -> None:
        marketplace = (
            ""
            if self.marketplace is None
            else "[marketplaces.codex-settings-adaptive]\n"
        )
        plugin = (
            ""
            if not self.plugin_enabled
            else (
                '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
                "enabled = true\n"
            )
        )
        path = codex_home / "config.toml"
        path.write_text("unrelated = 7\n" + marketplace + plugin, encoding="utf-8")
        path.chmod(0o600)

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_ms: int,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, timeout_ms
        self.calls.append(argv)
        command = argv[1:]
        if command == ("plugin", "marketplace", "list", "--json"):
            marketplaces = []
            if self.marketplace is not None:
                path = str(self.marketplace)
                marketplaces.append(
                    {
                        "name": "codex-settings-adaptive",
                        "root": path,
                        "marketplaceSource": {
                            "sourceType": "local",
                            "source": path,
                        },
                    }
                )
            stdout = json.dumps({"marketplaces": marketplaces})
        elif command == ("plugin", "list", "--json"):
            installed = []
            if self.plugin_enabled and self.marketplace is not None:
                marketplace = str(self.marketplace)
                installed.append(
                    {
                        "pluginId": ("codex-smart-subagents@codex-settings-adaptive"),
                        "name": "codex-smart-subagents",
                        "marketplaceName": "codex-settings-adaptive",
                        "version": "0.2.0",
                        "installed": True,
                        "enabled": True,
                        "source": {
                            "source": "local",
                            "path": str(self.marketplace / self.plugin_relative),
                        },
                        "marketplaceSource": {
                            "sourceType": "local",
                            "source": marketplace,
                        },
                        "installPolicy": "AVAILABLE",
                        "authPolicy": "ON_INSTALL",
                    }
                )
            stdout = json.dumps({"installed": installed, "available": []})
        elif command == (
            "plugin",
            "remove",
            "codex-smart-subagents@codex-settings-adaptive",
        ):
            self.plugin_enabled = False
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"removed": True})
        elif command == (
            "plugin",
            "marketplace",
            "remove",
            "codex-settings-adaptive",
        ):
            self.marketplace = None
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"removed": True})
        elif command[:3] == ("plugin", "marketplace", "add"):
            self.marketplace = Path(command[3]).resolve(strict=True)
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"name": "codex-settings-adaptive"})
        elif command == (
            "plugin",
            "add",
            "codex-smart-subagents@codex-settings-adaptive",
        ):
            self.plugin_enabled = True
            self.write_config(Path(env["CODEX_HOME"]))
            stdout = json.dumps({"installed": True})
        else:
            return subprocess.CompletedProcess(argv, 64, "", "unexpected command")
        return subprocess.CompletedProcess(argv, 0, stdout, "")


class _FakeProcess:
    def wait(self) -> int:
        return 0


class RollbackRuntimeBindingsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = rollback_fixture.InstallerRollbackCompositionV2Tests(
            methodName=("test_prepared_manifest_is_bound_to_swapped_receipt_pointers")
        )
        self.fixture.setUp()
        self.root = self.fixture.root
        self.state_home = self.root / "state"
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        (self.codex_home / "install-manifests").mkdir(mode=0o700)
        self.codex_binary = self.root / "bin/codex"
        self.codex_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.codex_binary.chmod(0o700)
        self.plugin_relative = Path("plugins/codex-smart-subagents")
        self._replace_launcher_layout()
        self._write_activation_contracts()
        self._create_controller_databases()
        self._refresh_evidence()
        self._refresh_installer_receipt()
        self.artifacts = read_rollback_external_artifacts_v2(
            evidence=self.fixture.evidence,
            installer_receipt_path=self.fixture.installer_receipt_path,
        )
        self.registry = _RegistryRunner(
            current_marketplace=self.artifacts.current_registered_marketplace,
            previous_marketplace=self.artifacts.previous_registered_marketplace,
            plugin_relative=self.plugin_relative,
        )
        self.registry.write_config(self.codex_home)
        self.readiness_token = "rollback-ready-secret-000000000000"
        self.popen_calls: list[dict[str, object]] = []
        self.main_journal_path = (
            self.codex_home
            / "install-manifests/codex-smart-subagents-v2.transaction.json"
        )
        self.authorization_path = self.fixture.evidence.receipts_root / (
            f"{self.fixture.rollback_operation_id}.candidate-spawn.authorization.json"
        )

    def tearDown(self) -> None:
        self.controller_socket.close()
        self.fixture.tearDown()

    def test_full_factory_builds_every_previous_runtime_binding(self) -> None:
        bindings = self._fresh_bindings()

        self.assertIsInstance(bindings, RollbackExternalStepBindingsV2)
        self.assertEqual(
            {
                "maintenance_begin",
                "wait_runtime_quiescent",
                "maintenance_strengthen",
                "controller_shutdown",
                "shutdown_socket_cleanup",
                "registry_restore",
                "launchers_restore",
                "controller_candidate_spawn",
                "controller_previous_accept",
                "verify_candidate",
                "maintenance_resume",
            },
            {
                kind
                for kind in (
                    "maintenance_begin",
                    "wait_runtime_quiescent",
                    "maintenance_strengthen",
                    "controller_shutdown",
                    "shutdown_socket_cleanup",
                    "registry_restore",
                    "launchers_restore",
                    "controller_candidate_spawn",
                    "controller_previous_accept",
                    "verify_candidate",
                    "maintenance_resume",
                )
                if bindings.require(kind).definition.kind == kind
            },
        )
        registry = bindings.require("registry_restore").definition
        self.assertEqual(
            str(self.artifacts.current_registered_marketplace),
            registry.before.value["marketplacePath"],
        )
        self.assertEqual(
            str(self.artifacts.previous_registered_marketplace),
            registry.expected_after.value["marketplacePath"],
        )
        spawn = bindings.require("controller_candidate_spawn").definition
        accept = bindings.require("controller_previous_accept").definition
        self.assertEqual(
            self.fixture.evidence.previous_activation_id,
            spawn.action["activationId"],
        )
        self.assertEqual(
            self.fixture.evidence.previous_database_binding.value["databaseId"],
            spawn.action["databaseId"],
        )
        self.assertEqual(
            ".r-" + self.fixture.rollback_operation_id[-12:] + ".sock",
            Path(spawn.action["privateReadyChannelPath"]).name,
        )
        self.assertEqual(spawn.expected_after, accept.before)
        self.assertEqual("EXPECTED_REGISTRATION", accept.before.value["status"])
        self.assertEqual("controller_accept", accept.action["method"])
        self.assertTrue(self.registry.calls)
        self.assertTrue(
            all(
                Path(argv[0])
                == self.snapshot_paths[rollback_fixture.PREVIOUS_ACTIVATION_ID]
                for argv in self.registry.calls
            )
        )
        self.assertTrue(
            all(Path(argv[0]) != self.codex_binary for argv in self.registry.calls)
        )

        composition = self._composition(bindings)
        self.assertEqual(
            spawn,
            next(
                step
                for step in composition.definition.mutable_steps
                if step.kind == "controller_candidate_spawn"
            ),
        )

    def test_fresh_factory_derives_previous_accept_epochs_from_stopped_database(
        self,
    ) -> None:
        bindings = self._fresh_bindings()
        accept = bindings.require("controller_previous_accept").definition
        resume = bindings.require("maintenance_resume").definition

        self.assertEqual(4, accept.action["expectedControlEpoch"])
        self.assertEqual(5, accept.expected_after.value["controlEpoch"])
        self.assertEqual(5, resume.action["expectedControlEpoch"])
        self.assertEqual(6, resume.expected_after.value["controlEpoch"])
        self.assertIs(False, resume.expected_after.value["quiescent"])

    def test_fresh_factory_rejects_previous_orphan_from_another_update(self) -> None:
        previous_path = self.state_home / "previous.sqlite3"
        with closing(sqlite3.connect(previous_path)) as connection:
            connection.execute(
                "update controller_state set operation_id=? where singleton=1",
                ("op2_" + "f" * 32,),
            )
            connection.commit()

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            self._fresh_bindings()

        self.assertEqual(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            raised.exception.code,
        )

    def test_predecessor_lineage_rejects_forged_controller_identity(self) -> None:
        current_receipt = copy.deepcopy(dict(self.fixture.evidence.current_receipt))
        lineage = current_receipt["transitionLineage"]
        assert isinstance(lineage, dict)
        stopped = lineage["stoppedController"]
        assert isinstance(stopped, dict)
        stopped["controllerIdentity"] = "f" * 64
        unsigned = {
            key: value
            for key, value in lineage.items()
            if key != "lineageFingerprint"
        }
        lineage["lineageFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            unsigned,
        )
        forged = replace(
            self.fixture.evidence,
            current_receipt=current_receipt,
        )

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            _rehydrate_predecessor_shutdown_lineage_v2(
                evidence=forged,
                previous_database=Path(
                    forged.previous_database_binding.value["path"]
                ),
            )

        self.assertEqual(
            "ROLLBACK_RUNTIME_PREDECESSOR_LINEAGE_INVALID",
            raised.exception.code,
        )

    def test_predecessor_lineage_rejects_database_controller_identity_drift(
        self,
    ) -> None:
        previous_path = Path(
            self.fixture.evidence.previous_database_binding.value["path"]
        )
        with closing(sqlite3.connect(previous_path)) as connection:
            connection.execute(
                "update controller_state set controller_identity=? where singleton=1",
                ("f" * 64,),
            )
            connection.commit()

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            _rehydrate_predecessor_shutdown_lineage_v2(
                evidence=self.fixture.evidence,
                previous_database=previous_path,
            )

        self.assertEqual(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            raised.exception.code,
        )

    def test_dispatch_crash_recovery_retains_token_until_registered_ready(self) -> None:
        fresh = self._fresh_bindings()
        spawn = fresh.require("controller_candidate_spawn")
        saved = self._composition(fresh).definition
        self._write_candidate_journal(spawn.definition, state="INTENT_DURABLE")

        self.assertTrue(self.authorization_path.exists())
        spawn.port.apply(spawn.definition)
        self.assertEqual(1, len(self.popen_calls))
        self.assertTrue(self.authorization_path.exists())
        persisted_payloads = b"\n".join(
            path.read_bytes() for path in self.root.rglob("*") if path.is_file()
        )
        self.assertIn(self.readiness_token.encode("utf-8"), persisted_payloads)

        ready_socket = self._bind_socket_node(
            Path(spawn.definition.action["privateReadyChannelPath"]),
            token="ready",
        )
        self.addCleanup(ready_socket.close)
        reconnect = self._candidate_reconnect(spawn.definition)
        recovered = recover_rollback_runtime_external_bindings_v2(
            evidence=self.fixture.evidence,
            external_artifacts=self.artifacts,
            definition=saved,
            readiness_token=None,
            codex_home=self.codex_home,
            state_home=self.state_home,
            registry_command_runner=self.registry,
            candidate_port_options={
                "candidate_reconnect": lambda **_kwargs: reconnect,
                "monotonic_ms": lambda: 10_000,
                "sleeper": lambda _seconds: None,
                "spawn_primitive": self._spawn,
            },
        )
        observed = recovered.require("controller_candidate_spawn").port.observe(
            spawn.definition
        )

        self.assertEqual("REGISTERED_READY", observed.value["status"])
        self.assertEqual(1, len(self.popen_calls))
        self.assertFalse(self.authorization_path.exists())

    def test_pre_dispatch_crash_recovers_authorization_and_calls_popen_once(
        self,
    ) -> None:
        fresh = self._fresh_bindings()
        spawn = fresh.require("controller_candidate_spawn")
        saved = self._composition(fresh).definition
        self._write_candidate_journal(spawn.definition, state="PLANNED")

        planned = self._recover(saved)
        observed = planned.require("controller_candidate_spawn").port.observe(
            spawn.definition
        )
        self.assertEqual(spawn.definition.before, observed)
        self.assertEqual([], self.popen_calls)
        self.assertTrue(self.authorization_path.exists())

        self._write_candidate_journal(spawn.definition, state="INTENT_DURABLE")
        intent = self._recover(saved)
        intent.require("controller_candidate_spawn").port.apply(spawn.definition)

        self.assertEqual(1, len(self.popen_calls))
        self.assertTrue(self.authorization_path.exists())
        self.assertIn(
            self.readiness_token.encode("utf-8"),
            b"\n".join(
                path.read_bytes() for path in self.root.rglob("*") if path.is_file()
            ),
        )

    def test_dispatch_recovery_reloads_persisted_authorization(self) -> None:
        fresh = self._fresh_bindings()
        definition = fresh.require("controller_candidate_spawn").definition
        self._write_candidate_journal(definition, state="INTENT_DURABLE")
        action = CandidateSpawnActionV2.from_mapping(definition.action)
        create_candidate_dispatch_intent_receipt_v2(
            action=action,
            codex_home=self.codex_home,
            monotonic_ms=lambda: 10_000,
        )
        store = CandidateSpawnAuthorizationStoreV2(
            path=self.authorization_path,
            installation_id=self.fixture.evidence.installation_id,
            operation_id=self.fixture.rollback_operation_id,
            action_fingerprint=action.action_fingerprint,
            readiness_token_hash=action.readiness_token_hash,
        )

        recovered = _recover_candidate_authorization(
            codex_home=self.codex_home,
            action=action,
            store=store,
            supplied_readiness_token=None,
        )

        self.assertEqual(self.readiness_token, recovered)
        self.assertEqual(self.readiness_token, store.load())

    def test_rollback_wrapper_retains_authorization_until_after_projection(
        self,
    ) -> None:
        fresh = self._fresh_bindings()
        definition = fresh.require("controller_candidate_spawn").definition
        action = CandidateSpawnActionV2.from_mapping(definition.action)
        store = CandidateSpawnAuthorizationStoreV2(
            path=self.authorization_path,
            installation_id=self.fixture.evidence.installation_id,
            operation_id=self.fixture.rollback_operation_id,
            action_fingerprint=action.action_fingerprint,
            readiness_token_hash=action.readiness_token_hash,
        )
        observations = iter((definition.before, definition.expected_after))
        wrapped = _wrap_candidate_authorization_port(
            port=UpdateStepPortV2(
                observe=lambda _definition: next(observations),
                apply=lambda _definition: None,
                matches_before=lambda observed, received: (
                    observed == received.before
                ),
                matches_after=lambda observed, received: (
                    observed == received.expected_after
                ),
            ),
            store=store,
        )

        wrapped.apply(definition)
        self.assertEqual(self.readiness_token, store.load())
        self.assertEqual(definition.before, wrapped.observe(definition))
        self.assertEqual(self.readiness_token, store.load())
        self.assertEqual(definition.expected_after, wrapped.observe(definition))
        self.assertFalse(self.authorization_path.exists())

    def test_shutdown_ports_follow_exact_candidate_in_fresh_and_recovered_bindings(
        self,
    ) -> None:
        reconnect_holder: dict[str, CandidateReadyReconnectV2] = {}

        def reconnect(**_kwargs) -> CandidateReadyReconnectV2:
            return reconnect_holder["value"]

        fresh = build_rollback_runtime_external_bindings_v2(
            evidence=self.fixture.evidence,
            external_artifacts=self.artifacts,
            operation_id=self.fixture.rollback_operation_id,
            readiness_token=self.readiness_token,
            codex_home=self.codex_home,
            state_home=self.state_home,
            interpreter=Path(sys.executable),
            registry_command_runner=self.registry,
            candidate_port_options={
                "candidate_reconnect": reconnect,
                "monotonic_ms": lambda: 10_000,
                "sleeper": lambda _seconds: None,
                "spawn_primitive": self._spawn,
            },
        )
        saved = self._composition(fresh).definition
        spawn = fresh.require("controller_candidate_spawn")
        self._write_candidate_journal(spawn.definition, state="INTENT_DURABLE")
        spawn.port.apply(spawn.definition)
        ready_socket = self._bind_socket_node(
            Path(spawn.definition.action["privateReadyChannelPath"]),
            token="successor-ready",
        )
        self.addCleanup(ready_socket.close)
        reconnect_holder["value"] = self._candidate_reconnect(spawn.definition)
        candidate_after = spawn.port.observe(spawn.definition)
        self._write_candidate_journal(
            spawn.definition,
            state="COMPLETED",
            observed_after=candidate_after,
        )

        recovered = recover_rollback_runtime_external_bindings_v2(
            evidence=self.fixture.evidence,
            external_artifacts=self.artifacts,
            definition=saved,
            readiness_token=None,
            codex_home=self.codex_home,
            state_home=self.state_home,
            registry_command_runner=self.registry,
            candidate_port_options={
                "candidate_reconnect": reconnect,
                "monotonic_ms": lambda: 10_000,
                "sleeper": lambda _seconds: None,
                "spawn_primitive": self._spawn,
            },
        )

        for bindings in (fresh, recovered):
            for kind in ("controller_shutdown", "shutdown_socket_cleanup"):
                binding = bindings.require(kind)
                current = binding.port.observe(binding.definition)
                self.assertEqual(candidate_after, current)

    def test_fresh_factory_requires_raw_token_and_absent_ready_path(self) -> None:
        with self.assertRaises(TypeError):
            build_rollback_runtime_external_bindings_v2(
                evidence=self.fixture.evidence,
                external_artifacts=self.artifacts,
                operation_id=self.fixture.rollback_operation_id,
                readiness_token=None,  # type: ignore[arg-type]
                codex_home=self.codex_home,
                state_home=self.state_home,
                interpreter=Path(sys.executable),
                registry_command_runner=self.registry,
            )

        fresh = self._fresh_bindings()
        ready_path = Path(
            fresh.require("controller_candidate_spawn").definition.action[
                "privateReadyChannelPath"
            ]
        )
        ready_socket = self._bind_socket_node(ready_path, token="fresh-conflict")
        self.addCleanup(ready_socket.close)
        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            self._fresh_bindings()
        self.assertEqual("ROLLBACK_RUNTIME_READY_PATH_CONFLICT", raised.exception.code)

    def _fresh_bindings(self) -> RollbackExternalStepBindingsV2:
        return build_rollback_runtime_external_bindings_v2(
            evidence=self.fixture.evidence,
            external_artifacts=self.artifacts,
            operation_id=self.fixture.rollback_operation_id,
            readiness_token=self.readiness_token,
            codex_home=self.codex_home,
            state_home=self.state_home,
            interpreter=Path(sys.executable),
            registry_command_runner=self.registry,
            candidate_port_options={
                "monotonic_ms": lambda: 10_000,
                "spawn_primitive": self._spawn,
            },
        )

    def _recover(self, definition):
        return recover_rollback_runtime_external_bindings_v2(
            evidence=self.fixture.evidence,
            external_artifacts=self.artifacts,
            definition=definition,
            readiness_token=None,
            codex_home=self.codex_home,
            state_home=self.state_home,
            registry_command_runner=self.registry,
            candidate_port_options={
                "monotonic_ms": lambda: 10_000,
                "spawn_primitive": self._spawn,
            },
        )

    def _composition(self, bindings: RollbackExternalStepBindingsV2):
        prepared = self.fixture._prepared_manifest()
        return build_rollback_composition_v2(
            evidence=self.fixture.evidence,
            execution_plan=self.fixture.execution_plan,
            operation_id=self.fixture.rollback_operation_id,
            journal_path=self.main_journal_path,
            prepared_manifest=prepared,
            preparation_receipt=self.fixture._preparation_receipt(prepared),
            external_bindings=bindings,
            external_artifacts=self.artifacts,
        )

    def _spawn(self, *, action, dispatch_intent, authorization, **kwargs):
        token = authorization.consume_for(action)
        self.popen_calls.append(
            {
                "argv": tuple(action.argv),
                "dispatchIntent": dispatch_intent,
                "readinessToken": token,
                **kwargs,
            }
        )
        return dispatch_intent

    def _replace_launcher_layout(self) -> None:
        for item in self.fixture.launcher_links:
            path = Path(item["path"])
            if os.path.lexists(path):
                path.unlink()
        self.fixture.launcher_links = []
        layouts = (
            ("codex-smart", "gateway"),
            ("codex-smart-subagents-admin", "admin"),
        )
        for activation_id in (
            rollback_fixture.CURRENT_ACTIVATION_ID,
            rollback_fixture.PREVIOUS_ACTIVATION_ID,
        ):
            marketplace = (
                self.fixture.managed / "activations" / activation_id / "marketplace"
            )
            plugin = marketplace / self.plugin_relative
            (plugin / "bin").mkdir(parents=True, exist_ok=True)
            (plugin / "controller").mkdir(parents=True, exist_ok=True)
            (marketplace / ".agents/plugins").mkdir(parents=True, exist_ok=True)
            for name, _role in layouts:
                target = plugin / "bin" / name
                target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                target.chmod(0o700)
            server = plugin / "controller/server.py"
            server.write_text("raise SystemExit(0)\n", encoding="utf-8")
            server.chmod(0o600)
            marketplace_contract = {
                "name": "codex-settings-adaptive",
                "plugins": [
                    {
                        "name": "codex-smart-subagents",
                        "source": {
                            "source": "local",
                            "path": "./plugins/codex-smart-subagents",
                        },
                        "policy": {
                            "installation": "AVAILABLE",
                            "authentication": "ON_INSTALL",
                        },
                    }
                ],
            }
            (marketplace / ".agents/plugins/marketplace.json").write_bytes(
                canonical_json_bytes(marketplace_contract)
            )
            manifest_dir = plugin / ".codex-plugin"
            manifest_dir.mkdir(exist_ok=True)
            (manifest_dir / "plugin.json").write_bytes(
                canonical_json_bytes(
                    {"name": "codex-smart-subagents", "version": "0.2.0"}
                )
            )
            activation_root = marketplace.parent
            activation_root.chmod(0o700)
            for directory, names, _files in os.walk(activation_root):
                Path(directory).chmod(0o700)
                for name in names:
                    (Path(directory) / name).chmod(0o700)
        for name, _role in layouts:
            path = self.fixture.launcher_root / name
            target = self.fixture.marketplace_link / self.plugin_relative / "bin" / name
            os.symlink(str(target), path)
            self.fixture.launcher_links.append(
                {"path": str(path), "target": str(target)}
            )

    def _write_activation_contracts(self) -> None:
        snapshot_root = self.fixture.managed / "codex-snapshots"
        snapshot_root.mkdir(mode=0o700)
        self.snapshot_paths: dict[str, Path] = {}
        for activation, database_path, nonce, snapshot_payload in (
            (
                self.fixture.current_activation,
                self.state_home / "current.sqlite3",
                "1" * 64,
                b"#!/bin/sh\n# current immutable Codex\nexit 0\n",
            ),
            (
                self.fixture.previous_activation,
                self.state_home / "previous.sqlite3",
                "2" * 64,
                b"#!/bin/sh\n# previous immutable Codex\nexit 0\n",
            ),
        ):
            snapshot_sha256 = hashlib.sha256(snapshot_payload).hexdigest()
            snapshot_directory = snapshot_root / snapshot_sha256
            snapshot_directory.mkdir(mode=0o700)
            snapshot_path = snapshot_directory / "codex"
            snapshot_path.write_bytes(snapshot_payload)
            snapshot_path.chmod(0o500)
            self.snapshot_paths[str(activation.value["activationId"])] = snapshot_path
            activation_file = Path(activation.value["activationFile"]["path"])
            activation_file.write_bytes(
                canonical_json_bytes(
                    {
                        "schemaVersion": 2,
                        "activationId": activation.value["activationId"],
                        "activationFingerprint": activation.value[
                            "activationFingerprint"
                        ],
                        "identity": {
                            "database": {
                                "databaseId": activation.value["databaseId"],
                                "absolutePath": str(database_path),
                                "activationBindingNonce": nonce,
                            },
                            "codexSnapshot": {
                                "absolutePath": str(snapshot_path),
                                "sha256": snapshot_sha256,
                            },
                        },
                    }
                )
            )
            activation_file.chmod(0o600)

    def _create_controller_databases(self) -> None:
        current_path = self.state_home / "current.sqlite3"
        previous_path = self.state_home / "previous.sqlite3"
        current_path.unlink()
        previous_path.unlink()
        lock = self.state_home / "controller.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        socket_path = self.state_home / "controller.sock"
        self.controller_socket = self._bind_socket_node(
            socket_path,
            token="controller",
        )
        socket_info = socket_path.lstat()
        now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)

        def identity(activation: ProjectionV2, nonce: str) -> DatabaseIdentityV2:
            return DatabaseIdentityV2(
                database_id=str(activation.value["databaseId"]),
                activation_binding_nonce=nonce,
                activation_id=str(activation.value["activationId"]),
                activation_fingerprint=str(activation.value["activationFingerprint"]),
                created_operation_id=self.fixture.rollback_operation_id,
                created_at=now,
            )

        def controller(activation: ProjectionV2) -> AcceptingControllerV2:
            return AcceptingControllerV2(
                controller_identity="2" * 64,
                instance_id="ci2_" + "1" * 32,
                controller_start_id="cs2_" + "2" * 32,
                controller_pid=os.getpid(),
                controller_process_start_marker=system_process_start_marker_v2(
                    os.getpid()
                ),
                controller_process_group_id=os.getpgrp(),
                control_epoch=7,
                activation_id=str(activation.value["activationId"]),
                activation_fingerprint=str(activation.value["activationFingerprint"]),
                compatibility_fingerprint="3" * 64,
                routing_policy_fingerprint="4" * 64,
                bundled_catalog_fingerprint="5" * 64,
                socket_path=str(socket_path),
                socket_device=socket_info.st_dev,
                socket_inode=socket_info.st_ino,
                socket_owner_uid=socket_info.st_uid,
                socket_owner_gid=socket_info.st_gid,
                socket_mode="0600",
                updated_at=now,
            )

        current_store = SmartStoreV2(
            current_path,
            database_identity=identity(self.fixture.current_activation, "1" * 64),
            controller=controller(self.fixture.current_activation),
        )
        current_store.close()
        previous_store = SmartStoreV2(
            previous_path,
            database_identity=identity(self.fixture.previous_activation, "2" * 64),
            controller=replace(
                controller(self.fixture.previous_activation),
                control_epoch=1,
            ),
        )
        previous_store.close()
        self.predecessor_shutdown_ids = ControllerShutdownLineageV2(
            maintenance_begin="cc2_" + "1" * 32,
            maintenance_strengthen="cc2_" + "2" * 32,
            shutdown="cc2_" + "3" * 32,
        )
        initial = controller(self.fixture.previous_activation)
        initial = replace(initial, control_epoch=1)
        protocol = LifecycleControllerProtocolV2(
            database_path=previous_path,
            codex_home=self.codex_home,
            controller_lock_path=lock,
            clock=lambda: now,
        )

        def request(
            method: str,
            *,
            command_id: str,
            epoch: int,
            params: dict[str, object],
        ) -> dict[str, object]:
            return build_lifecycle_controller_request_v2(
                codex_home=self.codex_home,
                shell_session_id="rollback-runtime-test",
                method=method,
                controller_identity=initial.controller_identity,
                instance_id=initial.instance_id,
                controller_start_id=initial.controller_start_id,
                command_id=command_id,
                expected_control_epoch=epoch,
                operation_id=rollback_fixture.CURRENT_OPERATION_ID,
                params=params,
            )

        begun = protocol.handle(
            request(
                "maintenance_begin",
                command_id=self.predecessor_shutdown_ids.maintenance_begin,
                epoch=1,
                params={"reasonCode": "UPGRADE"},
            )
        )
        strengthened = protocol.handle(
            request(
                "maintenance_strengthen",
                command_id=self.predecessor_shutdown_ids.maintenance_strengthen,
                epoch=int(begun["controlEpoch"]),
                params={"mode": "freeze"},
            )
        )
        protocol.handle(
            request(
                "shutdown",
                command_id=self.predecessor_shutdown_ids.shutdown,
                epoch=int(strengthened["controlEpoch"]),
                params={},
            )
        )

    def _refresh_evidence(self) -> None:
        current = self._refreshed_activation(self.fixture.current_activation)
        previous = self._refreshed_activation(self.fixture.previous_activation)
        current_database = self._database_binding(
            self.state_home / "current.sqlite3", current, "1" * 64
        )
        previous_database = self._database_binding(
            self.state_home / "previous.sqlite3", previous, "2" * 64
        )
        current_receipt = rollback_fixture._receipt(
            operation_id=rollback_fixture.CURRENT_OPERATION_ID,
            manifest=self.fixture.evidence.current_manifest_projection,
            activation=current,
            database=current_database,
            manifest_document=dict(self.fixture.evidence.manifest_document),
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="update",
                source_receipt=TransitionSourceReceiptV2.from_document(
                    self.fixture.evidence.current_receipt["transitionLineage"][
                        "sourceReceipt"
                    ]
                ),
                activation_proof_fingerprint="b" * 64,
                shutdown_command_ids=self.predecessor_shutdown_ids,
                stopped_controller=StoppedControllerLineageV2(
                    operation_id=rollback_fixture.CURRENT_OPERATION_ID,
                    activation_id=rollback_fixture.PREVIOUS_ACTIVATION_ID,
                    database_id=rollback_fixture.PREVIOUS_DATABASE_ID,
                    controller_identity="2" * 64,
                    control_epoch=4,
                ),
            ),
        )
        previous_receipt = rollback_fixture._receipt(
            operation_id=rollback_fixture.PREVIOUS_OPERATION_ID,
            manifest=ProjectionV2.from_document(
                self.fixture.evidence.previous_receipt["manifest"]
            ),
            activation=previous,
            database=previous_database,
            manifest_document=dict(
                self.fixture.evidence.previous_receipt["manifestDocument"]
            ),
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="initial",
                source_receipt=None,
                activation_proof_fingerprint=None,
                shutdown_command_ids=None,
                stopped_controller=None,
            ),
        )
        self.fixture.current_activation = current
        self.fixture.previous_activation = previous
        self.fixture.evidence = replace(
            self.fixture.evidence,
            current_receipt=current_receipt,
            previous_receipt=previous_receipt,
            current_activation_projection=current,
            previous_activation_projection=previous,
            previous_database_binding=previous_database,
        )

    def _refreshed_activation(self, activation: ProjectionV2) -> ProjectionV2:
        directory = Path(activation.value["directory"]["path"])
        activation_file = Path(activation.value["activationFile"]["path"])
        value = copy.deepcopy(dict(activation.value))
        value["directory"] = capture_tree_projection_v2(
            directory,
            schema_sha256=rollback_fixture.SCHEMA_SHA256,
        ).value
        value["activationFile"] = capture_file_projection_v2(
            activation_file,
            schema_sha256=rollback_fixture.SCHEMA_SHA256,
        ).value
        return rollback_fixture._projection(
            "activation-v2", value, "codex-smart/journal-state/v2"
        )

    def _database_binding(
        self,
        path: Path,
        activation: ProjectionV2,
        nonce: str,
    ) -> ProjectionV2:
        manifest = json.loads(
            (
                PLUGIN_SRC / "codex_smart_subagents/schema/state-v2.manifest.json"
            ).read_text(encoding="utf-8")
        )
        info = path.lstat()
        identity = {
            "databaseId": activation.value["databaseId"],
            "activationBindingNonce": nonce,
            "activationId": activation.value["activationId"],
            "activationFingerprint": activation.value["activationFingerprint"],
        }
        value = {
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": "0600",
            "linkCount": info.st_nlink,
            "databaseId": activation.value["databaseId"],
            "databaseIdentity": identity,
            "databaseIdentityFingerprint": domain_fingerprint(
                "codex-smart/database-identity/v2", identity
            ),
            "activationIdentity": {
                "activationId": activation.value["activationId"],
                "activationFingerprint": activation.value["activationFingerprint"],
            },
            "databaseVersion": "0.2.0",
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": manifest["schemaFingerprint"],
            "schemaArtifactSha256": manifest["stateSqlSha256"],
        }
        return rollback_fixture._projection(
            "database-binding-v2", value, "codex-smart/database-binding/v2"
        )

    def _refresh_installer_receipt(self) -> None:
        self.fixture.installer_receipt.update(
            {
                "codexHome": str(self.codex_home),
                "codexBinary": str(self.codex_binary),
                "stateHome": str(self.state_home),
                "links": copy.deepcopy(self.fixture.launcher_links),
            }
        )
        self.fixture.installer_receipt_path.write_bytes(
            canonical_json_bytes(self.fixture.installer_receipt)
        )
        self.fixture.installer_receipt_path.chmod(0o600)

    def _write_candidate_journal(
        self,
        definition,
        *,
        state: str,
        observed_after: ProjectionV2 | None = None,
    ) -> None:
        step = {
            "stepId": "st2_" + "1" * 32,
            "kind": "controller_candidate_spawn",
            "state": state,
            "action": copy.deepcopy(dict(definition.action)),
            "actionFingerprint": domain_fingerprint(
                "codex-smart/step-action/v2",
                {"action": copy.deepcopy(dict(definition.action))},
            ),
            "before": definition.before.to_document(),
            "expectedAfter": definition.expected_after.to_document(),
        }
        if observed_after is not None:
            step["observedAfter"] = observed_after.to_document()
        journal = {
            "operationId": self.fixture.rollback_operation_id,
            "steps": [step],
        }
        journal["journalFingerprint"] = domain_fingerprint(
            "codex-smart/operation-journal/v2", journal
        )
        path = (
            self.codex_home
            / "install-manifests/codex-smart-subagents-v2.transaction.json"
        )
        path.write_bytes(canonical_json_bytes(journal))
        path.chmod(0o600)

    def _candidate_reconnect(self, definition) -> CandidateReadyReconnectV2:
        expected = copy.deepcopy(dict(definition.expected_after.value))
        ready_path = Path(definition.action["privateReadyChannelPath"])
        info = ready_path.lstat()
        expected.update(
            {
                "privateReadyChannel": {
                    "path": str(ready_path),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "ownerUid": info.st_uid,
                    "ownerGid": info.st_gid,
                    "mode": "0600",
                },
                "pid": os.getpid(),
                "processStartMarker": "candidate-test-start",
                "processGroupId": os.getpgrp(),
                "registrationFingerprint": "7" * 64,
                "databaseLeaseProofFingerprint": "8" * 64,
                "databaseOpened": True,
                "status": "REGISTERED_READY",
            }
        )
        return CandidateReadyReconnectV2(
            response={},
            response_bytes=b"{}",
            registration=expected,
            database_lease={"proofFingerprint": "8" * 64},
            working_controller_socket={
                "path": str(self.state_home / "candidate.sock"),
                "device": 1,
                "inode": 2,
                "ownerUid": os.getuid(),
                "ownerGid": os.getgid(),
                "mode": "0600",
            },
        )

    def _bind_socket_node(self, path: Path, *, token: str) -> socket.socket:
        short = Path("/tmp") / (
            "rb2-"
            + hashlib.sha256((str(self.root) + token).encode("utf-8")).hexdigest()[:16]
            + ".sock"
        )
        if os.path.lexists(short):
            short.unlink()
        if os.path.lexists(path):
            path.unlink()
        result = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        result.bind(str(short))
        os.replace(short, path)
        os.chmod(path, 0o600)
        return result


class RollbackEvidenceRehydrationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = preparation_fixture._PublishedUpgradeFixture()
        self.evidence = self.fixture.evidence
        preparation = self.fixture.build_preparation(
            __import__(
                "codex_smart_subagents.rollback_manifest_preparation_v2",
                fromlist=["rollback_manifest_preparation_v2"],
            )
        )
        self.preparation_receipt_path = preparation.definition.receipt_path
        self.preparation_receipt = RollbackManifestPreparationExecutorV2(
            definition=preparation.definition
        ).execute()
        self.prepared_manifest = prepared_rollback_manifest_from_receipt_v2(
            self.preparation_receipt,
            self.evidence,
        )
        intent = self.fixture.current_preparation_receipt.activation_intent
        self.layout = GatewayLayout.for_codex_home(intent.codex_home)
        self.definition, self.callbacks = self._definition_and_callbacks()
        self.store = OperationJournalStoreV2(
            journal_path=self.layout.journal_path,
            lock_path=self.layout.lock_path,
            validate_document=lambda _document: None,
        )
        self.executor = OperationExecutorV2(
            store=self.store,
            now=rollback_fixture._Clock(),
            id_factory=rollback_fixture._Ids(),
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def test_rehydrator_is_part_of_the_public_runtime_contract(self) -> None:
        module = __import__(
            "codex_smart_subagents.rollback_runtime_bindings_v2",
            fromlist=["rollback_runtime_bindings_v2"],
        )

        self.assertIn("rehydrate_rollback_evidence_v2", module.__all__)

    def test_rehydrates_frozen_before_after_link_restore_crash(self) -> None:
        journal = self._crash_after("activation_link_restore")

        recovered = rehydrate_rollback_evidence_v2(
            definition=self.definition,
            journal=journal,
            preparation_receipt_path=self.preparation_receipt_path,
        )

        self.assertEqual(self.evidence, recovered)
        self.assertEqual(
            self.evidence.previous_pointer["symlinkTarget"],
            os.readlink(self.evidence.marketplace_link),
        )
        self.assertEqual(
            self.evidence.manifest_document,
            json.loads(self.evidence.manifest_path.read_text(encoding="utf-8")),
        )

    def test_rehydrates_frozen_before_after_manifest_restore_crash(self) -> None:
        journal = self._crash_after("manifest_restore")

        recovered = rehydrate_rollback_evidence_v2(
            definition=self.definition,
            journal=journal,
            preparation_receipt_path=self.preparation_receipt_path,
        )

        self.assertEqual(self.evidence, recovered)
        self.assertFalse(self.preparation_receipt.prepared_path.exists())
        self.assertEqual(
            self.preparation_receipt.manifest_document,
            json.loads(self.evidence.manifest_path.read_text(encoding="utf-8")),
        )

    def test_rehydrator_rejects_live_state_outside_frozen_before_after(self) -> None:
        journal = self._crash_after("activation_link_restore")
        temporary = self.evidence.marketplace_link.with_name(".foreign-link")
        os.symlink("activations/foreign/marketplace", temporary)
        os.replace(temporary, self.evidence.marketplace_link)

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            rehydrate_rollback_evidence_v2(
                definition=self.definition,
                journal=journal,
                preparation_receipt_path=self.preparation_receipt_path,
            )

        self.assertEqual(
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
            raised.exception.code,
        )

    def test_rehydrator_rejects_predecessor_not_derived_from_transition_source(
        self,
    ) -> None:
        journal = self._crash_after("activation_link_restore")
        foreign_operation_id = "op2_" + "f" * 32
        current_receipt = copy.deepcopy(dict(self.evidence.current_receipt))
        lineage = current_receipt["transitionLineage"]
        assert isinstance(lineage, dict)
        source_binding = lineage["sourceReceipt"]
        assert isinstance(source_binding, dict)
        source_path = Path(str(source_binding["path"]))
        source = json.loads(source_path.read_text(encoding="utf-8"))
        snapshot = source["transitionProofSnapshot"]
        assert isinstance(snapshot, dict)
        snapshot["currentOperationId"] = foreign_operation_id
        source_unsigned = {
            key: value for key, value in source.items() if key != "receiptFingerprint"
        }
        source["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-preparation-receipt/v2",
            source_unsigned,
        )
        source_raw = canonical_json_bytes(source)
        source_path.write_bytes(source_raw)
        source_path.chmod(0o600)
        source_binding["receiptFingerprint"] = source["receiptFingerprint"]
        source_binding["rawSha256"] = hashlib.sha256(source_raw).hexdigest()
        lineage_unsigned = {
            key: value for key, value in lineage.items() if key != "lineageFingerprint"
        }
        lineage["lineageFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            lineage_unsigned,
        )
        current_unsigned = {
            key: value
            for key, value in current_receipt.items()
            if key != "receiptFingerprint"
        }
        current_receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2",
            current_unsigned,
        )
        self.evidence.current_receipt_path.write_bytes(
            canonical_json_bytes(current_receipt)
        )
        self.evidence.current_receipt_path.chmod(0o600)

        preparation = self.preparation_receipt.to_document()
        preparation["currentPreparationReceiptFingerprint"] = source[
            "receiptFingerprint"
        ]
        preparation["currentPreparationReceiptSha256"] = hashlib.sha256(
            source_raw
        ).hexdigest()
        preparation["transitionProofSnapshotFingerprint"] = lineage[
            "lineageFingerprint"
        ]
        evidence_projection = {
            "installationId": preparation["installationId"],
            "currentOperationId": preparation["currentOperationId"],
            "previousOperationId": preparation["previousOperationId"],
            "currentActivationId": preparation["currentActivationId"],
            "previousActivationId": preparation["previousActivationId"],
            "manifestSha256": hashlib.sha256(
                canonical_json_bytes(self.evidence.manifest_document)
            ).hexdigest(),
            "currentReceiptFingerprint": current_receipt["receiptFingerprint"],
            "previousReceiptFingerprint": self.evidence.previous_receipt[
                "receiptFingerprint"
            ],
            "currentLinkTarget": self.evidence.current_pointer["symlinkTarget"],
        }
        preparation["evidenceFingerprint"] = domain_fingerprint(
            "codex-smart/rollback-evidence/v2",
            evidence_projection,
        )
        preparation_unsigned = {
            key: value
            for key, value in preparation.items()
            if key != "receiptFingerprint"
        }
        preparation["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/rollback-manifest-preparation-receipt/v2",
            preparation_unsigned,
        )
        self.preparation_receipt_path.write_bytes(canonical_json_bytes(preparation))
        self.preparation_receipt_path.chmod(0o600)

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            rehydrate_rollback_evidence_v2(
                definition=self.definition,
                journal=journal,
                preparation_receipt_path=self.preparation_receipt_path,
            )

        self.assertEqual(
            "ROLLBACK_EVIDENCE_RECOVERY_LINEAGE_INVALID",
            raised.exception.code,
            str(raised.exception),
        )

    def test_rehydrator_rejects_duplicate_commit_receipt_operation(self) -> None:
        journal = self._crash_after("activation_link_restore")
        duplicate = self.evidence.receipts_root / "duplicate.commit.json"
        duplicate.write_bytes(canonical_json_bytes(self.evidence.current_receipt))
        duplicate.chmod(0o600)

        with self.assertRaises(InstallerRollbackCompositionV2Error) as raised:
            rehydrate_rollback_evidence_v2(
                definition=self.definition,
                journal=journal,
                preparation_receipt_path=self.preparation_receipt_path,
            )

        self.assertEqual(
            "ROLLBACK_EVIDENCE_RECOVERY_COMMIT_CHAIN_INVALID",
            raised.exception.code,
        )

    def _crash_after(self, kind: str) -> dict[str, object]:
        def crash(point: FailurePointV2, observed_kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and observed_kind == kind
            ):
                raise InjectedCrashV2(point, observed_kind)

        with self.assertRaises(InjectedCrashV2):
            self.executor.execute(
                self.definition,
                callbacks=self.callbacks,
                terminal_callbacks=None,
                failure_injector=crash,
            )
        return self.store.read()

    def _definition_and_callbacks(
        self,
    ) -> tuple[OperationDefinitionV2, StepCallbacksV2]:
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        execution_plan = LifecyclePlanRegistryV2.from_document(automaton).select(
            machine_id="rollback",
            branch_id="rollback-matched-active",
            plan_id=rollback_fixture.PLAN_ID,
        )
        operation_id = self.preparation_receipt.operation_id
        journal_path = self.layout.journal_path
        link_definition, link_port = _activation_link_restore_binding(
            evidence=self.evidence,
            operation_id=operation_id,
        )
        manifest_definition, manifest_port = _manifest_restore_binding(
            evidence=self.evidence,
            operation_id=operation_id,
            prepared=self.prepared_manifest,
        )
        marker = rollback_fixture._projection(
            "absence-proof-v2",
            {
                "installationId": self.evidence.installation_id,
                "operationId": operation_id,
                "path": str(self.layout.manifest_root / "test-marker"),
                "status": "ABSENT",
            },
            "codex-smart/absence-proof-projection/v2",
        )
        ports = {
            "activation_link_restore": link_port,
            "manifest_restore": manifest_port,
        }
        by_kind: dict[str, StepDefinitionV2] = {}
        for kind in ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15]:
            if kind == "activation_link_restore":
                definition = link_definition
            elif kind == "recovery_forward_only":
                definition = _forward_only_definition(
                    journal_path=journal_path,
                    operation_id=operation_id,
                    plan_fingerprint=execution_plan.plan_definition_fingerprint,
                )
            elif kind == "manifest_restore":
                definition = manifest_definition
            else:
                definition = StepDefinitionV2(
                    kind=kind,
                    command_id=None,
                    action={"actionKind": "test-noop", "kind": kind},
                    before=marker,
                    expected_after=marker,
                )
                ports[kind] = UpdateStepPortV2(
                    observe=lambda _definition, value=marker: value,
                    apply=lambda _definition: None,
                )
            by_kind[kind] = definition

        absence = _absence_projection(
            journal_path,
            installation_id=self.evidence.installation_id,
            operation_id=operation_id,
        )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action=_journal_action("gate-close", journal_path),
            before=absence,
            expected_after=_journal_projection(
                journal_path,
                operation_id=operation_id,
                plan_fingerprint=execution_plan.plan_definition_fingerprint,
                phase="DISCOVERED",
                recovery_policy="REVERSIBLE",
                generation=1,
                frozen=False,
            ),
        )
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action=_journal_action("freeze-delete-intent", journal_path),
            before=_journal_projection(
                journal_path,
                operation_id=operation_id,
                plan_fingerprint=execution_plan.plan_definition_fingerprint,
                phase="COMMITTING",
                recovery_policy="FORWARD_ONLY",
                generation=16,
                frozen=False,
            ),
            expected_after=_journal_projection(
                journal_path,
                operation_id=operation_id,
                plan_fingerprint=execution_plan.plan_definition_fingerprint,
                phase="TERMINAL_FROZEN",
                recovery_policy="FORWARD_ONLY",
                generation=17,
                frozen=True,
            ),
        )
        discovery = self._bundle(
            manifest=self.evidence.current_manifest_projection,
            activation=self.evidence.current_activation_projection,
        )
        desired = self._bundle(
            manifest=self.preparation_receipt.expected_after,
            activation=self.evidence.previous_activation_projection,
        )
        terminal = TerminalDefinitionV2(
            terminal_kind="COMMIT",
            receipt_kind="activation-commit",
            receipt_path=(self.evidence.receipts_root / f"{operation_id}.commit.json"),
            freeze=freeze,
            journal_absence_target=absence,
            receipt_payload=ActivationCommitPayloadIntentV2(
                manifest=self.preparation_receipt.expected_after,
                manifest_document=self.preparation_receipt.manifest_document,
                transition_lineage=ActivationTransitionLineageV2(
                    transition_kind="rollback",
                    source_receipt=TransitionSourceReceiptV2(
                        receipt_kind="rollback-manifest-preparation",
                        path=self.preparation_receipt_path,
                        raw_sha256=hashlib.sha256(
                            canonical_json_bytes(
                                self.preparation_receipt.to_document()
                            )
                        ).hexdigest(),
                        receipt_fingerprint=(
                            self.preparation_receipt.receipt_fingerprint
                        ),
                    ),
                    activation_proof_fingerprint=self.evidence.evidence_fingerprint,
                    shutdown_command_ids=ControllerShutdownLineageV2(
                        maintenance_begin="cc2_" + "4" * 32,
                        maintenance_strengthen="cc2_" + "5" * 32,
                        shutdown="cc2_" + "6" * 32,
                    ),
                    stopped_controller=StoppedControllerLineageV2(
                        operation_id=operation_id,
                        activation_id=self.evidence.current_activation_id,
                        database_id=str(
                            self.evidence.current_receipt["databaseBinding"][
                                "value"
                            ]["databaseId"]
                        ),
                        controller_identity=str(
                            self.evidence.current_receipt["controllerIdentity"]
                        ),
                        control_epoch=2,
                    ),
                ),
                activation=self.evidence.previous_activation_projection,
                database_binding=self.evidence.previous_database_binding,
                journal_absence_target=absence,
                controller_identity=str(
                    self.evidence.previous_receipt["controllerIdentity"]
                ),
            ),
        )
        definition = OperationDefinitionV2(
            kind="rollback",
            installation_id=self.evidence.installation_id,
            operation_id=operation_id,
            operation="rollback",
            execution_plan=execution_plan,
            discovery_before=discovery,
            fenced_before=discovery,
            desired=desired,
            gate_close=gate,
            mutable_steps=tuple(
                by_kind[kind] for kind in ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15]
            ),
            terminal=terminal,
        )

        def port_for(step: StepDefinitionV2) -> UpdateStepPortV2:
            return ports[step.kind]

        callbacks = StepCallbacksV2(
            observe=lambda step: port_for(step).observe(step),
            apply=lambda step: port_for(step).apply(step),
            matches_before=lambda observed, step: port_for(step).matches_before(
                observed, step
            ),
            matches_after=lambda observed, step: port_for(step).matches_after(
                observed, step
            ),
        )
        return definition, callbacks

    @staticmethod
    def _bundle(
        *,
        manifest: ProjectionV2,
        activation: ProjectionV2,
    ) -> StateBundleV2:
        return StateBundleV2(
            file_objects=(),
            tree_objects=(),
            symlinks=(),
            manifest=manifest,
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


if __name__ == "__main__":
    unittest.main()
