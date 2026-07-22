from __future__ import annotations

import io
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.admin_v2 import (  # noqa: E402
    AdminConfigV2,
    ProvenAdminStateV2,
    main,
)
from codex_smart_subagents.admin_state_v2 import (  # noqa: E402
    AdminV2Error,
    require_controller_stopped_v2,
    stop_live_controller_v2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    PlannedNodeV2,
    RequestContextV2,
    SmartStoreV2,
)
from codex_smart_subagents.production_runtime_v2 import (  # noqa: E402
    accepting_controller_from_binding_v2,
    database_identity_from_binding_v2,
)
from codex_smart_subagents.runtime_recovery_v2 import (  # noqa: E402
    write_attempt_marker_v2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    ChildGuardV2Error,
    system_process_start_marker_v2,
)
from codex_smart_subagents.execution_recovery_v2 import (  # noqa: E402
    ExecutionRecoveryV2Error,
)
from codex_smart_subagents.activation_gateway_v2 import GatewayState  # noqa: E402


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)
ACTIVATION = "a" * 64
COMPATIBILITY = "b" * 64


class AdminV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="admin-v2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.environment = {"CODEX_HOME": str(self.codex_home)}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        code = main(
            list(arguments),
            environ=self.environment,
            stdout=output,
        )
        lines = output.getvalue().splitlines()
        self.assertEqual(1, len(lines))
        return code, json.loads(lines[0])

    def create_proven_state(
        self,
        *,
        with_route: bool = False,
        controller_marker: str = "test-process-marker",
    ) -> ProvenAdminStateV2:
        state_home = self.root / "state-v2"
        database_root = state_home / "databases" / ("db2_" + "1" * 32)
        database_root.mkdir(parents=True, mode=0o700)
        state_home.chmod(0o700)
        (state_home / "databases").chmod(0o700)
        database_root.chmod(0o700)
        database_path = database_root / "smart-subagents.sqlite3"
        identity = DatabaseIdentityV2(
            database_id="db2_" + "1" * 32,
            activation_binding_nonce="2" * 64,
            activation_id="act2_" + ACTIVATION,
            activation_fingerprint=ACTIVATION,
            created_operation_id="op2_" + "3" * 32,
            created_at=NOW,
        )
        controller = AcceptingControllerV2(
            controller_identity="4" * 64,
            instance_id="ci2_" + "5" * 32,
            controller_start_id="cs2_" + "6" * 32,
            controller_pid=os.getpid(),
            controller_process_start_marker=controller_marker,
            controller_process_group_id=os.getpgrp(),
            control_epoch=7,
            activation_id=identity.activation_id,
            activation_fingerprint=ACTIVATION,
            compatibility_fingerprint=COMPATIBILITY,
            routing_policy_fingerprint="8" * 64,
            bundled_catalog_fingerprint="9" * 64,
            socket_path=str(state_home / "controller.sock"),
            socket_device=1,
            socket_inode=2,
            socket_owner_uid=os.getuid(),
            socket_owner_gid=os.getgid(),
            socket_mode="0600",
            updated_at=NOW,
        )
        store = SmartStoreV2(
            database_path,
            database_identity=identity,
            controller=controller,
        )
        if with_route:
            context = RequestContextV2(
                shell_session_id="shell-1",
                session_id="session-1",
                turn_id="turn-1",
                codex_home=str(self.codex_home),
                repo_root=str(self.root / "секретный-репозиторий"),
                base_sha="a" * 40,
                worktree_fingerprint="c" * 64,
                activation_fingerprint=ACTIVATION,
                compatibility_fingerprint=COMPATIBILITY,
                issued_control_epoch=7,
            )
            binding = store.issue_turn_binding(
                context,
                ttl_seconds=60,
                now=NOW,
            )
            store.create_planned_route(
                binding_id=binding.binding_id,
                request_context=context,
                request_key="request-1",
                request_hash="d" * 64,
                catalog_generation="catalog-v2",
                algorithm_version="routing-v2",
                disposition="DELEGATE",
                expires_at=NOW + timedelta(minutes=5),
                plan_output={"secret": "нельзя-показывать"},
                nodes=[
                    PlannedNodeV2(
                        node_id="node2_" + "e" * 32,
                        ordinal=0,
                        role="researcher",
                        mission="секретная-миссия",
                        dependencies=(),
                        context_refs=(),
                        scope_id="scope-1",
                        artifact_profile_id="artifact-1",
                        validation_profile_id="validation-1",
                        assessment={"complexity": 1},
                        risk_flags=(),
                        selected_model="gpt-5.6-luna",
                        reasoning_effort="low",
                        permission_profile_id="read-only",
                        disposition="DELEGATE",
                    )
                ],
                now=NOW,
            )
        database_identity_row = store._database_identity_row()
        controller_row = store._controller_row()
        store.close()
        config = AdminConfigV2.from_environ(self.environment)
        return ProvenAdminStateV2(
            config=config,
            receipt={"activationId": identity.activation_id},
            binding=SimpleNamespace(
                activation_id=identity.activation_id,
                activation_fingerprint=ACTIVATION,
                compatibility_fingerprint=COMPATIBILITY,
                control_epoch=7,
                state_home=state_home,
                marketplace_path=self.root / "marketplace",
                database_path=database_path,
                database_identity_row=database_identity_row,
                controller_row=controller_row,
            ),
        )

    def write_valid_receipt(self) -> Path:
        manifests = self.codex_home / "install-manifests"
        manifests.mkdir(exist_ok=True, mode=0o700)
        receipt = manifests / "codex-smart-subagents-v2.installer.json"
        value = {
            "schemaVersion": 2,
            "kind": "codex-smart-installer-receipt/v2",
            "sourceDigest": "0" * 64,
            "installationId": "ins2_" + "1" * 32,
            "activationId": "act2_" + ACTIVATION,
            "codexHome": str(self.codex_home),
            "codexBinary": str(self.root / "codex"),
            "stateHome": str(self.root / "state-v2"),
            "marketplacePath": str(
                self.codex_home
                / "codex-smart-subagents-v2"
                / "marketplace-current"
            ),
            "registeredMarketplacePath": str(self.root / "marketplace"),
            "links": [
                {
                    "path": str(self.root / "bin" / "codex-smart"),
                    "target": str(
                        self.codex_home
                        / "codex-smart-subagents-v2"
                        / "marketplace-current"
                        / "plugins"
                        / "codex-smart-subagents"
                        / "bin"
                        / "codex-smart"
                    ),
                },
                {
                    "path": str(
                        self.root / "bin" / "codex-smart-subagents-admin"
                    ),
                    "target": str(
                        self.codex_home
                        / "codex-smart-subagents-v2"
                        / "marketplace-current"
                        / "plugins"
                        / "codex-smart-subagents"
                        / "bin"
                        / "codex-smart-subagents-admin"
                    ),
                },
            ],
            "marketplaceName": "codex-settings-adaptive",
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "extensions": {},
        }
        receipt.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        receipt.chmod(0o600)
        return receipt

    def prepare_receipt_artifacts(self) -> None:
        codex = self.root / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        codex.chmod(0o700)
        marketplace = self.root / "marketplace"
        targets = marketplace / "plugins" / "codex-smart-subagents" / "bin"
        targets.mkdir(parents=True, mode=0o700)
        links = self.root / "bin"
        links.mkdir(mode=0o700)
        managed = self.codex_home / "codex-smart-subagents-v2"
        managed.mkdir(mode=0o700)
        marketplace_link = managed / "marketplace-current"
        marketplace_link.symlink_to(marketplace)
        for name in ("codex-smart", "codex-smart-subagents-admin"):
            target = targets / name
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o700)
            lexical_target = (
                marketplace_link
                / "plugins"
                / "codex-smart-subagents"
                / "bin"
                / name
            )
            (links / name).symlink_to(lexical_target)

    def prepare_reserved_runtime(
        self,
        proven: ProvenAdminStateV2,
    ) -> tuple[str, Path]:
        attempts_root = proven.binding.state_home / "attempt-runtimes-v2"
        attempts_root.mkdir(mode=0o700)
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            route_id, node_id = connection.execute(
                "select route_id,node_id from nodes"
            ).fetchone()
        store = SmartStoreV2(
            proven.binding.database_path,
            database_identity=database_identity_from_binding_v2(proven.binding),
            controller=accepting_controller_from_binding_v2(proven.binding),
        )
        attempt_id = "att2_" + "f" * 32
        path = attempts_root / f"attempt-{attempt_id}"
        artifact_id = store.reserve_runtime_artifact(
            route_id=str(route_id),
            node_id=str(node_id),
            kind="attempt_runtime_v2",
            path=path,
            allowed_root=attempts_root,
        )
        path.mkdir(mode=0o700)
        write_attempt_marker_v2(
            path,
            artifact_id=artifact_id,
            attempt_id=attempt_id,
        )
        store.close()
        return artifact_id, path

    def test_status_refuses_when_v2_installer_receipt_is_missing(self) -> None:
        code, result = self.invoke("status")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual(2, result["schemaVersion"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])
        self.assertEqual(
            "INSTALLER_RECEIPT_MISSING",
            result["data"]["reasonCode"],
        )

    def test_status_refuses_malformed_v2_installer_receipt(self) -> None:
        manifests = self.codex_home / "install-manifests"
        manifests.mkdir(mode=0o700)
        receipt = manifests / "codex-smart-subagents-v2.installer.json"
        receipt.write_text('{"schemaVersion":2}', encoding="utf-8")
        receipt.chmod(0o600)

        code, result = self.invoke("status")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])
        self.assertEqual(
            "INSTALLER_RECEIPT_INVALID",
            result["data"]["reasonCode"],
        )

    def test_status_reads_only_a_proven_v2_database_and_reports_bounded_counts(self) -> None:
        proven = self.create_proven_state(with_route=True)
        with (
            patch(
                "codex_smart_subagents.admin_v2._load_proven_state",
                return_value=proven,
            ),
            patch(
                "codex_smart_subagents.admin_v2._probe_live_controller",
                return_value=(True, "READY"),
            ),
        ):
            code, result = self.invoke("status")

        self.assertEqual(0, code)
        self.assertTrue(result["ok"])
        self.assertEqual("READY", result["code"])
        self.assertEqual(
            {"PLANNED": 1},
            result["data"]["counts"]["routeStates"],
        )
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("нельзя-показывать", encoded)
        self.assertNotIn("секретная-миссия", encoded)

    def test_status_refuses_when_persisted_activation_proof_fails(self) -> None:
        self.write_valid_receipt()
        with patch(
            "codex_smart_subagents.admin_state_v2.ActivationResolver.resolve_persisted_activation",
            side_effect=RuntimeError("не подтверждено"),
        ):
            code, result = self.invoke("status")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])
        self.assertEqual(
            "ACTIVATION_PROOF_FAILED",
            result["data"]["reasonCode"],
        )

    def test_inspect_rejects_non_v2_route_identifier_before_state_access(self) -> None:
        code, result = self.invoke("inspect", "rt1_wrong")

        self.assertEqual(2, code)
        self.assertFalse(result["ok"])
        self.assertEqual("INVALID_ROUTE_ID", result["code"])

    def test_inspect_returns_bounded_operational_projection_without_payloads(self) -> None:
        proven = self.create_proven_state(with_route=True)
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            route_id = str(connection.execute("select route_id from routes").fetchone()[0])
        with patch(
            "codex_smart_subagents.admin_v2._load_proven_state",
            return_value=proven,
        ):
            code, result = self.invoke("inspect", route_id, "--limit", "10")

        self.assertEqual(0, code)
        self.assertTrue(result["ok"])
        self.assertEqual("ROUTE_INSPECTED", result["code"])
        self.assertEqual(route_id, result["data"]["route"]["routeId"])
        self.assertEqual("gpt-5.6-luna", result["data"]["nodes"][0]["model"])
        self.assertEqual("low", result["data"]["nodes"][0]["reasoningEffort"])
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("нельзя-показывать", encoded)
        self.assertNotIn("секретная-миссия", encoded)
        self.assertNotIn("секретный-репозиторий", encoded)

    def test_doctor_reports_persisted_state_when_controller_is_unavailable(self) -> None:
        proven = self.create_proven_state()
        (proven.binding.state_home / "attempt-runtimes-v2").mkdir(mode=0o700)
        with (
            patch(
                "codex_smart_subagents.admin_v2._load_proven_state",
                return_value=proven,
            ),
            patch(
                "codex_smart_subagents.admin_v2._probe_live_controller",
                return_value=(False, "CONTROLLER_UNAVAILABLE"),
            ),
        ):
            code, result = self.invoke("doctor")

        self.assertEqual(1, code)
        self.assertTrue(result["ok"])
        self.assertEqual("CONTROLLER_UNAVAILABLE", result["code"])
        self.assertEqual([], result["data"]["recovery"]["actions"])
        self.assertEqual([], result["data"]["recovery"]["blockers"])

    def test_doctor_maps_domain_recovery_failure_to_a_closed_result(self) -> None:
        proven = self.create_proven_state()
        (proven.binding.state_home / "attempt-runtimes-v2").mkdir(mode=0o700)
        with (
            patch(
                "codex_smart_subagents.admin_v2._load_proven_state",
                return_value=proven,
            ),
            patch(
                "codex_smart_subagents.admin_v2.RecoverySuiteV2.run",
                side_effect=ExecutionRecoveryV2Error(
                    "PROCESS_IDENTITY_INVALID",
                    "invalid identity",
                ),
            ),
        ):
            code, result = self.invoke("doctor")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("RECOVERY_BLOCKED", result["code"])
        self.assertEqual(
            "PROCESS_IDENTITY_INVALID",
            result["data"]["reasonCode"],
        )

    def test_recover_dry_run_plans_without_mutating_registered_runtime(self) -> None:
        proven = self.create_proven_state(with_route=True)
        artifact_id, path = self.prepare_reserved_runtime(proven)
        database_bytes = proven.binding.database_path.read_bytes()
        database_mtime = proven.binding.database_path.stat().st_mtime_ns
        database_siblings = sorted(
            item.name for item in proven.binding.database_path.parent.iterdir()
        )
        with patch(
            "codex_smart_subagents.admin_v2._load_proven_state",
            return_value=proven,
        ):
            code, result = self.invoke("recover", "--dry-run")

        self.assertEqual(1, code)
        self.assertTrue(result["ok"])
        self.assertEqual("RECOVERY_REQUIRED", result["code"])
        self.assertTrue(path.exists())
        self.assertEqual(
            [{
                "kind": "ADOPT_AND_REMOVE",
                "artifactId": artifact_id,
                "attemptId": "att2_" + "f" * 32,
            }],
            result["data"]["recovery"]["actions"],
        )
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            state = connection.execute(
                "select state from runtime_artifacts where artifact_id=?",
                (artifact_id,),
            ).fetchone()[0]
        self.assertEqual("RESERVED", state)
        self.assertEqual(database_bytes, proven.binding.database_path.read_bytes())
        self.assertEqual(database_mtime, proven.binding.database_path.stat().st_mtime_ns)
        self.assertEqual(
            database_siblings,
            sorted(item.name for item in proven.binding.database_path.parent.iterdir()),
        )

    def test_recover_apply_removes_only_registered_runtime_and_marks_it_missing(self) -> None:
        proven = self.create_proven_state(with_route=True)
        artifact_id, path = self.prepare_reserved_runtime(proven)
        lock = proven.binding.state_home / "controller.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        with (
            patch(
                "codex_smart_subagents.admin_v2._load_proven_state",
                return_value=proven,
            ),
            patch(
                "codex_smart_subagents.admin_v2._require_controller_stopped",
                return_value=None,
            ),
        ):
            code, result = self.invoke("recover", "--apply")

        self.assertEqual(0, code)
        self.assertTrue(result["ok"])
        self.assertEqual("RECOVERY_APPLIED", result["code"])
        self.assertFalse(path.exists())
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            state = connection.execute(
                "select state from runtime_artifacts where artifact_id=?",
                (artifact_id,),
            ).fetchone()[0]
        self.assertEqual("MISSING", state)

    def test_recover_dry_run_refuses_unregistered_attempt_directory(self) -> None:
        proven = self.create_proven_state()
        attempts = proven.binding.state_home / "attempt-runtimes-v2"
        attempts.mkdir(mode=0o700)
        unknown = attempts / ("attempt-att2_" + "9" * 32)
        unknown.mkdir(mode=0o700)
        with patch(
            "codex_smart_subagents.admin_v2._load_proven_state",
            return_value=proven,
        ):
            code, result = self.invoke("recover", "--dry-run")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("RECOVERY_BLOCKED", result["code"])
        self.assertEqual(
            ["UNREGISTERED_ATTEMPT_RUNTIME"],
            result["data"]["recovery"]["blockers"],
        )
        self.assertTrue(unknown.exists())

    def test_recover_apply_refuses_while_controller_process_is_live(self) -> None:
        proven = self.create_proven_state(
            with_route=True,
            controller_marker=system_process_start_marker_v2(os.getpid()),
        )
        artifact_id, path = self.prepare_reserved_runtime(proven)
        lock = proven.binding.state_home / "controller.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        with patch(
            "codex_smart_subagents.admin_v2._load_proven_state",
            return_value=proven,
        ):
            code, result = self.invoke("recover", "--apply")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("CONTROLLER_ACTIVE", result["code"])
        self.assertTrue(path.exists())
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            state = connection.execute(
                "select state from runtime_artifacts where artifact_id=?",
                (artifact_id,),
            ).fetchone()[0]
        self.assertEqual("RESERVED", state)

    def test_stop_terminates_only_the_twice_proven_controller_identity(self) -> None:
        proven = self.create_proven_state(controller_marker="controller-start")
        observations = iter(("EXACT", "EXACT", "ABSENT"))
        sent: list[tuple[int, signal.Signals]] = []

        report = stop_live_controller_v2(
            proven,
            timeout_seconds=1.0,
            process_observer=lambda pid, marker: next(observations),
            signal_sender=lambda pid, selected: sent.append((pid, selected)),
            monotonic=iter((0.0, 0.0)).__next__,
            sleeper=lambda delay: None,
        )

        self.assertTrue(report.stopped)
        self.assertTrue(report.signaled)
        self.assertEqual("CONTROLLER_STOPPED", report.reason_code)
        self.assertEqual([(os.getpid(), signal.SIGTERM)], sent)

    def test_stop_refuses_an_unverifiable_controller_without_signaling(self) -> None:
        proven = self.create_proven_state(controller_marker="controller-start")
        sent: list[tuple[int, signal.Signals]] = []

        with self.assertRaises(AdminV2Error) as raised:
            stop_live_controller_v2(
                proven,
                process_observer=lambda pid, marker: "UNVERIFIABLE",
                signal_sender=lambda pid, selected: sent.append((pid, selected)),
            )

        self.assertEqual("CONTROLLER_STATE_UNKNOWN", raised.exception.code)
        self.assertEqual([], sent)

    def test_recovery_accepts_a_controller_awaiting_process_collection(self) -> None:
        proven = self.create_proven_state(controller_marker="controller-start")
        with (
            patch("codex_smart_subagents.admin_state_v2.os.kill", return_value=None),
            patch(
                "codex_smart_subagents.admin_state_v2.system_process_start_marker_v2",
                side_effect=ChildGuardV2Error(
                    "PROCESS_NOT_RUNNING",
                    "process is awaiting collection",
                ),
            ),
        ):
            require_controller_stopped_v2(proven)

    def test_stop_command_is_idempotent_when_controller_is_already_absent(self) -> None:
        proven = self.create_proven_state(controller_marker="controller-start")
        with (
            patch(
                "codex_smart_subagents.admin_v2._load_proven_state",
                return_value=proven,
            ),
            patch(
                "codex_smart_subagents.admin_state_v2.observe_process_identity_v2",
                return_value="ABSENT",
            ),
        ):
            code, result = self.invoke("stop")

        self.assertEqual(0, code)
        self.assertTrue(result["ok"])
        self.assertEqual("CONTROLLER_ALREADY_STOPPED", result["code"])
        self.assertFalse(result["data"]["signaled"])

    def test_status_accepts_only_receipt_bound_to_the_proven_activation(self) -> None:
        proven = self.create_proven_state(with_route=True)
        self.prepare_receipt_artifacts()
        self.write_valid_receipt()
        decision = SimpleNamespace(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.root / "codex",
            runtime_binding=proven.binding,
        )
        with (
            patch(
                "codex_smart_subagents.admin_state_v2.ActivationResolver.resolve_persisted_activation",
                return_value=decision,
            ),
            patch(
                "codex_smart_subagents.admin_v2._probe_live_controller",
                return_value=(True, "READY"),
            ),
        ):
            code, result = self.invoke("status")

        self.assertEqual(0, code)
        self.assertTrue(result["ok"])
        self.assertEqual("READY", result["code"])

    def test_status_refuses_receipt_bound_to_another_state_home(self) -> None:
        proven = self.create_proven_state()
        self.prepare_receipt_artifacts()
        receipt_path = self.write_valid_receipt()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["stateHome"] = str(self.root / "another-state")
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        receipt_path.chmod(0o600)
        decision = SimpleNamespace(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.root / "codex",
            runtime_binding=proven.binding,
        )
        with patch(
            "codex_smart_subagents.admin_state_v2.ActivationResolver.resolve_persisted_activation",
            return_value=decision,
        ):
            code, result = self.invoke("status")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])
        self.assertEqual(
            "INSTALLER_RECEIPT_MISMATCH",
            result["data"]["reasonCode"],
        )

    def test_status_refuses_database_version_changed_after_activation_proof(self) -> None:
        proven = self.create_proven_state()
        with closing(sqlite3.connect(proven.binding.database_path)) as connection:
            connection.execute("pragma user_version=1")
        with patch(
            "codex_smart_subagents.admin_v2._load_proven_state",
            return_value=proven,
        ):
            code, result = self.invoke("status")

        self.assertEqual(4, code)
        self.assertFalse(result["ok"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])
        self.assertEqual("DATABASE_PROOF_MISMATCH", result["data"]["reasonCode"])

    def test_admin_entrypoint_routes_partial_v2_state_to_fail_closed_v2(self) -> None:
        (self.codex_home / "codex-smart-subagents-v2").mkdir(mode=0o700)
        completed = subprocess.run(
            [
                sys.executable,
                str(
                    REPO
                    / "plugins"
                    / "codex-smart-subagents"
                    / "bin"
                    / "codex-smart-subagents-admin"
                ),
                "status",
            ],
            env={**os.environ, **self.environment},
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(4, completed.returncode)
        result = json.loads(completed.stdout)
        self.assertEqual(2, result["schemaVersion"])
        self.assertEqual("V2_STATE_UNCONFIRMED", result["code"])


if __name__ == "__main__":
    unittest.main()
