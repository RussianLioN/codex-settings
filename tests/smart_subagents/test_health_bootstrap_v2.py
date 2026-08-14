from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    ActivationResolver,
    GatewayLayout,
    GatewayState,
    v2_gateway_state_present,
)
from codex_smart_subagents.activation_materializer_v2 import (  # noqa: E402
    ActivationMaterializationV2Error,
    cleanup_accepted_activation_v2,
    stage_activation_identity_v2,
)
from codex_smart_subagents.codex_binary_snapshot import (  # noqa: E402
    SnapshotCommand,
    SnapshotCommandResult,
)
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from codex_smart_subagents.controller_health_v2 import (  # noqa: E402
    ControllerHealthServerV2,
    ControllerHealthV2Error,
)
from codex_smart_subagents.health_bootstrap_v2 import (  # noqa: E402
    HealthBootstrapV2Error,
    bootstrap_health_activation_v2,
    observe_health_activation_v2,
)
import codex_smart_subagents.health_bootstrap_v2 as health_bootstrap_v2  # noqa: E402


NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


class _Snapshotter:
    def __init__(self, snapshot_root: Path) -> None:
        self.snapshot_root = snapshot_root

    def materialize(self, source_locator: str | os.PathLike[str]) -> dict[str, object]:
        source = Path(source_locator).absolute()
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = self.snapshot_root / digest / "codex"
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.snapshot_root.chmod(0o700)
        destination.parent.chmod(0o700)
        if not destination.exists():
            shutil.copyfile(source, destination)
            destination.chmod(0o500)
            os.utime(destination, ns=(1_000_000_000_000, 1_000_000_000_000))
        info = destination.stat()
        return {
            "snapshotSha256": digest,
            "snapshotPath": str(destination),
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mtimeNs": str(info.st_mtime_ns),
            "version": "codex-cli 0.144.6",
            "platform": "darwin",
            "architecture": "arm64",
            "signatureIdentifier": "codex",
            "teamIdentifier": "2DC432GLL2",
            "cdHash": "5" * 40,
            "sourceLocator": str(source),
            "sourceObservedSha256": digest,
        }

    def materialize_with_identity(
        self, source_locator: str | os.PathLike[str]
    ) -> SimpleNamespace:
        source = Path(source_locator).absolute()
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        directory = self.snapshot_root / digest
        destination = directory / "codex"
        directory_existed = directory.exists()
        snapshot_existed = destination.exists()
        subject = self.materialize(source_locator)
        return SimpleNamespace(
            subject=subject,
            snapshot_disposition="reused" if snapshot_existed else "created",
            digest_directory_disposition=("reused" if directory_existed else "created"),
        )


class _InterfaceExecutor:
    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        arguments = command.argv[1:]
        if arguments == ("debug", "models", "--bundled"):
            return SnapshotCommandResult(
                0,
                json.dumps(
                    {
                        "models": [
                            {
                                "slug": "gpt-5.6-sol",
                                "supported_reasoning_levels": [
                                    {"effort": "max"},
                                    {"effort": "xhigh"},
                                    {"effort": "high"},
                                ],
                            },
                            {
                                "slug": "gpt-5.6-luna",
                                "supported_reasoning_levels": [
                                    {"effort": "medium"},
                                    {"effort": "low"},
                                ],
                            },
                            {
                                "slug": "gpt-5.6-terra",
                                "supported_reasoning_levels": [
                                    {"effort": "xhigh"},
                                    {"effort": "high"},
                                    {"effort": "medium"},
                                ],
                            },
                        ]
                    }
                ).encode("utf-8"),
                b"",
            )
        if arguments == ("app-server", "--help"):
            return SnapshotCommandResult(0, b"--strict-config --listen\n", b"")
        if arguments == ("exec", "--help"):
            return SnapshotCommandResult(
                0,
                (
                    b"--strict-config --model --skip-git-repo-check --ephemeral "
                    b"--ignore-user-config --ignore-rules --output-schema --json\n"
                ),
                b"",
            )
        raise AssertionError(f"unexpected probe command: {command.argv!r}")


class _RejectingInterfaceExecutor:
    def run(self, _command: SnapshotCommand) -> SnapshotCommandResult:
        raise RuntimeError("forced interface probe rejection")


class _CoordinatorInspector:
    def __init__(self, observed=None) -> None:
        self.observed = observed or {
            "gpt-5.6-sol": frozenset({"medium"}),
        }
        self.calls = 0

    def inspect(self):
        self.calls += 1
        if isinstance(self.observed, BaseException):
            raise self.observed
        return self.observed


def _coordinator_deadline() -> OperationDeadlineExceededV2:
    return OperationDeadlineExceededV2(
        code="ROOT_OPERATION_EXPIRED",
        operation="controller-bootstrap",
        phase="model-list-cleanup",
        deadline_kind="root",
        configured_timeout_nanoseconds=5_000_000_000,
        elapsed_monotonic_nanoseconds=5_000_000_001,
    )


class HealthBootstrapV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cshb2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex-source"
        self.codex_binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.codex_binary.chmod(0o500)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_bytes(b"#!/bin/sh\n")
        self.wrapper.chmod(0o500)
        self.layout = GatewayLayout.for_codex_home(self.codex_home)
        vectors = ROOT / "docs" / "contracts" / "vectors"
        self.policy = load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=vectors / "routing-policy-v2.json",
            delegation_vector_path=vectors / "delegation-policy-v2.json",
            role_vector_path=vectors / "role-template-v1.json",
            child_profile_vector_path=vectors / "child-profile-v1.json",
        )
        self.snapshotter = _Snapshotter(self.layout.managed_root / "codex-snapshots")
        self.interface_executor = _InterfaceExecutor()
        self.runtimes = []

    def tearDown(self) -> None:
        for runtime in reversed(self.runtimes):
            runtime.close()
        self.temporary.cleanup()

    def _stage(self):
        return stage_activation_identity_v2(
            source_root=ROOT,
            codex_home=self.codex_home,
            state_home=self.codex_home / "state" / "codex-smart-subagents-v2",
            codex_binary=self.codex_binary,
            policy_bundle=self.policy,
            snapshotter=self.snapshotter,
            interface_executor=self.interface_executor,
            completed_at=NOW,
        )

    def _bootstrap(self, **overrides):
        arguments = {
            "source_root": ROOT,
            "codex_home": self.codex_home,
            "state_home": self.codex_home / "state" / "codex-smart-subagents-v2",
            "codex_binary": self.codex_binary,
            "wrapper": self.wrapper,
            "policy_bundle": self.policy,
            "snapshotter": self.snapshotter,
            "interface_executor": self.interface_executor,
            "snapshot_verifier": lambda _subject: None,
            "completed_at": NOW,
        }
        arguments.update(overrides)
        runtime = bootstrap_health_activation_v2(**arguments)
        self.runtimes.append(runtime)
        return runtime

    def _assert_clean_first_attempt_state(self) -> None:
        state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        snapshot = (
            self.layout.managed_root
            / "codex-snapshots"
            / hashlib.sha256(self.codex_binary.read_bytes()).hexdigest()
            / "codex"
        )
        self.assertFalse(v2_gateway_state_present(self.layout))
        self.assertFalse(snapshot.exists())
        self.assertFalse(self.layout.managed_root.exists())
        self.assertFalse(state_home.exists())
        self.assertFalse(self.layout.lock_path.exists())

    def _create_dead_persisted_activation(self) -> dict[str, object]:
        program = r"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
plugin_src = root / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(plugin_src))
sys.path.insert(0, str(root))
from tests.smart_subagents.test_health_bootstrap_v2 import _InterfaceExecutor, _Snapshotter
from codex_smart_subagents.activation_gateway_v2 import GatewayLayout
from codex_smart_subagents.health_bootstrap_v2 import bootstrap_health_activation_v2
from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2

codex_home = Path(sys.argv[2])
codex_binary = Path(sys.argv[3])
wrapper = Path(sys.argv[4])
vectors = root / "docs" / "contracts" / "vectors"
policy = load_policy_bundle_v2(
    catalog_path=root / ".codex" / "adaptive-subagents.toml",
    routing_vector_path=vectors / "routing-policy-v2.json",
    delegation_vector_path=vectors / "delegation-policy-v2.json",
    role_vector_path=vectors / "role-template-v1.json",
    child_profile_vector_path=vectors / "child-profile-v1.json",
)
layout = GatewayLayout.for_codex_home(codex_home)
runtime = bootstrap_health_activation_v2(
    source_root=root,
    codex_home=codex_home,
    state_home=codex_home / "state" / "codex-smart-subagents-v2",
    codex_binary=codex_binary,
    wrapper=wrapper,
    policy_bundle=policy,
    snapshotter=_Snapshotter(layout.managed_root / "codex-snapshots"),
    interface_executor=_InterfaceExecutor(),
    snapshot_verifier=lambda _subject: None,
    completed_at=datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc),
)
binding = runtime.gateway_decision.runtime_binding
assert binding is not None
print(json.dumps({
    "activationId": runtime.gateway_decision.activation_id,
    "databasePath": str(binding.database_path),
    "databaseIdentity": dict(binding.database_identity_row),
    "controller": dict(binding.controller_row),
    "receiptPath": str(runtime.materialization.receipt_path),
}, sort_keys=True), flush=True)
os._exit(0)
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                program,
                str(ROOT),
                str(self.codex_home),
                str(self.codex_binary),
                str(self.wrapper),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_stage_has_identity_without_controller_artifacts(self) -> None:
        staged = self._stage()
        state_home = self.codex_home / "state" / "codex-smart-subagents-v2"

        self.assertTrue(staged.activation_dir.is_dir())
        self.assertTrue((staged.activation_dir / "activation.json").is_file())
        self.assertTrue(staged.activation_id.startswith("act2_"))
        self.assertTrue(staged.database_id.startswith("db2_"))
        self.assertEqual(64, len(staged.activation_fingerprint))
        self.assertFalse(staged.socket_path.exists())
        self.assertFalse(staged.database_path.exists())
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.receipts_root.exists())
        self.assertFalse(self.layout.marketplace_link.exists())
        self.assertFalse((self.codex_home / "config.toml").exists())
        for name in ("databases", "backups", "quarantine"):
            with self.subTest(retained_root=name):
                path = state_home / name
                self.assertTrue(path.is_dir())
                self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))

    def test_real_two_phase_bootstrap_uses_one_socket_inode(self) -> None:
        claims = []
        original_claim = ControllerHealthServerV2._claim_socket

        def counted_claim(server):
            claims.append(server.socket_path)
            return original_claim(server)

        with patch.object(ControllerHealthServerV2, "_claim_socket", counted_claim):
            runtime = self._bootstrap()

        self.assertEqual("HEALTH_ONLY_READY", runtime.readiness)
        self.assertTrue(runtime.owns_runtime)
        self.assertEqual(GatewayState.READY, runtime.gateway_decision.state)
        self.assertTrue(runtime.thread_alive)
        self.assertEqual(
            [runtime.controller.socket_path],
            [str(path) for path in claims],
        )

        socket_info = Path(runtime.controller.socket_path).lstat()
        self.assertEqual(socket_info.st_dev, runtime.controller.socket_device)
        self.assertEqual(socket_info.st_ino, runtime.controller.socket_inode)
        binding = runtime.gateway_decision.runtime_binding
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(
            runtime.controller.socket_inode,
            binding.controller_row["socket_inode"],
        )
        with closing(sqlite3.connect(binding.database_path)) as connection:
            row = connection.execute(
                "select socket_device, socket_inode from controller_state"
            ).fetchone()
        self.assertEqual(
            (runtime.controller.socket_device, runtime.controller.socket_inode),
            row,
        )
        self.assertFalse((self.codex_home / "config.toml").exists())

    def test_initial_controller_collects_coordinator_selection_once(self) -> None:
        inspector = _CoordinatorInspector()
        factories: list[dict[str, object]] = []

        def factory(**arguments):
            factories.append(arguments)
            return inspector

        runtime = self._bootstrap(coordinator_inspector_factory=factory)

        self.assertEqual(1, len(factories))
        self.assertEqual(1.0, factories[0]["timeout_seconds"])
        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            {
                "model": "gpt-5.6-sol",
                "reasoning_effort": "medium",
            },
            runtime.gateway_decision.coordinator,
        )

    def test_recovery_collects_a_new_selection_once(self) -> None:
        self._create_dead_persisted_activation()
        inspector = _CoordinatorInspector(
            {"gpt-5.6-terra": frozenset({"medium"})}
        )
        factories: list[dict[str, object]] = []

        def factory(**arguments):
            factories.append(arguments)
            return inspector

        runtime = self._bootstrap(coordinator_inspector_factory=factory)

        self.assertEqual(1, len(factories))
        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            {
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
            runtime.gateway_decision.coordinator,
        )

    def test_initial_deadline_is_materialized_as_health_unavailable(self) -> None:
        inspector = _CoordinatorInspector(_coordinator_deadline())
        runtime = self._bootstrap(
            coordinator_inspector_factory=lambda **_arguments: inspector
        )

        selection = runtime.gateway_decision.coordinator_selection
        self.assertIsNotNone(selection)
        assert selection is not None
        deadline = time.monotonic() + 1.0
        while inspector.calls < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(2, inspector.calls)
        self.assertEqual("UNAVAILABLE", selection["status"])
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            selection["reasonCode"],
        )
        self.assertIsNone(selection["accountCatalogFingerprint"])
        self.assertEqual(
            selection,
            runtime.materialization.expected_health_payload[
                "coordinatorSelection"
            ],
        )
        assert runtime._server is not None
        refresh = runtime._server.coordinator_refresh_diagnostics
        self.assertEqual("UNAVAILABLE", refresh["status"])
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            refresh["reasonCode"],
        )
        self.assertIsNone(refresh["lastSuccessfulCheckAt"])
        self.assertIsNotNone(refresh["nextAttemptAt"])

    def test_temporary_catalog_failure_recovers_in_one_joined_background_loop(
        self,
    ) -> None:
        recovered = threading.Event()
        factory_calls = 0
        probe_timeouts: list[float] = []

        def factory(**arguments):
            nonlocal factory_calls
            factory_calls += 1
            probe_timeouts.append(arguments["timeout_seconds"])
            if factory_calls == 1:
                return _CoordinatorInspector(_coordinator_deadline())

            class RecoveredInspector(_CoordinatorInspector):
                def inspect(self):
                    result = super().inspect()
                    recovered.set()
                    return result

            return RecoveredInspector(
                {"gpt-5.6-sol": frozenset({"medium"})}
            )

        runtime = self._bootstrap(coordinator_inspector_factory=factory)
        self.assertTrue(recovered.wait(1.0))
        self.assertTrue(runtime.catalog_refresh_alive)
        assert runtime._server is not None
        self.assertEqual(
            "SELECTED",
            runtime._server.coordinator_selection["status"],
        )
        refresh = runtime._server.coordinator_refresh_diagnostics
        self.assertEqual("SELECTED", refresh["status"])
        self.assertEqual(
            "COORDINATOR_PAIR_SELECTED",
            refresh["reasonCode"],
        )
        self.assertIsNotNone(refresh["lastSuccessfulCheckAt"])
        self.assertIsNotNone(refresh["nextAttemptAt"])
        self.assertEqual([1.0, 20.0], probe_timeouts)

        runtime.close()
        self.assertFalse(runtime.catalog_refresh_alive)

    def test_recovery_deadline_is_materialized_as_health_unavailable(self) -> None:
        self._create_dead_persisted_activation()
        inspector = _CoordinatorInspector(_coordinator_deadline())
        runtime = self._bootstrap(
            coordinator_inspector_factory=lambda **_arguments: inspector
        )

        selection = runtime.gateway_decision.coordinator_selection
        self.assertIsNotNone(selection)
        assert selection is not None
        deadline = time.monotonic() + 1.0
        while inspector.calls < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(2, inspector.calls)
        self.assertEqual("UNAVAILABLE", selection["status"])
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            selection["reasonCode"],
        )
        self.assertIsNone(selection["accountCatalogFingerprint"])
        self.assertEqual(
            selection,
            runtime.materialization.expected_health_payload[
                "coordinatorSelection"
            ],
        )

    def test_explicit_state_home_binds_health_database_and_manifest(self) -> None:
        state_home = self.root / "s"

        runtime = self._bootstrap(state_home=state_home)

        binding = runtime.gateway_decision.runtime_binding
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(state_home, Path(binding.state_home))
        self.assertEqual(
            state_home / "controller.sock", Path(runtime.controller.socket_path)
        )
        manifest = json.loads(self.layout.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(str(state_home), manifest["stateHome"])
        self.assertTrue(Path(binding.database_path).is_relative_to(state_home))

    def test_repeat_owner_returns_the_same_live_runtime(self) -> None:
        first = self._bootstrap()
        second = self._bootstrap()

        self.assertIs(first, second)
        self.assertTrue(first.thread_alive)

    def test_foreign_live_activation_is_observed_without_ownership(self) -> None:
        owner = self._bootstrap()

        with (
            patch.object(health_bootstrap_v2, "_OWNER_RUNTIMES", {}),
            patch.object(
                ControllerHealthServerV2,
                "_claim_socket",
                side_effect=AssertionError("foreign observer must not claim socket"),
            ) as socket_claim,
        ):
            observed = self._bootstrap()

        self.assertFalse(observed.owns_runtime)
        socket_claim.assert_not_called()
        self.assertEqual("HEALTH_ONLY_READY", observed.readiness)
        self.assertEqual(GatewayState.READY, observed.gateway_decision.state)
        observed.close()
        self.assertTrue(owner.thread_alive)

    def test_direct_observation_never_claims_runtime_ownership(self) -> None:
        owner = self._bootstrap()

        observed = observe_health_activation_v2(
            codex_home=self.codex_home,
            wrapper=self.wrapper,
            snapshot_verifier=lambda _subject: None,
        )
        self.runtimes.append(observed)

        self.assertFalse(observed.owns_runtime)
        observed.close()
        self.assertTrue(owner.thread_alive)

    def test_dead_persisted_activation_recovers_with_next_control_epoch(self) -> None:
        previous = self._create_dead_persisted_activation()
        manifest_before = self.layout.manifest_path.read_bytes()
        activation_path = (
            self.layout.managed_root
            / "activations"
            / str(previous["activationId"])
            / "activation.json"
        )
        activation_before = activation_path.read_bytes()
        receipt_path = Path(str(previous["receiptPath"]))
        receipt_before = receipt_path.read_bytes()

        before_recovery = ActivationResolver(
            layout=self.layout,
            wrapper=self.wrapper,
            snapshot_verifier=lambda _subject: None,
        ).resolve()
        self.assertEqual(GatewayState.ORDINARY, before_recovery.state)
        self.assertEqual("CONTROLLER_UNAVAILABLE", before_recovery.reason_code)

        recovered = self._bootstrap()

        self.assertTrue(recovered.owns_runtime)
        self.assertEqual("HEALTH_ONLY_READY", recovered.readiness)
        self.assertEqual(GatewayState.READY, recovered.gateway_decision.state)
        self.assertEqual("CONTROLLER_RECOVERED", recovered.materialization.status)
        self.assertEqual(receipt_path, recovered.materialization.receipt_path)
        binding = recovered.gateway_decision.runtime_binding
        self.assertIsNotNone(binding)
        assert binding is not None
        previous_controller = previous["controller"]
        self.assertEqual(previous["activationId"], binding.activation_id)
        self.assertEqual(
            previous["databaseIdentity"],
            dict(binding.database_identity_row),
        )
        self.assertEqual(
            int(previous_controller["control_epoch"]) + 1,
            binding.control_epoch,
        )
        self.assertNotEqual(
            previous_controller["instance_id"],
            binding.controller_row["instance_id"],
        )
        self.assertNotEqual(
            previous_controller["controller_start_id"],
            binding.controller_row["controller_start_id"],
        )
        self.assertEqual(os.getpid(), binding.controller_row["controller_pid"])
        self.assertEqual(manifest_before, self.layout.manifest_path.read_bytes())
        self.assertEqual(activation_before, activation_path.read_bytes())
        self.assertEqual(receipt_before, receipt_path.read_bytes())

    def test_same_live_process_cannot_take_over_its_closed_runtime(self) -> None:
        owner = self._bootstrap()
        owner.close()

        self.assertTrue(self.layout.manifest_path.exists())
        self.assertTrue(self.layout.marketplace_link.is_symlink())
        with self.assertRaises(HealthBootstrapV2Error) as captured:
            self._bootstrap()

        self.assertEqual("PREVIOUS_CONTROLLER_STILL_LIVE", captured.exception.code)

    def test_recovery_does_not_take_over_an_occupied_controller_lock(self) -> None:
        previous = self._create_dead_persisted_activation()
        lock_path = (
            self.codex_home / "state" / "codex-smart-subagents-v2" / "controller.lock"
        )
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import fcntl,sys;"
                    "stream=open(sys.argv[1],'r+b',buffering=0);"
                    "fcntl.flock(stream.fileno(),fcntl.LOCK_EX);"
                    "print('locked',flush=True);"
                    "sys.stdin.read()"
                ),
                str(lock_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout is not None
            self.assertEqual("locked", holder.stdout.readline().strip())
            with self.assertRaises(ControllerHealthV2Error) as captured:
                self._bootstrap()
            self.assertEqual("CONTROLLER_ALREADY_RUNNING", captured.exception.code)
            self.assertTrue(self.layout.manifest_path.exists())
            with closing(
                sqlite3.connect(Path(str(previous["databasePath"])))
            ) as connection:
                connection.row_factory = sqlite3.Row
                controller = dict(
                    connection.execute("select * from controller_state").fetchone()
                )
            self.assertEqual(previous["controller"], controller)
            activation = json.loads(
                (
                    self.layout.managed_root
                    / "activations"
                    / str(previous["activationId"])
                    / "activation.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(previous["activationId"], activation["activationId"])
        finally:
            if holder.stdin is not None:
                holder.stdin.close()
            holder.wait(timeout=5)
            if holder.stdout is not None:
                holder.stdout.close()
            if holder.stderr is not None:
                holder.stderr.close()

    def test_failed_recovery_restores_the_previous_controller_row(self) -> None:
        previous = self._create_dead_persisted_activation()
        database_path = Path(str(previous["databasePath"]))
        receipt_path = Path(str(previous["receiptPath"]))
        manifest_before = self.layout.manifest_path.read_bytes()
        receipt_before = receipt_path.read_bytes()
        verifier_calls = 0

        def fail_only_after_registration(_subject) -> None:
            nonlocal verifier_calls
            verifier_calls += 1
            if verifier_calls == 3:
                raise RuntimeError("reject recovered controller")

        with self.assertRaises(HealthBootstrapV2Error) as captured:
            self._bootstrap(snapshot_verifier=fail_only_after_registration)

        self.assertEqual("RECOVERY_HEALTH_NOT_READY", captured.exception.code)
        with closing(sqlite3.connect(database_path)) as connection:
            connection.row_factory = sqlite3.Row
            controller = dict(
                connection.execute("select * from controller_state").fetchone()
            )
            identity = dict(
                connection.execute("select * from database_identity").fetchone()
            )
        self.assertEqual(previous["controller"], controller)
        self.assertEqual(previous["databaseIdentity"], identity)
        self.assertEqual(manifest_before, self.layout.manifest_path.read_bytes())
        self.assertEqual(receipt_before, receipt_path.read_bytes())
        self.assertFalse(
            (
                self.codex_home
                / "state"
                / "codex-smart-subagents-v2"
                / "controller.sock"
            ).exists()
        )

    def test_gateway_failure_removes_all_unpublished_candidate_artifacts(self) -> None:
        thread_names_before = {
            thread.name
            for thread in threading.enumerate()
            if thread.name.startswith("codex-smart-health-bootstrap-v2-")
        }

        def reject_snapshot(_subject) -> None:
            raise RuntimeError("forced snapshot rejection")

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._bootstrap(snapshot_verifier=reject_snapshot)

        self.assertEqual("CONTROLLER_HEALTH_NOT_READY", captured.exception.code)
        self.assertFalse(self.layout.marketplace_link.exists())
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.receipts_root.exists())
        activation_root = self.layout.managed_root / "activations"
        self.assertFalse(activation_root.exists())
        database_root = (
            self.codex_home / "state" / "codex-smart-subagents-v2" / "databases"
        )
        self.assertFalse(database_root.exists())
        self.assertFalse(
            (
                self.codex_home
                / "state"
                / "codex-smart-subagents-v2"
                / "controller.sock"
            ).exists()
        )
        self.assertEqual(
            thread_names_before,
            {
                thread.name
                for thread in threading.enumerate()
                if thread.name.startswith("codex-smart-health-bootstrap-v2-")
            },
        )
        self.assertFalse((self.codex_home / "config.toml").exists())
        self._assert_clean_first_attempt_state()

        retried = self._bootstrap()

        self.assertEqual(GatewayState.READY, retried.gateway_decision.state)

    def test_interface_probe_failure_removes_new_snapshot_and_all_scaffolding(
        self,
    ) -> None:
        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._bootstrap(interface_executor=_RejectingInterfaceExecutor())

        self.assertEqual("INTERFACE_PROBE_FAILED", captured.exception.code)
        self._assert_clean_first_attempt_state()

        retried = self._bootstrap()

        self.assertEqual(GatewayState.READY, retried.gateway_decision.state)

    def test_server_constructor_failure_after_stage_allows_retry(self) -> None:
        with (
            patch.object(
                health_bootstrap_v2,
                "ControllerHealthServerV2",
                side_effect=RuntimeError("forced constructor rejection"),
            ),
            self.assertRaisesRegex(RuntimeError, "forced constructor rejection"),
        ):
            self._bootstrap()

        self._assert_clean_first_attempt_state()

        retried = self._bootstrap()

        self.assertEqual(GatewayState.READY, retried.gateway_decision.state)

    def test_interface_probe_failure_preserves_a_reused_snapshot(self) -> None:
        self.layout.managed_root.mkdir(mode=0o700)
        (self.layout.managed_root / "codex-snapshots").mkdir(mode=0o700)
        subject = self.snapshotter.materialize(self.codex_binary)
        snapshot = Path(str(subject["snapshotPath"]))
        original_inode = snapshot.stat().st_ino

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            self._bootstrap(interface_executor=_RejectingInterfaceExecutor())

        self.assertEqual("INTERFACE_PROBE_FAILED", captured.exception.code)
        self.assertTrue(snapshot.is_file())
        self.assertEqual(original_inode, snapshot.stat().st_ino)

    def test_gateway_failure_preserves_foreign_content_in_created_parent(self) -> None:
        foreign = (
            self.codex_home
            / "state"
            / "codex-smart-subagents-v2"
            / "backups"
            / "foreign"
        )

        def add_foreign_content_then_reject(_subject) -> None:
            foreign.write_text("keep", encoding="utf-8")
            raise RuntimeError("forced snapshot rejection")

        with self.assertRaises(ActivationMaterializationV2Error):
            self._bootstrap(snapshot_verifier=add_foreign_content_then_reject)

        self.assertEqual("keep", foreign.read_text(encoding="utf-8"))
        self.assertTrue(foreign.parent.is_dir())
        self.assertFalse(v2_gateway_state_present(self.layout))

        retried = self._bootstrap()

        self.assertEqual(GatewayState.READY, retried.gateway_decision.state)

    def test_gateway_failure_does_not_remove_a_changed_activation_tree(self) -> None:
        foreign: Path | None = None

        def change_activation_then_reject(_subject) -> None:
            nonlocal foreign
            activation_dirs = list((self.layout.managed_root / "activations").iterdir())
            self.assertEqual(1, len(activation_dirs))
            foreign = activation_dirs[0] / "foreign"
            activation_dirs[0].chmod(0o700)
            foreign.write_text("keep", encoding="utf-8")
            activation_dirs[0].chmod(0o500)
            raise RuntimeError("forced snapshot rejection")

        with self.assertRaises(ActivationMaterializationV2Error):
            self._bootstrap(snapshot_verifier=change_activation_then_reject)

        self.assertIsNotNone(foreign)
        assert foreign is not None
        self.assertEqual("keep", foreign.read_text(encoding="utf-8"))

    def test_cleanup_accepted_activation_rejects_a_live_owner(self) -> None:
        runtime = self._bootstrap()
        materialization = runtime.materialization
        assert materialization is not None

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            cleanup_accepted_activation_v2(
                codex_home=self.codex_home,
                installation_id=materialization.installation_id,
                activation_id=materialization.activation_id,
            )

        self.assertEqual("CLEANUP_CONTROLLER_ACTIVE", captured.exception.code)
        self.assertTrue(self.layout.manifest_path.is_file())
        self.assertTrue(self.layout.marketplace_link.is_symlink())

    def test_cleanup_accepted_activation_requires_exact_identity(self) -> None:
        persisted = self._create_dead_persisted_activation()
        manifest = json.loads(self.layout.manifest_path.read_text(encoding="utf-8"))

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            cleanup_accepted_activation_v2(
                codex_home=self.codex_home,
                installation_id="ins2_" + "0" * 32,
                activation_id=str(persisted["activationId"]),
            )

        self.assertEqual("CLEANUP_IDENTITY_MISMATCH", captured.exception.code)
        self.assertEqual(
            manifest,
            json.loads(self.layout.manifest_path.read_text(encoding="utf-8")),
        )
        self.assertTrue(self.layout.marketplace_link.is_symlink())

    def test_cleanup_accepted_activation_removes_only_the_dead_exact_install(
        self,
    ) -> None:
        persisted = self._create_dead_persisted_activation()
        manifest = json.loads(self.layout.manifest_path.read_text(encoding="utf-8"))
        snapshot_path = Path(str(manifest["codexSnapshot"]["absolutePath"]))
        activation_dir = (
            self.layout.managed_root / "activations" / str(persisted["activationId"])
        )
        database_path = Path(str(persisted["databasePath"]))
        receipt_path = Path(str(persisted["receiptPath"]))

        result = cleanup_accepted_activation_v2(
            codex_home=self.codex_home,
            installation_id=str(manifest["installationId"]),
            activation_id=str(persisted["activationId"]),
        )

        self.assertEqual("ACCEPTED_ACTIVATION_REMOVED", result.status)
        self.assertEqual(str(persisted["activationId"]), result.activation_id)
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.marketplace_link.exists())
        self.assertFalse(self.layout.marketplace_link.is_symlink())
        self.assertFalse(activation_dir.exists())
        self.assertFalse(database_path.exists())
        self.assertFalse(receipt_path.exists())
        self.assertFalse(snapshot_path.exists())
        self.assertFalse(self.layout.fallback_path.exists())
        self.assertIn(self.layout.manifest_path, result.removed_paths)
        self.assertNotIn(self.layout.lock_path, result.removed_paths)
        self.assertTrue(self.layout.lock_path.is_file())

    def test_cleanup_accepted_activation_preserves_everything_if_artifact_changed(
        self,
    ) -> None:
        persisted = self._create_dead_persisted_activation()
        manifest_before = self.layout.manifest_path.read_bytes()
        database_path = Path(str(persisted["databasePath"]))
        receipt_path = Path(str(persisted["receiptPath"]))
        self.layout.fallback_path.write_bytes(b"foreign replacement")
        self.layout.fallback_path.chmod(0o600)

        with self.assertRaises(ActivationMaterializationV2Error) as captured:
            cleanup_accepted_activation_v2(
                codex_home=self.codex_home,
                installation_id=json.loads(manifest_before)["installationId"],
                activation_id=str(persisted["activationId"]),
            )

        self.assertEqual("CLEANUP_ARTIFACT_CHANGED", captured.exception.code)
        self.assertEqual(manifest_before, self.layout.manifest_path.read_bytes())
        self.assertTrue(self.layout.marketplace_link.is_symlink())
        self.assertTrue(database_path.is_file())
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(b"foreign replacement", self.layout.fallback_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
