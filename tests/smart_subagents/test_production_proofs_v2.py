from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    GuardExecConfirmationV2,
    system_process_start_marker_v2,
)
from codex_smart_subagents.child_launch_coordinator_v2 import (  # noqa: E402
    SnapshotObservationV2,
)
from codex_smart_subagents.live_canary import (  # noqa: E402
    ManagedConfigState,
)
from codex_smart_subagents.permissions import CanaryEvidence  # noqa: E402
from codex_smart_subagents.production_proofs_v2 import (  # noqa: E402
    CodexSnapshotDescriptorProbeV2,
    LivePreparedPermissionProbeV2,
    PermissionProbeContextV2,
    PreparedProcessProbeV2,
    SharedLaunchBarrierV2,
)


class _Inspector:
    def __init__(self) -> None:
        self.state = ManagedConfigState(
            sha256="b" * 64,
            legacy_sandbox_mode=False,
        )

    def inspect(self) -> ManagedConfigState:
        return self.state


class ProductionProofsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cppv2-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.executable = self.root / "codex"
        self.executable.write_bytes(b"codex-proof")
        self.executable.chmod(0o500)
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()

    def test_descriptor_probe_is_stable_and_rejects_content_change(self) -> None:
        probe = CodexSnapshotDescriptorProbeV2()
        first = probe(self.executable, self.digest)
        second = probe(self.executable, self.digest)
        self.assertEqual(first, second)
        self.assertEqual(self.digest, first.snapshot_sha256)

        self.executable.chmod(0o700)
        self.executable.write_bytes(b"changed")
        self.executable.chmod(0o500)
        with self.assertRaisesRegex(Exception, "CODEX_SNAPSHOT_CHANGED"):
            probe(self.executable, self.digest)

    def test_shared_barrier_is_reentrant_and_reports_ownership(self) -> None:
        barrier = SharedLaunchBarrierV2()
        self.assertFalse(barrier.held_by_current_thread)
        with barrier():
            self.assertTrue(barrier.held_by_current_thread)
            with barrier():
                self.assertTrue(barrier.held_by_current_thread)
        self.assertFalse(barrier.held_by_current_thread)

    def test_process_probe_compares_fresh_marker_executable_and_argv(self) -> None:
        prepared = SimpleNamespace(
            executable=self.executable,
            argv=(str(self.executable), "exec", "--model", "gpt-5.6-terra"),
            model="gpt-5.6-terra",
            reasoning_effort="high",
            permission_profile_id="codex-smart-reader",
            argv_fingerprint="1" * 64,
            snapshot_identity_fingerprint="2" * 64,
            compatibility_fingerprint="3" * 64,
            account_context_fingerprint="4" * 64,
            snapshot_sha256=self.digest,
        )
        confirmation = GuardExecConfirmationV2(
            pid=123,
            process_start_marker="marker-123",
        )
        probe = PreparedProcessProbeV2(
            snapshot_probe=lambda _path, _sha: SnapshotObservationV2(
                snapshot_sha256=self.digest,
                snapshot_identity_fingerprint="2" * 64,
            ),
            process_start_marker_provider=lambda _pid: "marker-123",
            process_executable_provider=lambda _pid: self.executable,
            process_argv_provider=lambda _pid: prepared.argv,
        )
        observed = probe(prepared, confirmation)
        self.assertEqual(123, observed.pid)
        self.assertEqual("gpt-5.6-terra", observed.model)
        self.assertEqual(self.digest, observed.codex_binary_sha256)

        probe.process_argv_provider = lambda _pid: (str(self.executable), "exec")
        with self.assertRaisesRegex(Exception, "PROCESS_ARGV_MISMATCH"):
            probe(prepared, confirmation)

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "live process inspection is platform-specific",
    )
    def test_default_process_probe_observes_a_real_exec(self) -> None:
        executable = Path("/bin/sleep").resolve(strict=True)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        snapshot = SnapshotObservationV2(
            snapshot_sha256=digest,
            snapshot_identity_fingerprint="2" * 64,
        )
        argv = (str(executable), "5")
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.addCleanup(process.kill)
        marker = system_process_start_marker_v2(process.pid)
        prepared = SimpleNamespace(
            executable=executable,
            argv=argv,
            model="gpt-5.6-luna",
            reasoning_effort="low",
            permission_profile_id="codex-smart-reader",
            argv_fingerprint="1" * 64,
            snapshot_identity_fingerprint=snapshot.snapshot_identity_fingerprint,
            compatibility_fingerprint="3" * 64,
            account_context_fingerprint="4" * 64,
            snapshot_sha256=digest,
        )
        observed = PreparedProcessProbeV2(
            snapshot_probe=lambda _path, _digest: snapshot,
        )(
            prepared,
            GuardExecConfirmationV2(
                pid=process.pid,
                process_start_marker=marker,
            ),
        )
        self.assertEqual(process.pid, observed.pid)
        process.terminate()
        process.wait(timeout=2)

    def test_live_permission_adapter_uses_exact_materialized_profile(self) -> None:
        snapshot = self.root / "snapshot"
        snapshot.mkdir(mode=0o700)
        read_probe = snapshot / "README.md"
        read_probe.write_text("read\n", encoding="utf-8")
        read_probe.chmod(0o400)
        snapshot.chmod(0o500)
        codex_home = self.root / "codex-home"
        codex_home.mkdir(mode=0o700)
        auth = codex_home / "auth.json"
        auth.write_text("{}\n", encoding="utf-8")
        auth.chmod(0o600)
        runtime_parent = self.root / "canary"
        runtime_parent.mkdir(mode=0o700)
        database = self.root / "state.sqlite3"
        database.write_bytes(b"db")
        database.chmod(0o600)
        protected = self.root / "source.txt"
        protected.write_text("source\n", encoding="utf-8")
        protected.chmod(0o600)
        controller_socket = self.root / "controller.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(controller_socket))
        os.chmod(controller_socket, 0o600)
        self.addCleanup(listener.close)

        permission_name = "codex-smart-reader"
        snapshot_json = '"' + str(snapshot) + '"'
        overrides = (
            f'permissions.{permission_name}.description="Adaptive child reader"',
            f"permissions.{permission_name}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f'{snapshot_json}="read"}}',
            f"permissions.{permission_name}.network.enabled=false",
        )
        argv: list[str] = [str(self.executable), "exec"]
        for value in overrides:
            argv.extend(("-c", value))
        prepared = SimpleNamespace(
            executable=self.executable,
            argv=tuple(argv),
            non_secret_environment={
                "CODEX_ADAPTIVE_SNAPSHOT_ROOT": str(snapshot),
            },
            permission_profile_id=permission_name,
            expected_cli_version="0.144.6",
            model="gpt-5.6-terra",
            reasoning_effort="high",
            role="reader",
        )
        captured: dict[str, object] = {}

        class Canary:
            pass

        def canary_factory(**kwargs):
            captured.update(kwargs)
            return Canary()

        class Gate:
            def require_verified(self, request):
                captured["request"] = request
                return CanaryEvidence(
                    probe_id="pc1_" + "A" * 43,
                    codex_version=request.codex_version,
                    permission_profile=request.permission_profile,
                    profile_sha256=request.profile_sha256,
                    managed_config_sha256=request.managed_config_sha256,
                    verified_at=datetime.now(timezone.utc),
                    legacy_sandbox_mode=False,
                    checks={},
                )

        context = PermissionProbeContextV2(
            codex_home=codex_home,
            runtime_parent=runtime_parent,
            managed_config_inspector=_Inspector(),
            secret_read_file=auth,
            source_git_read_file=protected,
            controller_database_read_file=database,
            source_worktree_write_file=protected,
            controller_socket=controller_socket,
            ruby_executable=Path("/usr/bin/ruby"),
        )
        probe = LivePreparedPermissionProbeV2(
            context,
            canary_factory=canary_factory,
            gate_factory=lambda _canary: Gate(),
        )
        self.assertEqual("pc1_" + "A" * 43, probe(prepared))
        profile = captured["profile"]
        self.assertEqual(overrides, profile.config_overrides)
        self.assertEqual(read_probe, captured["targets"].snapshot_read_file)
        self.assertEqual(
            self.digest, hashlib.sha256(self.executable.read_bytes()).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
