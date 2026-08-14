from __future__ import annotations

import hashlib
import http.client
import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    ChildGuardV2Error,
    GuardExecConfirmationV2,
    GuardExecutionResultV2,
    GuardHelloV2,
)
from codex_smart_subagents.child_launch_coordinator_v2 import (  # noqa: E402
    ChildLaunchCoordinatorV2,
    ChildLaunchCoordinatorV2Error,
    OTelAttemptResourceV2,
    ProcessObservationV2,
    SnapshotObservationV2,
)
from codex_smart_subagents.child_launch_v2 import (  # noqa: E402
    PreparedChildLaunchV2,
    child_argv_fingerprint_v2,
    child_environment_fingerprints_v1,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AttemptLaunchIdentityV2,
    CommittedLaunchV2,
    LaunchPermitV2,
    RequestContextV2,
)
from codex_smart_subagents.telemetry import OTelReceiver, RunAttestation  # noqa: E402


NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
SHA = {
    name: character * 64
    for name, character in {
        "argv": "1",
        "snapshot": "2",
        "identity": "3",
        "compatibility": "4",
        "account": "5",
    }.items()
}


class _FixtureAttemptResource:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.attestations = 0
        self.closed = False

    def attest(self, prepared, events, permission_probe_id):
        self.attestations += 1
        if self.error is not None:
            raise self.error
        if events[0]["type"] != "thread.started":
            raise AssertionError("unexpected terminal events")
        return RunAttestation(
            cli_version=prepared.expected_cli_version,
            requested_model=prepared.model,
            observed_model=prepared.model,
            requested_effort=prepared.reasoning_effort,
            observed_effort=prepared.reasoning_effort,
            conversation_hash="6" * 64,
            argv_fingerprint=prepared.argv_fingerprint,
            permission_probe_id=permission_probe_id,
            run_fingerprint="7" * 64,
        )

    def close(self) -> None:
        self.closed = True


def prepared_launch(attempt_resource=None, completion=None) -> PreparedChildLaunchV2:
    argv = ("/private/tmp/codex-snapshot/codex", "exec", "--json")
    non_secret_environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    raw_headers = "X-Test=bounded-coordinator-fixture"
    environment = MappingProxyType(
        {
            **non_secret_environment,
            "OTEL_EXPORTER_OTLP_HEADERS": raw_headers,
        }
    )
    environment_fingerprint, secret_sha256 = child_environment_fingerprints_v1(
        non_secret_environment=non_secret_environment,
        raw_otel_headers=raw_headers,
        environment_domain="codex-smart/environment/v1",
        secret_domain="codex-smart/launch-secret/v1",
    )
    fingerprint = child_argv_fingerprint_v2(
        argv=argv,
    )
    return PreparedChildLaunchV2(
        executable=Path("/private/tmp/codex-snapshot/codex"),
        argv=argv,
        environment=environment,
        stdin="Проверь договор.".encode(),
        argv_fingerprint=fingerprint,
        snapshot_sha256=SHA["snapshot"],
        snapshot_identity_fingerprint=SHA["identity"],
        model="catalog-model-a",
        reasoning_effort="catalog-effort-b",
        permission_profile_id="reader-v2",
        argv_domain="codex-smart/argv/v2",
        environment_domain="codex-smart/environment/v1",
        secret_domain="codex-smart/launch-secret/v1",
        non_secret_environment=MappingProxyType(non_secret_environment),
        environment_fingerprint=environment_fingerprint,
        secret_sha256=secret_sha256,
        compatibility_fingerprint=SHA["compatibility"],
        account_context_fingerprint=SHA["account"],
        expected_cli_version="0.107.0-test",
        role="reader",
        attempt_resource=attempt_resource or _FixtureAttemptResource(),
        completion=completion,
    )


class _Completion:
    def __init__(self, state: str) -> None:
        self.state = state
        self.calls = 0

    def complete(self, child_result):
        self.calls += 1
        if "runAttestation" not in child_result:
            raise AssertionError("completion ran before terminal attestation")
        return {
            "state": self.state,
            "errorCode": (
                "VALIDATION_FAILED" if self.state == "QUARANTINED" else None
            ),
            "proofHash": "8" * 64,
        }


def request_context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/Users/test/repo",
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
        activation_fingerprint="c" * 64,
        compatibility_fingerprint=SHA["compatibility"],
        issued_control_epoch=7,
    )


@dataclass
class _StartedRecord:
    state: str = "RUNNING"


@dataclass
class _TerminalRecord:
    state: str


class RecordingStore:
    def __init__(self, barrier_depth=lambda: 1) -> None:
        self.calls: list[tuple[str, object]] = []
        self.permit_id = "lp2_" + "a" * 32
        self.attempt_id = "att2_" + "b" * 32
        self.barrier_depth = barrier_depth

    def _require_barrier(self):
        if self.barrier_depth() != 1:
            raise AssertionError("launch transition escaped the shared barrier")

    def reserve_launch_permit(self, **arguments):
        self._require_barrier()
        self.calls.append(("reserve", arguments))
        return LaunchPermitV2(
            permit_id=self.permit_id,
            admission_id=arguments["admission_id"],
            route_id="route2_" + "c" * 32,
            node_id="node2_" + "d" * 32,
            reserved_control_epoch=arguments["expected_control_epoch"],
            activation_gate_fingerprint="6" * 64,
            permit_evidence_fingerprint="7" * 64,
            state="RESERVED",
        )

    def record_guard_hello(self, permit_id, **arguments):
        self._require_barrier()
        self.calls.append(("hello", {"permit_id": permit_id, **arguments}))

    def commit_launch_permit(self, **arguments):
        self._require_barrier()
        self.calls.append(("commit", arguments))
        return CommittedLaunchV2(
            permit_id=self.permit_id,
            attempt_id=self.attempt_id,
            route_id="route2_" + "c" * 32,
            node_id="node2_" + "d" * 32,
            permit_state="COMMIT_AUTHORIZED",
        )

    def read_attempt_launch_identity(self, attempt_id, context):
        self._require_barrier()
        self.calls.append(("read_identity", (attempt_id, context)))
        return AttemptLaunchIdentityV2(
            attempt_id=self.attempt_id,
            route_id="route2_" + "c" * 32,
            node_id="node2_" + "d" * 32,
            start_request_id="sr2_" + "e" * 32,
            evidence_job_id="aej2_" + "f" * 32,
            admission_id="adm2_" + "0" * 32,
            model="catalog-model-a",
            reasoning_effort="catalog-effort-b",
            permission_profile_id="reader-v2",
            argv_fingerprint=prepared_launch().argv_fingerprint,
            snapshot_identity_fingerprint=SHA["identity"],
            compatibility_fingerprint=SHA["compatibility"],
            account_context_fingerprint=SHA["account"],
            pid=4101,
            process_start_marker="pid-4101-start",
            codex_binary_sha256=SHA["snapshot"],
            state="STARTING",
        )

    def record_attempt_started(self, attempt_id, context, **arguments):
        self._require_barrier()
        self.calls.append(("started", {"attempt_id": attempt_id, **arguments}))
        return _StartedRecord()

    def record_attempt_terminal(self, attempt_id, context, **arguments):
        expected_depth = 0 if arguments["attestation"]["disposition"] == "MATCH" else 1
        if self.barrier_depth() != expected_depth:
            raise AssertionError("child terminal used the wrong barrier side")
        self.calls.append(("terminal", {"attempt_id": attempt_id, **arguments}))
        return _TerminalRecord(arguments["state"])

    def abort_launch_permit_before_commit(self, permit_id, context, **arguments):
        self._require_barrier()
        self.calls.append(("abort_permit", {"permit_id": permit_id, **arguments}))


class FakeGuardHandle:
    def __init__(self, *, token: str, snapshot_identity: str, argv: str) -> None:
        self.token = token
        self.snapshot_identity = snapshot_identity
        self.argv = argv
        self.permit_id = ""
        self.committed = False
        self.aborted = False
        self.collected_stdin: bytes | None = None

    def receive_hello(self, timeout_seconds: float) -> GuardHelloV2:
        return GuardHelloV2(
            protocol_version=2,
            permit_id=self.permit_id,
            one_time_token=self.token,
            pid=4101,
            process_start_marker="pid-4101-start",
            argv_fingerprint=self.argv,
            snapshot_identity_fingerprint=self.snapshot_identity,
        )

    def authorize_commit(self, one_time_token: str, timeout_seconds: float):
        if one_time_token != self.token:
            raise AssertionError("coordinator changed the one-time token")
        self.committed = True
        return GuardExecConfirmationV2(
            pid=4101,
            process_start_marker="pid-4101-start",
        )

    def collect(self, stdin: bytes, *, timeout_seconds: float, max_output_bytes: int):
        if not self.committed:
            raise AssertionError("mission was sent before durable commit")
        self.collected_stdin = stdin
        return GuardExecutionResultV2(
            exit_code=0,
            stdout=(
                b'{"type":"thread.started","thread_id":"thread-1"}\n'
                b'{"type":"turn.completed","usage":{}}\n'
            ),
            stderr=b"",
        )

    def abort(self) -> None:
        self.aborted = True


class FakeGuardFactory:
    def __init__(self, barrier_depth=lambda: 0) -> None:
        self.handle: FakeGuardHandle | None = None
        self.barrier_depth = barrier_depth

    def start(self, prepared, *, permit_id, one_time_token, snapshot_probe):
        self.handle = FakeGuardHandle(
            token=one_time_token,
            snapshot_identity=prepared.snapshot_identity_fingerprint,
            argv=prepared.argv_fingerprint,
        )
        self.handle.permit_id = permit_id
        original_collect = self.handle.collect

        def collect(*args, **kwargs):
            if self.barrier_depth() != 0:
                raise AssertionError("mission was collected under launch barrier")
            return original_collect(*args, **kwargs)

        self.handle.collect = collect
        return self.handle


class ChildLaunchCoordinatorV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.barrier_depth = 0
        self.barrier_trace: list[str] = []
        self.store = RecordingStore(lambda: self.barrier_depth)
        self.guard_factory = FakeGuardFactory(lambda: self.barrier_depth)
        self.gates = 0
        self.probes = 0
        self.process_probes = 0

    def _coordinator(
        self,
        *,
        expected_control_epoch: int = 7,
        allowed_pairs: tuple[dict[str, str], ...] | None = None,
    ) -> ChildLaunchCoordinatorV2:
        @contextmanager
        def launch_barrier():
            self.assertEqual(0, self.barrier_depth)
            self.barrier_depth = 1
            self.barrier_trace.append("enter")
            try:
                yield
            finally:
                self.barrier_depth = 0
                self.barrier_trace.append("exit")

        def gate():
            self.gates += 1
            return {
                "manifestSemanticFingerprint": "a" * 64,
                "activationReceiptFingerprint": "b" * 64,
                "journalAbsenceProof": {"proof": "stable"},
                "gateFingerprint": "c" * 64,
            }

        def snapshot(_prepared):
            self.probes += 1
            return SnapshotObservationV2(
                snapshot_sha256=SHA["snapshot"],
                snapshot_identity_fingerprint=SHA["identity"],
            )

        def process(prepared, confirmation):
            self.process_probes += 1
            return ProcessObservationV2(
                model=prepared.model,
                reasoning_effort=prepared.reasoning_effort,
                permission_profile_id=prepared.permission_profile_id,
                argv_fingerprint=prepared.argv_fingerprint,
                snapshot_identity_fingerprint=(prepared.snapshot_identity_fingerprint),
                compatibility_fingerprint=SHA["compatibility"],
                account_context_fingerprint=prepared.account_context_fingerprint,
                pid=confirmation.pid,
                process_start_marker=confirmation.process_start_marker,
                codex_binary_sha256=prepared.snapshot_sha256,
            )

        return ChildLaunchCoordinatorV2(
            store=self.store,
            guard_factory=self.guard_factory,
            launch_barrier=launch_barrier,
            allowed_pairs=allowed_pairs
            if allowed_pairs is not None
            else (
                {
                    "model": "catalog-model-a",
                    "reasoningEffort": "catalog-effort-b",
                },
            ),
            argv_domain="codex-smart/argv/v2",
            environment_domain="codex-smart/environment/v1",
            secret_domain="codex-smart/launch-secret/v1",
            activation_gate_provider=gate,
            fresh_permission_probe=lambda _prepared: "pc2_" + "a" * 32,
            fresh_snapshot_probe=snapshot,
            fresh_process_probe=process,
            expected_control_epoch=expected_control_epoch,
            clock=lambda: NOW,
            token_factory=lambda: "token-v2-abcdefghijklmnopqrstuvwxyz-123456",
        )

    def test_historical_owner_epoch_uses_current_epoch_for_live_transitions(
        self,
    ) -> None:
        historical_context = replace(request_context(), issued_control_epoch=7)

        outcome = self._coordinator(expected_control_epoch=8).run(
            admission_id="adm2_" + "0" * 32,
            request_context=historical_context,
            prepared=prepared_launch(),
            timeout_seconds=30,
            max_output_bytes=1024 * 1024,
        )

        self.assertEqual("SUCCEEDED", outcome.state)
        reserve = dict(self.store.calls[0][1])
        commit = dict(self.store.calls[2][1])
        self.assertEqual(8, reserve["expected_control_epoch"])
        self.assertEqual(8, commit["expected_control_epoch"])
        _, identity_context = self.store.calls[3][1]
        self.assertEqual(7, identity_context.issued_control_epoch)

    def test_commits_before_mission_and_records_attestation_and_terminal_result(
        self,
    ) -> None:
        prepared = prepared_launch()
        outcome = self._coordinator().run(
            admission_id="adm2_" + "0" * 32,
            request_context=request_context(),
            prepared=prepared,
            timeout_seconds=30,
            max_output_bytes=1024 * 1024,
        )

        self.assertEqual("SUCCEEDED", outcome.state)
        self.assertEqual(2, self.gates)
        self.assertEqual(2, self.probes)
        self.assertEqual(1, self.process_probes)
        self.assertEqual(1, prepared.attempt_resource.attestations)
        self.assertTrue(prepared.attempt_resource.closed)
        self.assertEqual(prepared.stdin, self.guard_factory.handle.collected_stdin)
        names = [name for name, _ in self.store.calls]
        self.assertEqual(
            ["reserve", "hello", "commit", "read_identity", "started", "terminal"],
            names,
        )
        hello = dict(self.store.calls[1][1])
        self.assertEqual(
            hashlib.sha256(b"token-v2-abcdefghijklmnopqrstuvwxyz-123456").hexdigest(),
            hello["one_time_token_hash"],
        )
        started = dict(self.store.calls[4][1])
        attestation = started["attestation"]
        self.assertEqual("MATCH", attestation["disposition"])
        self.assertEqual(
            {"model": "catalog-model-a", "reasoningEffort": "catalog-effort-b"},
            attestation["observed"]["pair"],
        )
        self.assertEqual(
            attestation["requested"],
            {
                key: attestation["observed"][key]
                for key in (
                    "pair",
                    "permissionProfileId",
                    "argvFingerprint",
                    "snapshotIdentityFingerprint",
                    "compatibilityFingerprint",
                    "accountContextFingerprint",
                )
            },
        )
        terminal = dict(self.store.calls[5][1])
        self.assertEqual("SUCCEEDED", terminal["state"])
        self.assertEqual(attestation, terminal["attestation"])
        self.assertEqual(
            "7" * 64,
            terminal["result"]["runAttestation"]["runFingerprint"],
        )

    def test_writer_completion_can_quarantine_a_successful_child_result(self) -> None:
        completion = _Completion("QUARANTINED")
        outcome = self._coordinator().run(
            admission_id="adm2_" + "0" * 32,
            request_context=request_context(),
            prepared=prepared_launch(completion=completion),
            timeout_seconds=30,
            max_output_bytes=1024 * 1024,
        )

        self.assertEqual(1, completion.calls)
        self.assertEqual("QUARANTINED", outcome.state)
        self.assertEqual(
            "QUARANTINED",
            outcome.result["writerPublication"]["state"],
        )
        terminal = dict(self.store.calls[-1][1])
        self.assertEqual("QUARANTINED", terminal["state"])
        self.assertEqual("VALIDATION_FAILED", terminal["error_code"])

    def test_rejects_changed_guard_identity_without_commit_or_exec(self) -> None:
        coordinator = self._coordinator()
        original_start = self.guard_factory.start

        def start(*args, **kwargs):
            handle = original_start(*args, **kwargs)
            handle.snapshot_identity = "9" * 64
            return handle

        self.guard_factory.start = start

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "GUARD_HELLO_MISMATCH",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared_launch(),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertTrue(self.guard_factory.handle.aborted)
        self.assertFalse(self.guard_factory.handle.committed)
        self.assertEqual(
            ["reserve", "abort_permit"],
            [name for name, _ in self.store.calls],
        )

    def test_rejects_pair_outside_fingerprinted_policy_before_reservation(self) -> None:
        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "PAIR_NOT_ALLOWED",
        ):
            self._coordinator().run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=replace(prepared_launch(), model="unapproved-model"),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)

    def test_rejects_coordinator_only_sol_medium_before_reservation(self) -> None:
        routing = json.loads(
            (
                ROOT / "docs/contracts/vectors/routing-policy-v2.json"
            ).read_text(encoding="utf-8")
        )
        child_pairs = tuple(routing["policy"]["allowedPairs"])
        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "PAIR_NOT_ALLOWED",
        ):
            self._coordinator(allowed_pairs=child_pairs).run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=replace(
                    prepared_launch(),
                    model="gpt-5.6-sol",
                    reasoning_effort="medium",
                ),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)
        self.assertEqual([], self.barrier_trace)

    def test_rejects_tampered_argv_fingerprint_before_barrier_or_reservation(
        self,
    ) -> None:
        prepared = prepared_launch()

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "ARGV_FINGERPRINT_MISMATCH",
        ):
            self._coordinator().run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=replace(prepared, argv=(*prepared.argv, "--tampered")),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)
        self.assertEqual([], self.barrier_trace)

    def test_rejects_tampered_environment_before_barrier_or_reservation(
        self,
    ) -> None:
        prepared = prepared_launch()
        tampered_environment = MappingProxyType(
            {
                **prepared.environment,
                "PATH": "/unexpected/bin",
            }
        )

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "ENVIRONMENT_FINGERPRINT_MISMATCH",
        ):
            self._coordinator().run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=replace(prepared, environment=tampered_environment),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)
        self.assertEqual([], self.barrier_trace)

    def test_rejects_changed_fingerprint_domain_before_barrier_or_reservation(
        self,
    ) -> None:
        prepared = prepared_launch()

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "CHILD_DOMAIN_MISMATCH",
        ):
            self._coordinator().run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=replace(
                    prepared,
                    environment_domain="codex-smart/environment/changed",
                ),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)
        self.assertEqual([], self.barrier_trace)

    def test_stale_fresh_process_observation_fails_before_mission(self) -> None:
        coordinator = self._coordinator()
        original_probe = coordinator.fresh_process_probe

        def stale_probe(prepared, confirmation):
            observed = original_probe(prepared, confirmation)
            return replace(observed, permission_profile_id="changed-profile")

        coordinator.fresh_process_probe = stale_probe

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "CHILD_PERMISSION_PROFILE_CHANGED",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared_launch(),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertIsNone(self.guard_factory.handle.collected_stdin)
        names = [name for name, _ in self.store.calls]
        self.assertEqual(
            ["reserve", "hello", "commit", "read_identity", "terminal"],
            names,
        )
        terminal = dict(self.store.calls[-1][1])
        self.assertEqual("FAILED", terminal["state"])
        self.assertEqual("STALE", terminal["attestation"]["disposition"])
        self.assertEqual(
            "changed-profile",
            terminal["attestation"]["observed"]["permissionProfileId"],
        )

    def test_unavailable_fresh_process_observation_fails_before_mission(
        self,
    ) -> None:
        coordinator = self._coordinator()
        coordinator.fresh_process_probe = lambda _prepared, _confirmation: (
            _ for _ in ()
        ).throw(RuntimeError("process observation unavailable"))

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "PROCESS_OBSERVATION_UNAVAILABLE",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared_launch(),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertIsNone(self.guard_factory.handle.collected_stdin)
        terminal = dict(self.store.calls[-1][1])
        self.assertEqual("UNAVAILABLE", terminal["attestation"]["disposition"])

    def test_rejects_execution_limits_before_barrier_or_reservation(self) -> None:
        for timeout_seconds, max_output_bytes in (
            (0, 1024),
            (3601, 1024),
            (30, 1023),
            (30, 64 * 1024 * 1024 + 1),
        ):
            with self.subTest(
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            ):
                with self.assertRaisesRegex(
                    ChildLaunchCoordinatorV2Error,
                    "INVALID_LAUNCH_LIMIT",
                ):
                    self._coordinator().run(
                        admission_id="adm2_" + "0" * 32,
                        request_context=request_context(),
                        prepared=prepared_launch(),
                        timeout_seconds=timeout_seconds,
                        max_output_bytes=max_output_bytes,
                    )

        self.assertEqual([], self.store.calls)
        self.assertEqual([], self.barrier_trace)

    def test_exec_failure_after_commit_is_durably_terminal_without_mission(
        self,
    ) -> None:
        coordinator = self._coordinator()
        original_start = self.guard_factory.start

        def start(*args, **kwargs):
            handle = original_start(*args, **kwargs)

            def fail_commit(_token, timeout_seconds):
                del timeout_seconds
                raise ChildGuardV2Error("CHILD_EXEC_FAILED", "exec failed")

            handle.authorize_commit = fail_commit
            return handle

        self.guard_factory.start = start

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "CHILD_EXEC_FAILED",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared_launch(),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertIsNone(self.guard_factory.handle.collected_stdin)
        names = [name for name, _ in self.store.calls]
        self.assertEqual(
            ["reserve", "hello", "commit", "read_identity", "terminal"],
            names,
        )
        terminal = dict(self.store.calls[-1][1])
        self.assertEqual("FAILED", terminal["state"])
        self.assertEqual("UNAVAILABLE", terminal["attestation"]["disposition"])

    def test_snapshot_failure_before_reserve_preserves_original_error(self) -> None:
        coordinator = self._coordinator()
        coordinator.fresh_snapshot_probe = lambda _prepared: SnapshotObservationV2(
            snapshot_sha256="9" * 64,
            snapshot_identity_fingerprint=SHA["identity"],
        )

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "SNAPSHOT_IDENTITY_MISMATCH",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared_launch(),
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        self.assertEqual([], self.store.calls)
        self.assertEqual(["enter", "exit"], self.barrier_trace)

    def test_terminal_attestation_failure_is_durably_failed(self) -> None:
        coordinator = self._coordinator()
        prepared = prepared_launch(
            _FixtureAttemptResource(RuntimeError("otel evidence missing"))
        )

        with self.assertRaisesRegex(
            ChildLaunchCoordinatorV2Error,
            "TERMINAL_ATTESTATION_FAILED",
        ):
            coordinator.run(
                admission_id="adm2_" + "0" * 32,
                request_context=request_context(),
                prepared=prepared,
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )

        terminal = dict(self.store.calls[-1][1])
        self.assertEqual("FAILED", terminal["state"])
        self.assertEqual("TERMINAL_ATTESTATION_FAILED", terminal["error_code"])
        self.assertTrue(prepared.attempt_resource.closed)

    def test_staged_auth_is_removed_on_success_and_early_rejection(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        for invalid_pair in (False, True):
            with self.subTest(invalid_pair=invalid_pair):
                codex_home = root / f"codex-home-{invalid_pair}"
                codex_home.mkdir(mode=0o700)
                staged = codex_home / "auth.json"
                staged.write_text("{}\n", encoding="utf-8")
                staged.chmod(0o600)
                base = prepared_launch()
                non_secret_environment = MappingProxyType(
                    {
                        **base.non_secret_environment,
                        "CODEX_HOME": str(codex_home),
                    }
                )
                raw_headers = base.environment["OTEL_EXPORTER_OTLP_HEADERS"]
                environment_fingerprint, secret_sha256 = (
                    child_environment_fingerprints_v1(
                        non_secret_environment=non_secret_environment,
                        raw_otel_headers=raw_headers,
                        environment_domain=base.environment_domain,
                        secret_domain=base.secret_domain,
                    )
                )
                prepared = replace(
                    base,
                    environment=MappingProxyType(
                        {
                            **non_secret_environment,
                            "OTEL_EXPORTER_OTLP_HEADERS": raw_headers,
                        }
                    ),
                    non_secret_environment=non_secret_environment,
                    environment_fingerprint=environment_fingerprint,
                    secret_sha256=secret_sha256,
                    staged_auth_path=staged,
                )
                if invalid_pair:
                    prepared = replace(prepared, model="unapproved-model")
                    with self.assertRaisesRegex(
                        ChildLaunchCoordinatorV2Error,
                        "PAIR_NOT_ALLOWED",
                    ):
                        self._coordinator().run(
                            admission_id="adm2_" + "0" * 32,
                            request_context=request_context(),
                            prepared=prepared,
                            timeout_seconds=30,
                            max_output_bytes=1024 * 1024,
                        )
                else:
                    self._coordinator().run(
                        admission_id="adm2_" + "0" * 32,
                        request_context=request_context(),
                        prepared=prepared,
                        timeout_seconds=30,
                        max_output_bytes=1024 * 1024,
                    )
                self.assertFalse(staged.exists())
                self.assertTrue(prepared.attempt_resource.closed)

    def test_otel_terminal_attestor_uses_receiver_and_attest_run(self) -> None:
        prepared = prepared_launch()
        receiver = OTelReceiver()
        receiver.events.append(
            {
                "event.name": "codex.conversation_starts",
                "app.version": prepared.expected_cli_version,
                "model": prepared.model,
                "reasoning_effort": prepared.reasoning_effort,
                "conversation.id": "thread-1",
            }
        )

        attestation = OTelAttemptResourceV2(receiver).attest(
            prepared,
            [{"type": "thread.started", "thread_id": "thread-1"}],
            "pc2_" + "a" * 32,
        )

        self.assertEqual(prepared.model, attestation.observed_model)
        self.assertEqual(prepared.reasoning_effort, attestation.observed_effort)
        self.assertRegex(attestation.run_fingerprint, r"^[0-9a-f]{64}$")

    def test_otel_attestor_exposes_general_endpoint_without_double_logs_path(
        self,
    ) -> None:
        with OTelReceiver() as receiver:
            adapter = OTelAttemptResourceV2(receiver)
            self.assertEqual(receiver.otlp_endpoint, adapter.telemetry_config.endpoint)
            self.assertNotIn("/v1/logs", adapter.telemetry_config.endpoint)
            self.assertEqual(receiver.path, receiver.base_path + "/v1/logs")

    def test_parallel_attempt_resources_do_not_mix_events_or_tokens(self) -> None:
        first_resource = OTelAttemptResourceV2.start()
        second_resource = OTelAttemptResourceV2.start()
        self.addCleanup(first_resource.close)
        self.addCleanup(second_resource.close)
        first = prepared_launch(first_resource)
        second = replace(
            prepared_launch(second_resource),
            model="catalog-model-second",
            reasoning_effort="catalog-effort-second",
        )
        self.assertNotEqual(
            first_resource.telemetry_config.token,
            second_resource.telemetry_config.token,
        )
        self.assertNotEqual(
            first_resource.telemetry_config.endpoint,
            second_resource.telemetry_config.endpoint,
        )

        def send(prepared, resource, thread_id, token=None):
            receiver = resource.receiver
            values = [
                {
                    "key": "event.name",
                    "value": {"stringValue": "codex.conversation_starts"},
                },
                {"key": "model", "value": {"stringValue": prepared.model}},
                {
                    "key": "reasoning_effort",
                    "value": {"stringValue": prepared.reasoning_effort},
                },
                {
                    "key": "conversation.id",
                    "value": {"stringValue": thread_id},
                },
                {
                    "key": "app.version",
                    "value": {"stringValue": prepared.expected_cli_version},
                },
            ]
            body = json.dumps(
                {
                    "resourceLogs": [
                        {
                            "scopeLogs": [
                                {
                                    "logRecords": [
                                        {"body": {"kvlistValue": {"values": values}}}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ).encode()
            connection = http.client.HTTPConnection(
                receiver.host,
                receiver.port,
                timeout=2,
            )
            connection.request(
                "POST",
                receiver.path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    receiver.header_name: token or receiver.token,
                },
            )
            response = connection.getresponse()
            response.read()
            connection.close()
            return response.status

        self.assertEqual(
            403,
            send(
                first,
                first_resource,
                "thread-crossed",
                token=second_resource.telemetry_config.token,
            ),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = tuple(
                executor.map(
                    lambda values: send(*values),
                    (
                        (first, first_resource, "thread-first"),
                        (second, second_resource, "thread-second"),
                    ),
                )
            )
        self.assertEqual((200, 200), statuses)

        coordinator = self._coordinator()
        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(
                coordinator._terminal_attestation,
                first,
                [{"type": "thread.started", "thread_id": "thread-first"}],
                "pc2_" + "1" * 32,
            )
            second_future = executor.submit(
                coordinator._terminal_attestation,
                second,
                [{"type": "thread.started", "thread_id": "thread-second"}],
                "pc2_" + "2" * 32,
            )
            first_attestation = first_future.result(timeout=3)
            second_attestation = second_future.result(timeout=3)

        self.assertEqual(first.model, first_attestation.observed_model)
        self.assertEqual(second.model, second_attestation.observed_model)
        self.assertNotEqual(
            first_attestation.conversation_hash,
            second_attestation.conversation_hash,
        )

    def test_runtime_contains_no_model_or_effort_catalog_literals(self) -> None:
        for name in ("child_guard_v2.py", "child_launch_coordinator_v2.py"):
            source = (PLUGIN_SRC / "codex_smart_subagents" / name).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("gpt-", source)
            self.assertNotIn('"low"', source)
            self.assertNotIn('"medium"', source)
            self.assertNotIn('"high"', source)


if __name__ == "__main__":
    unittest.main()
