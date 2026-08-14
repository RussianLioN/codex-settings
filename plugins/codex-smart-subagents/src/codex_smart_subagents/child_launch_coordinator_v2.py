"""Долговечная последовательность reserve → guard → commit → exec → аттестация."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from .canonical_json import canonical_json_v1, domain_fingerprint
from .child_guard_v2 import (
    GuardExecConfirmationV2,
    GuardFactoryV2,
    GuardHelloV2,
)
from .child_launch_v2 import (
    PreparedChildLaunchV2,
    child_argv_fingerprint_v2,
    cleanup_prepared_child_launch_v2,
    require_child_environment_integrity_v2,
)
from .child_runner import ChildTelemetryConfig
from .state_store_v2 import (
    AttemptLaunchIdentityV2,
    RequestContextV2,
    SmartStoreV2,
)
from .telemetry import OTelReceiver, RunAttestation, attest_run


_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


@dataclass
class ChildLaunchCoordinatorV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class SnapshotObservationV2:
    snapshot_sha256: str
    snapshot_identity_fingerprint: str

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.snapshot_sha256) is None
            or _SHA256.fullmatch(self.snapshot_identity_fingerprint) is None
        ):
            raise ValueError("snapshot observation fingerprints must be SHA-256")


@dataclass(frozen=True)
class ProcessObservationV2:
    """Свежая независимая проекция уже исполняемого дочернего процесса."""

    model: str
    reasoning_effort: str
    permission_profile_id: str
    argv_fingerprint: str
    snapshot_identity_fingerprint: str
    compatibility_fingerprint: str
    account_context_fingerprint: str
    pid: int
    process_start_marker: str
    codex_binary_sha256: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > limit
            or any(character in value for character in "\0\r\n")
            for value, limit in (
                (self.model, 128),
                (self.reasoning_effort, 32),
                (self.process_start_marker, 256),
            )
        ):
            raise ValueError("process observation contains an unsafe text value")
        if _PROFILE.fullmatch(self.permission_profile_id) is None:
            raise ValueError("process observation permission profile is invalid")
        for value in (
            self.argv_fingerprint,
            self.snapshot_identity_fingerprint,
            self.compatibility_fingerprint,
            self.account_context_fingerprint,
            self.codex_binary_sha256,
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError("process observation fingerprint is not SHA-256")
        if type(self.pid) is not int or self.pid <= 0:
            raise ValueError("process observation pid must be positive")


@dataclass(frozen=True)
class ChildLaunchOutcomeV2:
    attempt_id: str
    permit_id: str
    state: str
    result: dict[str, Any] | None
    attestation: dict[str, Any]


class OTelAttemptResourceV2:
    """Владеет отдельным приёмником OTel ровно одной дочерней попытки."""

    def __init__(self, receiver: OTelReceiver) -> None:
        if not isinstance(receiver, OTelReceiver):
            raise TypeError("receiver must be OTelReceiver")
        self.receiver = receiver
        self._closed = False
        self._lock = threading.Lock()

    @classmethod
    def start(cls) -> "OTelAttemptResourceV2":
        receiver = OTelReceiver()
        receiver.__enter__()
        return cls(receiver)

    @property
    def telemetry_config(self) -> ChildTelemetryConfig:
        """Даёт согласованную настройку общего OTLP endpoint для запуска."""

        with self._lock:
            if self._closed:
                raise RuntimeError("attempt telemetry resource is closed")
        return ChildTelemetryConfig(
            endpoint=self.receiver.otlp_endpoint,
            header_name=self.receiver.header_name,
            token=self.receiver.token,
        )

    def attest(
        self,
        prepared: PreparedChildLaunchV2,
        jsonl_events: list[dict[str, Any]],
        permission_probe_id: str,
    ) -> RunAttestation:
        with self._lock:
            if self._closed:
                raise RuntimeError("attempt telemetry resource is closed")
        return attest_run(
            events=self.receiver.snapshot_events(),
            jsonl_events=jsonl_events,
            requested_model=prepared.model,
            requested_effort=prepared.reasoning_effort,
            expected_cli_version=prepared.expected_cli_version,
            permission_probe_id=permission_probe_id,
            argv_fingerprint=prepared.argv_fingerprint,
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self.receiver.__exit__(None, None, None)


class ChildLaunchCoordinatorV2:
    """Не передаёт миссию, пока COMMIT и MATCH не зафиксированы в SQLite."""

    def __init__(
        self,
        *,
        store: SmartStoreV2,
        guard_factory: GuardFactoryV2,
        launch_barrier: Callable[[], Any],
        allowed_pairs: Sequence[Mapping[str, str]],
        argv_domain: str,
        environment_domain: str,
        secret_domain: str,
        activation_gate_provider: Callable[[], Mapping[str, Any]],
        fresh_permission_probe: Callable[[PreparedChildLaunchV2], str],
        fresh_snapshot_probe: Callable[[PreparedChildLaunchV2], SnapshotObservationV2],
        fresh_process_probe: Callable[
            [PreparedChildLaunchV2, GuardExecConfirmationV2],
            ProcessObservationV2,
        ],
        expected_control_epoch: int,
        clock: Callable[[], datetime] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        for name, value in (
            ("activation_gate_provider", activation_gate_provider),
            ("fresh_permission_probe", fresh_permission_probe),
            ("fresh_snapshot_probe", fresh_snapshot_probe),
            ("fresh_process_probe", fresh_process_probe),
            ("launch_barrier", launch_barrier),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        if not callable(getattr(guard_factory, "start", None)):
            raise TypeError("guard_factory must provide start()")
        self.store = store
        self.guard_factory = guard_factory
        self.launch_barrier = launch_barrier
        self.allowed_pairs = self._validated_allowed_pairs(allowed_pairs)
        self.child_domains = (argv_domain, environment_domain, secret_domain)
        if any(
            not isinstance(value, str)
            or not value
            or "\0" in value
            or len(value.encode("utf-8")) > 256
            for value in self.child_domains
        ):
            raise ValueError("child fingerprint domains are invalid")
        self.activation_gate_provider = activation_gate_provider
        self.fresh_permission_probe = fresh_permission_probe
        self.fresh_snapshot_probe = fresh_snapshot_probe
        self.fresh_process_probe = fresh_process_probe
        if (
            type(expected_control_epoch) is not int
            or not 1 <= expected_control_epoch <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("expected_control_epoch must be a live integer")
        self.expected_control_epoch = expected_control_epoch
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(32))

    def run(
        self,
        *,
        admission_id: str,
        request_context: RequestContextV2,
        prepared: PreparedChildLaunchV2,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ChildLaunchOutcomeV2:
        permit = None
        handle = None
        committed = None
        identity: AttemptLaunchIdentityV2 | None = None
        attestation: dict[str, Any] | None = None
        permission_probe_id: str | None = None
        terminal_written = False
        started_written = False
        barrier = ExitStack()
        barrier_held = False
        prepared_cleaned = False
        try:
            self._require_allowed_pair(prepared.model, prepared.reasoning_effort)
            self._validate_execution_limits(timeout_seconds, max_output_bytes)
            self._verify_prepared_argv_fingerprint(prepared)
            self._verify_prepared_environment(prepared)
            token = self.token_factory()
            if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
                self._fail("GUARD_TOKEN_INVALID", "one-time token is malformed")
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            barrier.enter_context(self.launch_barrier())
            barrier_held = True
            first_snapshot = self._snapshot(prepared)
            first_gate = self._activation_gate()
            permit = self.store.reserve_launch_permit(
                admission_id=admission_id,
                activation_gate=first_gate,
                expected_control_epoch=self.expected_control_epoch,
                argv_fingerprint=prepared.argv_fingerprint,
                codex_snapshot_sha256=first_snapshot.snapshot_sha256,
                snapshot_identity_fingerprint=first_snapshot.snapshot_identity_fingerprint,
                now=self._now(),
            )
            handle = self.guard_factory.start(
                prepared,
                permit_id=permit.permit_id,
                one_time_token=token,
                snapshot_probe=self.fresh_snapshot_probe,
            )
            hello = handle.receive_hello(timeout_seconds=2.0)
            self._verify_hello(
                hello,
                permit_id=permit.permit_id,
                token=token,
                prepared=prepared,
            )
            self.store.record_guard_hello(
                permit.permit_id,
                guard_pid=hello.pid,
                guard_start_marker=hello.process_start_marker,
                one_time_token_hash=token_hash,
                snapshot_identity_fingerprint=hello.snapshot_identity_fingerprint,
            )

            permission_probe_id = self.fresh_permission_probe(prepared)
            if (
                not isinstance(permission_probe_id, str)
                or not permission_probe_id
                or len(permission_probe_id.encode("utf-8")) > 256
                or any(character in permission_probe_id for character in "\0\r\n")
            ):
                self._fail(
                    "PERMISSION_PROBE_INVALID",
                    "fresh permission probe did not return a bounded identifier",
                )
            second_snapshot = self._snapshot(prepared)
            if second_snapshot != first_snapshot:
                self._fail(
                    "SNAPSHOT_IDENTITY_MISMATCH",
                    "snapshot changed between reserve and commit",
                )
            second_gate = self._activation_gate()
            if canonical_json_v1(second_gate) != canonical_json_v1(first_gate):
                self._fail(
                    "ACTIVATION_GATE_CHANGED",
                    "activation gate changed between reserve and commit",
                )
            committed = self.store.commit_launch_permit(
                permit_id=permit.permit_id,
                guard_pid=hello.pid,
                guard_start_marker=hello.process_start_marker,
                one_time_token_hash=token_hash,
                argv_fingerprint=prepared.argv_fingerprint,
                snapshot_identity_fingerprint=second_snapshot.snapshot_identity_fingerprint,
                activation_gate=second_gate,
                expected_control_epoch=self.expected_control_epoch,
                permission_probe_id=permission_probe_id,
                codex_binary_sha256=second_snapshot.snapshot_sha256,
                now=self._now(),
            )
            confirmation = handle.authorize_commit(token, timeout_seconds=1.0)
            self._verify_exec_confirmation(confirmation, hello)
            identity = self.store.read_attempt_launch_identity(
                committed.attempt_id,
                request_context,
            )
            self._require_allowed_pair(identity.model, identity.reasoning_effort)
            self._verify_attempt_identity(identity, committed, confirmation, prepared)
            observation = self._process_observation(prepared, confirmation)
            attestation = self._attestation(identity, observation)
            if attestation["disposition"] != "MATCH":
                problem = attestation["problem"]
                assert isinstance(problem, dict)
                self._fail(str(problem["code"]), str(problem["message"]))
            self.store.record_attempt_started(
                committed.attempt_id,
                request_context,
                attestation=attestation,
                now=self._now(),
            )
            started_written = True
            barrier.close()
            barrier_held = False

            execution = handle.collect(
                prepared.stdin,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            if execution.exit_code != 0:
                self._cleanup_prepared_launch(prepared)
                prepared_cleaned = True
                self.store.record_attempt_terminal(
                    committed.attempt_id,
                    request_context,
                    state="FAILED",
                    result={
                        "exitCode": execution.exit_code,
                        "stdoutSha256": hashlib.sha256(execution.stdout).hexdigest(),
                        "stderrSha256": hashlib.sha256(execution.stderr).hexdigest(),
                    },
                    attestation=attestation,
                    error_code="CHILD_EXIT_NONZERO",
                    error_message=f"child exited with code {execution.exit_code}",
                    now=self._now(),
                )
                terminal_written = True
                return ChildLaunchOutcomeV2(
                    attempt_id=committed.attempt_id,
                    permit_id=permit.permit_id,
                    state="FAILED",
                    result=None,
                    attestation=attestation,
                )
            result = _decode_child_result(execution.stdout, execution.stderr)
            if permission_probe_id is None:
                self._fail(
                    "PERMISSION_PROBE_INVALID",
                    "permission evidence disappeared before terminal attestation",
                )
            run_attestation = self._terminal_attestation(
                prepared,
                result["events"],
                permission_probe_id,
            )
            result["runAttestation"] = _run_attestation_payload(run_attestation)
            terminal_state = "SUCCEEDED"
            terminal_error_code: str | None = None
            terminal_error_message: str | None = None
            if prepared.completion is not None:
                try:
                    publication = dict(prepared.completion.complete(result))
                    canonical_json_v1(publication)
                except Exception as exc:
                    self._fail("CHILD_COMPLETION_FAILED", str(exc))
                publication_state = publication.get("state")
                if publication_state not in {"VERIFIED", "QUARANTINED"}:
                    self._fail(
                        "CHILD_COMPLETION_INVALID",
                        "completion returned an unknown state",
                    )
                result["writerPublication"] = publication
                if publication_state == "QUARANTINED":
                    terminal_state = "QUARANTINED"
                    raw_error_code = publication.get("errorCode")
                    terminal_error_code = (
                        raw_error_code
                        if isinstance(raw_error_code, str) and raw_error_code
                        else "WRITER_PUBLICATION_QUARANTINED"
                    )
                    terminal_error_message = "writer candidate was quarantined"
            self._cleanup_prepared_launch(prepared)
            prepared_cleaned = True
            self.store.record_attempt_terminal(
                committed.attempt_id,
                request_context,
                state=terminal_state,
                result=result,
                attestation=attestation,
                error_code=terminal_error_code,
                error_message=terminal_error_message,
                now=self._now(),
            )
            terminal_written = True
            return ChildLaunchOutcomeV2(
                attempt_id=committed.attempt_id,
                permit_id=permit.permit_id,
                state=terminal_state,
                result=result,
                attestation=attestation,
            )
        except Exception as exc:
            effective_error = exc
            if not prepared_cleaned:
                try:
                    self._cleanup_prepared_launch(prepared)
                except Exception as cleanup_error:
                    effective_error = ChildLaunchCoordinatorV2Error(
                        "LAUNCH_CLEANUP_FAILED",
                        f"{cleanup_error}; preceding error: {exc}",
                    )
                finally:
                    prepared_cleaned = True
            if barrier_held:
                if handle is not None:
                    handle.abort()
                if permit is not None and committed is None:
                    self._abort_before_commit_locked(
                        permit.permit_id,
                        request_context,
                        effective_error,
                    )
                elif committed is not None and not terminal_written:
                    self._record_committed_failure(
                        committed.attempt_id,
                        request_context,
                        identity=identity,
                        attestation=attestation,
                        error=effective_error,
                    )
                barrier.close()
                barrier_held = False
            else:
                if handle is not None:
                    handle.abort()
                if committed is not None and started_written and not terminal_written:
                    self._record_committed_failure(
                        committed.attempt_id,
                        request_context,
                        identity=identity,
                        attestation=attestation,
                        error=effective_error,
                    )
            if isinstance(effective_error, ChildLaunchCoordinatorV2Error):
                raise effective_error
            self._fail(self._error_code(effective_error), str(effective_error))
        finally:
            barrier.close()
            if handle is not None:
                handle.abort()
            if not prepared_cleaned:
                self._cleanup_prepared_launch(prepared)

    def _snapshot(self, prepared: PreparedChildLaunchV2) -> SnapshotObservationV2:
        try:
            observed = self.fresh_snapshot_probe(prepared)
        except Exception as exc:
            self._fail("SNAPSHOT_PROBE_FAILED", str(exc))
        if not isinstance(observed, SnapshotObservationV2):
            self._fail(
                "SNAPSHOT_PROBE_INVALID",
                "snapshot probe returned another type",
            )
        expected = SnapshotObservationV2(
            snapshot_sha256=prepared.snapshot_sha256,
            snapshot_identity_fingerprint=prepared.snapshot_identity_fingerprint,
        )
        if observed != expected:
            self._fail(
                "SNAPSHOT_IDENTITY_MISMATCH",
                "fresh snapshot observation differs from the prepared launch",
            )
        return observed

    @staticmethod
    def _validate_execution_limits(
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 3600
            or type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 64 * 1024 * 1024
        ):
            raise ChildLaunchCoordinatorV2Error(
                "INVALID_LAUNCH_LIMIT",
                "execution limits are outside the supported range",
            )

    @staticmethod
    def _verify_prepared_argv_fingerprint(
        prepared: PreparedChildLaunchV2,
    ) -> None:
        observed = child_argv_fingerprint_v2(
            argv=prepared.argv,
            argv_domain=prepared.argv_domain,
        )
        if observed != prepared.argv_fingerprint:
            raise ChildLaunchCoordinatorV2Error(
                "ARGV_FINGERPRINT_MISMATCH",
                "prepared launch differs from its argv fingerprint",
            )

    def _verify_prepared_environment(
        self,
        prepared: PreparedChildLaunchV2,
    ) -> None:
        if (
            prepared.argv_domain,
            prepared.environment_domain,
            prepared.secret_domain,
        ) != self.child_domains:
            self._fail(
                "CHILD_DOMAIN_MISMATCH",
                "prepared launch uses another fingerprint domain",
            )
        try:
            require_child_environment_integrity_v2(prepared)
        except Exception as exc:
            self._fail(self._error_code(exc), str(exc))

    @staticmethod
    def _cleanup_prepared_launch(prepared: PreparedChildLaunchV2) -> None:
        try:
            cleanup_prepared_child_launch_v2(prepared)
        except Exception as exc:
            raise ChildLaunchCoordinatorV2Error(
                "LAUNCH_CLEANUP_FAILED",
                str(exc),
            ) from exc

    def _activation_gate(self) -> dict[str, Any]:
        try:
            raw = self.activation_gate_provider()
            value = dict(raw)
            canonical_json_v1(value)
        except Exception as exc:
            self._fail("ACTIVATION_GATE_UNAVAILABLE", str(exc))
        if set(value) != {
            "manifestSemanticFingerprint",
            "activationReceiptFingerprint",
            "journalAbsenceProof",
            "gateFingerprint",
        }:
            self._fail(
                "ACTIVATION_GATE_INVALID",
                "activation gate is not a closed four-field object",
            )
        for name in (
            "manifestSemanticFingerprint",
            "activationReceiptFingerprint",
            "gateFingerprint",
        ):
            if _SHA256.fullmatch(value[name]) is None:
                self._fail("ACTIVATION_GATE_INVALID", f"{name} is not SHA-256")
        if type(value["journalAbsenceProof"]) is not dict:
            self._fail(
                "ACTIVATION_GATE_INVALID",
                "journalAbsenceProof is not an object",
            )
        return value

    @staticmethod
    def _verify_hello(
        hello: GuardHelloV2,
        *,
        permit_id: str,
        token: str,
        prepared: PreparedChildLaunchV2,
    ) -> None:
        if (
            hello.protocol_version != 2
            or hello.permit_id != permit_id
            or hello.one_time_token != token
            or hello.pid <= 0
            or not hello.process_start_marker
            or hello.argv_fingerprint != prepared.argv_fingerprint
            or hello.snapshot_identity_fingerprint
            != prepared.snapshot_identity_fingerprint
        ):
            raise ChildLaunchCoordinatorV2Error(
                "GUARD_HELLO_MISMATCH",
                "guard HELLO does not match the reserved launch",
            )

    @staticmethod
    def _verify_exec_confirmation(
        confirmation: GuardExecConfirmationV2,
        hello: GuardHelloV2,
    ) -> None:
        if (
            confirmation.pid != hello.pid
            or confirmation.process_start_marker != hello.process_start_marker
        ):
            raise ChildLaunchCoordinatorV2Error(
                "EXEC_CONFIRMATION_MISMATCH",
                "exec confirmation belongs to another process",
            )

    @staticmethod
    def _verify_attempt_identity(
        identity: AttemptLaunchIdentityV2,
        committed: Any,
        confirmation: GuardExecConfirmationV2,
        prepared: PreparedChildLaunchV2,
    ) -> None:
        expected = (
            committed.attempt_id,
            committed.route_id,
            committed.node_id,
            prepared.model,
            prepared.reasoning_effort,
            prepared.permission_profile_id,
            prepared.argv_fingerprint,
            prepared.snapshot_identity_fingerprint,
            prepared.compatibility_fingerprint,
            prepared.account_context_fingerprint,
            confirmation.pid,
            confirmation.process_start_marker,
            prepared.snapshot_sha256,
            "STARTING",
        )
        observed = (
            identity.attempt_id,
            identity.route_id,
            identity.node_id,
            identity.model,
            identity.reasoning_effort,
            identity.permission_profile_id,
            identity.argv_fingerprint,
            identity.snapshot_identity_fingerprint,
            identity.compatibility_fingerprint,
            identity.account_context_fingerprint,
            identity.pid,
            identity.process_start_marker,
            identity.codex_binary_sha256,
            identity.state,
        )
        if observed != expected:
            raise ChildLaunchCoordinatorV2Error(
                "ATTEMPT_IDENTITY_MISMATCH",
                "durable attempt differs from the confirmed child launch",
            )

    def _process_observation(
        self,
        prepared: PreparedChildLaunchV2,
        confirmation: GuardExecConfirmationV2,
    ) -> ProcessObservationV2:
        try:
            observed = self.fresh_process_probe(prepared, confirmation)
        except Exception as exc:
            self._fail("PROCESS_OBSERVATION_UNAVAILABLE", str(exc))
        if not isinstance(observed, ProcessObservationV2):
            self._fail(
                "PROCESS_OBSERVATION_UNAVAILABLE",
                "fresh process probe returned another type",
            )
        return observed

    def _terminal_attestation(
        self,
        prepared: PreparedChildLaunchV2,
        jsonl_events: list[dict[str, Any]],
        permission_probe_id: str,
    ) -> RunAttestation:
        try:
            value = prepared.attempt_resource.attest(
                prepared,
                jsonl_events,
                permission_probe_id,
            )
        except Exception as exc:
            self._fail("TERMINAL_ATTESTATION_FAILED", str(exc))
        if not isinstance(value, RunAttestation):
            self._fail(
                "TERMINAL_ATTESTATION_FAILED",
                "terminal attestor returned another type",
            )
        expected = (
            prepared.expected_cli_version,
            prepared.model,
            prepared.model,
            prepared.reasoning_effort,
            prepared.reasoning_effort,
            prepared.argv_fingerprint,
            permission_probe_id,
        )
        observed = (
            value.cli_version,
            value.requested_model,
            value.observed_model,
            value.requested_effort,
            value.observed_effort,
            value.argv_fingerprint,
            value.permission_probe_id,
        )
        if observed != expected or any(
            _SHA256.fullmatch(candidate) is None
            for candidate in (value.conversation_hash, value.run_fingerprint)
        ):
            self._fail(
                "TERMINAL_ATTESTATION_FAILED",
                "terminal attestation differs from committed launch",
            )
        return value

    def _attestation(
        self,
        identity: AttemptLaunchIdentityV2,
        observation: ProcessObservationV2,
    ) -> dict[str, Any]:
        requested = {
            "pair": {
                "model": identity.model,
                "reasoningEffort": identity.reasoning_effort,
            },
            "permissionProfileId": identity.permission_profile_id,
            "argvFingerprint": identity.argv_fingerprint,
            "snapshotIdentityFingerprint": identity.snapshot_identity_fingerprint,
            "compatibilityFingerprint": identity.compatibility_fingerprint,
            "accountContextFingerprint": identity.account_context_fingerprint,
        }
        observed = {
            "pair": {
                "model": observation.model,
                "reasoningEffort": observation.reasoning_effort,
            },
            "permissionProfileId": observation.permission_profile_id,
            "argvFingerprint": observation.argv_fingerprint,
            "snapshotIdentityFingerprint": (observation.snapshot_identity_fingerprint),
            "compatibilityFingerprint": observation.compatibility_fingerprint,
            "accountContextFingerprint": observation.account_context_fingerprint,
            "pid": observation.pid,
            "processStartMarker": observation.process_start_marker,
            "codexBinarySha256": observation.codex_binary_sha256,
        }
        expected_observed = {
            **requested,
            "pid": identity.pid,
            "processStartMarker": identity.process_start_marker,
            "codexBinarySha256": identity.codex_binary_sha256,
        }
        problem = self._observation_problem(
            requested=requested,
            expected_observed=expected_observed,
            observed=observed,
        )
        attestation_id = (
            "ca2_"
            + domain_fingerprint(
                "codex-smart/child-attestation-id/v2",
                {"attemptId": identity.attempt_id},
            )[:32]
        )
        projection: dict[str, Any] = {
            "schemaVersion": 2,
            "contractVersion": "codex-child-attestation-v2",
            "attestationId": attestation_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
            "attemptId": identity.attempt_id,
            "requested": requested,
            "observed": observed,
            "disposition": "MATCH" if problem is None else "STALE",
            "problem": problem,
            "observedAt": _iso(self._now()),
            "extensions": {},
        }
        return {
            **projection,
            "attestationFingerprint": domain_fingerprint(
                "codex-smart/child-attestation/v2",
                projection,
            ),
        }

    @staticmethod
    def _observation_problem(
        *,
        requested: Mapping[str, Any],
        expected_observed: Mapping[str, Any],
        observed: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if expected_observed == observed:
            return None
        requested_pair = requested["pair"]
        observed_pair = observed["pair"]
        if observed_pair["model"] != requested_pair["model"]:
            code = "CHILD_PAIR_CHANGED"
            message = "observed child model differs from the committed launch"
        elif observed_pair["reasoningEffort"] != requested_pair["reasoningEffort"]:
            code = "CHILD_REASONING_CHANGED"
            message = (
                "observed child reasoning effort differs from the committed launch"
            )
        elif observed["permissionProfileId"] != requested["permissionProfileId"]:
            code = "CHILD_PERMISSION_PROFILE_CHANGED"
            message = (
                "observed child permission profile differs from the committed launch"
            )
        elif (
            observed["accountContextFingerprint"]
            != requested["accountContextFingerprint"]
        ):
            code = "CHILD_ACCOUNT_CONTEXT_CHANGED"
            message = "observed child account context differs from the committed launch"
        else:
            code = "CHILD_SNAPSHOT_CHANGED"
            message = "observed child process image differs from the committed launch"
        return {
            "category": "STALE",
            "code": code,
            "message": message,
            "retryable": False,
        }

    def _abort_before_commit_locked(
        self,
        permit_id: str,
        request_context: RequestContextV2,
        error: BaseException,
    ) -> None:
        self.store.abort_launch_permit_before_commit(
            permit_id,
            request_context,
            failure_code=self._error_code(error),
            message=str(error)[:1024] or type(error).__name__,
            now=self._now(),
        )

    def _record_committed_failure(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
        *,
        identity: AttemptLaunchIdentityV2 | None,
        attestation: dict[str, Any] | None,
        error: BaseException,
    ) -> None:
        if identity is None:
            identity = self.store.read_attempt_launch_identity(
                attempt_id,
                request_context,
            )
        if attestation is None:
            attestation = self._unavailable_attestation(identity, error)
        self.store.record_attempt_terminal(
            attempt_id,
            request_context,
            state="FAILED",
            result=None,
            attestation=attestation,
            error_code=self._error_code(error),
            error_message=str(error)[:4096] or type(error).__name__,
            now=self._now(),
        )

    def _unavailable_attestation(
        self,
        identity: AttemptLaunchIdentityV2,
        error: BaseException,
    ) -> dict[str, Any]:
        requested = {
            "pair": {
                "model": identity.model,
                "reasoningEffort": identity.reasoning_effort,
            },
            "permissionProfileId": identity.permission_profile_id,
            "argvFingerprint": identity.argv_fingerprint,
            "snapshotIdentityFingerprint": identity.snapshot_identity_fingerprint,
            "compatibilityFingerprint": identity.compatibility_fingerprint,
            "accountContextFingerprint": identity.account_context_fingerprint,
        }
        projection: dict[str, Any] = {
            "schemaVersion": 2,
            "contractVersion": "codex-child-attestation-v2",
            "attestationId": "ca2_"
            + domain_fingerprint(
                "codex-smart/child-attestation-id/v2",
                {"attemptId": identity.attempt_id},
            )[:32],
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
            "attemptId": identity.attempt_id,
            "requested": requested,
            "observed": None,
            "disposition": "UNAVAILABLE",
            "problem": {
                "category": "UNAVAILABLE",
                "code": "CHILD_ATTESTATION_UNAVAILABLE",
                "message": str(error)[:1024] or type(error).__name__,
                "retryable": False,
            },
            "observedAt": _iso(self._now()),
            "extensions": {},
        }
        return {
            **projection,
            "attestationFingerprint": domain_fingerprint(
                "codex-smart/child-attestation/v2", projection
            ),
        }

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            self._fail("CLOCK_INVALID", "clock must return an aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _validated_allowed_pairs(
        pairs: Sequence[Mapping[str, str]],
    ) -> frozenset[tuple[str, str]]:
        if isinstance(pairs, (str, bytes)):
            raise ValueError("allowed_pairs must be a sequence of exact pairs")
        result: set[tuple[str, str]] = set()
        for raw in pairs:
            if type(raw) is not dict or set(raw) != {"model", "reasoningEffort"}:
                raise ValueError("allowed_pairs contains a malformed pair")
            pair = (raw["model"], raw["reasoningEffort"])
            if any(
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 128
                or any(character in value for character in "\0\r\n")
                for value in pair
            ):
                raise ValueError("allowed_pairs contains an unsafe value")
            if pair in result:
                raise ValueError("allowed_pairs contains a duplicate pair")
            result.add(pair)
        if not result:
            raise ValueError("allowed_pairs must not be empty")
        return frozenset(result)

    def _require_allowed_pair(self, model: str, reasoning_effort: str) -> None:
        if (model, reasoning_effort) not in self.allowed_pairs:
            self._fail(
                "PAIR_NOT_ALLOWED",
                "launch pair is outside the fingerprinted policy",
            )

    @staticmethod
    def _error_code(error: BaseException) -> str:
        code = getattr(error, "code", None)
        if isinstance(code, str) and code:
            return code[:256]
        return "CHILD_LAUNCH_FAILED"

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise ChildLaunchCoordinatorV2Error(code, message)


def _decode_child_result(stdout: bytes, stderr: bytes) -> dict[str, Any]:
    try:
        text = stdout.decode("utf-8", "strict")
        stderr_text = stderr.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ChildLaunchCoordinatorV2Error(
            "CHILD_PROTOCOL_ERROR", "child output is not UTF-8"
        ) from exc
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line:
            continue
        if len(line.encode("utf-8")) > 4 * 1024 * 1024:
            raise ChildLaunchCoordinatorV2Error(
                "CHILD_PROTOCOL_ERROR", "one JSONL record is too large"
            )
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ChildLaunchCoordinatorV2Error(
                "CHILD_PROTOCOL_ERROR", "child emitted invalid JSONL"
            ) from exc
        if type(value) is not dict or not isinstance(value.get("type"), str):
            raise ChildLaunchCoordinatorV2Error(
                "CHILD_PROTOCOL_ERROR", "child JSONL record has no string type"
            )
        events.append(value)
        if len(events) > 4096:
            raise ChildLaunchCoordinatorV2Error(
                "CHILD_PROTOCOL_ERROR", "child emitted too many JSONL records"
            )
    if (
        not events
        or events[0].get("type") != "thread.started"
        or events[-1].get("type") != "turn.completed"
        or sum(event.get("type") == "turn.completed" for event in events) != 1
    ):
        raise ChildLaunchCoordinatorV2Error(
            "CHILD_PROTOCOL_ERROR", "child JSONL terminal sequence is invalid"
        )
    return {
        "exitCode": 0,
        "events": events,
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stderr": stderr_text,
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
    }


def _run_attestation_payload(value: RunAttestation) -> dict[str, str]:
    return {
        "cliVersion": value.cli_version,
        "requestedModel": value.requested_model,
        "observedModel": value.observed_model,
        "requestedEffort": value.requested_effort,
        "observedEffort": value.observed_effort,
        "conversationHash": value.conversation_hash,
        "argvFingerprint": value.argv_fingerprint,
        "permissionProbeId": value.permission_probe_id,
        "runFingerprint": value.run_fingerprint,
    }


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
