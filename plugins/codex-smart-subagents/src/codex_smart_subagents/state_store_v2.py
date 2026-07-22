"""Производственное хранилище состояния адаптивных субагентов версии 2."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .canonical_json import canonical_json_v1, domain_fingerprint
from .graph import GraphError, TaskNode, validate_graph
from .identity import new_opaque_id
from .schema_projection import (
    APPLICATION_ID,
    database_schema_fingerprint,
    read_schema_artifact,
    sha256_file,
)
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2


RELEASE = "0.2.0"
SCHEMA_VERSION = 2
PROTOCOL_VERSION = 2
MAX_SAFE_INTEGER = 9_007_199_254_740_991
_SCHEMA_DIR = Path(__file__).with_name("schema")
_SCHEMA_PATH = _SCHEMA_DIR / "state-v2.sql"
_SCHEMA_MANIFEST_PATH = _SCHEMA_DIR / "state-v2.manifest.json"
_TERMINAL_ATTEMPT_STATES = {"SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED"}
_NONTERMINAL_NODE_STATES = {
    "PLANNED",
    "BLOCKED",
    "QUEUED",
    "LEASED",
    "PREPARING",
    "RUNNING",
    "COLLECTING",
    "ATTESTING",
    "VALIDATING",
    "CANDIDATE_BUILDING",
    "RETRYABLE",
    "RECOVERING",
    "CANCELLING",
    "SPLIT",
}
_MAX_INLINE_TERMINAL_RESULT_BYTES = 8 * 1024
_MAX_INLINE_DEPENDENCY_RESULT_BYTES = 512


@dataclass
class StateStoreV2Error(RuntimeError):
    code: str
    message: str
    committed_transitions: tuple[dict[str, Any], ...] = ()

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class _CommitThenFail(RuntimeError):
    """Внутренний исход транзакции: сохранить терминализацию и вернуть ошибку."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        transitions: tuple[dict[str, Any], ...] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.transitions = transitions


@dataclass(frozen=True)
class DatabaseIdentityV2:
    database_id: str
    activation_binding_nonce: str
    activation_id: str
    activation_fingerprint: str
    created_operation_id: str
    created_at: datetime


@dataclass(frozen=True)
class AcceptingControllerV2:
    controller_identity: str
    instance_id: str
    controller_start_id: str
    controller_pid: int
    controller_process_start_marker: str
    controller_process_group_id: int
    control_epoch: int
    activation_id: str
    activation_fingerprint: str
    compatibility_fingerprint: str
    routing_policy_fingerprint: str
    bundled_catalog_fingerprint: str
    socket_path: str
    socket_device: int
    socket_inode: int
    socket_owner_uid: int
    socket_owner_gid: int
    socket_mode: str
    updated_at: datetime


@dataclass(frozen=True)
class RequestContextV2:
    shell_session_id: str
    session_id: str
    turn_id: str
    codex_home: str
    repo_root: str
    base_sha: str
    worktree_fingerprint: str
    activation_fingerprint: str
    compatibility_fingerprint: str
    issued_control_epoch: int

    def contract_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "shellSessionId": self.shell_session_id,
            "sessionId": self.session_id,
            "turnId": self.turn_id,
            "codexHome": self.codex_home,
            "repoRoot": self.repo_root,
            "baseSha": self.base_sha,
            "worktreeFingerprint": self.worktree_fingerprint,
            "activationFingerprint": self.activation_fingerprint,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "issuedControlEpoch": self.issued_control_epoch,
        }


@dataclass(frozen=True)
class PlannedNodeV2:
    node_id: str
    ordinal: int
    role: str
    mission: str
    dependencies: tuple[str, ...]
    context_refs: tuple[str, ...]
    scope_id: str
    artifact_profile_id: str
    validation_profile_id: str
    assessment: dict[str, Any]
    risk_flags: tuple[str, ...]
    selected_model: str
    reasoning_effort: str
    permission_profile_id: str
    disposition: str


@dataclass(frozen=True)
class TurnBindingV2:
    binding_id: str
    context_fingerprint: str
    issued_control_epoch: int
    issued_at: datetime
    expires_at: datetime
    state: str
    replayed: bool = False


@dataclass(frozen=True)
class RoutePlanCommitV2:
    route_id: str
    state: str
    replayed: bool


@dataclass(frozen=True)
class StartRequestV2:
    start_request_id: str
    evidence_job_id: str
    attempt_id: str
    route_id: str
    node_id: str
    queue_position: int
    deadline_at: datetime
    state: str
    replayed: bool = False


@dataclass(frozen=True)
class QueuedStartDispatchV2:
    start_request_id: str
    evidence_job_id: str
    deadline_at: datetime
    request_context: RequestContextV2


@dataclass(frozen=True)
class AdmissionV2:
    admission_id: str
    start_request_id: str
    evidence_job_id: str
    route_id: str
    node_id: str
    activation_gate_fingerprint: str
    state: str


@dataclass(frozen=True)
class LaunchPermitV2:
    permit_id: str
    admission_id: str
    route_id: str
    node_id: str
    reserved_control_epoch: int
    activation_gate_fingerprint: str
    permit_evidence_fingerprint: str
    state: str


@dataclass(frozen=True)
class CommittedLaunchV2:
    permit_id: str
    attempt_id: str
    route_id: str
    node_id: str
    permit_state: str


@dataclass(frozen=True)
class AttemptLaunchIdentityV2:
    attempt_id: str
    route_id: str
    node_id: str
    start_request_id: str
    evidence_job_id: str
    admission_id: str
    model: str
    reasoning_effort: str
    permission_profile_id: str
    argv_fingerprint: str
    snapshot_identity_fingerprint: str
    compatibility_fingerprint: str
    account_context_fingerprint: str | None
    pid: int
    process_start_marker: str
    codex_binary_sha256: str
    state: str


@dataclass(frozen=True)
class QuiescenceSnapshotV2:
    work_counts: dict[str, int]
    database_predicates_fingerprint: str
    barrier_held: bool
    quiescent: bool


@dataclass(frozen=True)
class DependencyResultV2:
    node_id: str
    result: dict[str, Any]
    raw_result_fingerprint: str
    raw_result_bytes: int
    result_truncated: bool
    projection_fingerprint: str


@dataclass(frozen=True)
class NodePlanV2:
    route_id: str
    node_id: str
    plan_output: dict[str, Any]
    node: PlannedNodeV2
    node_state: str
    catalog_generation: str
    algorithm_version: str
    compatibility_fingerprint: str
    account_context_fingerprint: str
    dependency_results: tuple[DependencyResultV2, ...] = ()


@dataclass(frozen=True)
class StartEventV2:
    sequence: int
    event_at: datetime
    kind: str
    start_state: str
    evidence_job_id: str | None
    admission_id: str | None
    attestation: dict[str, Any] | None
    problem: dict[str, Any] | None


@dataclass(frozen=True)
class StartEventPageV2:
    cursor: str | None
    next_cursor: str | None
    items: tuple[StartEventV2, ...]


@dataclass(frozen=True)
class StartTerminalResultV2:
    attempt_id: str
    state: str
    result_fingerprint: str | None
    result_bytes: int
    inline_result: dict[str, Any]
    result_truncated: bool
    error_code: str | None


@dataclass(frozen=True)
class StartStatusV2:
    start_request_id: str
    state: str
    evidence_job_state: str
    admission_id: str | None
    terminal: bool
    page: StartEventPageV2
    terminal_result: StartTerminalResultV2 | None = None


@dataclass(frozen=True)
class CancellationV2:
    status: str
    start_request_id: str
    state: str
    terminal: bool
    idempotency_key: str
    idempotency_status: str


@dataclass(frozen=True)
class TerminalRecordV2:
    entity_id: str
    state: str
    terminal: bool
    replayed: bool


_QUIESCENCE_QUERIES = {
    "nonterminalRoutes": "select count(*) from routes where state in ('PLANNED','BLOCKED','QUEUED','LEASED','PREPARING','RUNNING','COLLECTING','ATTESTING','VALIDATING','CANDIDATE_BUILDING','RETRYABLE','RECOVERING','CANCELLING','SPLIT')",
    "nonterminalNodes": "select count(*) from nodes where state in ('PLANNED','BLOCKED','QUEUED','LEASED','PREPARING','RUNNING','COLLECTING','ATTESTING','VALIDATING','CANDIDATE_BUILDING','RETRYABLE','RECOVERING','CANCELLING','SPLIT')",
    "activeAttempts": "select count(*) from attempts where state in ('STARTING','RUNNING')",
    "activeLeases": "select count(*) from leases",
    "openIntents": "select count(*) from intents where state='PENDING'",
    "inflightLaunchPermits": "select count(*) from node_launch_permits where state in ('RESERVED','GUARDED','COMMIT_AUTHORIZED')",
    "activeRuntimeArtifacts": "select count(*) from runtime_artifacts where state in ('RESERVED','ACTIVE')",
    "pendingCandidatePublications": "select count(*) from candidate_publication_intents where state='PENDING'",
    "activeEvidenceJobs": "select count(*) from account_evidence_jobs where state in ('RUNNING','CANCEL_REQUESTED')",
    "queuedEvidenceJobs": "select count(*) from account_evidence_jobs where state='QUEUED'",
}


def attempt_id_for_evidence_job(evidence_job_id: str) -> str:
    """Возвращает единый идентификатор попытки для задания AccountEvidence."""

    _require_identifier(evidence_job_id, "aej2_")
    digest = domain_fingerprint(
        "codex-smart/attempt-id-for-evidence-job/v2",
        {"evidenceJobId": evidence_job_id},
    )
    return "att2_" + digest[:32]


class SmartStoreV2:
    """Отдельное хранилище версии 2, не изменяющее старую базу версии 1."""

    def __init__(
        self,
        path: Path,
        *,
        database_identity: DatabaseIdentityV2,
        controller: AcceptingControllerV2,
        allow_prepared_empty_database: bool = False,
    ) -> None:
        self.path = path.expanduser()
        self._expected_database_identity = database_identity
        self._expected_controller = controller
        self._allow_prepared_empty_database = bool(allow_prepared_empty_database)
        self._lock = threading.RLock()
        self._closed = False
        self._manifest = self._load_schema_manifest()
        created = self._prepare_database_file()
        before = self._safe_database_stat()
        self._connection = connect_sqlite_with_deadline_v2(
            self.path,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_connection()
            if created:
                self._create_schema()
            self._verify_schema()
            if created:
                self._insert_identity_and_controller()
            self._verify_identity_and_controller()
            mode = str(
                self._connection.execute("pragma journal_mode=WAL").fetchone()[0]
            )
            if mode.lower() != "wal":
                self._fail("DATABASE_PRAGMA_MISMATCH", "journal_mode is not WAL")
            after = self._safe_database_stat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                self._fail("UNSAFE_DATABASE", "database inode changed while opening")
        except BaseException:
            self._connection.close()
            self._closed = True
            raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def reserve_runtime_artifact(
        self,
        *,
        route_id: str,
        node_id: str,
        kind: str,
        path: Path,
        allowed_root: Path,
    ) -> str:
        """Резервирует ещё не существующий прямой дочерний каталог запуска."""

        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        if (
            type(kind) is not str
            or not kind
            or len(kind.encode("utf-8")) > 64
            or any(not (character.isascii() and (character.isalnum() or character == "_")) for character in kind)
        ):
            self._fail("RUNTIME_ARTIFACT_KIND_INVALID", "invalid artifact kind")
        root = _private_runtime_root_v2(allowed_root)
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.parent != root
        ):
            self._fail(
                "RUNTIME_ARTIFACT_PATH_INVALID",
                "runtime artifact must be a direct child of its allowed root",
            )
        if os.path.lexists(path):
            self._fail(
                "RUNTIME_ARTIFACT_PATH_EXISTS",
                "runtime artifact path must be fresh",
            )
        artifact_id = _new_id("ra2_")
        now = _iso(datetime.now(timezone.utc))
        with self._immediate():
            self._verify_identity_and_controller()
            found = self._connection.execute(
                "select 1 from nodes where route_id=? and node_id=?",
                (route_id, node_id),
            ).fetchone()
            if found is None:
                self._fail("ROUTE_NODE_NOT_FOUND", "route or node does not exist")
            self._connection.execute(
                "insert into runtime_artifacts "
                "(artifact_id,route_id,node_id,kind,path,allowed_root,state,"
                "device,inode,created_at,updated_at) "
                "values (?,?,?,?,?,?,'RESERVED',null,null,?,?)",
                (
                    artifact_id,
                    route_id,
                    node_id,
                    kind,
                    os.fspath(path),
                    os.fspath(root),
                    now,
                    now,
                ),
            )
        return artifact_id

    def seal_runtime_artifact(
        self,
        artifact_id: str,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        """Связывает запись с фактическим каталогом либо фиксирует его отсутствие."""

        _require_identifier(artifact_id, "ra2_")
        if type(terminal) is not bool:
            self._fail("RUNTIME_ARTIFACT_STATE_INVALID", "terminal must be boolean")
        with self._immediate():
            self._verify_identity_and_controller()
            row = self._connection.execute(
                "select * from runtime_artifacts where artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                self._fail(
                    "RUNTIME_ARTIFACT_NOT_FOUND",
                    "runtime artifact does not exist",
                )
            path = Path(str(row["path"]))
            root = _private_runtime_root_v2(Path(str(row["allowed_root"])))
            if not path.is_absolute() or path.parent != root:
                self._fail(
                    "RUNTIME_ARTIFACT_RECORD_INVALID",
                    "stored runtime artifact escaped its allowed root",
                )
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                state = "MISSING"
                device = None
                inode = None
            except OSError as exc:
                raise StateStoreV2Error(
                    "RUNTIME_ARTIFACT_UNAVAILABLE", str(exc)
                ) from exc
            else:
                if (
                    path.is_symlink()
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    self._fail(
                        "RUNTIME_ARTIFACT_IDENTITY_MISMATCH",
                        "runtime artifact is not the expected private directory",
                    )
                previous_state = str(row["state"])
                if previous_state == "MISSING":
                    self._fail(
                        "RUNTIME_ARTIFACT_IDENTITY_MISMATCH",
                        "a missing runtime artifact path reappeared",
                    )
                previous_device = row["device"]
                previous_inode = row["inode"]
                if previous_state in {"ACTIVE", "TERMINAL"} and (
                    previous_device != metadata.st_dev
                    or previous_inode != metadata.st_ino
                ):
                    self._fail(
                        "RUNTIME_ARTIFACT_IDENTITY_MISMATCH",
                        "runtime artifact inode changed",
                    )
                state = "TERMINAL" if terminal else "ACTIVE"
                device = int(metadata.st_dev)
                inode = int(metadata.st_ino)
            now = _iso(datetime.now(timezone.utc))
            self._connection.execute(
                "update runtime_artifacts set state=?,device=?,inode=?,updated_at=? "
                "where artifact_id=?",
                (state, device, inode, now, artifact_id),
            )
            updated = self._connection.execute(
                "select * from runtime_artifacts where artifact_id=?",
                (artifact_id,),
            ).fetchone()
        return _runtime_artifact_record_v2(updated)

    def runtime_artifacts(
        self,
        route_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Возвращает устойчивую проекцию учтённых каталогов запусков."""

        if route_id is not None:
            _require_identifier(route_id, "route2_")
        query = "select * from runtime_artifacts"
        parameters: tuple[str, ...] = ()
        if route_id is not None:
            query += " where route_id=?"
            parameters = (route_id,)
        query += " order by created_at,artifact_id"
        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(query, parameters).fetchall()
        return [_runtime_artifact_record_v2(row) for row in rows]

    def stranded_attempts(self) -> list[dict[str, Any]]:
        """Возвращает только дочерние процессы без конечного исхода."""

        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(
                "select attempt_id,route_id,node_id,state,pid,process_start_marker "
                "from attempts where state in ('STARTING','RUNNING') "
                "order by started_at,attempt_id"
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            marker = row["process_start_marker"]
            if marker is None:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "active attempt has no process start marker",
                )
            result.append(
                {
                    "attemptId": str(row["attempt_id"]),
                    "routeId": str(row["route_id"]),
                    "nodeId": str(row["node_id"]),
                    "state": str(row["state"]),
                    "pid": int(row["pid"]),
                    "processStartMarker": str(marker),
                }
            )
        return result

    def begin_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Долговечно фиксирует намерение до сигнала точному процессу."""

        _require_identifier(attempt_id, "att2_")
        if type(pid) is not int or pid <= 0:
            self._fail("INVALID_PROCESS", "attempt recovery pid must be positive")
        _require_nonempty(process_start_marker, "processStartMarker")
        created_at = _aware_utc(now)
        intent_id, payload_json, payload_hash = _attempt_recovery_intent_v2(
            attempt_id=attempt_id,
            pid=pid,
            process_start_marker=process_start_marker,
        )
        with self._immediate():
            self._verify_identity_and_controller()
            attempt = self._connection.execute(
                "select * from attempts where attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                self._fail("ATTEMPT_NOT_FOUND", "attempt does not exist")
            if (
                int(attempt["pid"]) != pid
                or str(attempt["process_start_marker"]) != process_start_marker
            ):
                self._fail(
                    "ATTEMPT_RECOVERY_IDENTITY_MISMATCH",
                    "attempt recovery belongs to another process identity",
                )
            existing = self._connection.execute(
                "select * from intents where intent_id=?",
                (intent_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["route_id"]) != str(attempt["route_id"])
                    or str(existing["node_id"]) != str(attempt["node_id"])
                    or str(existing["kind"]) != "STRANDED_ATTEMPT_RECOVERY_V2"
                    or str(existing["payload_hash"]) != payload_hash
                    or str(existing["payload_json"]) != payload_json
                ):
                    self._fail(
                        "ATTEMPT_RECOVERY_INTENT_CONFLICT",
                        "attempt recovery intent differs from its durable identity",
                    )
                return {
                    "attemptId": attempt_id,
                    "intentId": intent_id,
                    "state": str(existing["state"]),
                    "replayed": True,
                }
            if str(attempt["state"]) not in {"STARTING", "RUNNING"}:
                self._fail(
                    "ATTEMPT_NOT_RECOVERABLE",
                    "only a nonterminal attempt can begin recovery",
                )
            self._connection.execute(
                "insert into intents "
                "(intent_id,route_id,node_id,kind,payload_hash,payload_json,state,"
                "created_at,completed_at) values (?,?,?,?,?,?,'PENDING',?,null)",
                (
                    intent_id,
                    attempt["route_id"],
                    attempt["node_id"],
                    "STRANDED_ATTEMPT_RECOVERY_V2",
                    payload_hash,
                    payload_json,
                    _iso(created_at),
                ),
            )
        return {
            "attemptId": attempt_id,
            "intentId": intent_id,
            "state": "PENDING",
            "replayed": False,
        }

    def complete_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Атомарно закрывает попытку после доказанного исчезновения процесса."""

        _require_identifier(attempt_id, "att2_")
        if type(pid) is not int or pid <= 0:
            self._fail("INVALID_PROCESS", "attempt recovery pid must be positive")
        _require_nonempty(process_start_marker, "processStartMarker")
        ended_at = _aware_utc(now)
        intent_id, payload_json, payload_hash = _attempt_recovery_intent_v2(
            attempt_id=attempt_id,
            pid=pid,
            process_start_marker=process_start_marker,
        )
        failure_code = "CONTROLLER_RESTARTED"
        error_message = (
            "Дочерний процесс завершён при восстановлении после перезапуска "
            "контроллера."
        )
        with self._immediate():
            self._verify_identity_and_controller()
            attempt = self._connection.execute(
                "select a.*,p.state as permit_state,p.admission_id as permit_admission,"
                "s.start_request_id,s.evidence_job_id,s.state as start_state "
                "from attempts a join node_launch_permits p "
                "on p.permit_id=a.launch_permit_id "
                "join start_requests s on s.admission_id=p.admission_id "
                "where a.attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                self._fail("ATTEMPT_NOT_FOUND", "attempt does not exist")
            if (
                int(attempt["pid"]) != pid
                or str(attempt["process_start_marker"]) != process_start_marker
            ):
                self._fail(
                    "ATTEMPT_RECOVERY_IDENTITY_MISMATCH",
                    "attempt recovery belongs to another process identity",
                )
            intent = self._connection.execute(
                "select * from intents where intent_id=?",
                (intent_id,),
            ).fetchone()
            if intent is None:
                self._fail(
                    "ATTEMPT_RECOVERY_INTENT_MISSING",
                    "attempt recovery was not recorded before process handling",
                )
            if (
                str(intent["route_id"]) != str(attempt["route_id"])
                or str(intent["node_id"]) != str(attempt["node_id"])
                or str(intent["kind"]) != "STRANDED_ATTEMPT_RECOVERY_V2"
                or str(intent["payload_hash"]) != payload_hash
                or str(intent["payload_json"]) != payload_json
            ):
                self._fail(
                    "ATTEMPT_RECOVERY_INTENT_CONFLICT",
                    "attempt recovery intent differs from its durable identity",
                )
            if str(attempt["state"]) == "FAILED" and str(intent["state"]) == "COMPLETED":
                if (
                    str(attempt["error_code"]) != failure_code
                    or str(attempt["error_message"]) != error_message
                ):
                    self._fail(
                        "ATTEMPT_RECOVERY_REPLAY_CONFLICT",
                        "terminal attempt differs from the recovery result",
                    )
                return {
                    "attemptId": attempt_id,
                    "intentId": intent_id,
                    "state": "FAILED",
                    "errorCode": failure_code,
                    "replayed": True,
                }
            if (
                str(attempt["state"]) not in {"STARTING", "RUNNING"}
                or str(intent["state"]) != "PENDING"
                or str(attempt["permit_state"])
                not in {"COMMIT_AUTHORIZED", "STARTED"}
            ):
                self._fail(
                    "ATTEMPT_NOT_RECOVERABLE",
                    "attempt and recovery intent cannot become terminal",
                )
            was_running = str(attempt["state"]) == "RUNNING"
            self._connection.execute(
                "update node_launch_permits set state='STARTED',resolved_at=?,"
                "failure_code=null where permit_id=? and state='COMMIT_AUTHORIZED'",
                (_iso(ended_at), attempt["launch_permit_id"]),
            )
            self._connection.execute(
                "update attempts set state='FAILED',result_json=null,error_code=?,"
                "error_message=?,ended_at=? where attempt_id=? "
                "and state in ('STARTING','RUNNING')",
                (failure_code, error_message, _iso(ended_at), attempt_id),
            )
            self._connection.execute(
                "update nodes set state='FAILED',result_json=null,admission_state='STARTED',"
                "updated_at=? where route_id=? and node_id=?",
                (_iso(ended_at), attempt["route_id"], attempt["node_id"]),
            )
            self._connection.execute(
                "update start_requests set state='FAILED',terminal_at=?,failure_code=?,"
                "updated_at=? where start_request_id=?",
                (
                    _iso(ended_at),
                    failure_code,
                    _iso(ended_at),
                    attempt["start_request_id"],
                ),
            )
            self._terminalize_unstarted_descendants_locked(
                route_id=str(attempt["route_id"]),
                failed_node_id=str(attempt["node_id"]),
                now=ended_at,
            )
            route_completed, _ = self._complete_route_if_terminal_locked(
                route_id=str(attempt["route_id"]),
                fallback_state="FAILED",
                now=ended_at,
            )
            self._append_start_event_locked(
                start_request_id=str(attempt["start_request_id"]),
                route_id=str(attempt["route_id"]),
                node_id=str(attempt["node_id"]),
                kind=("CHILD_FAILED" if was_running else "CHILD_FAILED_BEFORE_START"),
                start_state="FAILED",
                evidence_job_id=str(attempt["evidence_job_id"]),
                admission_id=str(attempt["permit_admission"]),
                attestation=None,
                problem=_terminal_attempt_problem("FAILED"),
                now=ended_at,
                metadata={"failureCode": failure_code},
            )
            if route_completed:
                self._append_start_event_locked(
                    start_request_id=str(attempt["start_request_id"]),
                    route_id=str(attempt["route_id"]),
                    node_id=str(attempt["node_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state="FAILED",
                    evidence_job_id=str(attempt["evidence_job_id"]),
                    admission_id=str(attempt["permit_admission"]),
                    attestation=None,
                    problem=_terminal_attempt_problem("FAILED"),
                    now=ended_at,
                    metadata={"failureCode": failure_code},
                )
            self._connection.execute(
                "update intents set state='COMPLETED',completed_at=? "
                "where intent_id=? and state='PENDING'",
                (_iso(ended_at), intent_id),
            )
        return {
            "attemptId": attempt_id,
            "intentId": intent_id,
            "state": "FAILED",
            "errorCode": failure_code,
            "replayed": False,
        }

    def stranded_launch_permits(self) -> list[dict[str, Any]]:
        """Возвращает резервы, для которых ещё не создана попытка."""

        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(
                "select permit_id,route_id,node_id,state,guard_pid,guard_start_marker "
                "from node_launch_permits where state in ('RESERVED','GUARDED') "
                "order by reserved_at,permit_id"
            ).fetchall()
        return [
            {
                "permitId": str(row["permit_id"]),
                "routeId": str(row["route_id"]),
                "nodeId": str(row["node_id"]),
                "state": str(row["state"]),
                "guardPid": (
                    None if row["guard_pid"] is None else int(row["guard_pid"])
                ),
                "guardStartMarker": (
                    None
                    if row["guard_start_marker"] is None
                    else str(row["guard_start_marker"])
                ),
            }
            for row in rows
        ]

    def begin_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> dict[str, Any]:
        """Фиксирует намерение до возможного сигнала процессу сторожа."""

        _require_identifier(permit_id, "lp2_")
        _validate_optional_guard_identity_v2(guard_pid, guard_start_marker)
        created_at = _aware_utc(now)
        intent_id, payload_json, payload_hash = _permit_recovery_intent_v2(
            permit_id=permit_id,
            guard_pid=guard_pid,
            guard_start_marker=guard_start_marker,
        )
        with self._immediate():
            self._verify_identity_and_controller()
            permit = self._connection.execute(
                "select * from node_launch_permits where permit_id=?",
                (permit_id,),
            ).fetchone()
            if permit is None:
                self._fail("LAUNCH_PERMIT_NOT_FOUND", "launch permit does not exist")
            if (
                permit["guard_pid"] != guard_pid
                or permit["guard_start_marker"] != guard_start_marker
            ):
                self._fail(
                    "LAUNCH_PERMIT_RECOVERY_IDENTITY_MISMATCH",
                    "permit recovery belongs to another guard identity",
                )
            existing = self._connection.execute(
                "select * from intents where intent_id=?",
                (intent_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["route_id"]) != str(permit["route_id"])
                    or str(existing["node_id"]) != str(permit["node_id"])
                    or str(existing["kind"]) != "STRANDED_LAUNCH_PERMIT_RECOVERY_V2"
                    or str(existing["payload_hash"]) != payload_hash
                    or str(existing["payload_json"]) != payload_json
                ):
                    self._fail(
                        "LAUNCH_PERMIT_RECOVERY_INTENT_CONFLICT",
                        "permit recovery intent differs from its durable identity",
                    )
                return {
                    "permitId": permit_id,
                    "intentId": intent_id,
                    "state": str(existing["state"]),
                    "replayed": True,
                }
            if str(permit["state"]) not in {"RESERVED", "GUARDED"}:
                self._fail(
                    "LAUNCH_PERMIT_NOT_RECOVERABLE",
                    "only an uncommitted permit can begin recovery",
                )
            self._connection.execute(
                "insert into intents "
                "(intent_id,route_id,node_id,kind,payload_hash,payload_json,state,"
                "created_at,completed_at) values (?,?,?,?,?,?,'PENDING',?,null)",
                (
                    intent_id,
                    permit["route_id"],
                    permit["node_id"],
                    "STRANDED_LAUNCH_PERMIT_RECOVERY_V2",
                    payload_hash,
                    payload_json,
                    _iso(created_at),
                ),
            )
        return {
            "permitId": permit_id,
            "intentId": intent_id,
            "state": "PENDING",
            "replayed": False,
        }

    def complete_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> dict[str, Any]:
        """Закрывает резерв после доказанного отсутствия связанного сторожа."""

        _require_identifier(permit_id, "lp2_")
        _validate_optional_guard_identity_v2(guard_pid, guard_start_marker)
        ended_at = _aware_utc(now)
        intent_id, payload_json, payload_hash = _permit_recovery_intent_v2(
            permit_id=permit_id,
            guard_pid=guard_pid,
            guard_start_marker=guard_start_marker,
        )
        failure_code = "CONTROLLER_RESTARTED"
        with self._immediate():
            self._verify_identity_and_controller()
            permit = self._connection.execute(
                "select p.*,s.start_request_id,s.evidence_job_id,s.state as start_state "
                "from node_launch_permits p join start_requests s "
                "on s.admission_id=p.admission_id where p.permit_id=?",
                (permit_id,),
            ).fetchone()
            if permit is None:
                self._fail("LAUNCH_PERMIT_NOT_FOUND", "launch permit does not exist")
            if (
                permit["guard_pid"] != guard_pid
                or permit["guard_start_marker"] != guard_start_marker
            ):
                self._fail(
                    "LAUNCH_PERMIT_RECOVERY_IDENTITY_MISMATCH",
                    "permit recovery belongs to another guard identity",
                )
            intent = self._connection.execute(
                "select * from intents where intent_id=?",
                (intent_id,),
            ).fetchone()
            if intent is None:
                self._fail(
                    "LAUNCH_PERMIT_RECOVERY_INTENT_MISSING",
                    "permit recovery was not recorded before process handling",
                )
            if (
                str(intent["route_id"]) != str(permit["route_id"])
                or str(intent["node_id"]) != str(permit["node_id"])
                or str(intent["kind"]) != "STRANDED_LAUNCH_PERMIT_RECOVERY_V2"
                or str(intent["payload_hash"]) != payload_hash
                or str(intent["payload_json"]) != payload_json
            ):
                self._fail(
                    "LAUNCH_PERMIT_RECOVERY_INTENT_CONFLICT",
                    "permit recovery intent differs from its durable identity",
                )
            if (
                str(permit["state"]) == "FAILED_BEFORE_START"
                and str(intent["state"]) == "COMPLETED"
            ):
                if str(permit["failure_code"]) != failure_code:
                    self._fail(
                        "LAUNCH_PERMIT_RECOVERY_REPLAY_CONFLICT",
                        "terminal permit differs from the recovery result",
                    )
                return {
                    "permitId": permit_id,
                    "intentId": intent_id,
                    "state": "FAILED_BEFORE_START",
                    "errorCode": failure_code,
                    "replayed": True,
                }
            if (
                str(permit["state"]) not in {"RESERVED", "GUARDED"}
                or str(intent["state"]) != "PENDING"
            ):
                self._fail(
                    "LAUNCH_PERMIT_NOT_RECOVERABLE",
                    "permit and recovery intent cannot become terminal",
                )
            self._connection.execute(
                "update node_launch_permits set state='FAILED_BEFORE_START',"
                "resolved_at=?,failure_code=? where permit_id=? "
                "and state in ('RESERVED','GUARDED')",
                (_iso(ended_at), failure_code, permit_id),
            )
            self._connection.execute(
                "update nodes set state='FAILED',admission_state='ABORTED',updated_at=? "
                "where admission_id=?",
                (_iso(ended_at), permit["admission_id"]),
            )
            self._connection.execute(
                "update start_requests set state='FAILED',terminal_at=?,failure_code=?,"
                "updated_at=? where start_request_id=?",
                (
                    _iso(ended_at),
                    failure_code,
                    _iso(ended_at),
                    permit["start_request_id"],
                ),
            )
            self._terminalize_unstarted_descendants_locked(
                route_id=str(permit["route_id"]),
                failed_node_id=str(permit["node_id"]),
                now=ended_at,
            )
            route_completed, _ = self._complete_route_if_terminal_locked(
                route_id=str(permit["route_id"]),
                fallback_state="FAILED",
                now=ended_at,
            )
            problem = {
                "category": "INTERNAL",
                "code": "INTERNAL_ERROR",
                "message": "Незавершённый запуск закрыт после перезапуска контроллера.",
                "retryable": False,
            }
            self._append_start_event_locked(
                start_request_id=str(permit["start_request_id"]),
                route_id=str(permit["route_id"]),
                node_id=str(permit["node_id"]),
                kind="CHILD_FAILED_BEFORE_START",
                start_state="FAILED",
                evidence_job_id=str(permit["evidence_job_id"]),
                admission_id=str(permit["admission_id"]),
                attestation=None,
                problem=problem,
                now=ended_at,
                metadata={"failureCode": failure_code},
            )
            if route_completed:
                self._append_start_event_locked(
                    start_request_id=str(permit["start_request_id"]),
                    route_id=str(permit["route_id"]),
                    node_id=str(permit["node_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state="FAILED",
                    evidence_job_id=str(permit["evidence_job_id"]),
                    admission_id=str(permit["admission_id"]),
                    attestation=None,
                    problem=problem,
                    now=ended_at,
                    metadata={"failureCode": failure_code},
                )
            self._connection.execute(
                "update intents set state='COMPLETED',completed_at=? "
                "where intent_id=? and state='PENDING'",
                (_iso(ended_at), intent_id),
            )
        return {
            "permitId": permit_id,
            "intentId": intent_id,
            "state": "FAILED_BEFORE_START",
            "errorCode": failure_code,
            "replayed": False,
        }

    def register_quarantine_repository(
        self,
        *,
        source_root: Path,
        state_root: Path,
        git_dir: Path,
    ) -> str:
        """Регистрирует точную физическую идентичность карантина Git."""

        source, state, repository = _registered_quarantine_paths_v2(
            source_root=source_root,
            state_root=state_root,
            git_dir=git_dir,
        )
        repository_id = "qr2_" + _text_sha256(os.fspath(repository))[:43]
        identity = (
            repository_id,
            os.fspath(source),
            os.fspath(state),
            os.fspath(repository),
        )
        now = _iso(datetime.now(timezone.utc))
        with self._immediate():
            self._verify_identity_and_controller()
            existing = self._connection.execute(
                "select * from quarantine_repositories "
                "where repository_id=? or source_root=? or git_dir=?",
                (repository_id, os.fspath(source), os.fspath(repository)),
            ).fetchone()
            if existing is not None:
                observed = tuple(
                    str(existing[name])
                    for name in (
                        "repository_id",
                        "source_root",
                        "state_root",
                        "git_dir",
                    )
                )
                if observed != identity or str(existing["state"]) != "ACTIVE":
                    self._fail(
                        "QUARANTINE_REPOSITORY_CONFLICT",
                        "registered quarantine repository identity conflicts",
                    )
                return repository_id
            try:
                self._connection.execute(
                    "insert into quarantine_repositories "
                    "(repository_id,source_root,state_root,git_dir,state,created_at,updated_at) "
                    "values (?,?,?,?,'ACTIVE',?,?)",
                    (*identity, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise StateStoreV2Error(
                    "QUARANTINE_REPOSITORY_CONFLICT",
                    "registered quarantine repository identity conflicts",
                ) from exc
        return repository_id

    def quarantine_repositories(self) -> list[dict[str, Any]]:
        """Возвращает точные активные регистрации карантинов."""

        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(
                "select * from quarantine_repositories "
                "where state='ACTIVE' order by repository_id"
            ).fetchall()
        return [_quarantine_repository_record_v2(row) for row in rows]

    def begin_candidate_publication(
        self,
        *,
        route_id: str,
        node_id: str,
        repository_id: str,
        artifact_id: str,
        ref: str,
        base_source_sha: str,
        base_commit_sha: str,
        base_tree_sha: str,
        commit_sha: str,
        tree_sha: str,
        validation_proof_sha256: str,
    ) -> str:
        """До публикации ссылки сохраняет точное намерение ``PENDING``."""

        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        _require_opaque_identifier_v2(repository_id, "qr2_", 47)
        _require_opaque_identifier_v2(artifact_id, "art1_", 48)
        _require_candidate_ref_v2(ref, artifact_id)
        for name, value in (
            ("base_source_sha", base_source_sha),
            ("base_commit_sha", base_commit_sha),
            ("base_tree_sha", base_tree_sha),
            ("commit_sha", commit_sha),
            ("tree_sha", tree_sha),
        ):
            _require_git_sha_v2(value, name)
        _require_sha256(
            validation_proof_sha256,
            "validation_proof_sha256",
        )
        identity = (
            route_id,
            node_id,
            repository_id,
            artifact_id,
            ref,
            base_source_sha,
            base_commit_sha,
            base_tree_sha,
            commit_sha,
            tree_sha,
            validation_proof_sha256,
        )
        now = _iso(datetime.now(timezone.utc))
        with self._immediate():
            self._verify_identity_and_controller()
            node_exists = self._connection.execute(
                "select 1 from nodes where route_id=? and node_id=?",
                (route_id, node_id),
            ).fetchone()
            if node_exists is None:
                self._fail("ROUTE_NODE_NOT_FOUND", "route or node does not exist")
            repository_exists = self._connection.execute(
                "select 1 from quarantine_repositories "
                "where repository_id=? and state='ACTIVE'",
                (repository_id,),
            ).fetchone()
            if repository_exists is None:
                self._fail(
                    "QUARANTINE_REPOSITORY_NOT_FOUND",
                    "registered quarantine repository does not exist",
                )
            existing = self._connection.execute(
                "select * from candidate_publication_intents "
                "where repository_id=? and ref=?",
                (repository_id, ref),
            ).fetchone()
            if existing is not None:
                observed = tuple(
                    str(existing[name])
                    for name in (
                        "route_id",
                        "node_id",
                        "repository_id",
                        "artifact_id",
                        "ref",
                        "base_source_sha",
                        "base_commit_sha",
                        "base_tree_sha",
                        "commit_sha",
                        "tree_sha",
                        "validation_proof_sha256",
                    )
                )
                if observed != identity or str(existing["state"]) not in {
                    "PENDING",
                    "COMPLETED",
                    "RECOVERED",
                }:
                    self._fail(
                        "CANDIDATE_PUBLICATION_CONFLICT",
                        "candidate publication identity conflicts",
                    )
                return str(existing["intent_id"])
            registered = self._connection.execute(
                "select 1 from candidate_registry "
                "where repository_id=? and ref=?",
                (repository_id, ref),
            ).fetchone()
            if registered is not None:
                self._fail(
                    "CANDIDATE_REGISTRY_CONFLICT",
                    "candidate registry already contains this reference",
                )
            intent_id = new_opaque_id("cpi2")
            try:
                self._connection.execute(
                    "insert into candidate_publication_intents "
                    "(intent_id,route_id,node_id,repository_id,artifact_id,ref,"
                    "base_source_sha,base_commit_sha,base_tree_sha,commit_sha,tree_sha,"
                    "validation_proof_sha256,state,created_at,updated_at,completed_at) "
                    "values (?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?,?,null)",
                    (intent_id, *identity, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise StateStoreV2Error(
                    "CANDIDATE_PUBLICATION_CONFLICT",
                    "candidate publication identity conflicts",
                ) from exc
        return intent_id

    def candidate_intent(self, intent_id: str) -> dict[str, Any]:
        _require_opaque_identifier_v2(intent_id, "cpi2_", 48)
        with self._lock:
            self._verify_identity_and_controller()
            row = self._connection.execute(
                "select * from candidate_publication_intents where intent_id=?",
                (intent_id,),
            ).fetchone()
        if row is None:
            self._fail(
                "CANDIDATE_INTENT_NOT_FOUND",
                "candidate publication intent does not exist",
            )
        return _candidate_intent_record_v2(row)

    def pending_candidate_publications(
        self,
        repository_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if repository_id is not None:
            _require_opaque_identifier_v2(repository_id, "qr2_", 47)
        query = (
            "select * from candidate_publication_intents where state='PENDING'"
        )
        parameters: tuple[str, ...] = ()
        if repository_id is not None:
            query += " and repository_id=?"
            parameters = (repository_id,)
        query += " order by created_at,intent_id"
        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(query, parameters).fetchall()
        return [_candidate_intent_record_v2(row) for row in rows]

    def complete_candidate_publication(
        self,
        intent_id: str,
        *,
        observed_commit_sha: str,
        observed_tree_sha: str,
        proof_hash: str,
    ) -> dict[str, Any]:
        """Завершает точное намерение доверенной записью кандидата."""

        _require_opaque_identifier_v2(intent_id, "cpi2_", 48)
        _require_git_sha_v2(observed_commit_sha, "observed_commit_sha")
        _require_git_sha_v2(observed_tree_sha, "observed_tree_sha")
        _require_sha256(proof_hash, "proof_hash")
        return self._resolve_candidate_publication(
            intent_id,
            intent_state="COMPLETED",
            candidate_state="VERIFIED",
            validation_state="passed",
            proof_hash=proof_hash,
            observed_commit_sha=observed_commit_sha,
            observed_tree_sha=observed_tree_sha,
            trusted=True,
            require_saved_validation_proof=True,
        )

    def recover_candidate_publication(
        self,
        intent_id: str,
        *,
        observed_commit_sha: str,
        observed_tree_sha: str,
    ) -> dict[str, Any]:
        """Восстанавливает намерение только с сохранённой проверкой."""

        _require_opaque_identifier_v2(intent_id, "cpi2_", 48)
        _require_git_sha_v2(observed_commit_sha, "observed_commit_sha")
        _require_git_sha_v2(observed_tree_sha, "observed_tree_sha")
        return self._resolve_candidate_publication(
            intent_id,
            intent_state="RECOVERED",
            candidate_state="VERIFIED",
            validation_state="passed",
            proof_hash=None,
            observed_commit_sha=observed_commit_sha,
            observed_tree_sha=observed_tree_sha,
            trusted=True,
            require_saved_validation_proof=True,
        )

    def abort_candidate_publication(
        self,
        intent_id: str,
        *,
        proof_hash: str,
    ) -> dict[str, Any]:
        """Закрывает отсутствие ссылки недоверенной записью."""

        _require_opaque_identifier_v2(intent_id, "cpi2_", 48)
        _require_sha256(proof_hash, "proof_hash")
        return self._resolve_candidate_publication(
            intent_id,
            intent_state="ABORTED",
            candidate_state="REF_MISSING_QUARANTINED",
            validation_state="quarantined",
            proof_hash=proof_hash,
            observed_commit_sha="",
            observed_tree_sha="",
            trusted=False,
            require_saved_validation_proof=False,
        )

    def quarantine_mismatched_publication(
        self,
        intent_id: str,
        *,
        observed_commit_sha: str,
        observed_tree_sha: str,
        proof_hash: str,
    ) -> dict[str, Any]:
        """Закрывает несовпавшую ссылку недоверенной записью."""

        _require_opaque_identifier_v2(intent_id, "cpi2_", 48)
        _require_git_sha_v2(observed_commit_sha, "observed_commit_sha")
        if observed_tree_sha:
            _require_git_sha_v2(observed_tree_sha, "observed_tree_sha")
        _require_sha256(proof_hash, "proof_hash")
        return self._resolve_candidate_publication(
            intent_id,
            intent_state="QUARANTINED",
            candidate_state="REF_MISMATCH_QUARANTINED",
            validation_state="quarantined",
            proof_hash=proof_hash,
            observed_commit_sha=observed_commit_sha,
            observed_tree_sha=observed_tree_sha,
            trusted=False,
            require_saved_validation_proof=False,
        )

    def _resolve_candidate_publication(
        self,
        intent_id: str,
        *,
        intent_state: str,
        candidate_state: str,
        validation_state: str,
        proof_hash: str | None,
        observed_commit_sha: str,
        observed_tree_sha: str,
        trusted: bool,
        require_saved_validation_proof: bool,
    ) -> dict[str, Any]:
        now = _iso(datetime.now(timezone.utc))
        with self._immediate():
            self._verify_identity_and_controller()
            intent = self._connection.execute(
                "select * from candidate_publication_intents where intent_id=?",
                (intent_id,),
            ).fetchone()
            if intent is None:
                self._fail(
                    "CANDIDATE_INTENT_NOT_FOUND",
                    "candidate publication intent does not exist",
                )
            if trusted and (
                observed_commit_sha != str(intent["commit_sha"])
                or observed_tree_sha != str(intent["tree_sha"])
            ):
                self._fail(
                    "CANDIDATE_PUBLICATION_EVIDENCE_MISMATCH",
                    "observed candidate identity differs from its intent",
                )
            stored_validation_proof = intent["validation_proof_sha256"]
            if require_saved_validation_proof:
                if stored_validation_proof is None:
                    self._fail(
                        "CANDIDATE_VALIDATION_PROOF_UNAVAILABLE",
                        "candidate validation proof was not persisted",
                    )
                effective_proof_hash = str(stored_validation_proof)
                _require_sha256(
                    effective_proof_hash,
                    "validation_proof_sha256",
                )
                if proof_hash is not None and proof_hash != effective_proof_hash:
                    self._fail(
                        "CANDIDATE_VALIDATION_PROOF_MISMATCH",
                        "completion proof differs from the persisted validation proof",
                    )
            else:
                if proof_hash is None:
                    self._fail(
                        "CANDIDATE_RECOVERY_PROOF_UNAVAILABLE",
                        "candidate recovery proof is unavailable",
                    )
                effective_proof_hash = proof_hash
            state = str(intent["state"])
            if state == intent_state:
                registered = self._connection.execute(
                    "select * from candidate_registry where intent_id=?",
                    (intent_id,),
                ).fetchone()
                if registered is None or not _candidate_resolution_matches_v2(
                    registered,
                    intent,
                    observed_commit_sha=observed_commit_sha,
                    observed_tree_sha=observed_tree_sha,
                    candidate_state=candidate_state,
                    validation_state=validation_state,
                    proof_hash=effective_proof_hash,
                    trusted=trusted,
                ):
                    self._fail(
                        "CANDIDATE_REGISTRY_CONFLICT",
                        "resolved candidate registry identity conflicts",
                    )
                return _candidate_record_v2(registered)
            if state != "PENDING":
                self._fail(
                    "CANDIDATE_PUBLICATION_CONFLICT",
                    "candidate publication is no longer pending",
                )
            existing = self._connection.execute(
                "select * from candidate_registry "
                "where repository_id=? and ref=?",
                (intent["repository_id"], intent["ref"]),
            ).fetchone()
            if existing is not None:
                self._fail(
                    "CANDIDATE_REGISTRY_CONFLICT",
                    "candidate registry already contains this reference",
                )
            candidate_id = new_opaque_id("cand2")
            try:
                self._connection.execute(
                    "insert into candidate_registry "
                    "(candidate_id,route_id,node_id,repository_id,intent_id,artifact_id,"
                    "ref,base_source_sha,base_commit_sha,base_tree_sha,commit_sha,tree_sha,"
                    "observed_commit_sha,observed_tree_sha,state,validation_state,proof_hash,"
                    "trusted,created_at,updated_at) "
                    "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        candidate_id,
                        intent["route_id"],
                        intent["node_id"],
                        intent["repository_id"],
                        intent_id,
                        intent["artifact_id"],
                        intent["ref"],
                        intent["base_source_sha"],
                        intent["base_commit_sha"],
                        intent["base_tree_sha"],
                        intent["commit_sha"],
                        intent["tree_sha"],
                        observed_commit_sha,
                        observed_tree_sha,
                        candidate_state,
                        validation_state,
                        effective_proof_hash,
                        int(trusted),
                        now,
                        now,
                    ),
                )
                completed = self._connection.execute(
                    "update candidate_publication_intents "
                    "set state=?,updated_at=?,completed_at=? "
                    "where intent_id=? and state='PENDING'",
                    (intent_state, now, now, intent_id),
                )
            except sqlite3.IntegrityError as exc:
                raise StateStoreV2Error(
                    "CANDIDATE_REGISTRY_CONFLICT",
                    "candidate registry identity conflicts",
                ) from exc
            if completed.rowcount != 1:
                self._fail(
                    "CANDIDATE_PUBLICATION_CONFLICT",
                    "candidate publication changed during completion",
                )
            registered = self._connection.execute(
                "select * from candidate_registry where candidate_id=?",
                (candidate_id,),
            ).fetchone()
        return _candidate_record_v2(registered)

    def candidate_records(
        self,
        repository_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if repository_id is not None:
            _require_opaque_identifier_v2(repository_id, "qr2_", 47)
        query = "select * from candidate_registry"
        parameters: tuple[str, ...] = ()
        if repository_id is not None:
            query += " where repository_id=?"
            parameters = (repository_id,)
        query += " order by created_at,candidate_id"
        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(query, parameters).fetchall()
        return [_candidate_record_v2(row) for row in rows]

    def read_node_plan(
        self,
        route_id: str,
        node_id: str,
        request_context: RequestContextV2,
    ) -> NodePlanV2:
        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        with self._lock:
            self._verify_identity_and_controller()
            row = self._connection.execute(
                "select r.context_hash as route_context_hash,"
                "r.context_json as route_context_json,r.plan_output_json,"
                "r.catalog_generation as route_catalog_generation,"
                "r.algorithm_version as route_algorithm_version,"
                "r.compatibility_fingerprint as route_compatibility_fingerprint,n.* "
                "from routes r join nodes n on n.route_id=r.route_id "
                "where r.route_id=? and n.node_id=?",
                (route_id, node_id),
            ).fetchone()
            if row is None:
                self._fail("ROUTE_NODE_NOT_FOUND", "route or node does not exist")
            self._require_owner_values(
                request_context,
                context_hash=str(row["route_context_hash"]),
                context_json=str(row["route_context_json"]),
            )
            plan_output = _stored_json_object(
                row["plan_output_json"], "plan_output_json"
            )
            planned_node = PlannedNodeV2(
                node_id=str(row["node_id"]),
                ordinal=int(row["ordinal"]),
                role=str(row["role"]),
                mission=str(row["mission"]),
                dependencies=tuple(
                    _stored_json_list(row["dependencies_json"], "dependencies_json")
                ),
                context_refs=tuple(
                    _stored_json_list(row["context_refs_json"], "context_refs_json")
                ),
                scope_id=str(row["scope_id"]),
                artifact_profile_id=str(row["artifact_profile_id"]),
                validation_profile_id=str(row["validation_profile_id"]),
                assessment=_stored_json_object(
                    row["assessment_json"], "assessment_json"
                ),
                risk_flags=tuple(
                    _stored_json_list(row["risk_flags_json"], "risk_flags_json")
                ),
                selected_model=str(row["selected_model"]),
                reasoning_effort=str(row["reasoning_effort"]),
                permission_profile_id=str(row["permission_profile_id"]),
                disposition=str(row["disposition"]),
            )
            raw_account_context = row["account_context_fingerprint"]
            account_context_fingerprint = (
                None if raw_account_context is None else str(raw_account_context)
            )
            if account_context_fingerprint is not None:
                _require_sha256(
                    account_context_fingerprint,
                    "accountContextFingerprint",
                )
            dependency_results: list[DependencyResultV2] = []
            for dependency_node_id in planned_node.dependencies:
                dependency = self._connection.execute(
                    "select state,result_json from nodes "
                    "where route_id=? and node_id=?",
                    (route_id, dependency_node_id),
                ).fetchone()
                if dependency is None or str(dependency["state"]) != "SUCCEEDED":
                    self._fail(
                        "NODE_DEPENDENCIES_INCOMPLETE",
                        "node plan requires successful dependencies",
                    )
                if dependency["result_json"] is None:
                    self._fail(
                        "DEPENDENCY_RESULT_MISSING",
                        "successful dependency has no durable result",
                    )
                encoded_dependency_result = str(dependency["result_json"])
                dependency_result = _stored_json_object(
                    encoded_dependency_result,
                    "nodes.result_json",
                )
                raw_result = encoded_dependency_result.encode("utf-8")
                inline_result, inline_truncated = _bounded_inline_terminal_result(
                    dependency_result,
                    max_bytes=_MAX_INLINE_DEPENDENCY_RESULT_BYTES,
                )
                raw_result_fingerprint = hashlib.sha256(raw_result).hexdigest()
                result_truncated = (
                    inline_truncated
                    or canonical_json_v1(inline_result) != encoded_dependency_result
                )
                projection = {
                    "nodeId": dependency_node_id,
                    "result": inline_result,
                    "rawResultFingerprint": raw_result_fingerprint,
                    "rawResultBytes": len(raw_result),
                    "resultTruncated": result_truncated,
                }
                dependency_results.append(
                    DependencyResultV2(
                        node_id=dependency_node_id,
                        result=inline_result,
                        raw_result_fingerprint=raw_result_fingerprint,
                        raw_result_bytes=len(raw_result),
                        result_truncated=result_truncated,
                        projection_fingerprint=domain_fingerprint(
                            "codex-smart/dependency-result-projection/v2",
                            projection,
                        ),
                    )
                )
        return NodePlanV2(
            route_id=route_id,
            node_id=node_id,
            plan_output=plan_output,
            node=planned_node,
            node_state=str(row["state"]),
            catalog_generation=str(row["route_catalog_generation"]),
            algorithm_version=str(row["route_algorithm_version"]),
            compatibility_fingerprint=str(row["route_compatibility_fingerprint"]),
            account_context_fingerprint=account_context_fingerprint,
            dependency_results=tuple(dependency_results),
        )

    def read_start_status(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
        *,
        cursor: str | None,
        page_size: int,
    ) -> StartStatusV2:
        _require_identifier(start_request_id, "sr2_")
        if type(page_size) is not int or not 1 <= page_size <= 100:
            self._fail("CURSOR_REJECT", "pageSize must be between 1 and 100")
        after_sequence = _decode_cursor(cursor)
        with self._lock:
            self._verify_identity_and_controller()
            start = self._start_owner_row_locked(start_request_id, request_context)
            if cursor is not None:
                belongs = self._connection.execute(
                    "select 1 from events where sequence=? and route_id=? and code=?",
                    (after_sequence, start["route_id"], start_request_id),
                ).fetchone()
                if belongs is None:
                    self._fail(
                        "CURSOR_REJECT", "cursor does not belong to the start request"
                    )
            rows = self._connection.execute(
                "select * from events where route_id=? and code=? and sequence>? "
                "order by sequence limit ?",
                (start["route_id"], start_request_id, after_sequence, page_size + 1),
            ).fetchall()
            selected = rows[:page_size]
            items = tuple(
                _start_event_record(row, start_request_id) for row in selected
            )
            terminal_attempt = self._terminal_attempt_for_start_locked(start)
            terminal_result = (
                _start_terminal_result_record(terminal_attempt)
                if terminal_attempt is not None
                else None
            )
        stored_state = str(start["start_state"])
        state = terminal_result.state if terminal_result is not None else stored_state
        terminal = state in _TERMINAL_ATTEMPT_STATES | {"STALE"}
        next_cursor = (
            _encode_cursor(items[-1].sequence)
            if len(rows) > page_size and items
            else None
            if terminal
            else (_encode_cursor(items[-1].sequence) if items else cursor)
        )
        public_admission_id = (
            str(start["admission_id"])
            if start["admission_id"] is not None
            and (stored_state == "STARTED" or terminal_result is not None)
            else None
        )
        return StartStatusV2(
            start_request_id=start_request_id,
            state=state,
            evidence_job_state=str(start["evidence_state"]),
            admission_id=public_admission_id,
            terminal=terminal,
            terminal_result=terminal_result,
            page=StartEventPageV2(
                cursor=cursor,
                next_cursor=next_cursor,
                items=items,
            ),
        )

    def read_start_request(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
    ) -> StartRequestV2:
        """Возвращает авторитетную проекцию запроса запуска из базы."""

        _require_identifier(start_request_id, "sr2_")
        with self._lock:
            self._verify_identity_and_controller()
            start = self._start_owner_row_locked(start_request_id, request_context)
            job = self._connection.execute(
                "select queue_position,deadline_at,boundary_id from account_evidence_jobs "
                "where evidence_job_id=?",
                (start["evidence_job_id"],),
            ).fetchone()
            if job is None:
                self._fail(
                    "DATABASE_VALUE_INVALID", "start request has no evidence job"
                )
            queue_position = job["queue_position"]
            if start["evidence_state"] == "QUEUED":
                if type(queue_position) is not int or not 1 <= queue_position <= 32:
                    self._fail(
                        "DATABASE_VALUE_INVALID", "queued evidence position is invalid"
                    )
            else:
                queue_position = 0
            terminal_attempt = self._terminal_attempt_for_start_locked(start)
            state = (
                str(terminal_attempt["state"])
                if terminal_attempt is not None
                else str(start["start_state"])
            )
        evidence_job_id = str(start["evidence_job_id"])
        return StartRequestV2(
            start_request_id=start_request_id,
            evidence_job_id=evidence_job_id,
            attempt_id=attempt_id_for_evidence_job(evidence_job_id),
            route_id=str(start["route_id"]),
            node_id=str(job["boundary_id"]),
            queue_position=int(queue_position),
            deadline_at=_parse_iso(str(job["deadline_at"])),
            state=state,
        )

    def queued_start_dispatches(self) -> tuple[QueuedStartDispatchV2, ...]:
        """Возвращает всю ограниченную долговечную очередь для переподачи."""

        with self._lock:
            self._verify_identity_and_controller()
            rows = self._connection.execute(
                "select s.start_request_id,s.state as start_state,"
                "s.evidence_job_id as start_evidence_job_id,"
                "s.shell_session_id,s.session_id,s.turn_id,"
                "j.evidence_job_id,j.start_request_id as job_start_request_id,"
                "j.route_id as job_route_id,j.boundary_id,j.queue_position,"
                "j.deadline_at,j.queued_at,r.route_id,r.state as route_state,"
                "r.startable,r.context_hash,r.context_json,"
                "n.state as node_state,n.evidence_job_id as node_evidence_job_id,"
                "n.admission_id as node_admission_id "
                "from account_evidence_jobs j "
                "join start_requests s on s.start_request_id=j.start_request_id "
                "join routes r on r.route_id=j.route_id "
                "join nodes n on n.route_id=j.route_id and n.node_id=j.boundary_id "
                "where j.state='QUEUED' "
                "order by j.queue_position,j.queued_at,j.evidence_job_id limit 33"
            ).fetchall()
            if len(rows) > 32:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "durable evidence queue exceeds its bounded capacity",
                )
            result: list[QueuedStartDispatchV2] = []
            positions: set[int] = set()
            for row in rows:
                queue_position = row["queue_position"]
                if (
                    row["start_state"] != "ATTESTING"
                    or row["start_evidence_job_id"] != row["evidence_job_id"]
                    or row["job_start_request_id"] != row["start_request_id"]
                    or row["job_route_id"] != row["route_id"]
                    or row["route_state"] not in {"PLANNED", "RUNNING"}
                    or row["startable"] != 1
                    or row["node_state"] != "PLANNED"
                    or row["node_evidence_job_id"] is not None
                    or row["node_admission_id"] is not None
                    or type(queue_position) is not int
                    or not 1 <= queue_position <= 32
                    or queue_position in positions
                ):
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "queued start and evidence records are inconsistent",
                    )
                positions.add(queue_position)
                context = _request_context_from_stored_json_v2(
                    row["context_json"]
                )
                _, context_json, context_hash = self._validated_context(context)
                if (
                    context_json != row["context_json"]
                    or context_hash != row["context_hash"]
                    or context.shell_session_id != row["shell_session_id"]
                    or context.session_id != row["session_id"]
                    or context.turn_id != row["turn_id"]
                ):
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "queued start context does not match its durable owner",
                    )
                result.append(
                    QueuedStartDispatchV2(
                        start_request_id=str(row["start_request_id"]),
                        evidence_job_id=str(row["evidence_job_id"]),
                        deadline_at=_parse_iso(str(row["deadline_at"])),
                        request_context=context,
                    )
                )
        return tuple(result)

    def cancel_start_request(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
        *,
        idempotency_key: str,
        reason_code: str,
        now: datetime,
    ) -> CancellationV2:
        _require_identifier(start_request_id, "sr2_")
        _require_identifier(idempotency_key, "idem2_")
        _require_nonempty(reason_code, "reasonCode")
        cancelled_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            start = self._start_owner_row_locked(start_request_id, request_context)
            previous = self._connection.execute(
                "select * from events where route_id=? and code=? "
                "and event in ('CANCEL_REQUESTED','CANCELLED') "
                "order by sequence desc limit 1",
                (start["route_id"], start_request_id),
            ).fetchone()
            if previous is not None:
                payload = _stored_json_object(previous["message"], "events.message")
                metadata = payload.get("metadata")
                if type(metadata) is not dict:
                    self._fail(
                        "DATABASE_VALUE_INVALID", "cancellation metadata is absent"
                    )
                if metadata.get("idempotencyKey") == idempotency_key:
                    if metadata.get("reasonCode") != reason_code:
                        self._fail(
                            "CANCELLATION_REPLAY_CONFLICT",
                            "cancellation replay uses another reason",
                        )
                    return _cancellation_record(
                        start_request_id=start_request_id,
                        start_state=str(start["start_state"]),
                        evidence_state=str(start["evidence_state"]),
                        idempotency_key=idempotency_key,
                        idempotency_status="REPLAYED",
                    )
            if str(start["start_state"]) == "STARTED":
                self._fail(
                    "START_NOT_CANCELLABLE",
                    "a started child requires an execution-level cancellation path",
                )
            if str(start["start_state"]) in {"STALE", "FAILED", "CANCELLED"}:
                return CancellationV2(
                    status="ALREADY_TERMINAL",
                    start_request_id=start_request_id,
                    state=str(start["start_state"]),
                    terminal=True,
                    idempotency_key=idempotency_key,
                    idempotency_status="COMMITTED",
                )
            evidence_state = str(start["evidence_state"])
            route_completed = False
            route_state: str | None = None
            if evidence_state == "RUNNING":
                self._connection.execute(
                    "update account_evidence_jobs set state='CANCEL_REQUESTED',failure_code=?,"
                    "cancel_requested_at=?,progress_at=? where evidence_job_id=? and state='RUNNING'",
                    (
                        reason_code,
                        _iso(cancelled_at),
                        _iso(cancelled_at),
                        start["evidence_job_id"],
                    ),
                )
                kind = "CANCEL_REQUESTED"
                start_state = "ATTESTING"
                terminal = False
            elif evidence_state in {"QUEUED", "SUCCEEDED"}:
                self._connection.execute(
                    "update account_evidence_jobs set state='CANCELLED',failure_code=?,"
                    "cancel_requested_at=?,progress_at=?,completed_at=? "
                    "where evidence_job_id=? and state in ('QUEUED','SUCCEEDED')",
                    (
                        reason_code,
                        _iso(cancelled_at),
                        _iso(cancelled_at),
                        _iso(cancelled_at),
                        start["evidence_job_id"],
                    ),
                )
                self._connection.execute(
                    "update start_requests set state='CANCELLED',terminal_at=?,failure_code=?,"
                    "updated_at=? where start_request_id=? and state in ('ATTESTING','READY')",
                    (
                        _iso(cancelled_at),
                        reason_code,
                        _iso(cancelled_at),
                        start_request_id,
                    ),
                )
                self._connection.execute(
                    "update nodes set state='CANCELLED',result_json=?,"
                    "admission_state=case when admission_id is null then null "
                    "else 'ABORTED' end,updated_at=? "
                    "where route_id=? and node_id=? and state='PLANNED'",
                    (
                        canonical_json_v1(
                            {
                                "errorCode": reason_code,
                                "nodeId": str(start["boundary_id"]),
                            }
                        ),
                        _iso(cancelled_at),
                        start["route_id"],
                        start["boundary_id"],
                    ),
                )
                self._terminalize_unstarted_descendants_locked(
                    route_id=str(start["route_id"]),
                    failed_node_id=str(start["boundary_id"]),
                    now=cancelled_at,
                    descendant_state="CANCELLED",
                    error_code="DEPENDENCY_CANCELLED",
                )
                route_completed, route_state = (
                    self._complete_route_if_terminal_locked(
                        route_id=str(start["route_id"]),
                        fallback_state="CANCELLED",
                        now=cancelled_at,
                    )
                )
                kind = "CANCELLED"
                start_state = "CANCELLED"
                terminal = True
            elif evidence_state == "CANCEL_REQUESTED":
                self._fail(
                    "DATABASE_VALUE_INVALID", "cancel request has no durable event"
                )
            else:
                self._fail("START_NOT_CANCELLABLE", "start request cannot be cancelled")
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=str(start["route_id"]),
                node_id=str(start["boundary_id"]),
                kind=kind,
                start_state=start_state,
                evidence_job_id=str(start["evidence_job_id"]),
                admission_id=(
                    str(start["admission_id"])
                    if start["admission_id"] is not None
                    else None
                ),
                attestation=None,
                problem=None,
                now=cancelled_at,
                metadata={
                    "idempotencyKey": idempotency_key,
                    "reasonCode": reason_code,
                },
            )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=start_request_id,
                    route_id=str(start["route_id"]),
                    node_id=str(start["boundary_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=str(start["evidence_job_id"]),
                    admission_id=(
                        str(start["admission_id"])
                        if start["admission_id"] is not None
                        else None
                    ),
                    attestation=None,
                    problem=_terminal_attempt_problem(route_state),
                    now=cancelled_at,
                    metadata={
                        "idempotencyKey": idempotency_key,
                        "reasonCode": reason_code,
                    },
                )
        return CancellationV2(
            status=kind,
            start_request_id=start_request_id,
            state=start_state,
            terminal=terminal,
            idempotency_key=idempotency_key,
            idempotency_status="COMMITTED",
        )

    def record_account_evidence_terminal(
        self,
        evidence_job_id: str,
        request_context: RequestContextV2,
        *,
        state: str,
        failure_code: str,
        problem: Mapping[str, Any] | None,
        now: datetime,
    ) -> TerminalRecordV2:
        _require_identifier(evidence_job_id, "aej2_")
        if state not in {"FAILED", "CANCELLED"}:
            self._fail(
                "INVALID_EVIDENCE_TERMINAL",
                "evidence terminal must be FAILED or CANCELLED",
            )
        _require_nonempty(failure_code, "failureCode")
        if problem is not None:
            _validate_public_problem(problem)
        completed_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            job = self._connection.execute(
                "select * from account_evidence_jobs where evidence_job_id=?",
                (evidence_job_id,),
            ).fetchone()
            if job is None:
                self._fail("EVIDENCE_JOB_NOT_FOUND", "evidence job does not exist")
            start = self._start_owner_row_locked(
                str(job["start_request_id"]), request_context
            )
            if job["state"] in {"FAILED", "CANCELLED"}:
                if job["state"] != state or job["failure_code"] != failure_code:
                    self._fail(
                        "EVIDENCE_TERMINAL_REPLAY_CONFLICT", "evidence replay differs"
                    )
                return TerminalRecordV2(
                    entity_id=evidence_job_id,
                    state=state,
                    terminal=True,
                    replayed=True,
                )
            if job["state"] not in {"QUEUED", "RUNNING", "CANCEL_REQUESTED"}:
                self._fail(
                    "EVIDENCE_JOB_NOT_TERMINABLE", "evidence job cannot become terminal"
                )
            self._connection.execute(
                "update account_evidence_jobs set state=?,failure_code=?,progress_at=?,"
                "cancel_requested_at=case when ?='CANCELLED' then "
                "coalesce(cancel_requested_at,?) else cancel_requested_at end,completed_at=? "
                "where evidence_job_id=? and state in ('QUEUED','RUNNING','CANCEL_REQUESTED')",
                (
                    state,
                    failure_code,
                    _iso(completed_at),
                    state,
                    _iso(completed_at),
                    _iso(completed_at),
                    evidence_job_id,
                ),
            )
            self._connection.execute(
                "update start_requests set state=?,terminal_at=?,failure_code=?,updated_at=? "
                "where start_request_id=? and state in ('ATTESTING','READY')",
                (
                    state,
                    _iso(completed_at),
                    failure_code,
                    _iso(completed_at),
                    start["start_request_id"],
                ),
            )
            terminal_result_json = canonical_json_v1(
                {
                    "errorCode": failure_code,
                    "nodeId": str(start["boundary_id"]),
                }
            )
            self._connection.execute(
                "update nodes set state=?,result_json=?,"
                "admission_state=case when admission_id is null then null else 'ABORTED' end,"
                "updated_at=? where route_id=? and node_id=? and state='PLANNED'",
                (
                    state,
                    terminal_result_json,
                    _iso(completed_at),
                    start["route_id"],
                    start["boundary_id"],
                ),
            )
            descendant_error = (
                "DEPENDENCY_FAILED"
                if state == "FAILED"
                else "DEPENDENCY_CANCELLED"
            )
            self._terminalize_unstarted_descendants_locked(
                route_id=str(start["route_id"]),
                failed_node_id=str(start["boundary_id"]),
                now=completed_at,
                descendant_state=state,
                error_code=descendant_error,
            )
            route_completed, route_state = self._complete_route_if_terminal_locked(
                route_id=str(start["route_id"]),
                fallback_state=state,
                now=completed_at,
            )
            self._append_start_event_locked(
                start_request_id=str(start["start_request_id"]),
                route_id=str(start["route_id"]),
                node_id=str(start["boundary_id"]),
                kind="EVIDENCE_FAILED" if state == "FAILED" else "CANCELLED",
                start_state=state,
                evidence_job_id=evidence_job_id,
                admission_id=(
                    str(start["admission_id"])
                    if start["admission_id"] is not None
                    else None
                ),
                attestation=None,
                problem=problem,
                now=completed_at,
            )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=str(start["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(start["boundary_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=evidence_job_id,
                    admission_id=(
                        str(start["admission_id"])
                        if start["admission_id"] is not None
                        else None
                    ),
                    attestation=None,
                    problem=problem or _terminal_attempt_problem(route_state),
                    now=completed_at,
                    metadata={"failureCode": failure_code},
                )
        return TerminalRecordV2(
            entity_id=evidence_job_id,
            state=state,
            terminal=True,
            replayed=False,
        )

    def record_start_stale(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
        *,
        failure_code: str,
        problem: Mapping[str, Any],
        now: datetime,
    ) -> TerminalRecordV2:
        """Закрывает ещё не допущенный запрос при дрейфе его договора."""

        _require_identifier(start_request_id, "sr2_")
        _require_nonempty(failure_code, "failureCode")
        _validate_public_problem(problem)
        stale_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            start = self._start_owner_row_locked(start_request_id, request_context)
            if start["start_state"] == "STALE":
                if start["failure_code"] != failure_code:
                    self._fail("START_STALE_REPLAY_CONFLICT", "stale replay differs")
                return TerminalRecordV2(
                    entity_id=start_request_id,
                    state="STALE",
                    terminal=True,
                    replayed=True,
                )
            if start["start_state"] not in {"ATTESTING", "READY"}:
                self._fail("START_NOT_STALEABLE", "start request cannot become stale")
            self._connection.execute(
                "update account_evidence_jobs set state='FAILED',failure_code=?,progress_at=?,"
                "completed_at=? where evidence_job_id=? and state in ('QUEUED','RUNNING')",
                (
                    failure_code,
                    _iso(stale_at),
                    _iso(stale_at),
                    start["evidence_job_id"],
                ),
            )
            self._connection.execute(
                "update start_requests set state='STALE',terminal_at=?,failure_code=?,updated_at=? "
                "where start_request_id=? and state in ('ATTESTING','READY')",
                (_iso(stale_at), failure_code, _iso(stale_at), start_request_id),
            )
            stale_result_json = canonical_json_v1(
                {
                    "errorCode": failure_code,
                    "nodeId": str(start["boundary_id"]),
                }
            )
            self._connection.execute(
                "update nodes set state='STALE',result_json=?,"
                "admission_state=case when admission_id is null then null else 'ABORTED' end,"
                "updated_at=? where route_id=? and node_id=? and state='PLANNED'",
                (
                    stale_result_json,
                    _iso(stale_at),
                    start["route_id"],
                    start["boundary_id"],
                ),
            )
            self._terminalize_all_unstarted_nodes_locked(
                route_id=str(start["route_id"]),
                now=stale_at,
                error_code=failure_code,
            )
            route_completed, route_state = self._complete_route_if_terminal_locked(
                route_id=str(start["route_id"]),
                fallback_state="STALE",
                now=stale_at,
            )
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=str(start["route_id"]),
                node_id=str(start["boundary_id"]),
                kind="ROUTE_STALE",
                start_state="STALE",
                evidence_job_id=str(start["evidence_job_id"]),
                admission_id=(
                    None
                    if start["admission_id"] is None
                    else str(start["admission_id"])
                ),
                attestation=None,
                problem=problem,
                now=stale_at,
            )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=start_request_id,
                    route_id=str(start["route_id"]),
                    node_id=str(start["boundary_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=str(start["evidence_job_id"]),
                    admission_id=(
                        None
                        if start["admission_id"] is None
                        else str(start["admission_id"])
                    ),
                    attestation=None,
                    problem=problem,
                    now=stale_at,
                    metadata={"failureCode": failure_code},
                )
        return TerminalRecordV2(
            entity_id=start_request_id,
            state="STALE",
            terminal=True,
            replayed=False,
        )

    def read_attempt_launch_identity(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
    ) -> AttemptLaunchIdentityV2:
        """Читает только связанную с владельцем идентичность запуска."""

        _require_identifier(attempt_id, "att2_")
        with self._immediate():
            self._verify_identity_and_controller()
            row = self._connection.execute(
                "select a.*,s.start_request_id,s.evidence_job_id "
                "from attempts a join node_launch_permits p "
                "on p.permit_id=a.launch_permit_id "
                "join start_requests s on s.admission_id=p.admission_id "
                "where a.attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                self._fail("ATTEMPT_NOT_FOUND", "attempt does not exist")
            self._start_owner_row_locked(str(row["start_request_id"]), request_context)
            required = (
                "admission_id",
                "snapshot_identity_fingerprint",
                "account_context_fingerprint",
                "process_start_marker",
                "codex_binary_sha256",
            )
            if any(row[name] is None for name in required):
                self._fail(
                    "ATTEMPT_IDENTITY_INCOMPLETE",
                    "attempt launch identity is incomplete",
                )
            return AttemptLaunchIdentityV2(
                attempt_id=str(row["attempt_id"]),
                route_id=str(row["route_id"]),
                node_id=str(row["node_id"]),
                start_request_id=str(row["start_request_id"]),
                evidence_job_id=str(row["evidence_job_id"]),
                admission_id=str(row["admission_id"]),
                model=str(row["model"]),
                reasoning_effort=str(row["reasoning_effort"]),
                permission_profile_id=str(row["permission_profile_id"]),
                argv_fingerprint=str(row["argv_fingerprint"]),
                snapshot_identity_fingerprint=str(row["snapshot_identity_fingerprint"]),
                compatibility_fingerprint=str(row["compatibility_fingerprint"]),
                account_context_fingerprint=str(row["account_context_fingerprint"]),
                pid=int(row["pid"]),
                process_start_marker=str(row["process_start_marker"]),
                codex_binary_sha256=str(row["codex_binary_sha256"]),
                state=str(row["state"]),
            )

    def record_attempt_started(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
        *,
        attestation: Mapping[str, Any],
        now: datetime,
    ) -> TerminalRecordV2:
        """Фиксирует доказанный ``execve`` до передачи задания ребёнку."""

        _require_identifier(attempt_id, "att2_")
        if type(attestation) is not dict:
            self._fail("ATTESTATION_INVALID", "attestation must be an exact object")
        attestation_json = canonical_json_v1(dict(attestation))
        started_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            attempt = self._connection.execute(
                "select a.*,p.state as permit_state,p.admission_id as permit_admission,"
                "s.start_request_id,s.evidence_job_id,s.state as start_state "
                "from attempts a join node_launch_permits p "
                "on p.permit_id=a.launch_permit_id "
                "join start_requests s on s.admission_id=p.admission_id "
                "where a.attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                self._fail("ATTEMPT_NOT_FOUND", "attempt does not exist")
            start = self._start_owner_row_locked(
                str(attempt["start_request_id"]), request_context
            )
            expected_binding = {
                "attemptId": str(attempt["attempt_id"]),
                "routeId": str(attempt["route_id"]),
                "nodeId": str(attempt["node_id"]),
                "startRequestId": str(attempt["start_request_id"]),
                "evidenceJobId": str(attempt["evidence_job_id"]),
                "admissionId": str(attempt["permit_admission"]),
            }
            if any(
                attestation.get(name) != value
                for name, value in expected_binding.items()
            ):
                self._fail(
                    "ATTESTATION_BINDING_MISMATCH",
                    "attestation belongs to another launch",
                )
            if attestation.get("disposition") != "MATCH":
                self._fail(
                    "ATTESTATION_NOT_MATCHING",
                    "child launch cannot start without a matching attestation",
                )
            if attempt["state"] == "RUNNING":
                if (
                    attempt["permit_state"] != "STARTED"
                    or attempt["attestation_json"] != attestation_json
                ):
                    self._fail(
                        "ATTEMPT_STARTED_REPLAY_CONFLICT",
                        "started attempt replay differs",
                    )
                return TerminalRecordV2(
                    entity_id=attempt_id,
                    state="RUNNING",
                    terminal=False,
                    replayed=True,
                )
            if (
                attempt["state"] != "STARTING"
                or attempt["permit_state"] != "COMMIT_AUTHORIZED"
                or attempt["start_state"] != "READY"
            ):
                self._fail("ATTEMPT_NOT_STARTABLE", "attempt cannot enter RUNNING")
            self._connection.execute(
                "update node_launch_permits set state='STARTED',resolved_at=?,"
                "failure_code=null where permit_id=? and state='COMMIT_AUTHORIZED'",
                (_iso(started_at), attempt["launch_permit_id"]),
            )
            self._connection.execute(
                "update attempts set state='RUNNING',attestation_json=? "
                "where attempt_id=? and state='STARTING'",
                (attestation_json, attempt_id),
            )
            self._connection.execute(
                "update nodes set admission_state='STARTED',state='RUNNING',updated_at=? "
                "where admission_id=? and admission_state='COMMIT_AUTHORIZED'",
                (_iso(started_at), attempt["permit_admission"]),
            )
            self._connection.execute(
                "update routes set state='RUNNING',updated_at=? where route_id=? "
                "and state in ('PLANNED','QUEUED','ATTESTING')",
                (_iso(started_at), attempt["route_id"]),
            )
            self._connection.execute(
                "update start_requests set state='STARTED',terminal_at=?,failure_code=null,"
                "updated_at=? where start_request_id=? and state='READY'",
                (
                    _iso(started_at),
                    _iso(started_at),
                    attempt["start_request_id"],
                ),
            )
            self._append_start_event_locked(
                start_request_id=str(attempt["start_request_id"]),
                route_id=str(start["route_id"]),
                node_id=str(attempt["node_id"]),
                kind="CHILD_ATTESTED",
                start_state="STARTED",
                evidence_job_id=str(attempt["evidence_job_id"]),
                admission_id=str(attempt["permit_admission"]),
                attestation=attestation,
                problem=None,
                now=started_at,
            )
        return TerminalRecordV2(
            entity_id=attempt_id,
            state="RUNNING",
            terminal=False,
            replayed=False,
        )

    def abort_launch_permit_before_commit(
        self,
        permit_id: str,
        request_context: RequestContextV2,
        *,
        failure_code: str,
        message: str,
        now: datetime,
    ) -> TerminalRecordV2:
        """Закрывает резерв или сторожа, если ``COMMIT`` ещё не разрешён."""

        _require_identifier(permit_id, "lp2_")
        _require_nonempty(failure_code, "failureCode")
        _require_nonempty(message, "message")
        failed_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            permit = self._connection.execute(
                "select p.*,s.start_request_id,s.state as start_state,s.evidence_job_id "
                "from node_launch_permits p join start_requests s "
                "on s.admission_id=p.admission_id where p.permit_id=?",
                (permit_id,),
            ).fetchone()
            if permit is None:
                self._fail("LAUNCH_PERMIT_NOT_FOUND", "launch permit does not exist")
            start = self._start_owner_row_locked(
                str(permit["start_request_id"]), request_context
            )
            if permit["state"] == "FAILED_BEFORE_START":
                if permit["failure_code"] != failure_code:
                    self._fail(
                        "LAUNCH_ABORT_REPLAY_CONFLICT",
                        "launch abort replay differs",
                    )
                return TerminalRecordV2(
                    entity_id=permit_id,
                    state="FAILED_BEFORE_START",
                    terminal=True,
                    replayed=True,
                )
            if permit["state"] not in {"RESERVED", "GUARDED"}:
                self._fail(
                    "LAUNCH_PERMIT_NOT_ABORTABLE",
                    "only an uncommitted permit can be failed before start",
                )
            self._connection.execute(
                "update node_launch_permits set state='FAILED_BEFORE_START',resolved_at=?,"
                "failure_code=? where permit_id=? and state in ('RESERVED','GUARDED')",
                (_iso(failed_at), failure_code, permit_id),
            )
            self._connection.execute(
                "update nodes set admission_state='ABORTED',state='FAILED',updated_at=? "
                "where admission_id=?",
                (_iso(failed_at), permit["admission_id"]),
            )
            self._terminalize_unstarted_descendants_locked(
                route_id=str(permit["route_id"]),
                failed_node_id=str(permit["node_id"]),
                now=failed_at,
            )
            route_completed, route_state = self._complete_route_if_terminal_locked(
                route_id=str(permit["route_id"]),
                fallback_state="FAILED",
                now=failed_at,
            )
            self._connection.execute(
                "update start_requests set state='FAILED',terminal_at=?,failure_code=?,"
                "updated_at=? where start_request_id=? and state='READY'",
                (
                    _iso(failed_at),
                    failure_code,
                    _iso(failed_at),
                    permit["start_request_id"],
                ),
            )
            problem = {
                "category": "INTERNAL",
                "code": "INTERNAL_ERROR",
                "message": message[:1024],
                "retryable": False,
            }
            self._append_start_event_locked(
                start_request_id=str(permit["start_request_id"]),
                route_id=str(start["route_id"]),
                node_id=str(permit["node_id"]),
                kind="CHILD_FAILED_BEFORE_START",
                start_state="FAILED",
                evidence_job_id=str(permit["evidence_job_id"]),
                admission_id=str(permit["admission_id"]),
                attestation=None,
                problem=problem,
                now=failed_at,
                metadata={"failureCode": failure_code},
            )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=str(permit["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(permit["node_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=str(permit["evidence_job_id"]),
                    admission_id=str(permit["admission_id"]),
                    attestation=None,
                    problem=_terminal_attempt_problem(route_state),
                    now=failed_at,
                    metadata={"failureCode": failure_code},
                )
        return TerminalRecordV2(
            entity_id=permit_id,
            state="FAILED_BEFORE_START",
            terminal=True,
            replayed=False,
        )

    def abort_admission_before_permit(
        self,
        *,
        admission_id: str,
        request_context: RequestContextV2,
        failure_code: str,
        message: str,
        now: datetime,
    ) -> TerminalRecordV2:
        """Атомарно закрывает допуск, пока для него ещё нет разрешения запуска."""

        _require_identifier(admission_id, "adm2_")
        _require_nonempty(failure_code, "failureCode")
        _require_nonempty(message, "message")
        failed_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            row = self._connection.execute(
                "select n.*,s.start_request_id,s.state as start_state,"
                "s.failure_code as start_failure_code,s.evidence_job_id "
                "from nodes n join start_requests s on s.admission_id=n.admission_id "
                "where n.admission_id=?",
                (admission_id,),
            ).fetchone()
            if row is None:
                self._fail("ADMISSION_NOT_FOUND", "admission does not exist")
            start = self._start_owner_row_locked(
                str(row["start_request_id"]),
                request_context,
            )
            permit = self._connection.execute(
                "select permit_id from node_launch_permits where admission_id=?",
                (admission_id,),
            ).fetchone()
            if permit is not None:
                self._fail(
                    "ADMISSION_ALREADY_RESERVED",
                    "coordinator owns an admission that already has a permit",
                )
            if row["start_state"] == "FAILED":
                if (
                    row["start_failure_code"] != failure_code
                    or row["state"] != "FAILED"
                    or row["admission_state"] != "ABORTED"
                ):
                    self._fail(
                        "ADMISSION_ABORT_REPLAY_CONFLICT",
                        "admission abort replay differs",
                    )
                return TerminalRecordV2(
                    entity_id=admission_id,
                    state="FAILED_BEFORE_START",
                    terminal=True,
                    replayed=True,
                )
            if row["start_state"] != "READY" or row["admission_state"] != "ADMITTED":
                self._fail(
                    "ADMISSION_NOT_ABORTABLE",
                    "only an admitted launch without a permit can be aborted",
                )
            self._connection.execute(
                "update nodes set admission_state='ABORTED',state='FAILED',updated_at=? "
                "where admission_id=? and admission_state='ADMITTED'",
                (_iso(failed_at), admission_id),
            )
            self._terminalize_unstarted_descendants_locked(
                route_id=str(row["route_id"]),
                failed_node_id=str(row["node_id"]),
                now=failed_at,
            )
            route_completed, route_state = self._complete_route_if_terminal_locked(
                route_id=str(row["route_id"]),
                fallback_state="FAILED",
                now=failed_at,
            )
            self._connection.execute(
                "update start_requests set state='FAILED',terminal_at=?,failure_code=?,"
                "updated_at=? where start_request_id=? and state='READY'",
                (
                    _iso(failed_at),
                    failure_code,
                    _iso(failed_at),
                    row["start_request_id"],
                ),
            )
            problem = {
                "category": "INTERNAL",
                "code": "INTERNAL_ERROR",
                "message": message[:1024],
                "retryable": False,
            }
            self._append_start_event_locked(
                start_request_id=str(row["start_request_id"]),
                route_id=str(start["route_id"]),
                node_id=str(row["node_id"]),
                kind="CHILD_FAILED_BEFORE_START",
                start_state="FAILED",
                evidence_job_id=str(row["evidence_job_id"]),
                admission_id=admission_id,
                attestation=None,
                problem=problem,
                now=failed_at,
                metadata={"failureCode": failure_code},
            )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=str(row["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(row["node_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=str(row["evidence_job_id"]),
                    admission_id=admission_id,
                    attestation=None,
                    problem=_terminal_attempt_problem(route_state),
                    now=failed_at,
                    metadata={"failureCode": failure_code},
                )
        return TerminalRecordV2(
            entity_id=admission_id,
            state="FAILED_BEFORE_START",
            terminal=True,
            replayed=False,
        )

    def record_attempt_terminal(
        self,
        attempt_id: str,
        request_context: RequestContextV2,
        *,
        state: str,
        result: Mapping[str, Any] | None,
        attestation: Mapping[str, Any] | None,
        error_code: str | None,
        error_message: str | None,
        now: datetime,
    ) -> TerminalRecordV2:
        _require_identifier(attempt_id, "att2_")
        if state not in {"SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED"}:
            self._fail(
                "INVALID_ATTEMPT_TERMINAL", "attempt terminal state is outside the set"
            )
        if state == "SUCCEEDED":
            if result is None or error_code is not None or error_message is not None:
                self._fail(
                    "INVALID_ATTEMPT_TERMINAL",
                    "successful attempt requires a result and cannot have an error",
                )
        else:
            _require_nonempty(error_code, "errorCode")
            _require_nonempty(error_message, "errorMessage")
        result_json = canonical_json_v1(dict(result)) if result is not None else None
        attestation_json = (
            canonical_json_v1(dict(attestation)) if attestation is not None else None
        )
        ended_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            attempt = self._connection.execute(
                "select a.*,p.state as permit_state,p.admission_id as permit_admission,"
                "s.start_request_id,s.state as start_state "
                "from attempts a join node_launch_permits p on p.permit_id=a.launch_permit_id "
                "join start_requests s on s.admission_id=p.admission_id "
                "where a.attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                self._fail("ATTEMPT_NOT_FOUND", "attempt does not exist")
            start = self._start_owner_row_locked(
                str(attempt["start_request_id"]), request_context
            )
            if attempt["state"] in _TERMINAL_ATTEMPT_STATES:
                if (
                    attempt["state"] != state
                    or attempt["result_json"] != result_json
                    or attempt["attestation_json"] != attestation_json
                    or attempt["error_code"] != error_code
                    or attempt["error_message"] != error_message
                ):
                    self._fail(
                        "ATTEMPT_TERMINAL_REPLAY_CONFLICT", "attempt replay differs"
                    )
                return TerminalRecordV2(
                    entity_id=attempt_id,
                    state=state,
                    terminal=True,
                    replayed=True,
                )
            if attempt["state"] not in {"STARTING", "RUNNING"}:
                self._fail("ATTEMPT_NOT_TERMINABLE", "attempt cannot become terminal")
            if attempt["permit_state"] not in {"COMMIT_AUTHORIZED", "STARTED"}:
                self._fail(
                    "LAUNCH_PERMIT_NOT_COMMITTED", "attempt permit is not committed"
                )
            was_running = attempt["state"] == "RUNNING"
            if was_running and attempt["attestation_json"] != attestation_json:
                self._fail(
                    "ATTEMPT_ATTESTATION_MISMATCH",
                    "terminal attestation differs from the launch attestation",
                )
            self._connection.execute(
                "update node_launch_permits set state='STARTED',resolved_at=?,failure_code=null "
                "where permit_id=? and state='COMMIT_AUTHORIZED'",
                (_iso(ended_at), attempt["launch_permit_id"]),
            )
            self._connection.execute(
                "update attempts set state=?,result_json=?,attestation_json=?,error_code=?,"
                "error_message=?,ended_at=? where attempt_id=? and state in ('STARTING','RUNNING')",
                (
                    state,
                    result_json,
                    attestation_json,
                    error_code,
                    error_message,
                    _iso(ended_at),
                    attempt_id,
                ),
            )
            self._connection.execute(
                "update nodes set state=?,result_json=?,updated_at=? "
                "where route_id=? and node_id=?",
                (
                    state,
                    result_json,
                    _iso(ended_at),
                    attempt["route_id"],
                    attempt["node_id"],
                ),
            )
            if state != "SUCCEEDED":
                descendant_state, descendant_error = {
                    "FAILED": ("FAILED", "DEPENDENCY_FAILED"),
                    "CANCELLED": ("CANCELLED", "DEPENDENCY_CANCELLED"),
                    "QUARANTINED": (
                        "QUARANTINED",
                        "DEPENDENCY_QUARANTINED",
                    ),
                }[state]
                self._terminalize_unstarted_descendants_locked(
                    route_id=str(attempt["route_id"]),
                    failed_node_id=str(attempt["node_id"]),
                    now=ended_at,
                    descendant_state=descendant_state,
                    error_code=descendant_error,
                )
            route_completed, route_state = self._complete_route_if_terminal_locked(
                route_id=str(attempt["route_id"]),
                fallback_state=state,
                now=ended_at,
            )
            if not was_running:
                self._connection.execute(
                    "update nodes set admission_state='STARTED',updated_at=? where admission_id=? "
                    "and admission_state='COMMIT_AUTHORIZED'",
                    (_iso(ended_at), attempt["permit_admission"]),
                )
                failed_before_start = state != "SUCCEEDED"
                start_state = (
                    "CANCELLED"
                    if state == "CANCELLED"
                    else "FAILED"
                    if failed_before_start
                    else "STARTED"
                )
                self._connection.execute(
                    "update start_requests set state=?,terminal_at=?,failure_code=?,"
                    "updated_at=? where start_request_id=? and state='READY'",
                    (
                        start_state,
                        _iso(ended_at),
                        error_code if failed_before_start else None,
                        _iso(ended_at),
                        attempt["start_request_id"],
                    ),
                )
                problem = None
                if error_code is not None:
                    problem = {
                        "category": "INTERNAL",
                        "code": "INTERNAL_ERROR",
                        "message": error_message,
                        "retryable": False,
                    }
                self._append_start_event_locked(
                    start_request_id=str(attempt["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(attempt["node_id"]),
                    kind=(
                        "CHILD_FAILED_BEFORE_START"
                        if failed_before_start
                        else "CHILD_ATTESTED"
                        if attestation is not None
                        else "CHILD_STARTED"
                    ),
                    start_state=start_state,
                    evidence_job_id=str(start["evidence_job_id"]),
                    admission_id=str(attempt["permit_admission"]),
                    attestation=attestation,
                    problem=problem,
                    now=ended_at,
                )
            else:
                self._append_start_event_locked(
                    start_request_id=str(attempt["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(attempt["node_id"]),
                    kind={
                        "SUCCEEDED": "CHILD_SUCCEEDED",
                        "FAILED": "CHILD_FAILED",
                        "CANCELLED": "CHILD_CANCELLED",
                        "QUARANTINED": "CHILD_QUARANTINED",
                    }[state],
                    start_state=state,
                    evidence_job_id=str(start["evidence_job_id"]),
                    admission_id=str(attempt["permit_admission"]),
                    attestation=None,
                    problem=_terminal_attempt_problem(state),
                    now=ended_at,
                )
            if route_completed:
                if route_state is None:
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "completed route has no terminal state",
                    )
                self._append_start_event_locked(
                    start_request_id=str(attempt["start_request_id"]),
                    route_id=str(start["route_id"]),
                    node_id=str(attempt["node_id"]),
                    kind="ROUTE_COMPLETED",
                    start_state=route_state,
                    evidence_job_id=str(start["evidence_job_id"]),
                    admission_id=str(attempt["permit_admission"]),
                    attestation=None,
                    problem=_terminal_attempt_problem(route_state),
                    now=ended_at,
                )
        return TerminalRecordV2(
            entity_id=attempt_id,
            state=state,
            terminal=True,
            replayed=False,
        )

    def issue_turn_binding(
        self,
        request_context: RequestContextV2,
        *,
        ttl_seconds: int,
        now: datetime,
        request_key: str | None = None,
    ) -> TurnBindingV2:
        if type(ttl_seconds) is not int or not 30 <= ttl_seconds <= 300:
            self._fail(
                "INVALID_TURN_BINDING_TTL", "ttlSeconds must be between 30 and 300"
            )
        context_value, context_json, context_hash = self._validated_context(
            request_context
        )
        if request_key is not None:
            _require_identifier(request_key, "idem2_")
        binding_id = (
            _new_id("tb2_")
            if request_key is None
            else "tb2_"
            + domain_fingerprint(
                "codex-smart/turn-binding-idempotency/v2",
                {
                    "contextHash": context_hash,
                    "requestKey": request_key,
                },
            )[:32]
        )
        issued_at = _aware_utc(now)
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        with self._immediate():
            self._require_accepting_controller(request_context.issued_control_epoch)
            replay = self._connection.execute(
                "select * from turn_bindings where token_hash=?",
                (_token_hash(binding_id),),
            ).fetchone()
            if replay is not None:
                replay_issued_at = _parse_iso(str(replay["created_at"]))
                replay_expires_at = _parse_iso(str(replay["expires_at"]))
                if (
                    request_key is None
                    or replay["context_hash"] != context_hash
                    or replay["context_json"] != context_json
                    or replay["activation_fingerprint"]
                    != request_context.activation_fingerprint
                    or replay["compatibility_fingerprint"]
                    != request_context.compatibility_fingerprint
                    or replay["issued_control_epoch"]
                    != request_context.issued_control_epoch
                    or replay_expires_at - replay_issued_at
                    != timedelta(seconds=ttl_seconds)
                ):
                    self._fail(
                        "TURN_BINDING_REPLAY_CONFLICT",
                        "turn binding key was replayed with another request",
                    )
                replay_state = (
                    "CONSUMED"
                    if replay["consumed_at"] is not None
                    else "EXPIRED"
                    if issued_at > replay_expires_at
                    else "ACTIVE"
                )
                return TurnBindingV2(
                    binding_id=binding_id,
                    context_fingerprint=context_hash,
                    issued_control_epoch=request_context.issued_control_epoch,
                    issued_at=replay_issued_at,
                    expires_at=replay_expires_at,
                    state=replay_state,
                    replayed=True,
                )
            self._connection.execute(
                "insert into turn_bindings "
                "(token_hash,context_hash,context_json,created_at,expires_at,consumed_at,"
                "request_key,request_hash,activation_fingerprint,compatibility_fingerprint,"
                "issued_control_epoch) values (?,?,?,?,?,null,null,null,?,?,?)",
                (
                    _token_hash(binding_id),
                    context_hash,
                    context_json,
                    _iso(issued_at),
                    _iso(expires_at),
                    request_context.activation_fingerprint,
                    request_context.compatibility_fingerprint,
                    request_context.issued_control_epoch,
                ),
            )
        return TurnBindingV2(
            binding_id=binding_id,
            context_fingerprint=context_hash,
            issued_control_epoch=request_context.issued_control_epoch,
            issued_at=issued_at,
            expires_at=expires_at,
            state="ACTIVE",
            replayed=False,
        )

    def consume_turn_binding(
        self,
        binding_id: str,
        request_context: RequestContextV2,
        *,
        request_key: str,
        request_hash: str,
        now: datetime,
    ) -> TurnBindingV2:
        _require_identifier(binding_id, "tb2_")
        _require_nonempty(request_key, "requestKey")
        _require_sha256(request_hash, "requestHash")
        _, context_json, context_hash = self._validated_context(request_context)
        with self._immediate():
            self._require_accepting_controller(request_context.issued_control_epoch)
            return self._consume_turn_binding_locked(
                binding_id=binding_id,
                request_context=request_context,
                context_json=context_json,
                context_hash=context_hash,
                request_key=request_key,
                request_hash=request_hash,
                now=_aware_utc(now),
            )

    def create_planned_route(
        self,
        *,
        binding_id: str,
        request_context: RequestContextV2,
        request_key: str,
        request_hash: str,
        catalog_generation: str,
        algorithm_version: str,
        disposition: str,
        expires_at: datetime,
        plan_output: Mapping[str, Any],
        nodes: Sequence[PlannedNodeV2],
        now: datetime,
    ) -> str:
        return self.create_planned_route_receipt(
            binding_id=binding_id,
            request_context=request_context,
            request_key=request_key,
            request_hash=request_hash,
            catalog_generation=catalog_generation,
            algorithm_version=algorithm_version,
            disposition=disposition,
            expires_at=expires_at,
            plan_output=plan_output,
            nodes=nodes,
            now=now,
        ).route_id

    def create_planned_route_receipt(
        self,
        *,
        binding_id: str,
        request_context: RequestContextV2,
        request_key: str,
        request_hash: str,
        catalog_generation: str,
        algorithm_version: str,
        disposition: str,
        expires_at: datetime,
        plan_output: Mapping[str, Any],
        nodes: Sequence[PlannedNodeV2],
        now: datetime,
    ) -> RoutePlanCommitV2:
        _require_identifier(binding_id, "tb2_")
        for name, value in (
            ("requestKey", request_key),
            ("catalogGeneration", catalog_generation),
            ("algorithmVersion", algorithm_version),
            ("disposition", disposition),
        ):
            _require_nonempty(value, name)
        _require_sha256(request_hash, "requestHash")
        if disposition == "DELEGATE":
            if not nodes:
                self._fail(
                    "INVALID_ROUTE_PLAN", "DELEGATE must contain at least one node"
                )
            route_state = "PLANNED"
            startable = 1
        elif disposition in {"DIRECT", "CLARIFY"}:
            if nodes:
                self._fail(
                    "INVALID_ROUTE_PLAN", f"{disposition} must not contain nodes"
                )
            route_state = disposition
            startable = 0
        else:
            self._fail(
                "INVALID_ROUTE_PLAN", "route disposition is outside the closed set"
            )
        node_ids = {item.node_id for item in nodes}
        ordinals = {item.ordinal for item in nodes}
        if len(node_ids) != len(nodes) or len(ordinals) != len(nodes):
            self._fail("INVALID_ROUTE_PLAN", "node ids and ordinals must be unique")
        for item in nodes:
            _require_identifier(item.node_id, "node2_")
            if type(item.ordinal) is not int or item.ordinal < 0:
                self._fail("INVALID_ROUTE_PLAN", "node ordinal must be non-negative")
            for name in (
                "role",
                "mission",
                "scope_id",
                "artifact_profile_id",
                "validation_profile_id",
                "selected_model",
                "reasoning_effort",
                "permission_profile_id",
                "disposition",
            ):
                _require_nonempty(getattr(item, name), name)
            if item.node_id in item.dependencies or not set(item.dependencies).issubset(
                node_ids
            ):
                self._fail(
                    "INVALID_ROUTE_PLAN",
                    "node dependencies must reference other plan nodes",
                )
        if nodes:
            try:
                validate_graph(
                    [
                        TaskNode(
                            node_id=item.node_id,
                            role=item.role,
                            dependencies=item.dependencies,
                        )
                        for item in nodes
                    ],
                    max_nodes=20,
                    max_edges=60,
                    max_depth=4,
                )
            except GraphError as exc:
                self._fail(exc.code, exc.message)
        _, context_json, context_hash = self._validated_context(request_context)
        created_at = _aware_utc(now)
        expiration = _aware_utc(expires_at)
        if expiration <= created_at:
            self._fail("INVALID_ROUTE_PLAN", "route expiry must be in the future")
        plan_json = canonical_json_v1(dict(plan_output))
        route_id = _new_id("route2_")
        with self._immediate():
            self._require_accepting_controller(request_context.issued_control_epoch)
            self._consume_turn_binding_locked(
                binding_id=binding_id,
                request_context=request_context,
                context_json=context_json,
                context_hash=context_hash,
                request_key=request_key,
                request_hash=request_hash,
                now=created_at,
            )
            replay = self._connection.execute(
                "select route_id,request_hash,plan_output_json,disposition,state,startable "
                ",catalog_generation,algorithm_version,activation_fingerprint,"
                "compatibility_fingerprint from routes "
                "where context_hash=? and request_key=?",
                (context_hash, request_key),
            ).fetchone()
            if replay is not None:
                if (
                    replay["request_hash"] != request_hash
                    or replay["plan_output_json"] != plan_json
                    or replay["disposition"] != disposition
                    or replay["startable"] != startable
                    or replay["catalog_generation"] != catalog_generation
                    or replay["algorithm_version"] != algorithm_version
                    or replay["activation_fingerprint"]
                    != request_context.activation_fingerprint
                    or replay["compatibility_fingerprint"]
                    != request_context.compatibility_fingerprint
                ):
                    self._fail(
                        "ROUTE_REPLAY_CONFLICT",
                        "route request was replayed with other data",
                    )
                actual_nodes = [
                    dict(row)
                    for row in self._connection.execute(
                        "select node_id,ordinal,role,mission,dependencies_json,context_refs_json,"
                        "scope_id,artifact_profile_id,validation_profile_id,assessment_json,"
                        "risk_flags_json,selected_model,reasoning_effort,permission_profile_id,"
                        "disposition,activation_fingerprint from nodes where route_id=? "
                        "order by ordinal",
                        (replay["route_id"],),
                    )
                ]
                expected_nodes = [
                    _node_plan_projection(item, request_context.activation_fingerprint)
                    for item in sorted(nodes, key=lambda candidate: candidate.ordinal)
                ]
                if actual_nodes != expected_nodes:
                    self._fail("ROUTE_REPLAY_CONFLICT", "route node projection differs")
                return RoutePlanCommitV2(
                    route_id=str(replay["route_id"]),
                    state=str(replay["state"]),
                    replayed=True,
                )
            self._connection.execute(
                "insert into routes "
                "(route_id,request_key,request_hash,context_hash,context_json,"
                "shell_session_id,session_id,turn_id,codex_home_hash,repo_root_hash,"
                "base_sha,worktree_fingerprint,catalog_generation,algorithm_version,"
                "disposition,startable,state,expires_at,run_id,cancel_reason,"
                "plan_output_json,terminal_result_json,created_at,updated_at,"
                "activation_fingerprint,compatibility_fingerprint) "
                "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    route_id,
                    request_key,
                    request_hash,
                    context_hash,
                    context_json,
                    request_context.shell_session_id,
                    request_context.session_id,
                    request_context.turn_id,
                    _text_sha256(request_context.codex_home),
                    _text_sha256(request_context.repo_root),
                    request_context.base_sha,
                    request_context.worktree_fingerprint,
                    catalog_generation,
                    algorithm_version,
                    disposition,
                    startable,
                    route_state,
                    _iso(expiration),
                    None,
                    None,
                    plan_json,
                    None,
                    _iso(created_at),
                    _iso(created_at),
                    request_context.activation_fingerprint,
                    request_context.compatibility_fingerprint,
                ),
            )
            for item in sorted(nodes, key=lambda candidate: candidate.ordinal):
                self._connection.execute(
                    "insert into nodes "
                    "(route_id,node_id,ordinal,role,mission,dependencies_json,context_refs_json,"
                    "scope_id,artifact_profile_id,validation_profile_id,assessment_json,"
                    "risk_flags_json,selected_model,reasoning_effort,permission_profile_id,"
                    "disposition,state,attempt_count,result_json,updated_at,activation_fingerprint,"
                    "account_context_fingerprint,account_catalog_fingerprint,evidence_job_id,"
                    "admission_id,admission_state,admission_manifest_semantic_fingerprint,"
                    "admission_activation_receipt_fingerprint,admission_journal_absence_proof_json,"
                    "admission_gate_fingerprint) "
                    "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PLANNED',0,null,?,?,?,?,"
                    "null,null,null,null,null,null,null)",
                    (
                        route_id,
                        item.node_id,
                        item.ordinal,
                        item.role,
                        item.mission,
                        canonical_json_v1(list(item.dependencies)),
                        canonical_json_v1(list(item.context_refs)),
                        item.scope_id,
                        item.artifact_profile_id,
                        item.validation_profile_id,
                        canonical_json_v1(item.assessment),
                        canonical_json_v1(list(item.risk_flags)),
                        item.selected_model,
                        item.reasoning_effort,
                        item.permission_profile_id,
                        item.disposition,
                        _iso(created_at),
                        request_context.activation_fingerprint,
                        None,
                        None,
                    ),
                )
        return RoutePlanCommitV2(
            route_id=route_id,
            state=route_state,
            replayed=False,
        )

    def create_start_request(
        self,
        *,
        route_id: str,
        node_id: str,
        request_context: RequestContextV2,
        idempotency_key: str | None = None,
        activation_gate_fingerprint: str | None = None,
        deadline_at: datetime,
        now: datetime,
    ) -> StartRequestV2:
        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        if idempotency_key is not None:
            _require_identifier(idempotency_key, "idem2_")
            if activation_gate_fingerprint is None:
                self._fail(
                    "INVALID_START_REQUEST_IDEMPOTENCY",
                    "idempotent start requires an activation gate fingerprint",
                )
            _require_sha256(
                activation_gate_fingerprint,
                "activationGateFingerprint",
            )
        self._validated_context(request_context)
        created_at = _aware_utc(now)
        deadline = _aware_utc(deadline_at)
        if deadline <= created_at or deadline > created_at + timedelta(seconds=180):
            self._fail(
                "INVALID_EVIDENCE_DEADLINE",
                "evidence deadline must be within 180 seconds",
            )
        start_request_id = _new_id("sr2_")
        evidence_job_id = _new_id("aej2_")
        attempt_id = attempt_id_for_evidence_job(evidence_job_id)
        with self._immediate():
            self._require_accepting_controller(self._expected_controller.control_epoch)
            route = self._connection.execute(
                "select * from routes where route_id=?", (route_id,)
            ).fetchone()
            target = self._connection.execute(
                "select * from nodes where route_id=? and node_id=?",
                (route_id, node_id),
            ).fetchone()
            if route is None or target is None:
                self._fail("ROUTE_NODE_NOT_FOUND", "route or node does not exist")
            self._require_owner_values(
                request_context,
                context_hash=str(route["context_hash"]),
                context_json=str(route["context_json"]),
                error_code="ROUTE_OWNER_MISMATCH",
            )
            if (
                route["shell_session_id"] != request_context.shell_session_id
                or route["session_id"] != request_context.session_id
                or route["turn_id"] != request_context.turn_id
            ):
                self._fail("ROUTE_OWNER_MISMATCH", "route belongs to another turn")
            intent_id = (
                None
                if idempotency_key is None
                else "sri2_"
                + domain_fingerprint(
                    "codex-smart/start-request-idempotency/v2",
                    {
                        "contextHash": str(route["context_hash"]),
                        "idempotencyKey": idempotency_key,
                    },
                )[:32]
            )
            if intent_id is not None:
                replay = self._connection.execute(
                    "select * from intents where intent_id=?",
                    (intent_id,),
                ).fetchone()
                if replay is not None:
                    replay_payload = _stored_json_object(
                        replay["payload_json"],
                        "intents.payload_json",
                    )
                    if (
                        str(replay["kind"]) != "START_REQUEST_IDEMPOTENCY_V2"
                        or str(replay["state"]) != "COMPLETED"
                        or str(replay["route_id"]) != route_id
                        or str(replay["node_id"]) != node_id
                        or set(replay_payload)
                        != {
                            "evidenceJobId",
                            "activationGateFingerprint",
                            "idempotencyKey",
                            "nodeId",
                            "routeId",
                            "startRequestId",
                        }
                        or replay_payload.get("idempotencyKey") != idempotency_key
                        or replay_payload.get("activationGateFingerprint")
                        != activation_gate_fingerprint
                        or replay_payload.get("routeId") != route_id
                        or replay_payload.get("nodeId") != node_id
                        or str(replay["payload_hash"])
                        != domain_fingerprint(
                            "codex-smart/start-request-receipt/v2",
                            replay_payload,
                        )
                    ):
                        self._fail(
                            "START_REQUEST_REPLAY_CONFLICT",
                            "start request key was replayed with another target",
                        )
                    replay_start = self._connection.execute(
                        "select s.start_request_id,s.evidence_job_id,j.queue_position,"
                        "j.deadline_at,j.boundary_id from start_requests s "
                        "join account_evidence_jobs j "
                        "on j.evidence_job_id=s.evidence_job_id "
                        "where s.start_request_id=? and s.route_id=?",
                        (replay_payload.get("startRequestId"), route_id),
                    ).fetchone()
                    if (
                        replay_start is None
                        or str(replay_start["boundary_id"]) != node_id
                        or str(replay_start["evidence_job_id"])
                        != replay_payload.get("evidenceJobId")
                    ):
                        self._fail(
                            "DATABASE_VALUE_INVALID",
                            "start request replay receipt has no durable target",
                        )
                    replay_evidence_job_id = str(replay_start["evidence_job_id"])
                    return StartRequestV2(
                        start_request_id=str(replay_start["start_request_id"]),
                        evidence_job_id=replay_evidence_job_id,
                        attempt_id=attempt_id_for_evidence_job(
                            replay_evidence_job_id
                        ),
                        route_id=route_id,
                        node_id=node_id,
                        queue_position=int(replay_start["queue_position"]),
                        deadline_at=_parse_iso(str(replay_start["deadline_at"])),
                        state="ATTESTING",
                        replayed=True,
                    )
            prior_start_count = int(
                self._connection.execute(
                    "select count(*) from start_requests where route_id=?",
                    (route_id,),
                ).fetchone()[0]
            )
            if (
                prior_start_count == 0
                and str(route["state"]) == "PLANNED"
                and _parse_iso(str(route["expires_at"])) < created_at
            ):
                self._terminalize_all_unstarted_nodes_locked(
                    route_id=route_id,
                    now=created_at,
                    error_code="ROUTE_EXPIRED",
                )
                completed, route_state = self._complete_route_if_terminal_locked(
                    route_id=route_id,
                    fallback_state="STALE",
                    now=created_at,
                )
                if not completed or route_state != "STALE":
                    self._fail(
                        "DATABASE_VALUE_INVALID",
                        "expired unstarted route did not become STALE",
                    )
                raise _CommitThenFail(
                    "ROUTE_EXPIRED",
                    "route expired before its first start request",
                    transitions=(
                        {
                            "table": "routes",
                            "entityId": route_id,
                            "beforeState": "PLANNED",
                            "afterState": "STALE",
                        },
                    ),
                )
            if route["state"] not in {"PLANNED", "RUNNING"} or route["startable"] != 1:
                self._fail(
                    "ROUTE_NOT_STARTABLE",
                    "route is not startable from its current state",
                )
            if target["state"] != "PLANNED" or target["admission_id"] is not None:
                self._fail("NODE_NOT_STARTABLE", "node is not startable from PLANNED")
            dependencies = tuple(
                _stored_json_list(target["dependencies_json"], "dependencies_json")
            )
            if dependencies:
                placeholders = ",".join("?" for _ in dependencies)
                dependency_rows = self._connection.execute(
                    "select node_id,state,result_json from nodes "
                    "where route_id=? and node_id in ("
                    + placeholders
                    + ")",
                    (route_id, *dependencies),
                ).fetchall()
                dependency_states = {
                    str(row["node_id"]): str(row["state"])
                    for row in dependency_rows
                }
                if len(dependency_states) != len(dependencies) or any(
                    dependency_states.get(str(dependency_node_id)) != "SUCCEEDED"
                    for dependency_node_id in dependencies
                ) or any(row["result_json"] is None for row in dependency_rows):
                    self._fail(
                        "NODE_DEPENDENCIES_INCOMPLETE",
                        "all node dependencies must be SUCCEEDED",
                    )
            unfinished = int(
                self._connection.execute(
                    "select count(*) from start_requests "
                    "where route_id=? and state in ('ATTESTING','READY')",
                    (route_id,),
                ).fetchone()[0]
            )
            if unfinished:
                self._fail(
                    "START_REQUEST_INFLIGHT", "route already has an unfinished start"
                )
            queued = int(
                self._connection.execute(
                    "select count(*) from account_evidence_jobs "
                    "where state in ('QUEUED','RUNNING','CANCEL_REQUESTED')"
                ).fetchone()[0]
            )
            if queued >= 32:
                self._fail("ACCOUNT_EVIDENCE_QUEUE_FULL", "evidence queue is full")
            active_positions = {
                int(row["queue_position"])
                for row in self._connection.execute(
                    "select queue_position from account_evidence_jobs "
                    "where state in ('QUEUED','RUNNING','CANCEL_REQUESTED')"
                ).fetchall()
            }
            queue_position = next(
                (
                    candidate
                    for candidate in range(1, 33)
                    if candidate not in active_positions
                ),
                0,
            )
            if queue_position == 0:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "active evidence queue has no free bounded position",
                )
            self._connection.execute(
                "insert into start_requests "
                "(start_request_id,route_id,shell_session_id,session_id,turn_id,state,"
                "evidence_job_id,admission_id,created_at,updated_at,terminal_at,failure_code) "
                "values (?,?,?,?,?,'ATTESTING',null,null,?,?,null,null)",
                (
                    start_request_id,
                    route_id,
                    request_context.shell_session_id,
                    request_context.session_id,
                    request_context.turn_id,
                    _iso(created_at),
                    _iso(created_at),
                ),
            )
            self._connection.execute(
                "insert into account_evidence_jobs "
                "(evidence_job_id,start_request_id,route_id,boundary_id,state,queue_position,"
                "owner_id,deadline_at,pid,process_start_marker,current_stage,"
                "account_catalog_fingerprint,account_context_fingerprint,record_fingerprint,"
                "failure_code,queued_at,started_at,progress_at,cancel_requested_at,completed_at) "
                "values (?,?,?,?,'QUEUED',?,null,?,null,null,null,null,null,null,null,?,null,null,null,null)",
                (
                    evidence_job_id,
                    start_request_id,
                    route_id,
                    node_id,
                    queue_position,
                    _iso(deadline),
                    _iso(created_at),
                ),
            )
            self._connection.execute(
                "update start_requests set evidence_job_id=? where start_request_id=?",
                (evidence_job_id, start_request_id),
            )
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=route_id,
                node_id=node_id,
                kind="EVIDENCE_QUEUED",
                start_state="ATTESTING",
                evidence_job_id=evidence_job_id,
                admission_id=None,
                attestation=None,
                problem=None,
                now=created_at,
            )
            if intent_id is not None:
                intent_payload = {
                    "activationGateFingerprint": activation_gate_fingerprint,
                    "evidenceJobId": evidence_job_id,
                    "idempotencyKey": idempotency_key,
                    "nodeId": node_id,
                    "routeId": route_id,
                    "startRequestId": start_request_id,
                }
                intent_json = canonical_json_v1(intent_payload)
                self._connection.execute(
                    "insert into intents "
                    "(intent_id,route_id,node_id,kind,payload_hash,payload_json,state,"
                    "created_at,completed_at) values (?,?,?,?,?,?,'COMPLETED',?,?)",
                    (
                        intent_id,
                        route_id,
                        node_id,
                        "START_REQUEST_IDEMPOTENCY_V2",
                        domain_fingerprint(
                            "codex-smart/start-request-receipt/v2",
                            intent_payload,
                        ),
                        intent_json,
                        _iso(created_at),
                        _iso(created_at),
                    ),
                )
        return StartRequestV2(
            start_request_id=start_request_id,
            evidence_job_id=evidence_job_id,
            attempt_id=attempt_id,
            route_id=route_id,
            node_id=node_id,
            queue_position=queue_position,
            deadline_at=deadline,
            state="ATTESTING",
            replayed=False,
        )

    def claim_account_evidence_job(
        self,
        evidence_job_id: str,
        *,
        owner_id: str,
        pid: int,
        process_start_marker: str,
        current_stage: str,
        now: datetime,
    ) -> None:
        _require_identifier(evidence_job_id, "aej2_")
        _require_nonempty(owner_id, "ownerId")
        _require_nonempty(process_start_marker, "processStartMarker")
        if type(pid) is not int or pid <= 0:
            self._fail("INVALID_PROCESS", "evidence process pid must be positive")
        if current_stage not in {
            "requirements-a",
            "catalog-a",
            "requirements-b",
            "catalog-b",
            "requirements-c",
        }:
            self._fail(
                "INVALID_EVIDENCE_STAGE", "evidence stage is outside the closed set"
            )
        started_at = _aware_utc(now)
        with self._immediate():
            self._require_accepting_controller(self._expected_controller.control_epoch)
            active = int(
                self._connection.execute(
                    "select count(*) from account_evidence_jobs "
                    "where state in ('RUNNING','CANCEL_REQUESTED')"
                ).fetchone()[0]
            )
            if active >= 2:
                self._fail(
                    "ACCOUNT_EVIDENCE_CAPACITY", "two evidence jobs are already running"
                )
            job = self._connection.execute(
                "select * from account_evidence_jobs where evidence_job_id=?",
                (evidence_job_id,),
            ).fetchone()
            if job is None or job["state"] != "QUEUED":
                self._fail("EVIDENCE_JOB_NOT_QUEUED", "evidence job is not queued")
            if started_at > _parse_iso(str(job["deadline_at"])):
                self._fail("ACCOUNT_EVIDENCE_DEADLINE", "evidence deadline elapsed")
            self._connection.execute(
                "update account_evidence_jobs set state='RUNNING',owner_id=?,pid=?,"
                "process_start_marker=?,current_stage=?,started_at=?,progress_at=? "
                "where evidence_job_id=? and state='QUEUED'",
                (
                    owner_id,
                    pid,
                    process_start_marker,
                    current_stage,
                    _iso(started_at),
                    _iso(started_at),
                    evidence_job_id,
                ),
            )
            self._append_start_event_locked(
                start_request_id=str(job["start_request_id"]),
                route_id=str(job["route_id"]),
                node_id=str(job["boundary_id"]),
                kind="EVIDENCE_RUNNING",
                start_state="ATTESTING",
                evidence_job_id=evidence_job_id,
                admission_id=None,
                attestation=None,
                problem=None,
                now=started_at,
            )

    def update_account_evidence_stage(
        self,
        evidence_job_id: str,
        *,
        owner_id: str,
        current_stage: str,
        now: datetime,
    ) -> None:
        """Фиксирует строго последовательный прогресс пятистадийного сбора."""

        _require_identifier(evidence_job_id, "aej2_")
        _require_nonempty(owner_id, "ownerId")
        stages = (
            "requirements-a",
            "catalog-a",
            "requirements-b",
            "catalog-b",
            "requirements-c",
        )
        if current_stage not in stages:
            self._fail(
                "INVALID_EVIDENCE_STAGE", "evidence stage is outside the closed set"
            )
        progressed_at = _aware_utc(now)
        with self._immediate():
            self._verify_identity_and_controller()
            job = self._connection.execute(
                "select * from account_evidence_jobs where evidence_job_id=?",
                (evidence_job_id,),
            ).fetchone()
            if job is None or job["state"] != "RUNNING":
                self._fail("EVIDENCE_JOB_NOT_RUNNING", "evidence job is not running")
            if job["owner_id"] != owner_id:
                self._fail("EVIDENCE_JOB_OWNER_MISMATCH", "evidence worker changed")
            if progressed_at > _parse_iso(str(job["deadline_at"])):
                self._fail("ACCOUNT_EVIDENCE_DEADLINE", "evidence deadline elapsed")
            previous = str(job["current_stage"])
            previous_index = stages.index(previous)
            next_index = stages.index(current_stage)
            if next_index == previous_index:
                self._connection.execute(
                    "update account_evidence_jobs set progress_at=? where evidence_job_id=?",
                    (_iso(progressed_at), evidence_job_id),
                )
                return
            if next_index != previous_index + 1:
                self._fail(
                    "INVALID_EVIDENCE_STAGE", "evidence stages are not sequential"
                )
            self._connection.execute(
                "update account_evidence_jobs set current_stage=?,progress_at=? "
                "where evidence_job_id=? and state='RUNNING' and owner_id=?",
                (current_stage, _iso(progressed_at), evidence_job_id, owner_id),
            )
            self._append_start_event_locked(
                start_request_id=str(job["start_request_id"]),
                route_id=str(job["route_id"]),
                node_id=str(job["boundary_id"]),
                kind="EVIDENCE_PROGRESS",
                start_state="ATTESTING",
                evidence_job_id=evidence_job_id,
                admission_id=None,
                attestation=None,
                problem=None,
                now=progressed_at,
                metadata={"stage": current_stage},
            )

    def account_evidence_cancel_requested(
        self,
        evidence_job_id: str,
        *,
        owner_id: str,
    ) -> bool:
        """Без побочного эффекта сообщает рабочему процессу о долговечной отмене."""

        _require_identifier(evidence_job_id, "aej2_")
        _require_nonempty(owner_id, "ownerId")
        with self._lock:
            self._verify_identity_and_controller()
            job = self._connection.execute(
                "select state,owner_id from account_evidence_jobs where evidence_job_id=?",
                (evidence_job_id,),
            ).fetchone()
            if job is None:
                self._fail("EVIDENCE_JOB_NOT_FOUND", "evidence job does not exist")
            if job["owner_id"] != owner_id:
                self._fail("EVIDENCE_JOB_OWNER_MISMATCH", "evidence worker changed")
            if job["state"] not in {"RUNNING", "CANCEL_REQUESTED", "CANCELLED"}:
                self._fail(
                    "EVIDENCE_JOB_NOT_RUNNING",
                    "evidence job cannot be checked for cancellation",
                )
            return str(job["state"]) in {"CANCEL_REQUESTED", "CANCELLED"}

    def complete_account_evidence_job(
        self,
        evidence_job_id: str,
        *,
        account_catalog_fingerprint: str,
        account_context_fingerprint: str,
        record_fingerprint: str,
        now: datetime,
    ) -> None:
        _require_identifier(evidence_job_id, "aej2_")
        _require_sha256(account_catalog_fingerprint, "accountCatalogFingerprint")
        _require_sha256(account_context_fingerprint, "accountContextFingerprint")
        _require_sha256(record_fingerprint, "recordFingerprint")
        completed_at = _aware_utc(now)
        with self._immediate():
            self._require_accepting_controller(self._expected_controller.control_epoch)
            job = self._connection.execute(
                "select * from account_evidence_jobs where evidence_job_id=?",
                (evidence_job_id,),
            ).fetchone()
            if job is None or job["state"] != "RUNNING":
                self._fail("EVIDENCE_JOB_NOT_RUNNING", "evidence job is not running")
            self._connection.execute(
                "update account_evidence_jobs set state='SUCCEEDED',"
                "account_catalog_fingerprint=?,account_context_fingerprint=?,"
                "record_fingerprint=?,failure_code=null,progress_at=?,completed_at=? "
                "where evidence_job_id=? and state='RUNNING'",
                (
                    account_catalog_fingerprint,
                    account_context_fingerprint,
                    record_fingerprint,
                    _iso(completed_at),
                    _iso(completed_at),
                    evidence_job_id,
                ),
            )
            self._append_start_event_locked(
                start_request_id=str(job["start_request_id"]),
                route_id=str(job["route_id"]),
                node_id=str(job["boundary_id"]),
                kind="EVIDENCE_SUCCEEDED",
                start_state="ATTESTING",
                evidence_job_id=evidence_job_id,
                admission_id=None,
                attestation=None,
                problem=None,
                now=completed_at,
            )

    def complete_account_evidence_and_admit(
        self,
        *,
        start_request_id: str,
        evidence_job_id: str,
        route_id: str,
        node_id: str,
        account_catalog_fingerprint: str,
        account_context_fingerprint: str,
        record_fingerprint: str,
        activation_gate: Mapping[str, Any],
        expected_control_epoch: int,
        now: datetime,
    ) -> AdmissionV2:
        """Одной транзакцией завершает доказательство и создаёт допуск."""

        _require_identifier(start_request_id, "sr2_")
        _require_identifier(evidence_job_id, "aej2_")
        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        _require_sha256(account_catalog_fingerprint, "accountCatalogFingerprint")
        _require_sha256(account_context_fingerprint, "accountContextFingerprint")
        _require_sha256(record_fingerprint, "recordFingerprint")
        gate, journal_json = _canonical_activation_gate(activation_gate)
        completed_at = _aware_utc(now)
        with self._immediate():
            self._require_accepting_controller(expected_control_epoch)
            row = self._connection.execute(
                "select s.state as start_state,s.evidence_job_id as start_evidence,"
                "s.admission_id as start_admission,j.state as job_state,"
                "j.start_request_id as job_start,j.route_id as job_route,j.boundary_id,"
                "j.deadline_at,n.account_catalog_fingerprint as node_catalog,"
                "n.account_context_fingerprint as node_context,n.admission_id as node_admission "
                "from start_requests s "
                "join account_evidence_jobs j on j.evidence_job_id=? "
                "join nodes n on n.route_id=? and n.node_id=? "
                "where s.start_request_id=? and s.route_id=?",
                (evidence_job_id, route_id, node_id, start_request_id, route_id),
            ).fetchone()
            if row is None:
                self._fail(
                    "ADMISSION_INPUT_MISMATCH", "start, evidence, route or node differs"
                )
            if completed_at > _parse_iso(str(row["deadline_at"])):
                self._fail("ACCOUNT_EVIDENCE_DEADLINE", "evidence deadline elapsed")
            if (
                row["start_state"] != "ATTESTING"
                or row["start_evidence"] != evidence_job_id
                or row["start_admission"] is not None
                or row["job_state"] != "RUNNING"
                or row["job_start"] != start_request_id
                or row["job_route"] != route_id
                or row["boundary_id"] != node_id
                or row["node_catalog"] is not None
                or row["node_context"] is not None
                or row["node_admission"] is not None
            ):
                self._fail(
                    "ADMISSION_INPUT_MISMATCH", "admission prerequisites do not match"
                )

            self._connection.execute(
                "update account_evidence_jobs set state='SUCCEEDED',"
                "account_catalog_fingerprint=?,account_context_fingerprint=?,"
                "record_fingerprint=?,failure_code=null,progress_at=?,completed_at=? "
                "where evidence_job_id=? and state='RUNNING'",
                (
                    account_catalog_fingerprint,
                    account_context_fingerprint,
                    record_fingerprint,
                    _iso(completed_at),
                    _iso(completed_at),
                    evidence_job_id,
                ),
            )
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=route_id,
                node_id=node_id,
                kind="EVIDENCE_SUCCEEDED",
                start_state="ATTESTING",
                evidence_job_id=evidence_job_id,
                admission_id=None,
                attestation=None,
                problem=None,
                now=completed_at,
            )

            admission_id = _new_id("adm2_")
            self._connection.execute(
                "update nodes set account_catalog_fingerprint=?,account_context_fingerprint=?,"
                "evidence_job_id=?,admission_id=?,admission_state='ADMITTED',"
                "admission_manifest_semantic_fingerprint=?,"
                "admission_activation_receipt_fingerprint=?,"
                "admission_journal_absence_proof_json=?,admission_gate_fingerprint=?,updated_at=? "
                "where route_id=? and node_id=? and admission_id is null",
                (
                    account_catalog_fingerprint,
                    account_context_fingerprint,
                    evidence_job_id,
                    admission_id,
                    gate["manifestSemanticFingerprint"],
                    gate["activationReceiptFingerprint"],
                    journal_json,
                    gate["gateFingerprint"],
                    _iso(completed_at),
                    route_id,
                    node_id,
                ),
            )
            self._connection.execute(
                "update start_requests set state='READY',admission_id=?,updated_at=? "
                "where start_request_id=? and state='ATTESTING'",
                (admission_id, _iso(completed_at), start_request_id),
            )
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=route_id,
                node_id=node_id,
                kind="ADMITTED",
                start_state="READY",
                evidence_job_id=evidence_job_id,
                admission_id=admission_id,
                attestation=None,
                problem=None,
                now=completed_at,
            )
        return AdmissionV2(
            admission_id=admission_id,
            start_request_id=start_request_id,
            evidence_job_id=evidence_job_id,
            route_id=route_id,
            node_id=node_id,
            activation_gate_fingerprint=str(gate["gateFingerprint"]),
            state="ADMITTED",
        )

    def admit_node(
        self,
        *,
        start_request_id: str,
        evidence_job_id: str,
        route_id: str,
        node_id: str,
        activation_gate: Mapping[str, Any],
        expected_control_epoch: int,
        now: datetime,
    ) -> AdmissionV2:
        _require_identifier(start_request_id, "sr2_")
        _require_identifier(evidence_job_id, "aej2_")
        _require_identifier(route_id, "route2_")
        _require_identifier(node_id, "node2_")
        gate, journal_json = _canonical_activation_gate(activation_gate)
        admitted_at = _aware_utc(now)
        with self._immediate():
            self._require_accepting_controller(expected_control_epoch)
            row = self._connection.execute(
                "select s.state as start_state,s.evidence_job_id as start_evidence,"
                "s.admission_id as start_admission,j.state as job_state,"
                "j.start_request_id as job_start,j.route_id as job_route,j.boundary_id,"
                "j.account_catalog_fingerprint as job_catalog,"
                "j.account_context_fingerprint as job_context,n.* "
                "from start_requests s "
                "join account_evidence_jobs j on j.evidence_job_id=? "
                "join nodes n on n.route_id=? and n.node_id=? "
                "where s.start_request_id=? and s.route_id=?",
                (evidence_job_id, route_id, node_id, start_request_id, route_id),
            ).fetchone()
            if row is None:
                self._fail(
                    "ADMISSION_INPUT_MISMATCH", "start, evidence, route or node differs"
                )
            if row["start_admission"] is not None:
                return self._replayed_admission(row, gate)
            if (
                row["start_state"] != "ATTESTING"
                or row["start_evidence"] != evidence_job_id
                or row["job_state"] != "SUCCEEDED"
                or row["job_start"] != start_request_id
                or row["job_route"] != route_id
                or row["boundary_id"] != node_id
                or row["job_catalog"] is None
                or row["job_context"] is None
                or row["account_catalog_fingerprint"] is not None
                or row["account_context_fingerprint"] is not None
                or row["admission_id"] is not None
            ):
                self._fail(
                    "ADMISSION_INPUT_MISMATCH", "admission prerequisites do not match"
                )
            admission_id = _new_id("adm2_")
            self._connection.execute(
                "update nodes set account_catalog_fingerprint=?,account_context_fingerprint=?,"
                "evidence_job_id=?,admission_id=?,admission_state='ADMITTED',"
                "admission_manifest_semantic_fingerprint=?,"
                "admission_activation_receipt_fingerprint=?,"
                "admission_journal_absence_proof_json=?,admission_gate_fingerprint=?,updated_at=? "
                "where route_id=? and node_id=? and admission_id is null",
                (
                    row["job_catalog"],
                    row["job_context"],
                    evidence_job_id,
                    admission_id,
                    gate["manifestSemanticFingerprint"],
                    gate["activationReceiptFingerprint"],
                    journal_json,
                    gate["gateFingerprint"],
                    _iso(admitted_at),
                    route_id,
                    node_id,
                ),
            )
            self._connection.execute(
                "update start_requests set state='READY',admission_id=?,updated_at=? "
                "where start_request_id=? and state='ATTESTING'",
                (admission_id, _iso(admitted_at), start_request_id),
            )
            self._append_start_event_locked(
                start_request_id=start_request_id,
                route_id=route_id,
                node_id=node_id,
                kind="ADMITTED",
                start_state="READY",
                evidence_job_id=evidence_job_id,
                admission_id=admission_id,
                attestation=None,
                problem=None,
                now=admitted_at,
            )
        return AdmissionV2(
            admission_id=admission_id,
            start_request_id=start_request_id,
            evidence_job_id=evidence_job_id,
            route_id=route_id,
            node_id=node_id,
            activation_gate_fingerprint=str(gate["gateFingerprint"]),
            state="ADMITTED",
        )

    def reserve_launch_permit(
        self,
        *,
        admission_id: str,
        activation_gate: Mapping[str, Any],
        expected_control_epoch: int,
        argv_fingerprint: str,
        codex_snapshot_sha256: str,
        snapshot_identity_fingerprint: str,
        now: datetime,
    ) -> LaunchPermitV2:
        _require_identifier(admission_id, "adm2_")
        _require_sha256(argv_fingerprint, "argvFingerprint")
        _require_sha256(codex_snapshot_sha256, "codexSnapshotSha256")
        _require_sha256(snapshot_identity_fingerprint, "snapshotIdentityFingerprint")
        gate, _ = _canonical_activation_gate(activation_gate)
        reserved_at = _aware_utc(now)
        aborted = False
        result: LaunchPermitV2 | None = None
        with self._immediate():
            controller = self._require_accepting_controller(expected_control_epoch)
            node = self._connection.execute(
                "select n.*,r.compatibility_fingerprint,j.state as evidence_state "
                "from nodes n join routes r on r.route_id=n.route_id "
                "join account_evidence_jobs j on j.evidence_job_id=n.evidence_job_id "
                "where n.admission_id=?",
                (admission_id,),
            ).fetchone()
            if node is None:
                self._fail("ADMISSION_NOT_FOUND", "admission does not exist")
            replay = self._connection.execute(
                "select * from node_launch_permits where admission_id=?",
                (admission_id,),
            ).fetchone()
            if replay is not None:
                return self._replayed_launch_permit(
                    replay,
                    gate=gate,
                    expected_control_epoch=expected_control_epoch,
                    argv_fingerprint=argv_fingerprint,
                    codex_snapshot_sha256=codex_snapshot_sha256,
                    snapshot_identity_fingerprint=snapshot_identity_fingerprint,
                )
            if (
                node["admission_state"] != "ADMITTED"
                or node["evidence_state"] != "SUCCEEDED"
            ):
                self._fail(
                    "ADMISSION_NOT_RESERVABLE", "admission is not ready for reservation"
                )
            accepted_gate = _gate_from_node(node)
            permit_id = _new_id("lp2_")
            if canonical_json_v1(accepted_gate) != canonical_json_v1(gate):
                result = self._insert_launch_permit_locked(
                    permit_id=permit_id,
                    node=node,
                    controller=controller,
                    gate=accepted_gate,
                    argv_fingerprint=argv_fingerprint,
                    codex_snapshot_sha256=codex_snapshot_sha256,
                    snapshot_identity_fingerprint=snapshot_identity_fingerprint,
                    state="ABORTED_ACTIVATION_GATE_CHANGED",
                    reserved_at=reserved_at,
                )
                self._terminalize_activation_gate_change_locked(
                    admission_id=admission_id,
                    route_id=str(node["route_id"]),
                    node_id=str(node["node_id"]),
                    now=reserved_at,
                )
                aborted = True
            else:
                result = self._insert_launch_permit_locked(
                    permit_id=permit_id,
                    node=node,
                    controller=controller,
                    gate=gate,
                    argv_fingerprint=argv_fingerprint,
                    codex_snapshot_sha256=codex_snapshot_sha256,
                    snapshot_identity_fingerprint=snapshot_identity_fingerprint,
                    state="RESERVED",
                    reserved_at=reserved_at,
                )
                self._connection.execute(
                    "update nodes set admission_state='RESERVED',updated_at=? "
                    "where admission_id=? and admission_state='ADMITTED'",
                    (_iso(reserved_at), admission_id),
                )
        if aborted:
            self._fail(
                "ACTIVATION_GATE_CHANGED", "activation gate changed after admission"
            )
        assert result is not None
        return result

    def record_guard_hello(
        self,
        permit_id: str,
        *,
        guard_pid: int,
        guard_start_marker: str,
        one_time_token_hash: str,
        snapshot_identity_fingerprint: str,
    ) -> LaunchPermitV2:
        _require_identifier(permit_id, "lp2_")
        if type(guard_pid) is not int or guard_pid <= 0:
            self._fail("INVALID_PROCESS", "guard pid must be positive")
        _require_nonempty(guard_start_marker, "guardStartMarker")
        _require_sha256(one_time_token_hash, "oneTimeTokenHash")
        _require_sha256(snapshot_identity_fingerprint, "snapshotIdentityFingerprint")
        with self._immediate():
            self._require_accepting_controller(self._expected_controller.control_epoch)
            permit = self._connection.execute(
                "select * from node_launch_permits where permit_id=?", (permit_id,)
            ).fetchone()
            if permit is None:
                self._fail("LAUNCH_PERMIT_NOT_FOUND", "launch permit does not exist")
            if permit["state"] == "GUARDED":
                if (
                    permit["guard_pid"] != guard_pid
                    or permit["guard_start_marker"] != guard_start_marker
                    or permit["one_time_token_hash"] != one_time_token_hash
                    or permit["snapshot_identity_fingerprint"]
                    != snapshot_identity_fingerprint
                ):
                    self._fail("GUARD_REPLAY_CONFLICT", "guard HELLO replay differs")
            elif permit["state"] == "RESERVED":
                if (
                    permit["snapshot_identity_fingerprint"]
                    != snapshot_identity_fingerprint
                ):
                    self._fail(
                        "SNAPSHOT_IDENTITY_MISMATCH", "guard observed another snapshot"
                    )
                self._connection.execute(
                    "update node_launch_permits set state='GUARDED',guard_pid=?,"
                    "guard_start_marker=?,one_time_token_hash=? where permit_id=? and state='RESERVED'",
                    (guard_pid, guard_start_marker, one_time_token_hash, permit_id),
                )
                self._connection.execute(
                    "update nodes set admission_state='GUARDED' "
                    "where admission_id=? and admission_state='RESERVED'",
                    (permit["admission_id"],),
                )
                permit = self._connection.execute(
                    "select * from node_launch_permits where permit_id=?", (permit_id,)
                ).fetchone()
            else:
                self._fail(
                    "LAUNCH_PERMIT_NOT_RESERVED", "permit cannot accept guard HELLO"
                )
            return _launch_permit_record(permit)

    def commit_launch_permit(
        self,
        *,
        permit_id: str,
        guard_pid: int,
        guard_start_marker: str,
        one_time_token_hash: str,
        argv_fingerprint: str,
        snapshot_identity_fingerprint: str,
        activation_gate: Mapping[str, Any],
        expected_control_epoch: int,
        permission_probe_id: str,
        codex_binary_sha256: str,
        now: datetime,
    ) -> CommittedLaunchV2:
        _require_identifier(permit_id, "lp2_")
        if type(guard_pid) is not int or guard_pid <= 0:
            self._fail("INVALID_PROCESS", "guard pid must be positive")
        _require_nonempty(guard_start_marker, "guardStartMarker")
        _require_sha256(one_time_token_hash, "oneTimeTokenHash")
        _require_sha256(argv_fingerprint, "argvFingerprint")
        _require_sha256(snapshot_identity_fingerprint, "snapshotIdentityFingerprint")
        _require_nonempty(permission_probe_id, "permissionProbeId")
        _require_sha256(codex_binary_sha256, "codexBinarySha256")
        gate, journal_json = _canonical_activation_gate(activation_gate)
        committed_at = _aware_utc(now)
        aborted = False
        result: CommittedLaunchV2 | None = None
        with self._immediate():
            controller = self._require_accepting_controller(expected_control_epoch)
            permit = self._connection.execute(
                "select * from node_launch_permits where permit_id=?", (permit_id,)
            ).fetchone()
            if permit is None:
                self._fail("LAUNCH_PERMIT_NOT_FOUND", "launch permit does not exist")
            node = self._connection.execute(
                "select evidence_job_id from nodes "
                "where route_id=? and node_id=? and admission_id=?",
                (permit["route_id"], permit["node_id"], permit["admission_id"]),
            ).fetchone()
            if node is None or node["evidence_job_id"] is None:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "launch permit is not bound to an evidence job",
                )
            attempt_id = attempt_id_for_evidence_job(str(node["evidence_job_id"]))
            attempt = self._connection.execute(
                "select * from attempts where launch_permit_id=?", (permit_id,)
            ).fetchone()
            if attempt is not None:
                return self._replayed_committed_launch(
                    permit,
                    attempt,
                    gate=gate,
                    expected_control_epoch=expected_control_epoch,
                    guard_pid=guard_pid,
                    guard_start_marker=guard_start_marker,
                    one_time_token_hash=one_time_token_hash,
                    argv_fingerprint=argv_fingerprint,
                    snapshot_identity_fingerprint=snapshot_identity_fingerprint,
                    permission_probe_id=permission_probe_id,
                    codex_binary_sha256=codex_binary_sha256,
                    expected_attempt_id=attempt_id,
                )
            if permit["state"] != "GUARDED":
                self._fail("LAUNCH_PERMIT_NOT_GUARDED", "permit is not guarded")
            if (
                permit["guard_pid"] != guard_pid
                or permit["guard_start_marker"] != guard_start_marker
                or permit["one_time_token_hash"] != one_time_token_hash
                or permit["argv_fingerprint"] != argv_fingerprint
                or permit["snapshot_identity_fingerprint"]
                != snapshot_identity_fingerprint
                or permit["reserved_control_epoch"] != expected_control_epoch
            ):
                self._fail("LAUNCH_IDENTITY_MISMATCH", "commit launch identity differs")
            stored_gate = _gate_from_permit(permit)
            if canonical_json_v1(stored_gate) != canonical_json_v1(gate):
                self._connection.execute(
                    "update node_launch_permits set state='ABORTED_ACTIVATION_GATE_CHANGED',"
                    "resolved_at=?,failure_code='ABORTED_ACTIVATION_GATE_CHANGED' "
                    "where permit_id=? and state='GUARDED'",
                    (_iso(committed_at), permit_id),
                )
                self._terminalize_activation_gate_change_locked(
                    admission_id=str(permit["admission_id"]),
                    route_id=str(permit["route_id"]),
                    node_id=str(permit["node_id"]),
                    now=committed_at,
                )
                aborted = True
            else:
                self._connection.execute(
                    "update node_launch_permits set state='COMMIT_AUTHORIZED',pid=?,start_marker=? "
                    "where permit_id=? and state='GUARDED'",
                    (guard_pid, guard_start_marker, permit_id),
                )
                self._connection.execute(
                    "insert into attempts "
                    "(attempt_id,route_id,node_id,state,model,reasoning_effort,"
                    "permission_profile_id,pid,argv_fingerprint,permission_probe_id,"
                    "attestation_json,result_json,error_code,error_message,started_at,ended_at,"
                    "launch_permit_id,activation_fingerprint,account_context_fingerprint,"
                    "account_catalog_fingerprint,launch_control_epoch,controller_identity,"
                    "controller_instance_id,evidence_kind,codex_binary_sha256,codex_snapshot_sha256,"
                    "compatibility_fingerprint,snapshot_identity_fingerprint,"
                    "permit_evidence_fingerprint,admission_id,manifest_semantic_fingerprint,"
                    "activation_receipt_fingerprint,journal_absence_proof_json,"
                    "activation_gate_fingerprint,process_start_marker) "
                    "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        attempt_id,
                        permit["route_id"],
                        permit["node_id"],
                        "STARTING",
                        permit["model"],
                        permit["reasoning_effort"],
                        permit["permission_profile_id"],
                        guard_pid,
                        argv_fingerprint,
                        permission_probe_id,
                        None,
                        None,
                        None,
                        None,
                        _iso(committed_at),
                        None,
                        permit_id,
                        permit["activation_fingerprint"],
                        permit["account_context_fingerprint"],
                        permit["account_catalog_fingerprint"],
                        expected_control_epoch,
                        controller["controller_identity"],
                        controller["instance_id"],
                        "V2_ATTESTED",
                        codex_binary_sha256,
                        permit["codex_snapshot_sha256"],
                        permit["compatibility_fingerprint"],
                        snapshot_identity_fingerprint,
                        permit["permit_evidence_fingerprint"],
                        permit["admission_id"],
                        gate["manifestSemanticFingerprint"],
                        gate["activationReceiptFingerprint"],
                        journal_json,
                        gate["gateFingerprint"],
                        guard_start_marker,
                    ),
                )
                self._connection.execute(
                    "update nodes set admission_state='COMMIT_AUTHORIZED',attempt_count=attempt_count+1,"
                    "updated_at=? where admission_id=? and admission_state='GUARDED'",
                    (_iso(committed_at), permit["admission_id"]),
                )
                result = CommittedLaunchV2(
                    permit_id=permit_id,
                    attempt_id=attempt_id,
                    route_id=str(permit["route_id"]),
                    node_id=str(permit["node_id"]),
                    permit_state="COMMIT_AUTHORIZED",
                )
        if aborted:
            self._fail(
                "ACTIVATION_GATE_CHANGED", "activation gate changed before commit"
            )
        assert result is not None
        return result

    def quiescence_snapshot(self, *, barrier_held: bool) -> QuiescenceSnapshotV2:
        if barrier_held is not True:
            self._fail(
                "LAUNCH_BARRIER_REQUIRED", "quiescence requires the launch barrier"
            )
        with self._immediate():
            self._verify_identity_and_controller()
            counts = {
                name: int(self._connection.execute(statement).fetchone()[0])
                for name, statement in _QUIESCENCE_QUERIES.items()
            }
        predicate_projection = {
            "predicates": [
                {
                    "name": name,
                    "sql": statement,
                    "parameters": [],
                    "result": counts[name],
                }
                for name, statement in _QUIESCENCE_QUERIES.items()
            ]
        }
        return QuiescenceSnapshotV2(
            work_counts=counts,
            database_predicates_fingerprint=domain_fingerprint(
                "codex-smart/database-predicates/v2", predicate_projection
            ),
            barrier_held=True,
            quiescent=all(value == 0 for value in counts.values()),
        )

    def _consume_turn_binding_locked(
        self,
        *,
        binding_id: str,
        request_context: RequestContextV2,
        context_json: str,
        context_hash: str,
        request_key: str,
        request_hash: str,
        now: datetime,
    ) -> TurnBindingV2:
        row = self._connection.execute(
            "select * from turn_bindings where token_hash=?", (_token_hash(binding_id),)
        ).fetchone()
        if row is None:
            self._fail("TURN_BINDING_NOT_FOUND", "turn binding does not exist")
        if (
            row["context_hash"] != context_hash
            or row["context_json"] != context_json
            or row["activation_fingerprint"] != request_context.activation_fingerprint
            or row["compatibility_fingerprint"]
            != request_context.compatibility_fingerprint
            or row["issued_control_epoch"] != request_context.issued_control_epoch
        ):
            self._fail(
                "TURN_BINDING_CONTEXT_MISMATCH",
                "turn binding belongs to another context",
            )
        if row["consumed_at"] is not None:
            if row["request_key"] != request_key or row["request_hash"] != request_hash:
                self._fail(
                    "TURN_BINDING_USED", "turn binding was consumed by another request"
                )
        else:
            if now > _parse_iso(str(row["expires_at"])):
                self._fail("TURN_BINDING_EXPIRED", "turn binding expired")
            self._connection.execute(
                "update turn_bindings set consumed_at=?,request_key=?,request_hash=? "
                "where token_hash=? and consumed_at is null",
                (_iso(now), request_key, request_hash, _token_hash(binding_id)),
            )
        return TurnBindingV2(
            binding_id=binding_id,
            context_fingerprint=context_hash,
            issued_control_epoch=int(row["issued_control_epoch"]),
            issued_at=_parse_iso(str(row["created_at"])),
            expires_at=_parse_iso(str(row["expires_at"])),
            state="CONSUMED",
        )

    def _validated_context(
        self, request_context: RequestContextV2
    ) -> tuple[dict[str, Any], str, str]:
        value = request_context.contract_value()
        for name, item in value.items():
            if name in {"schemaVersion", "issuedControlEpoch"}:
                continue
            _require_nonempty(item, name)
            if len(item.encode("utf-8")) > 4096:
                self._fail(
                    "INVALID_REQUEST_CONTEXT", f"{name} exceeds 4096 UTF-8 bytes"
                )
        _require_sha256(request_context.worktree_fingerprint, "worktreeFingerprint")
        _require_sha256(request_context.activation_fingerprint, "activationFingerprint")
        _require_sha256(
            request_context.compatibility_fingerprint, "compatibilityFingerprint"
        )
        if not 1 <= request_context.issued_control_epoch <= MAX_SAFE_INTEGER:
            self._fail(
                "INVALID_REQUEST_CONTEXT",
                "issuedControlEpoch is outside the live range",
            )
        projection = dict(value)
        projection["codexHome"] = _text_sha256(request_context.codex_home)
        projection["repoRoot"] = _text_sha256(request_context.repo_root)
        return (
            value,
            canonical_json_v1(value),
            domain_fingerprint("codex-smart/request-context/v2", projection),
        )

    def _require_owner_values(
        self,
        request_context: RequestContextV2,
        *,
        context_hash: str,
        context_json: str,
        error_code: str = "START_OWNER_MISMATCH",
    ) -> None:
        candidate, _, _ = self._validated_context(request_context)
        stored_context = _request_context_from_stored_json_v2(context_json)
        stored, expected_json, expected_hash = self._validated_context(stored_context)
        owner_fields = set(stored) - {"issuedControlEpoch"}
        if (
            context_hash != expected_hash
            or context_json != expected_json
            or any(candidate[name] != stored[name] for name in owner_fields)
        ):
            self._fail(error_code, "start request belongs to another turn")
        if candidate["issuedControlEpoch"] == stored["issuedControlEpoch"]:
            return
        if (
            candidate["issuedControlEpoch"]
            != self._expected_controller.control_epoch
        ):
            self._fail(error_code, "start request belongs to another turn")
        self._require_accepting_controller(candidate["issuedControlEpoch"])

    def _start_owner_row_locked(
        self, start_request_id: str, request_context: RequestContextV2
    ) -> sqlite3.Row:
        row = self._connection.execute(
            "select s.start_request_id,s.route_id,s.shell_session_id,s.session_id,s.turn_id,"
            "s.state as start_state,s.evidence_job_id,s.admission_id,s.terminal_at,"
            "s.failure_code,j.state as evidence_state,j.boundary_id,j.failure_code as job_failure,"
            "r.context_hash as route_context_hash,r.context_json as route_context_json "
            "from start_requests s join account_evidence_jobs j "
            "on j.evidence_job_id=s.evidence_job_id "
            "join routes r on r.route_id=s.route_id where s.start_request_id=?",
            (start_request_id,),
        ).fetchone()
        if row is None:
            self._fail("START_REQUEST_NOT_FOUND", "start request does not exist")
        self._require_owner_values(
            request_context,
            context_hash=str(row["route_context_hash"]),
            context_json=str(row["route_context_json"]),
        )
        if (
            row["shell_session_id"] != request_context.shell_session_id
            or row["session_id"] != request_context.session_id
            or row["turn_id"] != request_context.turn_id
        ):
            self._fail("START_OWNER_MISMATCH", "start request belongs to another turn")
        return row

    def _terminal_attempt_for_start_locked(
        self,
        start: sqlite3.Row,
    ) -> sqlite3.Row | None:
        admission_id = start["admission_id"]
        if admission_id is None:
            return None
        row = self._connection.execute(
            "select a.attempt_id,a.state,a.result_json,a.error_code "
            "from attempts a join node_launch_permits p "
            "on p.permit_id=a.launch_permit_id where p.admission_id=? "
            "order by a.started_at desc,a.attempt_id desc limit 1",
            (admission_id,),
        ).fetchone()
        if row is None or str(row["state"]) not in _TERMINAL_ATTEMPT_STATES:
            return None
        return row

    def _append_start_event_locked(
        self,
        *,
        start_request_id: str,
        route_id: str,
        node_id: str,
        kind: str,
        start_state: str,
        evidence_job_id: str | None,
        admission_id: str | None,
        attestation: Mapping[str, Any] | None,
        problem: Mapping[str, Any] | None,
        now: datetime,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "startRequestId": start_request_id,
            "evidenceJobId": evidence_job_id,
            "admissionId": admission_id,
            "attestation": dict(attestation) if attestation is not None else None,
            "problem": dict(problem) if problem is not None else None,
        }
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        self._connection.execute(
            "insert into events (route_id,node_id,event,state,code,message,created_at) "
            "values (?,?,?,?,?,?,?)",
            (
                route_id,
                node_id,
                kind,
                start_state,
                start_request_id,
                canonical_json_v1(payload),
                _iso(now),
            ),
        )

    def _terminalize_unstarted_descendants_locked(
        self,
        *,
        route_id: str,
        failed_node_id: str,
        now: datetime,
        descendant_state: str = "FAILED",
        error_code: str = "DEPENDENCY_FAILED",
    ) -> tuple[str, ...]:
        """Закрывает ещё не запускавшихся транзитивных потомков сбойного узла."""

        if descendant_state not in {
            "FAILED",
            "CANCELLED",
            "QUARANTINED",
            "STALE",
        }:
            self._fail(
                "DATABASE_VALUE_INVALID",
                "dependency cascade uses a nonterminal state",
            )
        _require_nonempty(error_code, "dependencyErrorCode")
        rows = self._connection.execute(
            "select node_id,ordinal,state,dependencies_json,admission_id "
            "from nodes where route_id=? order by ordinal,node_id",
            (route_id,),
        ).fetchall()
        known_node_ids = {str(row["node_id"]) for row in rows}
        if failed_node_id not in known_node_ids:
            self._fail("ROUTE_NODE_NOT_FOUND", "failed route node does not exist")
        blocked_by_failure = {failed_node_id}
        descendants: list[sqlite3.Row] = []
        pending = list(rows)
        while pending:
            progressed = False
            next_pending: list[sqlite3.Row] = []
            for row in pending:
                node_id = str(row["node_id"])
                if node_id == failed_node_id or node_id in blocked_by_failure:
                    continue
                dependencies = tuple(
                    str(item)
                    for item in _stored_json_list(
                        row["dependencies_json"],
                        "dependencies_json",
                    )
                )
                if any(item in blocked_by_failure for item in dependencies):
                    blocked_by_failure.add(node_id)
                    descendants.append(row)
                    progressed = True
                else:
                    next_pending.append(row)
            if not progressed:
                break
            pending = next_pending

        terminalized: list[str] = []
        for row in descendants:
            node_id = str(row["node_id"])
            if str(row["state"]) != "PLANNED" or row["admission_id"] is not None:
                continue
            result_json = canonical_json_v1(
                {
                    "blockedNodeId": node_id,
                    "errorCode": error_code,
                    "failedDependencyNodeId": failed_node_id,
                }
            )
            cursor = self._connection.execute(
                "update nodes set state=?,result_json=?,updated_at=? "
                "where route_id=? and node_id=? and state='PLANNED' "
                "and admission_id is null",
                (descendant_state, result_json, _iso(now), route_id, node_id),
            )
            if cursor.rowcount == 1:
                terminalized.append(node_id)
        return tuple(terminalized)

    def _terminalize_all_unstarted_nodes_locked(
        self,
        *,
        route_id: str,
        now: datetime,
        error_code: str,
    ) -> tuple[str, ...]:
        """Закрывает весь ещё не запущенный остаток глобально устаревшего маршрута."""

        _require_nonempty(error_code, "routeStaleErrorCode")
        rows = self._connection.execute(
            "select node_id from nodes where route_id=? and state='PLANNED' "
            "order by ordinal,node_id",
            (route_id,),
        ).fetchall()
        terminalized: list[str] = []
        for row in rows:
            node_id = str(row["node_id"])
            cursor = self._connection.execute(
                "update nodes set state='STALE',result_json=?,"
                "admission_state=case when admission_id is null then null else 'ABORTED' end,"
                "updated_at=? where route_id=? and node_id=? and state='PLANNED'",
                (
                    canonical_json_v1(
                        {
                            "errorCode": error_code,
                            "nodeId": node_id,
                        }
                    ),
                    _iso(now),
                    route_id,
                    node_id,
                ),
            )
            if cursor.rowcount == 1:
                terminalized.append(node_id)
        return tuple(terminalized)

    def _complete_route_if_terminal_locked(
        self,
        *,
        route_id: str,
        fallback_state: str,
        now: datetime,
    ) -> tuple[bool, str | None]:
        """Собирает итог маршрута, только когда каждый узел терминален."""

        route_nodes = self._connection.execute(
            "select node_id,state from nodes where route_id=? "
            "order by ordinal,node_id",
            (route_id,),
        ).fetchall()
        if not route_nodes or any(
            str(row["state"]) in _NONTERMINAL_NODE_STATES for row in route_nodes
        ):
            return False, None
        node_states = {str(row["state"]) for row in route_nodes}
        route_state = next(
            (
                candidate
                for candidate in (
                    "FAILED",
                    "QUARANTINED",
                    "CANCELLED",
                    "STALE",
                    "CANDIDATE_READY",
                    "SUCCEEDED",
                )
                if candidate in node_states
            ),
            fallback_state,
        )
        projected_results: list[dict[str, Any]] = []
        for row in route_nodes:
            node_id = str(row["node_id"])
            result_row = self._connection.execute(
                "select result_json from nodes where route_id=? and node_id=?",
                (route_id, node_id),
            ).fetchone()
            if result_row is None:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "terminal route node disappeared while projecting its result",
                )
            encoded_result = result_row["result_json"]
            if encoded_result is None:
                raw_result_fingerprint = None
                raw_result_bytes = 0
                inline_result = {"resultAvailable": False}
                result_truncated = False
            else:
                encoded_result = str(encoded_result)
                parsed_result = _stored_json_object(
                    encoded_result,
                    "nodes.result_json",
                )
                raw_result = encoded_result.encode("utf-8")
                raw_result_fingerprint = hashlib.sha256(raw_result).hexdigest()
                raw_result_bytes = len(raw_result)
                inline_result, inline_truncated = _bounded_inline_terminal_result(
                    parsed_result,
                    max_bytes=_MAX_INLINE_DEPENDENCY_RESULT_BYTES,
                )
                result_truncated = (
                    inline_truncated
                    or canonical_json_v1(inline_result) != encoded_result
                )
            projected_results.append(
                {
                    "nodeId": node_id,
                    "state": str(row["state"]),
                    "rawResultFingerprint": raw_result_fingerprint,
                    "rawResultBytes": raw_result_bytes,
                    "inlineResult": inline_result,
                    "resultTruncated": result_truncated,
                }
            )
        terminal_result_json = canonical_json_v1({"nodes": projected_results})
        self._connection.execute(
            "update routes set state=?,terminal_result_json=?,updated_at=? "
            "where route_id=?",
            (route_state, terminal_result_json, _iso(now), route_id),
        )
        return True, route_state

    def _terminalize_activation_gate_change_locked(
        self,
        *,
        admission_id: str,
        route_id: str,
        node_id: str,
        now: datetime,
    ) -> None:
        start = self._connection.execute(
            "select start_request_id,evidence_job_id from start_requests "
            "where admission_id=?",
            (admission_id,),
        ).fetchone()
        if start is None:
            self._fail(
                "DATABASE_VALUE_INVALID",
                "admission has no bound start request",
            )
        self._connection.execute(
            "update nodes set admission_state='ABORTED',state='STALE',result_json=?,"
            "updated_at=? where admission_id=?",
            (
                canonical_json_v1(
                    {
                        "errorCode": "ACTIVATION_GATE_CHANGED",
                        "nodeId": node_id,
                    }
                ),
                _iso(now),
                admission_id,
            ),
        )
        self._terminalize_all_unstarted_nodes_locked(
            route_id=route_id,
            now=now,
            error_code="ACTIVATION_GATE_CHANGED",
        )
        route_completed, route_state = self._complete_route_if_terminal_locked(
            route_id=route_id,
            fallback_state="STALE",
            now=now,
        )
        self._connection.execute(
            "update start_requests set state='STALE',terminal_at=?,"
            "failure_code='ACTIVATION_GATE_CHANGED',updated_at=? "
            "where start_request_id=? and state='READY'",
            (_iso(now), _iso(now), start["start_request_id"]),
        )
        problem = {
            "category": "STALE",
            "code": "ROUTE_STALE",
            "message": "Шлюз активации изменился до запуска дочернего процесса.",
            "retryable": False,
        }
        self._append_start_event_locked(
            start_request_id=str(start["start_request_id"]),
            route_id=route_id,
            node_id=node_id,
            kind="ROUTE_STALE",
            start_state="STALE",
            evidence_job_id=str(start["evidence_job_id"]),
            admission_id=admission_id,
            attestation=None,
            problem=problem,
            now=now,
            metadata={"failureCode": "ACTIVATION_GATE_CHANGED"},
        )
        if route_completed:
            if route_state is None:
                self._fail(
                    "DATABASE_VALUE_INVALID",
                    "completed route has no terminal state",
                )
            self._append_start_event_locked(
                start_request_id=str(start["start_request_id"]),
                route_id=route_id,
                node_id=node_id,
                kind="ROUTE_COMPLETED",
                start_state=route_state,
                evidence_job_id=str(start["evidence_job_id"]),
                admission_id=admission_id,
                attestation=None,
                problem=problem,
                now=now,
                metadata={"failureCode": "ACTIVATION_GATE_CHANGED"},
            )

    def _require_accepting_controller(self, expected_control_epoch: int) -> sqlite3.Row:
        self._verify_identity_and_controller()
        row = self._connection.execute("select * from controller_state").fetchone()
        if (
            row["state"] != "ACCEPTING"
            or row["maintenance_mode"] != "NONE"
            or row["accepting_new_routes"] != 1
            or row["lock_held"] != 1
        ):
            self._fail("CONTROLLER_NOT_ACCEPTING", "controller is not accepting work")
        if row["control_epoch"] != expected_control_epoch:
            self._fail("CONTROL_EPOCH_MISMATCH", "control epoch changed")
        return row

    def _replayed_admission(
        self, row: sqlite3.Row, gate: Mapping[str, Any]
    ) -> AdmissionV2:
        journal_json = canonical_json_v1(gate["journalAbsenceProof"])
        if (
            row["job_state"] != "SUCCEEDED"
            or row["start_admission"] != row["admission_id"]
            or row["admission_state"]
            not in {
                "ADMITTED",
                "RESERVED",
                "GUARDED",
                "COMMIT_AUTHORIZED",
                "STARTED",
            }
            or row["admission_manifest_semantic_fingerprint"]
            != gate["manifestSemanticFingerprint"]
            or row["admission_activation_receipt_fingerprint"]
            != gate["activationReceiptFingerprint"]
            or row["admission_journal_absence_proof_json"] != journal_json
            or row["admission_gate_fingerprint"] != gate["gateFingerprint"]
        ):
            self._fail("ADMISSION_REPLAY_CONFLICT", "admission replay differs")
        return AdmissionV2(
            admission_id=str(row["admission_id"]),
            start_request_id=str(row["job_start"]),
            evidence_job_id=str(row["evidence_job_id"]),
            route_id=str(row["route_id"]),
            node_id=str(row["node_id"]),
            activation_gate_fingerprint=str(row["admission_gate_fingerprint"]),
            state=str(row["admission_state"]),
        )

    def _insert_launch_permit_locked(
        self,
        *,
        permit_id: str,
        node: sqlite3.Row,
        controller: sqlite3.Row,
        gate: Mapping[str, Any],
        argv_fingerprint: str,
        codex_snapshot_sha256: str,
        snapshot_identity_fingerprint: str,
        state: str,
        reserved_at: datetime,
    ) -> LaunchPermitV2:
        journal_json = canonical_json_v1(gate["journalAbsenceProof"])
        evidence_value = {
            "permitId": permit_id,
            "routeId": node["route_id"],
            "nodeId": node["node_id"],
            "admissionId": node["admission_id"],
            "activationFingerprint": node["activation_fingerprint"],
            "accountContextFingerprint": node["account_context_fingerprint"],
            "accountCatalogFingerprint": node["account_catalog_fingerprint"],
            "controllerIdentity": controller["controller_identity"],
            "controllerInstanceId": controller["instance_id"],
            "reservedControlEpoch": controller["control_epoch"],
            "model": node["selected_model"],
            "reasoningEffort": node["reasoning_effort"],
            "permissionProfileId": node["permission_profile_id"],
            "argvFingerprint": argv_fingerprint,
            "compatibilityFingerprint": node["compatibility_fingerprint"],
            "codexSnapshotSha256": codex_snapshot_sha256,
            "snapshotIdentityFingerprint": snapshot_identity_fingerprint,
            "manifestSemanticFingerprint": gate["manifestSemanticFingerprint"],
            "activationReceiptFingerprint": gate["activationReceiptFingerprint"],
            "journalAbsenceProof": gate["journalAbsenceProof"],
            "activationGateFingerprint": gate["gateFingerprint"],
        }
        permit_evidence = domain_fingerprint(
            "codex-smart/permit-evidence/v2", evidence_value
        )
        resolved_at = _iso(reserved_at) if state != "RESERVED" else None
        failure_code = state if state != "RESERVED" else None
        columns = (
            "permit_id",
            "admission_id",
            "route_id",
            "node_id",
            "activation_fingerprint",
            "account_context_fingerprint",
            "account_catalog_fingerprint",
            "manifest_semantic_fingerprint",
            "activation_receipt_fingerprint",
            "journal_absence_proof_json",
            "activation_gate_fingerprint",
            "controller_identity",
            "controller_instance_id",
            "reserved_control_epoch",
            "model",
            "reasoning_effort",
            "permission_profile_id",
            "argv_fingerprint",
            "compatibility_fingerprint",
            "codex_snapshot_sha256",
            "permit_evidence_fingerprint",
            "state",
            "guard_pid",
            "guard_start_marker",
            "pid",
            "start_marker",
            "one_time_token_hash",
            "snapshot_identity_fingerprint",
            "legacy_source_backup_sha256",
            "legacy_attempt_id",
            "reserved_at",
            "resolved_at",
            "failure_code",
        )
        values = (
            permit_id,
            node["admission_id"],
            node["route_id"],
            node["node_id"],
            node["activation_fingerprint"],
            node["account_context_fingerprint"],
            node["account_catalog_fingerprint"],
            gate["manifestSemanticFingerprint"],
            gate["activationReceiptFingerprint"],
            journal_json,
            gate["gateFingerprint"],
            controller["controller_identity"],
            controller["instance_id"],
            controller["control_epoch"],
            node["selected_model"],
            node["reasoning_effort"],
            node["permission_profile_id"],
            argv_fingerprint,
            node["compatibility_fingerprint"],
            codex_snapshot_sha256,
            permit_evidence,
            state,
            None,
            None,
            None,
            None,
            None,
            snapshot_identity_fingerprint,
            None,
            None,
            _iso(reserved_at),
            resolved_at,
            failure_code,
        )
        self._connection.execute(
            f"insert into node_launch_permits ({','.join(columns)}) "
            f"values ({','.join('?' for _ in columns)})",
            values,
        )
        row = self._connection.execute(
            "select * from node_launch_permits where permit_id=?", (permit_id,)
        ).fetchone()
        return _launch_permit_record(row)

    def _replayed_launch_permit(
        self,
        row: sqlite3.Row,
        *,
        gate: Mapping[str, Any],
        expected_control_epoch: int,
        argv_fingerprint: str,
        codex_snapshot_sha256: str,
        snapshot_identity_fingerprint: str,
    ) -> LaunchPermitV2:
        if (
            row["state"] not in {"RESERVED", "GUARDED", "COMMIT_AUTHORIZED", "STARTED"}
            or row["reserved_control_epoch"] != expected_control_epoch
            or row["argv_fingerprint"] != argv_fingerprint
            or row["codex_snapshot_sha256"] != codex_snapshot_sha256
            or row["snapshot_identity_fingerprint"] != snapshot_identity_fingerprint
            or canonical_json_v1(_gate_from_permit(row)) != canonical_json_v1(gate)
        ):
            self._fail("LAUNCH_PERMIT_REPLAY_CONFLICT", "launch permit replay differs")
        return _launch_permit_record(row)

    def _replayed_committed_launch(
        self,
        permit: sqlite3.Row,
        attempt: sqlite3.Row,
        *,
        gate: Mapping[str, Any],
        expected_control_epoch: int,
        guard_pid: int,
        guard_start_marker: str,
        one_time_token_hash: str,
        argv_fingerprint: str,
        snapshot_identity_fingerprint: str,
        permission_probe_id: str,
        codex_binary_sha256: str,
        expected_attempt_id: str,
    ) -> CommittedLaunchV2:
        if (
            permit["state"] != "COMMIT_AUTHORIZED"
            or permit["reserved_control_epoch"] != expected_control_epoch
            or permit["guard_pid"] != guard_pid
            or permit["guard_start_marker"] != guard_start_marker
            or permit["one_time_token_hash"] != one_time_token_hash
            or permit["argv_fingerprint"] != argv_fingerprint
            or permit["snapshot_identity_fingerprint"] != snapshot_identity_fingerprint
            or attempt["permission_probe_id"] != permission_probe_id
            or attempt["codex_binary_sha256"] != codex_binary_sha256
            or attempt["attempt_id"] != expected_attempt_id
            or canonical_json_v1(_gate_from_permit(permit)) != canonical_json_v1(gate)
        ):
            self._fail("COMMIT_REPLAY_CONFLICT", "launch commit replay differs")
        return CommittedLaunchV2(
            permit_id=str(permit["permit_id"]),
            attempt_id=str(attempt["attempt_id"]),
            route_id=str(permit["route_id"]),
            node_id=str(permit["node_id"]),
            permit_state="COMMIT_AUTHORIZED",
        )

    def _load_schema_manifest(self) -> dict[str, Any]:
        try:
            manifest = json.loads(_SCHEMA_MANIFEST_PATH.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StateStoreV2Error(
                "SCHEMA_MANIFEST_INVALID", "cannot read the normative schema manifest"
            ) from error
        required = {
            "schemaVersion",
            "applicationId",
            "stateSqlSha256",
            "schemaFingerprint",
        }
        if not required.issubset(manifest):
            self._fail("SCHEMA_MANIFEST_INVALID", "schema manifest is incomplete")
        if (
            manifest["schemaVersion"] != 2
            or manifest["applicationId"] != APPLICATION_ID
        ):
            self._fail("SCHEMA_MANIFEST_INVALID", "schema manifest identity changed")
        if sha256_file(_SCHEMA_PATH) != manifest["stateSqlSha256"]:
            self._fail("SCHEMA_ARTIFACT_MISMATCH", "state-v2.sql hash changed")
        return manifest

    def _prepare_database_file(self) -> bool:
        parent = self.path.parent
        if parent.exists():
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                self._fail("UNSAFE_DATABASE_DIRECTORY", "database directory is unsafe")
        else:
            parent.mkdir(mode=0o700, parents=True)
            os.chmod(parent, 0o700)
        parent_info = parent.lstat()
        if (
            parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            self._fail(
                "UNSAFE_DATABASE_DIRECTORY",
                "database directory ownership or mode differs",
            )
        try:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            if self._allow_prepared_empty_database:
                info = self._safe_database_stat()
                if info.st_size != 0:
                    self._fail(
                        "UNSAFE_DATABASE",
                        "prepared database file must be empty",
                    )
                return True
            return False
        else:
            os.close(descriptor)
            return True

    def _safe_database_stat(self) -> os.stat_result:
        info = self.path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            self._fail(
                "UNSAFE_DATABASE",
                "database file ownership, type, link count or mode differs",
            )
        return info

    def _configure_connection(self) -> None:
        for pragma in (
            "foreign_keys=ON",
            "trusted_schema=OFF",
            "synchronous=FULL",
            "secure_delete=FAST",
        ):
            self._connection.execute(f"pragma {pragma}")

    def _create_schema(self) -> None:
        schema = read_schema_artifact(_SCHEMA_PATH)
        self._connection.execute(f"pragma application_id={APPLICATION_ID}")
        self._connection.executescript(schema)
        self._connection.execute("pragma user_version=2")

    def _verify_schema(self) -> None:
        quick = [tuple(row) for row in self._connection.execute("pragma quick_check")]
        if quick != [("ok",)]:
            self._fail(
                "DATABASE_INTEGRITY_FAILED", "quick_check did not return exactly ok"
            )
        if [tuple(row) for row in self._connection.execute("pragma foreign_key_check")]:
            self._fail(
                "DATABASE_INTEGRITY_FAILED", "foreign_key_check found violations"
            )
        application_id = int(
            self._connection.execute("pragma application_id").fetchone()[0]
        )
        user_version = int(
            self._connection.execute("pragma user_version").fetchone()[0]
        )
        if application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
            self._fail("UNSUPPORTED_DATABASE", "application_id or user_version differs")
        actual = database_schema_fingerprint(self._connection, version=2).fingerprint
        if actual != self._manifest["schemaFingerprint"]:
            self._fail("DATABASE_SCHEMA_MISMATCH", "actual schema fingerprint differs")

    def _insert_identity_and_controller(self) -> None:
        identity = self._database_identity_row()
        controller = self._controller_row()
        with self._immediate():
            self._connection.execute(
                f"insert into database_identity ({','.join(identity)}) "
                f"values ({','.join('?' for _ in identity)})",
                tuple(identity.values()),
            )
            self._connection.execute(
                f"insert into controller_state ({','.join(controller)}) "
                f"values ({','.join('?' for _ in controller)})",
                tuple(controller.values()),
            )

    def _verify_identity_and_controller(self) -> None:
        identity_rows = self._connection.execute(
            "select * from database_identity"
        ).fetchall()
        if (
            len(identity_rows) != 1
            or dict(identity_rows[0]) != self._database_identity_row()
        ):
            self._fail("DATABASE_IDENTITY_MISMATCH", "database_identity differs")
        controller_rows = self._connection.execute(
            "select * from controller_state"
        ).fetchall()
        if (
            len(controller_rows) != 1
            or dict(controller_rows[0]) != self._controller_row()
        ):
            self._fail("CONTROLLER_STATE_MISMATCH", "controller_state differs")

    def _database_identity_row(self) -> dict[str, Any]:
        value = self._expected_database_identity
        return {
            "singleton": 1,
            "database_id": value.database_id,
            "schema_version": 2,
            "schema_fingerprint": self._manifest["schemaFingerprint"],
            "schema_artifact_sha256": self._manifest["stateSqlSha256"],
            "activation_binding_nonce": value.activation_binding_nonce,
            "activation_id": value.activation_id,
            "activation_fingerprint": value.activation_fingerprint,
            "source_shape": "fresh-v2",
            "source_schema_fingerprint": None,
            "source_backup_sha256": None,
            "created_operation_id": value.created_operation_id,
            "created_at": _iso(value.created_at),
        }

    def _controller_row(self) -> dict[str, Any]:
        value = self._expected_controller
        return {
            "singleton": 1,
            "database_id": self._expected_database_identity.database_id,
            "protocol_version": 2,
            "release": RELEASE,
            "controller_identity": value.controller_identity,
            "instance_id": value.instance_id,
            "controller_start_id": value.controller_start_id,
            "controller_pid": value.controller_pid,
            "controller_process_start_marker": value.controller_process_start_marker,
            "controller_process_group_id": value.controller_process_group_id,
            "control_epoch": value.control_epoch,
            "state": "ACCEPTING",
            "maintenance_mode": "NONE",
            "reason_code": "NONE",
            "operation_id": None,
            "activation_id": value.activation_id,
            "activation_fingerprint": value.activation_fingerprint,
            "compatibility_fingerprint": value.compatibility_fingerprint,
            "routing_policy_fingerprint": value.routing_policy_fingerprint,
            "bundled_catalog_fingerprint": value.bundled_catalog_fingerprint,
            "socket_path": value.socket_path,
            "socket_device": value.socket_device,
            "socket_inode": value.socket_inode,
            "socket_owner_uid": value.socket_owner_uid,
            "socket_owner_gid": value.socket_owner_gid,
            "socket_mode": value.socket_mode,
            "lock_held": 1,
            "accepting_new_routes": 1,
            "quiescent": 0,
            "updated_at": _iso(value.updated_at),
        }

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
            except _CommitThenFail as exc:
                self._commit_or_rollback_on_failure()
                raise StateStoreV2Error(
                    exc.code,
                    exc.message,
                    committed_transitions=exc.transitions,
                ) from None
            except BaseException as primary:
                try:
                    self._connection.rollback_for_cleanup_v2()
                except BaseException as cleanup_error:
                    primary.add_note(
                        "SQLite cleanup rollback also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise
            else:
                self._commit_or_rollback_on_failure()

    def _commit_or_rollback_on_failure(self) -> None:
        try:
            self._connection.execute("COMMIT")
        except BaseException as primary:
            try:
                self._connection.rollback_for_cleanup_v2()
            except BaseException as cleanup_error:
                primary.add_note(
                    "SQLite cleanup rollback after failed commit also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise StateStoreV2Error(code, message)


def _iso(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StateStoreV2Error("INVALID_TIME", "time must include a UTC offset")
    return value.astimezone(timezone.utc)


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", "stored time is invalid"
        ) from error
    return _aware_utc(parsed)


def _new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(16)


def _private_runtime_root_v2(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise StateStoreV2Error(
            "RUNTIME_ARTIFACT_ROOT_INVALID",
            "runtime artifact root must be an absolute ordinary directory",
        )
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat()
    except OSError as exc:
        raise StateStoreV2Error(
            "RUNTIME_ARTIFACT_ROOT_INVALID", str(exc)
        ) from exc
    if (
        canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StateStoreV2Error(
            "RUNTIME_ARTIFACT_ROOT_INVALID",
            "runtime artifact root must be canonical, owned, and private",
        )
    return canonical


def _runtime_artifact_record_v2(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "artifactId": str(row["artifact_id"]),
        "routeId": str(row["route_id"]),
        "nodeId": str(row["node_id"]),
        "kind": str(row["kind"]),
        "path": str(row["path"]),
        "allowedRoot": str(row["allowed_root"]),
        "state": str(row["state"]),
        "device": None if row["device"] is None else int(row["device"]),
        "inode": None if row["inode"] is None else int(row["inode"]),
        "createdAt": str(row["created_at"]),
        "updatedAt": str(row["updated_at"]),
    }


def _registered_quarantine_paths_v2(
    *,
    source_root: Path,
    state_root: Path,
    git_dir: Path,
) -> tuple[Path, Path, Path]:
    for path, name in (
        (source_root, "source_root"),
        (state_root, "state_root"),
        (git_dir, "git_dir"),
    ):
        if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
            raise StateStoreV2Error(
                "QUARANTINE_REPOSITORY_PATH_INVALID",
                f"{name} must be an absolute ordinary path",
            )
    try:
        source = source_root.resolve(strict=True)
        state = state_root.resolve(strict=True)
        repository = git_dir.resolve(strict=True)
        repositories = (state / "quarantine").resolve(strict=True)
    except OSError as exc:
        raise StateStoreV2Error(
            "QUARANTINE_REPOSITORY_PATH_INVALID",
            "registered quarantine path is unavailable",
        ) from exc
    if (
        not source.is_dir()
        or not state.is_dir()
        or not repositories.is_dir()
        or not repository.is_dir()
        or repository.parent != repositories
        or repository.name != f"{_text_sha256(os.fspath(source))[:24]}.git"
    ):
        raise StateStoreV2Error(
            "QUARANTINE_REPOSITORY_PATH_INVALID",
            "registered quarantine path identity is invalid",
        )
    for path in (state, repositories, repository):
        metadata = path.stat()
        if (
            metadata.st_uid != os.getuid()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise StateStoreV2Error(
                "QUARANTINE_REPOSITORY_PATH_INVALID",
                "registered quarantine directory must be owned and private",
            )
    return source, state, repository


def _quarantine_repository_record_v2(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "repositoryId": str(row["repository_id"]),
        "sourceRoot": str(row["source_root"]),
        "stateRoot": str(row["state_root"]),
        "gitDir": str(row["git_dir"]),
        "state": str(row["state"]),
        "createdAt": str(row["created_at"]),
        "updatedAt": str(row["updated_at"]),
    }


def _candidate_intent_record_v2(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "intentId": str(row["intent_id"]),
        "routeId": str(row["route_id"]),
        "nodeId": str(row["node_id"]),
        "repositoryId": str(row["repository_id"]),
        "artifactId": str(row["artifact_id"]),
        "ref": str(row["ref"]),
        "baseSourceSha": str(row["base_source_sha"]),
        "baseCommitSha": str(row["base_commit_sha"]),
        "baseTreeSha": str(row["base_tree_sha"]),
        "commitSha": str(row["commit_sha"]),
        "treeSha": str(row["tree_sha"]),
        "validationProofSha256": (
            None
            if row["validation_proof_sha256"] is None
            else str(row["validation_proof_sha256"])
        ),
        "state": str(row["state"]),
        "createdAt": str(row["created_at"]),
        "updatedAt": str(row["updated_at"]),
        "completedAt": (
            None if row["completed_at"] is None else str(row["completed_at"])
        ),
    }


def _candidate_record_v2(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "candidateId": str(row["candidate_id"]),
        "routeId": None if row["route_id"] is None else str(row["route_id"]),
        "nodeId": None if row["node_id"] is None else str(row["node_id"]),
        "repositoryId": str(row["repository_id"]),
        "intentId": None if row["intent_id"] is None else str(row["intent_id"]),
        "artifactId": str(row["artifact_id"]),
        "ref": str(row["ref"]),
        "baseSourceSha": str(row["base_source_sha"]),
        "baseCommitSha": str(row["base_commit_sha"]),
        "baseTreeSha": str(row["base_tree_sha"]),
        "commitSha": str(row["commit_sha"]),
        "treeSha": str(row["tree_sha"]),
        "observedCommitSha": str(row["observed_commit_sha"]),
        "observedTreeSha": str(row["observed_tree_sha"]),
        "state": str(row["state"]),
        "validationState": str(row["validation_state"]),
        "proofHash": str(row["proof_hash"]),
        "trusted": bool(row["trusted"]),
        "createdAt": str(row["created_at"]),
        "updatedAt": str(row["updated_at"]),
    }


def _candidate_resolution_matches_v2(
    registered: sqlite3.Row,
    intent: sqlite3.Row,
    *,
    observed_commit_sha: str,
    observed_tree_sha: str,
    candidate_state: str,
    validation_state: str,
    proof_hash: str,
    trusted: bool,
) -> bool:
    return (
        str(registered["route_id"]) == str(intent["route_id"])
        and str(registered["node_id"]) == str(intent["node_id"])
        and str(registered["repository_id"]) == str(intent["repository_id"])
        and str(registered["intent_id"]) == str(intent["intent_id"])
        and str(registered["artifact_id"]) == str(intent["artifact_id"])
        and str(registered["ref"]) == str(intent["ref"])
        and str(registered["base_source_sha"]) == str(intent["base_source_sha"])
        and str(registered["base_commit_sha"]) == str(intent["base_commit_sha"])
        and str(registered["base_tree_sha"]) == str(intent["base_tree_sha"])
        and str(registered["commit_sha"]) == str(intent["commit_sha"])
        and str(registered["tree_sha"]) == str(intent["tree_sha"])
        and str(registered["observed_commit_sha"]) == observed_commit_sha
        and str(registered["observed_tree_sha"]) == observed_tree_sha
        and str(registered["state"]) == candidate_state
        and str(registered["validation_state"]) == validation_state
        and str(registered["proof_hash"]) == proof_hash
        and int(registered["trusted"]) == int(trusted)
    )


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_identifier(value: str, prefix: str) -> None:
    if (
        type(value) is not str
        or len(value) != len(prefix) + 32
        or not value.startswith(prefix)
        or any(
            character not in "0123456789abcdef" for character in value[len(prefix) :]
        )
    ):
        raise StateStoreV2Error(
            "INVALID_IDENTIFIER", f"identifier must use {prefix}<32-hex>"
        )


def _require_opaque_identifier_v2(
    value: str,
    prefix: str,
    exact_length: int,
) -> None:
    suffix = value[len(prefix) :] if isinstance(value, str) else ""
    if (
        type(value) is not str
        or len(value) != exact_length
        or not value.startswith(prefix)
        or not suffix
        or any(
            not (
                character.isascii()
                and (character.isalnum() or character in "_-")
            )
            for character in suffix
        )
    ):
        raise StateStoreV2Error(
            "INVALID_IDENTIFIER",
            f"identifier must use {prefix}<opaque> with length {exact_length}",
        )


def _require_candidate_ref_v2(ref: str, artifact_id: str) -> None:
    if (
        type(ref) is not str
        or not 1 <= len(ref) <= 512
        or ref != f"refs/candidates/{artifact_id}"
    ):
        raise StateStoreV2Error(
            "CANDIDATE_REF_INVALID",
            "candidate reference does not match its artifact",
        )


def _require_git_sha_v2(value: str, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StateStoreV2Error(
            "INVALID_VALUE",
            f"{name} must be 40 lowercase hex",
        )


def _require_nonempty(value: Any, name: str) -> None:
    if type(value) is not str or not value:
        raise StateStoreV2Error("INVALID_VALUE", f"{name} must be a non-empty string")


def _require_sha256(value: str, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StateStoreV2Error("INVALID_VALUE", f"{name} must be 64 lowercase hex")


def _validate_public_problem(value: Mapping[str, Any]) -> None:
    categories = {
        "TURN_BINDING_EXPIRED": "STALE",
        "ROUTE_STALE": "STALE",
        "ACCOUNT_CONTEXT_CHANGED": "STALE",
        "CHILD_ATTESTATION_STALE": "STALE",
        "ADAPTIVE_ACTIVATION_UNCOMMITTED": "UNAVAILABLE",
        "ACCOUNT_EVIDENCE_UNAVAILABLE": "UNAVAILABLE",
        "ACCOUNT_EVIDENCE_QUEUE_FULL": "UNAVAILABLE",
        "ROUTING_PAIR_UNAVAILABLE": "UNAVAILABLE",
        "CONTROLLER_UNAVAILABLE": "UNAVAILABLE",
        "REQUEST_DEADLINE_EXCEEDED": "UNAVAILABLE",
        "TURN_BINDING_OWNERSHIP_MISMATCH": "INVALID",
        "INVALID_REQUEST": "INVALID",
        "CURSOR_INVALID": "INVALID",
        "ROUTE_OWNERSHIP_MISMATCH": "INVALID",
        "IDEMPOTENCY_CONFLICT": "CONFLICT",
        "INTERNAL_ERROR": "INTERNAL",
    }
    if type(value) is not dict or set(value) != {
        "category",
        "code",
        "message",
        "retryable",
    }:
        raise StateStoreV2Error(
            "INVALID_PUBLIC_PROBLEM", "problem does not match the public contract"
        )
    code = value["code"]
    message = value["message"]
    if (
        type(code) is not str
        or code not in categories
        or value["category"] != categories[code]
        or type(message) is not str
        or not 1 <= len(message) <= 1024
        or type(value["retryable"]) is not bool
    ):
        raise StateStoreV2Error(
            "INVALID_PUBLIC_PROBLEM", "problem value is outside the public contract"
        )
    canonical_json_v1(dict(value))


def _canonical_activation_gate(
    value: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    required = {
        "manifestSemanticFingerprint",
        "activationReceiptFingerprint",
        "journalAbsenceProof",
        "gateFingerprint",
    }
    if type(value) is not dict or set(value) != required:
        raise StateStoreV2Error(
            "ACTIVATION_GATE_INVALID", "activationGate must contain exactly four fields"
        )
    gate = dict(value)
    _require_sha256(
        str(gate["manifestSemanticFingerprint"]), "manifestSemanticFingerprint"
    )
    _require_sha256(
        str(gate["activationReceiptFingerprint"]), "activationReceiptFingerprint"
    )
    _require_sha256(str(gate["gateFingerprint"]), "gateFingerprint")
    proof = gate["journalAbsenceProof"]
    if type(proof) is not dict or set(proof) != {
        "schemaId",
        "schemaSha256",
        "value",
        "valueFingerprint",
    }:
        raise StateStoreV2Error(
            "ACTIVATION_GATE_INVALID", "journalAbsenceProof is not a full projection"
        )
    if proof["schemaId"] != "absence-proof-v2" or type(proof["value"]) is not dict:
        raise StateStoreV2Error(
            "ACTIVATION_GATE_INVALID", "journalAbsenceProof has another schema"
        )
    _require_sha256(str(proof["schemaSha256"]), "journalAbsenceProof.schemaSha256")
    _require_sha256(
        str(proof["valueFingerprint"]), "journalAbsenceProof.valueFingerprint"
    )
    if proof["value"].get("directorySyncCompleted") is not True:
        raise StateStoreV2Error(
            "ACTIVATION_GATE_INVALID", "journal absence was not directory-synchronized"
        )
    projection = {
        "manifestSemanticFingerprint": gate["manifestSemanticFingerprint"],
        "activationReceiptFingerprint": gate["activationReceiptFingerprint"],
        "journalAbsenceProof": proof,
    }
    expected = domain_fingerprint("codex-smart/activation-gate/v2", projection)
    if gate["gateFingerprint"] != expected:
        raise StateStoreV2Error(
            "ACTIVATION_GATE_INVALID", "gateFingerprint does not match the full gate"
        )
    canonical_json_v1(gate)
    return gate, canonical_json_v1(proof)


def _gate_from_node(row: sqlite3.Row) -> dict[str, Any]:
    try:
        proof = json.loads(str(row["admission_journal_absence_proof_json"]))
    except json.JSONDecodeError as error:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", "stored node gate proof is invalid JSON"
        ) from error
    gate = {
        "manifestSemanticFingerprint": row["admission_manifest_semantic_fingerprint"],
        "activationReceiptFingerprint": row["admission_activation_receipt_fingerprint"],
        "journalAbsenceProof": proof,
        "gateFingerprint": row["admission_gate_fingerprint"],
    }
    return _canonical_activation_gate(gate)[0]


def _gate_from_permit(row: sqlite3.Row) -> dict[str, Any]:
    try:
        proof = json.loads(str(row["journal_absence_proof_json"]))
    except json.JSONDecodeError as error:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", "stored permit gate proof is invalid JSON"
        ) from error
    gate = {
        "manifestSemanticFingerprint": row["manifest_semantic_fingerprint"],
        "activationReceiptFingerprint": row["activation_receipt_fingerprint"],
        "journalAbsenceProof": proof,
        "gateFingerprint": row["activation_gate_fingerprint"],
    }
    return _canonical_activation_gate(gate)[0]


def _launch_permit_record(row: sqlite3.Row) -> LaunchPermitV2:
    return LaunchPermitV2(
        permit_id=str(row["permit_id"]),
        admission_id=str(row["admission_id"]),
        route_id=str(row["route_id"]),
        node_id=str(row["node_id"]),
        reserved_control_epoch=int(row["reserved_control_epoch"]),
        activation_gate_fingerprint=str(row["activation_gate_fingerprint"]),
        permit_evidence_fingerprint=str(row["permit_evidence_fingerprint"]),
        state=str(row["state"]),
    )


def _stored_json_object(value: Any, name: str) -> dict[str, Any]:
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError as error:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", f"{name} is invalid JSON"
        ) from error
    if type(loaded) is not dict or canonical_json_v1(loaded) != value:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", f"{name} is not canonical JSON"
        )
    return loaded


def _request_context_from_stored_json_v2(value: Any) -> RequestContextV2:
    context = _stored_json_object(value, "routes.context_json")
    fields = {
        "schemaVersion",
        "shellSessionId",
        "sessionId",
        "turnId",
        "codexHome",
        "repoRoot",
        "baseSha",
        "worktreeFingerprint",
        "activationFingerprint",
        "compatibilityFingerprint",
        "issuedControlEpoch",
    }
    string_fields = fields - {"schemaVersion", "issuedControlEpoch"}
    if (
        set(context) != fields
        or context.get("schemaVersion") != 2
        or any(type(context.get(name)) is not str for name in string_fields)
        or type(context.get("issuedControlEpoch")) is not int
    ):
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID",
            "routes.context_json is not request-context-v2",
        )
    return RequestContextV2(
        shell_session_id=context["shellSessionId"],
        session_id=context["sessionId"],
        turn_id=context["turnId"],
        codex_home=context["codexHome"],
        repo_root=context["repoRoot"],
        base_sha=context["baseSha"],
        worktree_fingerprint=context["worktreeFingerprint"],
        activation_fingerprint=context["activationFingerprint"],
        compatibility_fingerprint=context["compatibilityFingerprint"],
        issued_control_epoch=context["issuedControlEpoch"],
    )


def _node_plan_projection(
    item: PlannedNodeV2, activation_fingerprint: str
) -> dict[str, Any]:
    return {
        "node_id": item.node_id,
        "ordinal": item.ordinal,
        "role": item.role,
        "mission": item.mission,
        "dependencies_json": canonical_json_v1(list(item.dependencies)),
        "context_refs_json": canonical_json_v1(list(item.context_refs)),
        "scope_id": item.scope_id,
        "artifact_profile_id": item.artifact_profile_id,
        "validation_profile_id": item.validation_profile_id,
        "assessment_json": canonical_json_v1(item.assessment),
        "risk_flags_json": canonical_json_v1(list(item.risk_flags)),
        "selected_model": item.selected_model,
        "reasoning_effort": item.reasoning_effort,
        "permission_profile_id": item.permission_profile_id,
        "disposition": item.disposition,
        "activation_fingerprint": activation_fingerprint,
    }


def _stored_json_list(value: Any, name: str) -> list[Any]:
    try:
        loaded = json.loads(str(value))
    except json.JSONDecodeError as error:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", f"{name} is invalid JSON"
        ) from error
    if type(loaded) is not list or canonical_json_v1(loaded) != value:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", f"{name} is not canonical JSON"
        )
    return loaded


def _encode_cursor(sequence: int) -> str:
    if not 1 <= sequence <= MAX_SAFE_INTEGER:
        raise StateStoreV2Error(
            "CURSOR_REJECT", "event sequence is outside the cursor range"
        )
    return f"cur2_{sequence:032x}"


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    _require_identifier(cursor, "cur2_")
    sequence = int(cursor[5:], 16)
    if not 1 <= sequence <= MAX_SAFE_INTEGER:
        raise StateStoreV2Error("CURSOR_REJECT", "cursor sequence is outside the range")
    return sequence


def _start_event_record(row: sqlite3.Row, start_request_id: str) -> StartEventV2:
    payload = _stored_json_object(row["message"], "events.message")
    required = {
        "startRequestId",
        "evidenceJobId",
        "admissionId",
        "attestation",
        "problem",
    }
    if set(payload) not in (required, required | {"metadata"}):
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", "start event payload shape differs"
        )
    if payload["startRequestId"] != start_request_id:
        raise StateStoreV2Error("DATABASE_VALUE_INVALID", "start event owner differs")
    for name in ("attestation", "problem"):
        if payload[name] is not None and type(payload[name]) is not dict:
            raise StateStoreV2Error(
                "DATABASE_VALUE_INVALID", f"event {name} is not an object"
            )
    return StartEventV2(
        sequence=int(row["sequence"]),
        event_at=_parse_iso(str(row["created_at"])),
        kind=str(row["event"]),
        start_state=str(row["state"]),
        evidence_job_id=(
            str(payload["evidenceJobId"])
            if payload["evidenceJobId"] is not None
            else None
        ),
        admission_id=(
            str(payload["admissionId"]) if payload["admissionId"] is not None else None
        ),
        attestation=payload["attestation"],
        problem=payload["problem"],
    )


def _start_terminal_result_record(row: sqlite3.Row) -> StartTerminalResultV2:
    attempt_id = str(row["attempt_id"])
    _require_identifier(attempt_id, "att2_")
    state = str(row["state"])
    if state not in _TERMINAL_ATTEMPT_STATES:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID",
            "attempt terminal projection is not terminal",
        )
    encoded = row["result_json"]
    if encoded is None:
        result_fingerprint = None
        result_bytes = 0
        inline_result = {"resultAvailable": False}
        result_truncated = False
    else:
        if not isinstance(encoded, str):
            raise StateStoreV2Error(
                "DATABASE_VALUE_INVALID",
                "attempt terminal result is not encoded text",
            )
        raw = encoded.encode("utf-8")
        result_fingerprint = hashlib.sha256(raw).hexdigest()
        result_bytes = len(raw)
        result = _stored_json_object(encoded, "attempts.result_json")
        inline_result, result_truncated = _bounded_inline_terminal_result(result)
    raw_error_code = row["error_code"]
    error_code = None if raw_error_code is None else str(raw_error_code)[:256]
    return StartTerminalResultV2(
        attempt_id=attempt_id,
        state=state,
        result_fingerprint=result_fingerprint,
        result_bytes=result_bytes,
        inline_result=inline_result,
        result_truncated=result_truncated,
        error_code=error_code,
    )


def _bounded_inline_terminal_result(
    result: dict[str, Any],
    *,
    max_bytes: int = _MAX_INLINE_TERMINAL_RESULT_BYTES,
) -> tuple[dict[str, Any], bool]:
    candidate: dict[str, Any] | None = None
    events = result.get("events")
    if type(events) is list:
        for event in reversed(events):
            if type(event) is not dict or event.get("type") != "item.completed":
                continue
            item = event.get("item")
            if type(item) is not dict or item.get("type") != "agent_message":
                continue
            text = item.get("text")
            if not isinstance(text, str):
                continue
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                continue
            if type(decoded) is dict:
                candidate = decoded
                break
    else:
        candidate = result
    if candidate is None:
        return {"resultAvailable": True}, True
    writer_publication = result.get("writerPublication")
    if type(events) is list and type(writer_publication) is dict:
        candidate = {
            **candidate,
            "writerPublication": writer_publication,
        }
    try:
        encoded = canonical_json_v1(candidate).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return {"resultAvailable": True}, True
    if len(encoded) <= max_bytes:
        return json.loads(encoded.decode("utf-8")), False
    summary = candidate.get("summary")
    if isinstance(summary, str) and summary:
        bounded = {"summary": summary[:4000]}
        while len(canonical_json_v1(bounded).encode("utf-8")) > max_bytes:
            bounded["summary"] = bounded["summary"][:-1]
        return bounded, True
    return {"resultAvailable": True}, True


def _attempt_recovery_intent_v2(
    *,
    attempt_id: str,
    pid: int,
    process_start_marker: str,
) -> tuple[str, str, str]:
    payload = {
        "attemptId": attempt_id,
        "failureCode": "CONTROLLER_RESTARTED",
        "pid": pid,
        "processStartMarker": process_start_marker,
        "schemaVersion": 2,
    }
    payload_json = canonical_json_v1(payload)
    payload_hash = domain_fingerprint(
        "codex-smart/stranded-attempt-recovery-payload/v2",
        payload,
    )
    intent_id = (
        "eri2_"
        + domain_fingerprint(
            "codex-smart/stranded-attempt-recovery-intent/v2",
            payload,
        )[:32]
    )
    return intent_id, payload_json, payload_hash


def _validate_optional_guard_identity_v2(
    guard_pid: int | None,
    guard_start_marker: str | None,
) -> None:
    if guard_pid is None and guard_start_marker is None:
        return
    if (
        type(guard_pid) is not int
        or guard_pid <= 0
        or type(guard_start_marker) is not str
        or not guard_start_marker
    ):
        raise StateStoreV2Error(
            "INVALID_PROCESS",
            "guard recovery identity must be wholly present or absent",
        )


def _permit_recovery_intent_v2(
    *,
    permit_id: str,
    guard_pid: int | None,
    guard_start_marker: str | None,
) -> tuple[str, str, str]:
    payload = {
        "failureCode": "CONTROLLER_RESTARTED",
        "guardPid": guard_pid,
        "guardStartMarker": guard_start_marker,
        "permitId": permit_id,
        "schemaVersion": 2,
    }
    payload_json = canonical_json_v1(payload)
    payload_hash = domain_fingerprint(
        "codex-smart/stranded-launch-permit-recovery-payload/v2",
        payload,
    )
    intent_id = (
        "epr2_"
        + domain_fingerprint(
            "codex-smart/stranded-launch-permit-recovery-intent/v2",
            payload,
        )[:32]
    )
    return intent_id, payload_json, payload_hash


def _terminal_attempt_problem(state: str) -> dict[str, Any] | None:
    if state == "SUCCEEDED":
        return None
    messages = {
        "FAILED": "Дочерний процесс завершился ошибкой.",
        "CANCELLED": "Дочерний процесс был отменён.",
        "QUARANTINED": "Результат дочернего процесса помещён в карантин.",
    }
    return {
        "category": "INTERNAL",
        "code": "INTERNAL_ERROR",
        "message": messages[state],
        "retryable": False,
    }


def _cancellation_record(
    *,
    start_request_id: str,
    start_state: str,
    evidence_state: str,
    idempotency_key: str,
    idempotency_status: str,
) -> CancellationV2:
    if start_state == "CANCELLED":
        status = "CANCELLED"
        terminal = True
    elif evidence_state == "CANCEL_REQUESTED":
        status = "CANCEL_REQUESTED"
        terminal = False
    elif start_state in {"STALE", "FAILED"}:
        status = "ALREADY_TERMINAL"
        terminal = True
    else:
        raise StateStoreV2Error(
            "DATABASE_VALUE_INVALID", "cancellation event and current state differ"
        )
    return CancellationV2(
        status=status,
        start_request_id=start_request_id,
        state=start_state,
        terminal=terminal,
        idempotency_key=idempotency_key,
        idempotency_status=idempotency_status,
    )
