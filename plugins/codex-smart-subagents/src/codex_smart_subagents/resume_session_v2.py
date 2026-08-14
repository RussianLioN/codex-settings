"""Долговечная аренда корневого Codex-сеанса для умного возобновления."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterator

from . import finite_file_lock_v2, operation_deadline_v2, sqlite_deadline_v2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .child_guard_v2 import system_process_start_marker_v2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BASE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_MAX_DOCUMENT_BYTES = 64 * 1024
_LEASE_LOCK_TIMEOUT_SECONDS = 0.25
_ELIGIBLE_ROUTE_STATES = frozenset(
    {
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
        "SUCCEEDED",
        "CANDIDATE_READY",
        "QUARANTINED",
        "CANCELLED",
        "FAILED",
        "STALE",
        "SKIPPED",
    }
)
_TERMINAL_ROUTE_STATES = frozenset(
    {
        "SUCCEEDED",
        "CANDIDATE_READY",
        "QUARANTINED",
        "CANCELLED",
        "FAILED",
        "STALE",
        "SKIPPED",
    }
)
_ATTACHMENT_STATES = frozenset(
    {
        "PREPARED",
        "CLAIMING",
        "BOUND",
        "PENDING_NEXT_TURN",
        "ACKNOWLEDGED",
        "DETACHED",
    }
)


def _deadline_limited_timeout(
    deadline: float | None,
    default_timeout_seconds: float,
) -> float:
    if deadline is None:
        return default_timeout_seconds
    if type(deadline) not in {int, float}:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_INVALID",
            "абсолютный срок resume неверен",
        )
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_EXCEEDED",
            "истёк абсолютный срок resume",
        )
    return min(default_timeout_seconds, remaining)


def _require_deadline_remaining(deadline: float | None) -> None:
    _deadline_limited_timeout(deadline, _LEASE_LOCK_TIMEOUT_SECONDS)


def _deadline_remaining_seconds(deadline: float | None) -> float:
    if deadline is None:
        return 0.2
    if type(deadline) not in {int, float}:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_INVALID",
            "абсолютный срок resume неверен",
        )
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_EXCEEDED",
            "истёк абсолютный срок resume",
        )
    return remaining


def _operation_deadline_for_resume_sqlite_v2(
    *,
    operation: str,
    deadline: float | None,
) -> operation_deadline_v2.OperationDeadlineV2:
    current = operation_deadline_v2.current_operation_deadline_v2()
    if current is not None:
        return current
    return operation_deadline_v2.OperationDeadlineV2.start(
        operation=operation,
        timeout_seconds=_deadline_remaining_seconds(deadline),
        timeout_code="RESUME_DEADLINE_EXCEEDED",
    )


class ResumeSessionV2Error(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class RootIdentityV2:
    pid: int
    process_start_marker: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise ValueError("pid корневого процесса неверен")
        _require_text(self.process_start_marker, "processStartMarker")

    def value(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "processStartMarker": self.process_start_marker,
        }


@dataclass(frozen=True)
class ProjectIdentityV2:
    repo_root: str
    base_sha: str
    worktree_fingerprint: str
    compatibility_fingerprint: str

    def __post_init__(self) -> None:
        if not Path(self.repo_root).is_absolute():
            raise ValueError("repoRoot не является абсолютным путём")
        if _BASE_SHA.fullmatch(self.base_sha) is None:
            raise ValueError("baseSha неверен")
        for value, name in (
            (self.worktree_fingerprint, "worktreeFingerprint"),
            (self.compatibility_fingerprint, "compatibilityFingerprint"),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} неверен")

    def value(self) -> dict[str, str]:
        return {
            "repoRoot": self.repo_root,
            "baseSha": self.base_sha,
            "worktreeFingerprint": self.worktree_fingerprint,
            "compatibilityFingerprint": self.compatibility_fingerprint,
        }

    def stable_value(self) -> dict[str, str]:
        return {
            "repoRoot": self.repo_root,
            "compatibilityFingerprint": self.compatibility_fingerprint,
        }

    def snapshot_value(self) -> dict[str, str]:
        return {
            "baseSha": self.base_sha,
            "worktreeFingerprint": self.worktree_fingerprint,
        }

    def same_stable_identity(self, other: "ProjectIdentityV2") -> bool:
        return self.stable_value() == other.stable_value()

    def same_snapshot(self, other: "ProjectIdentityV2") -> bool:
        return self.snapshot_value() == other.snapshot_value()


@dataclass(frozen=True)
class ResumeCandidateV2:
    route_id: str
    original_shell_session_id: str
    original_session_id: str
    original_turn_id: str
    route_state: str
    start_request_id: str | None
    node_id: str | None
    terminal_result_unacknowledged: bool

    def __post_init__(self) -> None:
        for value, name in (
            (self.route_id, "routeId"),
            (self.original_shell_session_id, "originalShellSessionId"),
            (self.original_session_id, "originalSessionId"),
            (self.original_turn_id, "originalTurnId"),
            (self.route_state, "routeState"),
        ):
            _require_text(value, name)
        if type(self.terminal_result_unacknowledged) is not bool:
            raise ValueError("terminalResultUnacknowledged неверен")


@dataclass(frozen=True)
class ResumeAttachmentV2:
    candidate: ResumeCandidateV2
    state: str
    bound_turn_id: str | None
    claim_nonce: str | None = None
    detached_reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in _ATTACHMENT_STATES:
            raise ValueError("состояние присоединения неверно")
        if self.state in {"PREPARED", "PENDING_NEXT_TURN"}:
            if self.bound_turn_id is not None:
                raise ValueError("ход присоединения неверен")
            if self.claim_nonce is not None or self.detached_reason is not None:
                raise ValueError("доказательство присоединения неверно")
            return
        if self.state == "DETACHED":
            if self.bound_turn_id is not None or self.claim_nonce is not None:
                raise ValueError("отсоединённое присоединение неверно")
            _require_text(self.detached_reason, "detachedReason")
            return
        _require_text(self.bound_turn_id, "boundTurnId")
        _require_text(self.claim_nonce, "claimNonce")
        if self.detached_reason is not None:
            raise ValueError("причина отсоединения неожиданна")


@dataclass(frozen=True)
class RootSessionLeaseV2:
    session_id: str
    shell_session_id: str
    generation: int
    root: RootIdentityV2
    project: ProjectIdentityV2
    attachment: ResumeAttachmentV2 | None
    active: bool = True
    schema_version: int = 3


@dataclass(frozen=True)
class ResumePreparationV2:
    status: str
    lease_generation: int
    route_id: str | None


@dataclass(frozen=True)
class ResumeClaimV2:
    status: str
    claim_nonce: str | None
    route_id: str | None


class RootSessionLeaseStoreV2:
    """Хранит одну проверяемую аренду на Codex-диалог."""

    def __init__(
        self,
        state_home: Path,
        *,
        process_marker_reader: Callable[[int], str | None],
    ) -> None:
        self.directory = state_home.expanduser().resolve() / "root-session-leases"
        self.process_marker_reader = process_marker_reader

    def register_startup(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
    ) -> RootSessionLeaseV2:
        _require_text(session_id, "sessionId")
        _require_text(shell_session_id, "shellSessionId")
        with self._locked(session_id):
            try:
                previous = self._read_unlocked(session_id)
            except (OSError, ValueError, ResumeSessionV2Error):
                previous = None
            if previous is not None and previous.active and self._root_is_live(previous.root):
                if previous.root != root or previous.shell_session_id != shell_session_id:
                    raise ResumeSessionV2Error(
                        "SESSION_OWNER_ACTIVE",
                        "диалог уже принадлежит другому живому корневому процессу",
                    )
                return previous
            lease = RootSessionLeaseV2(
                session_id=session_id,
                shell_session_id=shell_session_id,
                generation=1 if previous is None else previous.generation + 1,
                root=root,
                project=project,
                attachment=None,
                active=True,
            )
            self._write_unlocked(lease)
            return lease

    def prepare_resume(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
        candidate: ResumeCandidateV2 | None,
    ) -> ResumePreparationV2:
        _require_text(session_id, "sessionId")
        _require_text(shell_session_id, "shellSessionId")
        with self._locked(session_id):
            damaged_previous = False
            try:
                previous = self._read_unlocked(session_id)
            except (OSError, ValueError, ResumeSessionV2Error):
                previous = None
                damaged_previous = True
            if previous is not None and previous.active and self._root_is_live(previous.root):
                if previous.root == root and previous.shell_session_id == shell_session_id:
                    route_id = (
                        None
                        if previous.attachment is None
                        else previous.attachment.candidate.route_id
                    )
                    return ResumePreparationV2(
                        "RESUME_PREPARED", previous.generation, route_id
                    )
                return ResumePreparationV2(
                    "RESUME_OWNER_ACTIVE", previous.generation, None
                )

            generation = 1 if previous is None else previous.generation + 1
            status = "RESUME_NO_ROUTE"
            attachment: ResumeAttachmentV2 | None = None
            if damaged_previous:
                status = "RESUME_LEASE_INVALID"
                attachment = _detached_attachment(candidate, status)
            elif candidate is not None and candidate.original_session_id != session_id:
                status = "RESUME_ATTACHMENT_CHANGED"
                attachment = _detached_attachment(candidate, status)
            elif (
                candidate is not None
                and previous is not None
                and previous.attachment is not None
                and previous.attachment.state == "ACKNOWLEDGED"
                and previous.attachment.candidate.route_id == candidate.route_id
            ):
                status = "RESUME_NO_ROUTE"
            elif candidate is not None and previous is None:
                status = "RESUME_OWNER_UNPROVED"
                attachment = _detached_attachment(candidate, status)
            elif candidate is not None and previous is not None:
                if not previous.project.same_stable_identity(project):
                    status = "RESUME_COMPATIBILITY_MISMATCH"
                    if previous.project.repo_root != project.repo_root:
                        status = "RESUME_CONTEXT_MISMATCH"
                    attachment = _detached_attachment(candidate, status)
                elif not previous.project.same_snapshot(project):
                    status = "RESUME_SNAPSHOT_MISMATCH"
                    attachment = _detached_attachment(candidate, status)
                elif (
                    previous.attachment is not None
                    and previous.attachment.candidate.route_id != candidate.route_id
                ):
                    status = "RESUME_ATTACHMENT_CHANGED"
                    attachment = _detached_attachment(candidate, status)
                else:
                    status = "RESUME_PREPARED"
                    attachment = ResumeAttachmentV2(candidate, "PREPARED", None)
            lease = RootSessionLeaseV2(
                session_id=session_id,
                shell_session_id=shell_session_id,
                generation=generation,
                root=root,
                project=project,
                attachment=attachment,
                active=True,
            )
            self._write_unlocked(lease)
            return ResumePreparationV2(
                status,
                generation,
                None if attachment is None else attachment.candidate.route_id,
            )

    def begin_resume_claim(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
    ) -> ResumeClaimV2:
        """Атомарно отзывает прежнюю привязку и выдаёт одноразовый claim."""

        _require_text(turn_id, "turnId")
        with self._locked(session_id):
            lease = self._require_owner_unlocked(
                session_id, shell_session_id, root
            )
            attachment = lease.attachment
            if attachment is None or attachment.state in {"ACKNOWLEDGED", "DETACHED"}:
                return ResumeClaimV2(
                    "NO_ROUTE" if attachment is None else attachment.state,
                    None,
                    None if attachment is None else attachment.candidate.route_id,
                )
            if not lease.project.same_stable_identity(project):
                return self._detach_unlocked(lease, project, "STABLE_IDENTITY_MISMATCH")
            if not lease.project.same_snapshot(project):
                return self._detach_unlocked(lease, project, "SNAPSHOT_MISMATCH")
            if attachment.state == "CLAIMING":
                if attachment.bound_turn_id == turn_id:
                    return ResumeClaimV2(
                        "CLAIMING",
                        attachment.claim_nonce,
                        attachment.candidate.route_id,
                    )
                return self._detach_unlocked(lease, project, "INCOMPLETE_CLAIM")
            if attachment.state == "BOUND" and attachment.bound_turn_id == turn_id:
                return ResumeClaimV2(
                    "BOUND", attachment.claim_nonce, attachment.candidate.route_id
                )
            claim_nonce = "claim3_" + secrets.token_hex(16)
            claiming = replace(
                attachment,
                state="CLAIMING",
                bound_turn_id=turn_id,
                claim_nonce=claim_nonce,
                detached_reason=None,
            )
            self._write_unlocked(replace(lease, project=project, attachment=claiming))
            return ResumeClaimV2(
                "CLAIMING", claim_nonce, attachment.candidate.route_id
            )

    def finalize_resume_claim(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
        claim_nonce: str,
        context_claim_nonce: str,
    ) -> RootSessionLeaseV2:
        """Идемпотентно публикует BOUND только после записи того же nonce."""

        _require_text(claim_nonce, "claimNonce")
        _require_text(context_claim_nonce, "contextClaimNonce")
        if claim_nonce != context_claim_nonce:
            raise ResumeSessionV2Error(
                "RESUME_CLAIM_MISMATCH", "контекст хода не доказал claim"
            )
        with self._locked(session_id):
            lease = self._require_current_unlocked(
                session_id, shell_session_id, root, project
            )
            attachment = lease.attachment
            if attachment is None:
                raise ResumeSessionV2Error(
                    "RESUME_ATTACHMENT_CHANGED", "присоединение отсутствует"
                )
            if (
                attachment.state == "BOUND"
                and attachment.bound_turn_id == turn_id
                and attachment.claim_nonce == claim_nonce
            ):
                return lease
            if (
                attachment.state != "CLAIMING"
                or attachment.bound_turn_id != turn_id
                or attachment.claim_nonce != claim_nonce
            ):
                raise ResumeSessionV2Error(
                    "RESUME_CLAIM_MISMATCH", "claim аренды изменился"
                )
            updated = replace(
                lease,
                attachment=replace(attachment, state="BOUND"),
            )
            self._write_unlocked(updated)
            return updated

    def bind_resume(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
    ) -> RootSessionLeaseV2:
        claim = self.begin_resume_claim(
            session_id=session_id,
            shell_session_id=shell_session_id,
            turn_id=turn_id,
            root=root,
            project=project,
        )
        if claim.claim_nonce is None:
            lease = self.load(session_id)
            if lease is None:
                raise ResumeSessionV2Error(
                    "RESUME_ATTACHMENT_CHANGED", "аренда отсутствует"
                )
            return lease
        return self.finalize_resume_claim(
            session_id=session_id,
            shell_session_id=shell_session_id,
            turn_id=turn_id,
            root=root,
            project=project,
            claim_nonce=claim.claim_nonce,
            context_claim_nonce=claim.claim_nonce,
        )

    def defer_resume_to_next_turn(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
        route_id: str,
        deadline: float | None = None,
    ) -> RootSessionLeaseV2:
        _require_text(turn_id, "turnId")
        _require_text(route_id, "routeId")
        _require_deadline_remaining(deadline)
        with self._locked(session_id, deadline=deadline):
            lease = self._require_current_unlocked(
                session_id, shell_session_id, root, project
            )
            _require_deadline_remaining(deadline)
            attachment = lease.attachment
            if attachment is None or attachment.state == "ACKNOWLEDGED":
                return lease
            if attachment.candidate.route_id != route_id:
                raise ResumeSessionV2Error(
                    "RESUME_ATTACHMENT_CHANGED",
                    "присоединение относится к другому маршруту",
                )
            if attachment.state == "PENDING_NEXT_TURN":
                return lease
            if attachment.state != "BOUND" or attachment.bound_turn_id != turn_id:
                raise ResumeSessionV2Error(
                    "RESUME_ATTACHMENT_CHANGED",
                    "присоединение связано с другим активным ходом",
                )
            updated = replace(
                lease,
                attachment=replace(
                    attachment,
                    state="PENDING_NEXT_TURN",
                    bound_turn_id=None,
                    claim_nonce=None,
                ),
            )
            _require_deadline_remaining(deadline)
            self._write_unlocked(updated)
            return updated

    def authorize_route(
        self,
        *,
        route_id: str,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
        deadline: float | None = None,
    ) -> bool:
        try:
            lease = self.load(session_id, deadline=deadline)
        except ResumeSessionV2Error as exc:
            if exc.code == "RESUME_DEADLINE_EXCEEDED":
                raise
            return False
        except (OSError, ValueError):
            return False
        if (
            lease is None
            or lease.shell_session_id != shell_session_id
            or lease.root != root
            or lease.project != project
            or not lease.active
            or not self._root_is_live(root)
            or lease.attachment is None
            or lease.attachment.state != "BOUND"
            or lease.attachment.bound_turn_id != turn_id
            or lease.attachment.candidate.route_id != route_id
            or lease.attachment.candidate.original_session_id != session_id
        ):
            return False
        return True

    def acknowledge_result(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        turn_id: str,
        root: RootIdentityV2,
        route_id: str,
        deadline: float | None = None,
    ) -> RootSessionLeaseV2:
        _require_deadline_remaining(deadline)
        with self._locked(session_id, deadline=deadline):
            lease = self._read_unlocked(session_id)
            _require_deadline_remaining(deadline)
            if (
                lease is None
                or lease.shell_session_id != shell_session_id
                or lease.root != root
                or lease.attachment is None
                or lease.attachment.bound_turn_id != turn_id
                or lease.attachment.candidate.route_id != route_id
            ):
                raise ResumeSessionV2Error(
                    "RESUME_ATTACHMENT_CHANGED",
                    "результат относится к другому присоединению",
                )
            if lease.attachment.state == "ACKNOWLEDGED":
                return lease
            if lease.attachment.state != "BOUND":
                raise ResumeSessionV2Error(
                    "RESUME_RESULT_NOT_BINDABLE",
                    "результат нельзя подтвердить в текущем состоянии",
                )
            updated = replace(
                lease,
                attachment=replace(lease.attachment, state="ACKNOWLEDGED"),
            )
            _require_deadline_remaining(deadline)
            self._write_unlocked(updated)
            return updated

    def release(
        self,
        *,
        session_id: str,
        shell_session_id: str,
        root: RootIdentityV2,
    ) -> bool:
        with self._locked(session_id):
            lease = self._read_unlocked(session_id)
            if lease is None:
                return True
            if lease.shell_session_id != shell_session_id or lease.root != root:
                return False
            self._write_unlocked(replace(lease, active=False))
            return True

    def load(
        self,
        session_id: str,
        *,
        deadline: float | None = None,
    ) -> RootSessionLeaseV2 | None:
        _require_text(session_id, "sessionId")
        _require_deadline_remaining(deadline)
        with self._locked(session_id, deadline=deadline):
            _require_deadline_remaining(deadline)
            return self._read_unlocked(session_id)

    def _require_current_unlocked(
        self,
        session_id: str,
        shell_session_id: str,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
    ) -> RootSessionLeaseV2:
        lease = self._require_owner_unlocked(session_id, shell_session_id, root)
        if (
            not lease.project.same_stable_identity(project)
            or not lease.project.same_snapshot(project)
        ):
            raise ResumeSessionV2Error(
                "RESUME_ATTACHMENT_CHANGED",
                "аренда корневого сеанса изменилась",
            )
        return lease

    def _require_owner_unlocked(
        self,
        session_id: str,
        shell_session_id: str,
        root: RootIdentityV2,
    ) -> RootSessionLeaseV2:
        lease = self._read_unlocked(session_id)
        if (
            lease is None
            or lease.shell_session_id != shell_session_id
            or lease.root != root
            or not lease.active
            or not self._root_is_live(root)
        ):
            raise ResumeSessionV2Error(
                "RESUME_ATTACHMENT_CHANGED",
                "аренда корневого сеанса изменилась",
            )
        return lease

    def _detach_unlocked(
        self,
        lease: RootSessionLeaseV2,
        project: ProjectIdentityV2,
        reason: str,
    ) -> ResumeClaimV2:
        attachment = lease.attachment
        if attachment is None:
            return ResumeClaimV2("NO_ROUTE", None, None)
        detached = replace(
            attachment,
            state="DETACHED",
            bound_turn_id=None,
            claim_nonce=None,
            detached_reason=reason,
        )
        self._write_unlocked(replace(lease, project=project, attachment=detached))
        return ResumeClaimV2("DETACHED", None, attachment.candidate.route_id)

    def _root_is_live(self, root: RootIdentityV2) -> bool:
        try:
            observed = self.process_marker_reader(root.pid)
        except (OSError, ValueError):
            return False
        return observed == root.process_start_marker

    def _path(self, session_id: str) -> Path:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"session-{token}.json"

    def _lock_path(self, session_id: str) -> Path:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"session-{token}.lock"

    @contextmanager
    def _locked(
        self,
        session_id: str,
        *,
        deadline: float | None = None,
    ) -> Iterator[None]:
        lock_timeout = _deadline_limited_timeout(deadline, _LEASE_LOCK_TIMEOUT_SECONDS)
        self._prepare_directory()
        descriptor = os.open(
            self._lock_path(session_id),
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        acquired = False
        try:
            self._require_private_regular_descriptor(descriptor, "файл блокировки")
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=True,
                    timeout_seconds=lock_timeout,
                    timeout_code="RESUME_LEASE_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as exc:
                raise ResumeSessionV2Error(
                    "RESUME_LEASE_BUSY",
                    "аренда корневого сеанса временно занята",
                ) from exc
            acquired = True
            _require_deadline_remaining(deadline)
            yield
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_unlocked(self, session_id: str) -> RootSessionLeaseV2 | None:
        path = self._path(session_id)
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return None
        try:
            self._require_private_regular_descriptor(descriptor, "файл аренды")
            raw = os.read(descriptor, _MAX_DOCUMENT_BYTES + 1)
        finally:
            os.close(descriptor)
        if not raw or len(raw) > _MAX_DOCUMENT_BYTES:
            raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "размер аренды неверен")
        value = json.loads(raw.decode("utf-8"))
        return _lease_from_value(value)

    def _write_unlocked(self, lease: RootSessionLeaseV2) -> None:
        value = _lease_value(lease)
        encoded = canonical_json_bytes(value)
        if len(encoded) > _MAX_DOCUMENT_BYTES:
            raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "аренда слишком велика")
        path = self._path(lease.session_id)
        temporary = self.directory / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        self._fsync_directory()

    def _prepare_directory(self) -> None:
        try:
            self.directory.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            pass
        info = os.lstat(self.directory)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise ResumeSessionV2Error(
                "RESUME_LEASE_INVALID",
                "каталог аренды имеет недоверенного владельца или тип",
            )
        os.chmod(self.directory, 0o700)

    @staticmethod
    def _require_private_regular_descriptor(descriptor: int, label: str) -> None:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise ResumeSessionV2Error(
                "RESUME_LEASE_INVALID",
                f"{label} имеет недоверенного владельца или тип",
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(descriptor, 0o600)

    def _fsync_directory(self) -> None:
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def system_process_marker_reader_v2(pid: int) -> str | None:
    try:
        return system_process_start_marker_v2(pid)
    except (OSError, ValueError):
        return None


def discover_resume_candidate_v2(
    database_path: Path,
    *,
    session_id: str,
    deadline: float | None = None,
) -> ResumeCandidateV2 | None:
    """Выбирает самый новый доказуемый маршрут выбранного Codex-диалога."""

    _require_text(session_id, "sessionId")
    _require_deadline_remaining(deadline)
    operation_deadline = _operation_deadline_for_resume_sqlite_v2(
        operation="resume-candidate-discovery",
        deadline=deadline,
    )
    connection: sqlite3.Connection | None = None
    try:
        with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
            operation_deadline.checkpoint()
            timeout = operation_deadline.bounded_timeout_seconds(
                local_cap_seconds=0.2
            )
            connection = sqlite_deadline_v2.connect_sqlite_with_deadline_v2(
                database_path.resolve().as_uri() + "?mode=ro",
                uri=True,
                timeout=timeout,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("pragma query_only=on")
            rows = connection.execute(
                "select route_id,shell_session_id,session_id,turn_id,state,"
                "terminal_result_json from routes where session_id=? "
                "and disposition='DELEGATE' "
                "order by created_at desc,route_id desc limit 32",
                (session_id,),
            ).fetchall()
            for route in rows:
                state = str(route["state"])
                if state not in _ELIGIBLE_ROUTE_STATES:
                    continue
                start = connection.execute(
                    "select s.start_request_id,j.boundary_id from start_requests s "
                    "left join account_evidence_jobs j on "
                    "j.evidence_job_id=s.evidence_job_id "
                    "where s.route_id=? "
                    "order by s.created_at desc,s.start_request_id desc limit 1",
                    (route["route_id"],),
                ).fetchone()
                node_id: str | None
                start_request_id: str | None
                if start is not None:
                    start_request_id = str(start["start_request_id"])
                    node_id = (
                        None
                        if start["boundary_id"] is None
                        else str(start["boundary_id"])
                    )
                else:
                    node = connection.execute(
                        "select node_id from nodes where route_id=? "
                        "order by ordinal,node_id limit 1",
                        (route["route_id"],),
                    ).fetchone()
                    start_request_id = None
                    node_id = None if node is None else str(node["node_id"])
                if node_id is None:
                    continue
                candidate = ResumeCandidateV2(
                    route_id=str(route["route_id"]),
                    original_shell_session_id=str(route["shell_session_id"]),
                    original_session_id=str(route["session_id"]),
                    original_turn_id=str(route["turn_id"]),
                    route_state=state,
                    start_request_id=start_request_id,
                    node_id=node_id,
                    terminal_result_unacknowledged=(
                        state in _TERMINAL_ROUTE_STATES
                        and route["terminal_result_json"] is not None
                    ),
                )
                operation_deadline.checkpoint()
                _require_deadline_remaining(deadline)
                return candidate
            operation_deadline.checkpoint()
            _require_deadline_remaining(deadline)
    except operation_deadline_v2.OperationDeadlineExceededV2 as exc:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_EXCEEDED",
            "истёк абсолютный срок resume",
        ) from exc
    except sqlite3.Error as exc:
        raise ResumeSessionV2Error(
            "RESUME_ROUTE_READ_FAILED",
            "не удалось прочитать маршрут resume",
        ) from exc
    finally:
        if connection is not None:
            connection.close()
    return None


def route_is_terminal_v2(
    database_path: Path,
    route_id: str,
    *,
    deadline: float | None = None,
) -> bool:
    _require_text(route_id, "routeId")
    _require_deadline_remaining(deadline)
    operation_deadline = _operation_deadline_for_resume_sqlite_v2(
        operation="resume-route-terminal-check",
        deadline=deadline,
    )
    connection: sqlite3.Connection | None = None
    try:
        with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
            operation_deadline.checkpoint()
            timeout_seconds = operation_deadline.bounded_timeout_seconds(
                local_cap_seconds=0.2
            )
            connection = sqlite_deadline_v2.connect_sqlite_with_deadline_v2(
                database_path.resolve().as_uri() + "?mode=ro",
                uri=True,
                timeout=timeout_seconds,
            )
            connection.execute("pragma query_only=on")
            operation_deadline.checkpoint()
            row = connection.execute(
                "select state from routes where route_id=?",
                (route_id,),
            ).fetchone()
            operation_deadline.checkpoint()
            _require_deadline_remaining(deadline)
    except operation_deadline_v2.OperationDeadlineExceededV2 as exc:
        raise ResumeSessionV2Error(
            "RESUME_DEADLINE_EXCEEDED",
            "истёк абсолютный срок resume",
        ) from exc
    except sqlite3.Error as exc:
        raise ResumeSessionV2Error(
            "RESUME_ROUTE_READ_FAILED",
            "не удалось прочитать маршрут resume",
        ) from exc
    finally:
        if connection is not None:
            connection.close()
    if row is None:
        raise ResumeSessionV2Error(
            "RESUME_ATTACHMENT_CHANGED", "присоединённый маршрут отсутствует"
        )
    return str(row[0]) in _TERMINAL_ROUTE_STATES


def _lease_value(lease: RootSessionLeaseV2) -> dict[str, object]:
    attachment: dict[str, object] | None = None
    if lease.attachment is not None:
        candidate = lease.attachment.candidate
        attachment = {
            "routeId": candidate.route_id,
            "originalShellSessionId": candidate.original_shell_session_id,
            "originalSessionId": candidate.original_session_id,
            "originalTurnId": candidate.original_turn_id,
            "routeState": candidate.route_state,
            "startRequestId": candidate.start_request_id,
            "nodeId": candidate.node_id,
            "terminalResultUnacknowledged": candidate.terminal_result_unacknowledged,
            "state": lease.attachment.state,
            "boundTurnId": lease.attachment.bound_turn_id,
            "claimNonce": lease.attachment.claim_nonce,
            "detachedReason": lease.attachment.detached_reason,
        }
    projection: dict[str, object] = {
        "schemaVersion": 3,
        "sessionId": lease.session_id,
        "shellSessionId": lease.shell_session_id,
        "generation": lease.generation,
        "root": lease.root.value(),
        "stableProjectIdentity": lease.project.stable_value(),
        "turnSnapshot": lease.project.snapshot_value(),
        "attachment": attachment,
        "active": lease.active,
    }
    return {
        **projection,
        "leaseFingerprint": domain_fingerprint(
            "codex-smart/root-session-lease/v3", projection
        ),
    }


def _lease_from_value(value: object) -> RootSessionLeaseV2:
    if type(value) is not dict:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "форма аренды неверна")
    if value.get("schemaVersion") == 2:
        return _lease_from_v2_value(value)
    if type(value) is not dict or set(value) != {
        "schemaVersion",
        "sessionId",
        "shellSessionId",
        "generation",
        "root",
        "stableProjectIdentity",
        "turnSnapshot",
        "attachment",
        "active",
        "leaseFingerprint",
    }:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "форма аренды неверна")
    projection = dict(value)
    fingerprint = projection.pop("leaseFingerprint")
    if value["schemaVersion"] != 3 or fingerprint != domain_fingerprint(
        "codex-smart/root-session-lease/v3", projection
    ):
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "отпечаток аренды неверен")
    root_value = value["root"]
    stable_value = value["stableProjectIdentity"]
    snapshot_value = value["turnSnapshot"]
    if (
        type(root_value) is not dict
        or type(stable_value) is not dict
        or type(snapshot_value) is not dict
    ):
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "личность аренды неверна")
    root = RootIdentityV2(
        pid=root_value.get("pid"),
        process_start_marker=root_value.get("processStartMarker"),
    )
    project = ProjectIdentityV2(
        repo_root=stable_value.get("repoRoot"),
        base_sha=snapshot_value.get("baseSha"),
        worktree_fingerprint=snapshot_value.get("worktreeFingerprint"),
        compatibility_fingerprint=stable_value.get("compatibilityFingerprint"),
    )
    attachment_value = value["attachment"]
    attachment = None
    if attachment_value is not None:
        if type(attachment_value) is not dict or set(attachment_value) != {
            "routeId",
            "originalShellSessionId",
            "originalSessionId",
            "originalTurnId",
            "routeState",
            "startRequestId",
            "nodeId",
            "terminalResultUnacknowledged",
            "state",
            "boundTurnId",
            "claimNonce",
            "detachedReason",
        }:
            raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "присоединение неверно")
        candidate = ResumeCandidateV2(
            route_id=attachment_value.get("routeId"),
            original_shell_session_id=attachment_value.get("originalShellSessionId"),
            original_session_id=attachment_value.get("originalSessionId"),
            original_turn_id=attachment_value.get("originalTurnId"),
            route_state=attachment_value.get("routeState"),
            start_request_id=attachment_value.get("startRequestId"),
            node_id=attachment_value.get("nodeId"),
            terminal_result_unacknowledged=attachment_value.get(
                "terminalResultUnacknowledged"
            ),
        )
        attachment = ResumeAttachmentV2(
            candidate=candidate,
            state=attachment_value.get("state"),
            bound_turn_id=attachment_value.get("boundTurnId"),
            claim_nonce=attachment_value.get("claimNonce"),
            detached_reason=attachment_value.get("detachedReason"),
        )
    generation = value["generation"]
    if type(generation) is not int or generation < 1:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "поколение аренды неверно")
    if type(value["active"]) is not bool:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "признак активности неверен")
    return RootSessionLeaseV2(
        session_id=value["sessionId"],
        shell_session_id=value["shellSessionId"],
        generation=generation,
        root=root,
        project=project,
        attachment=attachment,
        active=value["active"],
        schema_version=3,
    )


def _lease_from_v2_value(value: dict[str, object]) -> RootSessionLeaseV2:
    expected_fields = {
        "schemaVersion",
        "sessionId",
        "shellSessionId",
        "generation",
        "root",
        "project",
        "attachment",
        "active",
        "leaseFingerprint",
    }
    if set(value) != expected_fields:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "форма аренды v2 неверна")
    projection = dict(value)
    fingerprint = projection.pop("leaseFingerprint")
    if fingerprint != domain_fingerprint(
        "codex-smart/root-session-lease/v2", projection
    ):
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "отпечаток аренды v2 неверен")
    root_value = value["root"]
    project_value = value["project"]
    if type(root_value) is not dict or type(project_value) is not dict:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "личность аренды v2 неверна")
    root = RootIdentityV2(
        pid=root_value.get("pid"),
        process_start_marker=root_value.get("processStartMarker"),
    )
    project = ProjectIdentityV2(
        repo_root=project_value.get("repoRoot"),
        base_sha=project_value.get("baseSha"),
        worktree_fingerprint=project_value.get("worktreeFingerprint"),
        compatibility_fingerprint=project_value.get("compatibilityFingerprint"),
    )
    attachment_value = value["attachment"]
    attachment: ResumeAttachmentV2 | None = None
    if attachment_value is not None:
        if type(attachment_value) is not dict or set(attachment_value) != {
            "routeId",
            "originalShellSessionId",
            "originalSessionId",
            "originalTurnId",
            "routeState",
            "startRequestId",
            "nodeId",
            "terminalResultUnacknowledged",
            "state",
            "boundTurnId",
        }:
            raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "присоединение v2 неверно")
        candidate = ResumeCandidateV2(
            route_id=attachment_value.get("routeId"),
            original_shell_session_id=attachment_value.get("originalShellSessionId"),
            original_session_id=attachment_value.get("originalSessionId"),
            original_turn_id=attachment_value.get("originalTurnId"),
            route_state=attachment_value.get("routeState"),
            start_request_id=attachment_value.get("startRequestId"),
            node_id=attachment_value.get("nodeId"),
            terminal_result_unacknowledged=attachment_value.get(
                "terminalResultUnacknowledged"
            ),
        )
        state = attachment_value.get("state")
        bound_turn_id = attachment_value.get("boundTurnId")
        claim_nonce = None
        if state in {"BOUND", "ACKNOWLEDGED"}:
            claim_nonce = "claim3_" + str(fingerprint)[:32]
        attachment = ResumeAttachmentV2(
            candidate=candidate,
            state=state,
            bound_turn_id=bound_turn_id,
            claim_nonce=claim_nonce,
        )
    generation = value["generation"]
    if type(generation) is not int or generation < 1 or type(value["active"]) is not bool:
        raise ResumeSessionV2Error("RESUME_LEASE_INVALID", "поля аренды v2 неверны")
    return RootSessionLeaseV2(
        session_id=value["sessionId"],
        shell_session_id=value["shellSessionId"],
        generation=generation,
        root=root,
        project=project,
        attachment=attachment,
        active=value["active"],
        schema_version=2,
    )


def _detached_attachment(
    candidate: ResumeCandidateV2 | None,
    reason: str,
) -> ResumeAttachmentV2 | None:
    if candidate is None:
        return None
    return ResumeAttachmentV2(
        candidate=candidate,
        state="DETACHED",
        bound_turn_id=None,
        detached_reason=reason,
    )


def _require_text(value: object, name: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\0" in value
    ):
        raise ValueError(f"{name} неверен")


__all__ = [
    "ProjectIdentityV2",
    "ResumeAttachmentV2",
    "ResumeCandidateV2",
    "ResumeClaimV2",
    "ResumePreparationV2",
    "ResumeSessionV2Error",
    "RootIdentityV2",
    "RootSessionLeaseStoreV2",
    "RootSessionLeaseV2",
    "discover_resume_candidate_v2",
    "route_is_terminal_v2",
    "system_process_marker_reader_v2",
]
