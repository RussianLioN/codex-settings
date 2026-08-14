"""Долговечное владение временными группами процессов версии 2.

Хранилище является узким адаптером между надзором одной операции и следующим
запуском установщика. Оно не выбирает процессы по одному PID: каждая запись
содержит полную, повторно проверяемую личность лидера нового сеанса.
"""

from __future__ import annotations

import copy
import errno
import fcntl
import hmac
import json
import os
import re
import signal
import stat
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from . import finite_file_lock_v2, operation_deadline_v2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .operation_process_group_supervisor_v2 import (
    ProcessIdentityV2,
    TransientProcessLeaseV2,
    validate_cleanup_obligation_v2,
)


_RECORD_KEYS = frozenset(
    {
        "schemaVersion",
        "recordKind",
        "leaseId",
        "processLabel",
        "pid",
        "processGroupId",
        "sessionId",
        "processStartMarker",
        "context",
        "state",
        "cleanupObligation",
        "recordFingerprint",
    }
)
_CANDIDATE_CONTEXT_KEYS = frozenset(
    {
        "schemaVersion",
        "contextKind",
        "operationId",
        "candidateId",
        "controllerStartId",
        "actionFingerprint",
        "dispatchReceiptFingerprint",
    }
)
_GENERIC_CONTEXT_KEYS = frozenset(
    {
        "schemaVersion",
        "contextKind",
        "processLabel",
        "operation",
        "phase",
        "invocationId",
    }
)
_GENERIC_SUPERVISOR_CONTEXT_KEYS = frozenset(
    {"schemaVersion", "contextKind", "processLabel"}
)
_RESOLVED_OUTCOMES = frozenset(
    {"accepted", "verified-exit", "soft-terminated"}
)
_RECORD_DOMAIN = "codex-smart/transient-process-ownership/v2"
_LEASE_ID = re.compile(r"^transient-[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_CANDIDATE_ID = re.compile(r"^cand2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_INVOCATION_ID = re.compile(r"^inv2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_RECORD_BYTES = 512 * 1024
_DIRECTORY_NAME = "transient-process-ownership-v2"
_HOME_LOCK_TIMEOUT_SECONDS = 30.0
_HOME_LOCK_TIMEOUT_CODE = "DURABLE_OWNERSHIP_LOCK_TIMEOUT"
_RECOVERY_LOCK_TIMEOUT_SECONDS = 30.0
_RECOVERY_LOCK_TIMEOUT_CODE = "DURABLE_OWNERSHIP_RECOVERY_LOCK_TIMEOUT"
_RECOVERY_LOCK_NAME = ".durable-process-ownership-recovery-v2.lock"
_RECOVERY_THREAD_LOCKS_GUARD = threading.Lock()
_RECOVERY_THREAD_LOCKS: weakref.WeakValueDictionary[
    tuple[int, int], Any
] = weakref.WeakValueDictionary()


@dataclass
class DurableProcessOwnershipV2Error(RuntimeError):
    """Отказ долговечного адаптера с устойчивым машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class OutstandingDurableProcessOwnershipV2(DurableProcessOwnershipV2Error):
    """Обычное продолжение закрыто до явного восстановления."""

    def __init__(self, lease_ids: tuple[str, ...]) -> None:
        self.lease_ids = lease_ids
        super().__init__(
            "DURABLE_PROCESS_OWNERSHIP_OUTSTANDING",
            "не разрешено долговечное владение: " + ", ".join(lease_ids),
        )


@dataclass(frozen=True)
class DurableOwnershipRecoveryResultV2:
    """Итог одного явного прохода восстановления."""

    resolved_lease_ids: tuple[str, ...]
    remaining_lease_ids: tuple[str, ...]


@dataclass(frozen=True)
class DurableProcessOwnershipRecordV2:
    """Одна закрытая запись точного временного процесса."""

    lease_id: str
    process_label: str
    pid: int
    process_group_id: int
    session_id: int
    process_start_marker: str
    context: Mapping[str, object]
    state: str
    cleanup_obligation: Mapping[str, object] | None
    record_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "context", copy.deepcopy(dict(self.context)))
        if self.cleanup_obligation is not None:
            object.__setattr__(
                self,
                "cleanup_obligation",
                copy.deepcopy(dict(self.cleanup_obligation)),
            )

    @classmethod
    def create(
        cls,
        *,
        lease: TransientProcessLeaseV2,
        context: Mapping[str, object],
        state: str = "OWNED",
        cleanup_obligation: Mapping[str, object] | None = None,
    ) -> DurableProcessOwnershipRecordV2:
        _validate_lease(lease)
        checked_context = _validate_complete_context(context)
        unsigned = {
            "schemaVersion": 2,
            "recordKind": "transient-process-ownership-v2",
            "leaseId": lease.lease_id,
            "processLabel": lease.label,
            "pid": lease.pid,
            "processGroupId": lease.process_group_id,
            "sessionId": lease.session_id,
            "processStartMarker": lease.process_start_marker,
            "context": checked_context,
            "state": state,
            "cleanupObligation": (
                None
                if cleanup_obligation is None
                else copy.deepcopy(dict(cleanup_obligation))
            ),
        }
        return cls.from_mapping(
            {
                **unsigned,
                "recordFingerprint": domain_fingerprint(
                    _RECORD_DOMAIN,
                    unsigned,
                ),
            }
        )

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> DurableProcessOwnershipRecordV2:
        if type(value) is not dict or set(value) != _RECORD_KEYS:
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "запись имеет неполный или расширенный набор полей",
            )
        if (
            value.get("schemaVersion") != 2
            or value.get("recordKind") != "transient-process-ownership-v2"
        ):
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "вид или версия записи неверны",
            )
        lease_id = value.get("leaseId")
        if type(lease_id) is not str or _LEASE_ID.fullmatch(lease_id) is None:
            _fail("DURABLE_OWNERSHIP_RECORD_INVALID", "leaseId неверен")
        process_label = _bounded_name(
            value.get("processLabel"),
            "processLabel",
            code="DURABLE_OWNERSHIP_RECORD_INVALID",
        )
        integers: dict[str, int] = {}
        for name in ("pid", "processGroupId", "sessionId"):
            item = value.get(name)
            if type(item) is not int or item <= 0:
                _fail(
                    "DURABLE_OWNERSHIP_RECORD_INVALID",
                    f"{name} должен быть положительным целым",
                )
            integers[name] = item
        if not (
            integers["pid"]
            == integers["processGroupId"]
            == integers["sessionId"]
        ):
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "процесс должен быть лидером отдельной группы и сеанса",
            )
        marker = value.get("processStartMarker")
        if (
            type(marker) is not str
            or not marker
            or "\0" in marker
            or len(marker.encode("utf-8")) > 4096
        ):
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "processStartMarker неверен",
            )
        context = _validate_complete_context(value.get("context"))
        state = value.get("state")
        cleanup = value.get("cleanupObligation")
        if state == "OWNED":
            if cleanup is not None:
                _fail(
                    "DURABLE_OWNERSHIP_RECORD_INVALID",
                    "OWNED не должен содержать обязанность очистки",
                )
            checked_cleanup = None
        elif state == "CLEANUP_REQUIRED":
            try:
                checked_cleanup = validate_cleanup_obligation_v2(cleanup)
            except (TypeError, ValueError) as exc:
                raise DurableProcessOwnershipV2Error(
                    "DURABLE_OWNERSHIP_RECORD_INVALID",
                    "обязанность очистки не прошла закрытую проверку",
                ) from exc
            expected_identity = checked_cleanup["expectedProcessIdentity"]
            if (
                checked_cleanup["obligationId"] != lease_id
                or checked_cleanup["processLabel"] != process_label
                or checked_cleanup["pid"] != integers["pid"]
                or checked_cleanup["processGroupId"]
                != integers["processGroupId"]
                or expected_identity
                != {
                    "pid": integers["pid"],
                    "processGroupId": integers["processGroupId"],
                    "sessionId": integers["sessionId"],
                    "startMarker": marker,
                }
            ):
                _fail(
                    "DURABLE_OWNERSHIP_RECORD_INVALID",
                    "обязанность очистки относится к другой личности",
                )
        else:
            _fail("DURABLE_OWNERSHIP_RECORD_INVALID", "state неверен")
        fingerprint = value.get("recordFingerprint")
        if type(fingerprint) is not str or _SHA256.fullmatch(fingerprint) is None:
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "recordFingerprint не является SHA-256",
            )
        unsigned = copy.deepcopy(dict(value))
        unsigned.pop("recordFingerprint")
        if not hmac.compare_digest(
            fingerprint,
            domain_fingerprint(_RECORD_DOMAIN, unsigned),
        ):
            _fail(
                "DURABLE_OWNERSHIP_RECORD_INVALID",
                "recordFingerprint не совпал с содержимым",
            )
        return cls(
            lease_id=lease_id,
            process_label=process_label,
            pid=integers["pid"],
            process_group_id=integers["processGroupId"],
            session_id=integers["sessionId"],
            process_start_marker=marker,
            context=context,
            state=state,
            cleanup_obligation=checked_cleanup,
            record_fingerprint=fingerprint,
        )

    def to_document(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "recordKind": "transient-process-ownership-v2",
            "leaseId": self.lease_id,
            "processLabel": self.process_label,
            "pid": self.pid,
            "processGroupId": self.process_group_id,
            "sessionId": self.session_id,
            "processStartMarker": self.process_start_marker,
            "context": copy.deepcopy(dict(self.context)),
            "state": self.state,
            "cleanupObligation": (
                None
                if self.cleanup_obligation is None
                else copy.deepcopy(dict(self.cleanup_obligation))
            ),
            "recordFingerprint": self.record_fingerprint,
        }


class DurableProcessOwnershipStoreV2:
    """Атомарное частное хранилище записей одного CODEX_HOME."""

    def __init__(
        self,
        codex_home: Path,
        *,
        operation: str | None = None,
        phase: str | None = None,
        invocation_id: str | None = None,
    ) -> None:
        if not isinstance(codex_home, Path) or not codex_home.is_absolute():
            raise TypeError("codex_home must be an absolute Path")
        self.codex_home = codex_home
        self.operation = operation
        self.phase = phase
        self.invocation_id = invocation_id
        if any(item is not None for item in (operation, phase, invocation_id)):
            if not all(item is not None for item in (operation, phase, invocation_id)):
                raise ValueError(
                    "operation, phase and invocation_id must be configured together"
                )
            _bounded_name(
                operation,
                "operation",
                code="DURABLE_OWNERSHIP_CONTEXT_INVALID",
            )
            _bounded_name(
                phase,
                "phase",
                code="DURABLE_OWNERSHIP_CONTEXT_INVALID",
            )
            if (
                type(invocation_id) is not str
                or _INVOCATION_ID.fullmatch(invocation_id) is None
            ):
                _fail(
                    "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                    "invocationId неверен",
                )

    def publish(
        self,
        lease: TransientProcessLeaseV2,
        context: Mapping[str, object],
    ) -> DurableProcessOwnershipRecordV2:
        """Создать запись либо доказать, что точная запись уже существует."""

        checked_context = self._complete_context(context)
        record = DurableProcessOwnershipRecordV2.create(
            lease=lease,
            context=checked_context,
        )
        home_descriptor = self._lock_home()
        try:
            root = self._ensure_ownership_directory()
            path = root / f"{lease.lease_id}.json"
            if _lexists(path):
                existing = _read_record(path)
                if existing != record:
                    _fail(
                        "DURABLE_OWNERSHIP_CONFLICT",
                        "leaseId уже связан с другой записью",
                    )
                return existing
            _publish_new_record(path, record)
            loaded = _read_record(path)
            if loaded != record:
                _fail(
                    "DURABLE_OWNERSHIP_PUBLICATION_CHANGED",
                    "запись изменилась после публикации",
                )
            return loaded
        finally:
            _unlock_close(home_descriptor)

    def transition(
        self,
        lease: TransientProcessLeaseV2,
        context: Mapping[str, object],
        outcome: str,
        cleanup_obligation: Mapping[str, object] | None,
    ) -> DurableProcessOwnershipRecordV2 | None:
        """Атомарно сохранить cleanup либо удалить точно разрешённую запись."""

        _validate_lease(lease)
        checked_context = self._complete_context(context)
        if outcome == "cleanup-required":
            if cleanup_obligation is None:
                _fail(
                    "DURABLE_OWNERSHIP_TRANSITION_INVALID",
                    "cleanup-required требует обязанность очистки",
                )
        elif outcome in _RESOLVED_OUTCOMES:
            if cleanup_obligation is not None:
                _fail(
                    "DURABLE_OWNERSHIP_TRANSITION_INVALID",
                    "разрешённый исход не принимает обязанность очистки",
                )
        else:
            _fail(
                "DURABLE_OWNERSHIP_TRANSITION_INVALID",
                "исход перехода не поддерживается",
            )
        home_descriptor = self._lock_home()
        try:
            root = ownership_directory_path_v2(self.codex_home)
            path = root / f"{lease.lease_id}.json"
            if not _lexists(root) or not _lexists(path):
                if outcome in _RESOLVED_OUTCOMES and not _lexists(path):
                    return None
                _fail(
                    "DURABLE_OWNERSHIP_RECORD_MISSING",
                    "исходная запись владения отсутствует",
                )
            _require_private_directory(
                root,
                code="DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
            )
            current = _read_record(path)
            self._require_binding(current, lease, checked_context)
            if outcome == "cleanup-required":
                replacement = DurableProcessOwnershipRecordV2.create(
                    lease=lease,
                    context=checked_context,
                    state="CLEANUP_REQUIRED",
                    cleanup_obligation=cleanup_obligation,
                )
                if replacement == current:
                    return current
                _replace_record(path, replacement)
                loaded = _read_record(path)
                if loaded != replacement:
                    _fail(
                        "DURABLE_OWNERSHIP_PUBLICATION_CHANGED",
                        "запись изменилась после перехода",
                    )
                return loaded
            os.unlink(path)
            _fsync_directory(root)
            self._remove_empty_ownership_directory(root)
            return None
        except OSError as exc:
            raise DurableProcessOwnershipV2Error(
                "DURABLE_OWNERSHIP_IO_FAILED",
                "не удалось завершить долговечный переход",
            ) from exc
        finally:
            _unlock_close(home_descriptor)

    def load_all(self) -> tuple[DurableProcessOwnershipRecordV2, ...]:
        """Прочитать все записи, не создавая отсутствующие пути."""

        if not _lexists(self.codex_home):
            return ()
        home_descriptor = self._lock_home()
        try:
            manifests = self.codex_home / "install-manifests"
            root = ownership_directory_path_v2(self.codex_home)
            if not _lexists(manifests):
                return ()
            _require_private_directory(
                manifests,
                code="DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
            )
            if not _lexists(root):
                return ()
            _require_private_directory(
                root,
                code="DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
            )
            records: list[DurableProcessOwnershipRecordV2] = []
            for path in sorted(root.iterdir(), key=lambda item: item.name):
                if (
                    not path.name.endswith(".json")
                    or _LEASE_ID.fullmatch(path.name.removesuffix(".json")) is None
                ):
                    _fail(
                        "DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
                        "каталог содержит неизвестный артефакт",
                    )
                record = _read_record(path)
                if path.name != f"{record.lease_id}.json":
                    _fail(
                        "DURABLE_OWNERSHIP_RECORD_INVALID",
                        "имя файла не совпало с leaseId",
                    )
                records.append(record)
            return tuple(records)
        finally:
            _unlock_close(home_descriptor)

    def assert_continuation_allowed(self) -> None:
        """Запретить обычную операцию при любой неразрешённой записи."""

        lease_ids = tuple(record.lease_id for record in self.load_all())
        if lease_ids:
            raise OutstandingDurableProcessOwnershipV2(lease_ids)

    def release_accepted_candidate_identity(
        self,
        *,
        operation_id: str,
        candidate_id: str,
        controller_start_id: str,
        pid: int,
        process_group_id: int,
        process_start_marker: str,
    ) -> bool:
        """Удалить запись только после внешне доказанного точного принятия."""

        for value, pattern, name in (
            (operation_id, _OPERATION_ID, "operationId"),
            (candidate_id, _CANDIDATE_ID, "candidateId"),
            (controller_start_id, _CONTROLLER_START_ID, "controllerStartId"),
        ):
            if type(value) is not str or pattern.fullmatch(value) is None:
                _fail(
                    "DURABLE_OWNERSHIP_BINDING_MISMATCH",
                    f"{name} доказательства принятия неверен",
                )
        if (
            type(pid) is not int
            or pid <= 0
            or type(process_group_id) is not int
            or process_group_id <= 0
            or type(process_start_marker) is not str
            or not process_start_marker
        ):
            _fail(
                "DURABLE_OWNERSHIP_BINDING_MISMATCH",
                "личность доказательства принятия неполна",
            )
        matches = [
            record
            for record in self.load_all()
            if record.context.get("contextKind") == "candidate-dispatch-v2"
            and record.context.get("operationId") == operation_id
            and record.context.get("candidateId") == candidate_id
            and record.context.get("controllerStartId") == controller_start_id
        ]
        if not matches:
            return False
        if len(matches) != 1:
            _fail(
                "DURABLE_OWNERSHIP_CONFLICT",
                "доказательство принятия соответствует нескольким записям",
            )
        record = matches[0]
        if (
            record.process_label != "candidate-controller"
            or record.pid != pid
            or record.process_group_id != process_group_id
            or record.session_id != pid
            or record.process_start_marker != process_start_marker
        ):
            _fail(
                "DURABLE_OWNERSHIP_BINDING_MISMATCH",
                "доказательство принятия относится к другой личности",
            )
        self.transition(
            _lease_from_record(record),
            record.context,
            "accepted",
            None,
        )
        return True

    def recover(
        self,
        *,
        accepted_candidate_proof: Callable[
            [DurableProcessOwnershipRecordV2], bool
        ],
        candidate_termination_authorized: Callable[
            [DurableProcessOwnershipRecordV2], bool
        ]
        | None = None,
        identity_reader: Callable[[int], ProcessIdentityV2 | None] | None = None,
        group_exists: Callable[[int], bool] | None = None,
        killpg: Callable[[int, int], None] = os.killpg,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        max_wait_seconds: float = 0.5,
        poll_interval_seconds: float = 0.01,
        context_kinds: frozenset[str] | None = None,
    ) -> DurableOwnershipRecoveryResultV2:
        """Сериализовать один проход доказательств и внешних сигналов."""

        _validate_recovery_arguments_v2(
            accepted_candidate_proof=accepted_candidate_proof,
            candidate_termination_authorized=candidate_termination_authorized,
            identity_reader=identity_reader,
            group_exists=group_exists,
            killpg=killpg,
            monotonic=monotonic,
            sleep=sleep,
            max_wait_seconds=max_wait_seconds,
            poll_interval_seconds=poll_interval_seconds,
            context_kinds=context_kinds,
        )
        with _durable_recovery_critical_section_v2(
            self.codex_home
        ) as contended:
            if contended:
                operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
                remaining = tuple(
                    record.lease_id for record in self.load_all()
                )
                return DurableOwnershipRecoveryResultV2(
                    resolved_lease_ids=(),
                    remaining_lease_ids=remaining,
                )
            return self._recover_without_serialization(
                accepted_candidate_proof=accepted_candidate_proof,
                candidate_termination_authorized=(
                    candidate_termination_authorized
                ),
                identity_reader=identity_reader,
                group_exists=group_exists,
                killpg=killpg,
                monotonic=monotonic,
                sleep=sleep,
                max_wait_seconds=max_wait_seconds,
                poll_interval_seconds=poll_interval_seconds,
                context_kinds=context_kinds,
            )

    def _recover_without_serialization(
        self,
        *,
        accepted_candidate_proof: Callable[
            [DurableProcessOwnershipRecordV2], bool
        ],
        candidate_termination_authorized: Callable[
            [DurableProcessOwnershipRecordV2], bool
        ]
        | None = None,
        identity_reader: Callable[[int], ProcessIdentityV2 | None] | None = None,
        group_exists: Callable[[int], bool] | None = None,
        killpg: Callable[[int, int], None] = os.killpg,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        max_wait_seconds: float = 0.5,
        poll_interval_seconds: float = 0.01,
        context_kinds: frozenset[str] | None = None,
    ) -> DurableOwnershipRecoveryResultV2:
        """Явно согласовать точные личности и мягко завершить непринятые.

        Сам факт наличия записи не разрешает сигнал. Для кандидата дополнительно
        требуется отдельное положительное разрешение на завершение, а перед
        каждым сигналом — свежее совпадение четырёх полей личности.
        """

        reader, exists = _validate_recovery_arguments_v2(
            accepted_candidate_proof=accepted_candidate_proof,
            candidate_termination_authorized=candidate_termination_authorized,
            identity_reader=identity_reader,
            group_exists=group_exists,
            killpg=killpg,
            monotonic=monotonic,
            sleep=sleep,
            max_wait_seconds=max_wait_seconds,
            poll_interval_seconds=poll_interval_seconds,
            context_kinds=context_kinds,
        )
        resolved: list[str] = []
        operation_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )
        for record in self.load_all():
            _checkpoint_deadline(operation_deadline)
            if (
                context_kinds is not None
                and record.context["contextKind"] not in context_kinds
            ):
                continue
            if record.context["contextKind"] == "candidate-dispatch-v2":
                try:
                    accepted = accepted_candidate_proof(record)
                except operation_deadline_v2.OperationDeadlineExceededV2:
                    raise
                except BaseException as exc:
                    raise DurableProcessOwnershipV2Error(
                        "DURABLE_OWNERSHIP_ACCEPTANCE_PROOF_FAILED",
                        "не удалось проверить принятие кандидата",
                    ) from exc
                if type(accepted) is not bool:
                    raise TypeError("accepted_candidate_proof must return bool")
                if accepted:
                    self.transition(
                        _lease_from_record(record),
                        record.context,
                        "accepted",
                        None,
                    )
                    resolved.append(record.lease_id)
                    continue
                if candidate_termination_authorized is None:
                    if self._resolve_if_gone(
                        record,
                        identity_reader=reader,
                        group_exists=exists,
                        operation_deadline=operation_deadline,
                    ):
                        resolved.append(record.lease_id)
                    continue
                _checkpoint_deadline(operation_deadline)
                try:
                    authorized = candidate_termination_authorized(record)
                except operation_deadline_v2.OperationDeadlineExceededV2:
                    raise
                except BaseException as exc:
                    raise DurableProcessOwnershipV2Error(
                        "DURABLE_OWNERSHIP_TERMINATION_AUTHORIZATION_FAILED",
                        "не удалось доказать право завершить кандидата",
                    ) from exc
                if type(authorized) is not bool:
                    raise TypeError(
                        "candidate_termination_authorized must return bool"
                    )
                if not authorized:
                    if self._resolve_if_gone(
                        record,
                        identity_reader=reader,
                        group_exists=exists,
                        operation_deadline=operation_deadline,
                    ):
                        resolved.append(record.lease_id)
                    continue
            if self._recover_record(
                record,
                identity_reader=reader,
                group_exists=exists,
                killpg=killpg,
                monotonic=monotonic,
                sleep=sleep,
                max_wait_seconds=float(max_wait_seconds),
                poll_interval_seconds=float(poll_interval_seconds),
                operation_deadline=operation_deadline,
            ):
                resolved.append(record.lease_id)
        _checkpoint_deadline(operation_deadline)
        remaining = tuple(record.lease_id for record in self.load_all())
        return DurableOwnershipRecoveryResultV2(
            resolved_lease_ids=tuple(resolved),
            remaining_lease_ids=remaining,
        )

    def _recover_record(
        self,
        record: DurableProcessOwnershipRecordV2,
        *,
        identity_reader: Callable[[int], ProcessIdentityV2 | None],
        group_exists: Callable[[int], bool],
        killpg: Callable[[int, int], None],
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        max_wait_seconds: float,
        poll_interval_seconds: float,
        operation_deadline: operation_deadline_v2.OperationDeadlineV2 | None,
    ) -> bool:
        expected = _record_identity(record)
        if _signal_sequence_already_sent(record):
            return self._wait_after_signal_sequence(
                record,
                identity_reader=identity_reader,
                group_exists=group_exists,
                monotonic=monotonic,
                sleep=sleep,
                max_wait_seconds=max_wait_seconds,
                poll_interval_seconds=poll_interval_seconds,
                operation_deadline=operation_deadline,
            )
        _checkpoint_deadline(operation_deadline)
        initial_identity = _safe_read_identity(identity_reader, record.pid)
        _checkpoint_deadline(operation_deadline)
        initial_alive = _safe_group_exists(group_exists, record.process_group_id)
        if initial_identity is None and not initial_alive:
            self.transition(
                _lease_from_record(record),
                record.context,
                "verified-exit",
                None,
            )
            return True
        failure = _identity_failure(
            expected,
            initial_identity,
            group_alive=initial_alive,
            after_term=False,
        )
        if failure is not None:
            self._persist_recovery_obligation(
                record,
                observed_identity=initial_identity,
                identity_failure_code=failure,
            )
            return False

        _checkpoint_deadline(operation_deadline)
        pre_identity = _safe_read_identity(identity_reader, record.pid)
        _checkpoint_deadline(operation_deadline)
        pre_alive = _safe_group_exists(group_exists, record.process_group_id)
        failure = _identity_failure(
            expected,
            pre_identity,
            group_alive=pre_alive,
            after_term=False,
        )
        if failure is not None:
            self._persist_recovery_obligation(
                record,
                observed_identity=pre_identity,
                identity_failure_code=failure,
            )
            return False
        _checkpoint_deadline(operation_deadline)
        _read_monotonic(monotonic)
        _checkpoint_deadline(operation_deadline)
        pre_cont_sent, pre_cont_errno = _send_signal(
            killpg,
            record.process_group_id,
            signal.SIGCONT,
        )
        if not pre_cont_sent:
            if self._resolve_if_gone(
                record,
                identity_reader=identity_reader,
                group_exists=group_exists,
                operation_deadline=operation_deadline,
            ):
                return True
            self._persist_recovery_obligation(
                record,
                observed_identity=pre_identity,
                pre_cont_errno=pre_cont_errno,
            )
            return False

        _checkpoint_deadline(operation_deadline)
        term_identity = _safe_read_identity(identity_reader, record.pid)
        _checkpoint_deadline(operation_deadline)
        term_alive = _safe_group_exists(group_exists, record.process_group_id)
        failure = _identity_failure(
            expected,
            term_identity,
            group_alive=term_alive,
            after_term=False,
        )
        if failure is not None:
            self._persist_recovery_obligation(
                record,
                observed_identity=term_identity,
                identity_failure_code=failure,
                pre_cont_sent=True,
            )
            return False
        _checkpoint_deadline(operation_deadline)
        term_sent, term_errno = _send_signal(
            killpg,
            record.process_group_id,
            signal.SIGTERM,
        )
        if not term_sent:
            if self._resolve_if_gone(
                record,
                identity_reader=identity_reader,
                group_exists=group_exists,
                operation_deadline=operation_deadline,
            ):
                return True
            self._persist_recovery_obligation(
                record,
                observed_identity=term_identity,
                pre_cont_sent=True,
                term_errno=term_errno,
            )
            return False

        _checkpoint_deadline(operation_deadline)
        post_identity = _safe_read_identity(identity_reader, record.pid)
        _checkpoint_deadline(operation_deadline)
        post_alive = _safe_group_exists(group_exists, record.process_group_id)
        if post_identity is None and not post_alive:
            self.transition(
                _lease_from_record(record),
                record.context,
                "soft-terminated",
                None,
            )
            return True
        failure = _identity_failure(
            expected,
            post_identity,
            group_alive=post_alive,
            after_term=True,
        )
        if failure is not None:
            self._persist_recovery_obligation(
                record,
                observed_identity=post_identity,
                identity_failure_code=failure,
                pre_cont_sent=True,
                term_sent=True,
            )
            return False
        _checkpoint_deadline(operation_deadline)
        post_cont_sent, post_cont_errno = _send_signal(
            killpg,
            record.process_group_id,
            signal.SIGCONT,
        )
        if not post_cont_sent:
            if self._resolve_if_gone(
                record,
                identity_reader=identity_reader,
                group_exists=group_exists,
                operation_deadline=operation_deadline,
            ):
                return True
            self._persist_recovery_obligation(
                record,
                observed_identity=post_identity,
                pre_cont_sent=True,
                term_sent=True,
                post_cont_errno=post_cont_errno,
            )
            return False

        self._persist_recovery_obligation(
            record,
            observed_identity=post_identity,
            pre_cont_sent=True,
            term_sent=True,
            post_cont_sent=True,
        )
        return self._wait_after_signal_sequence(
            record,
            identity_reader=identity_reader,
            group_exists=group_exists,
            monotonic=monotonic,
            sleep=sleep,
            max_wait_seconds=max_wait_seconds,
            poll_interval_seconds=poll_interval_seconds,
            operation_deadline=operation_deadline,
        )

    def _wait_after_signal_sequence(
        self,
        record: DurableProcessOwnershipRecordV2,
        *,
        identity_reader: Callable[[int], ProcessIdentityV2 | None],
        group_exists: Callable[[int], bool],
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        max_wait_seconds: float,
        poll_interval_seconds: float,
        operation_deadline: operation_deadline_v2.OperationDeadlineV2 | None,
    ) -> bool:
        expected = _record_identity(record)
        _checkpoint_deadline(operation_deadline)
        started = _read_monotonic(monotonic)
        deadline = started + max_wait_seconds
        while True:
            _checkpoint_deadline(operation_deadline)
            alive = _safe_group_exists(group_exists, record.process_group_id)
            _checkpoint_deadline(operation_deadline)
            observed = _safe_read_identity(identity_reader, record.pid)
            if observed is None and not alive:
                self.transition(
                    _lease_from_record(record),
                    record.context,
                    "soft-terminated",
                    None,
                )
                return True
            failure = _identity_failure(
                expected,
                observed,
                group_alive=alive,
                after_term=True,
            )
            if failure is not None:
                self._persist_recovery_obligation(
                    record,
                    observed_identity=observed,
                    identity_failure_code=failure,
                    pre_cont_sent=True,
                    term_sent=True,
                    post_cont_sent=True,
                )
                return False
            _checkpoint_deadline(operation_deadline)
            now = _read_monotonic(monotonic)
            if now >= deadline:
                self._persist_recovery_obligation(
                    record,
                    observed_identity=observed,
                    pre_cont_sent=True,
                    term_sent=True,
                    post_cont_sent=True,
                    configured_timeout_seconds=max_wait_seconds,
                    elapsed_seconds=max(max_wait_seconds, now - started),
                )
                return False
            sleep_seconds = min(poll_interval_seconds, deadline - now)
            if operation_deadline is not None:
                _checkpoint_deadline(operation_deadline)
                sleep_seconds = min(
                    sleep_seconds,
                    operation_deadline.remaining_seconds(),
                )
                if sleep_seconds <= 0:
                    operation_deadline.checkpoint()
            sleep(sleep_seconds)
            _checkpoint_deadline(operation_deadline)

    def _resolve_if_gone(
        self,
        record: DurableProcessOwnershipRecordV2,
        *,
        identity_reader: Callable[[int], ProcessIdentityV2 | None],
        group_exists: Callable[[int], bool],
        operation_deadline: operation_deadline_v2.OperationDeadlineV2 | None,
    ) -> bool:
        _checkpoint_deadline(operation_deadline)
        identity = _safe_read_identity(identity_reader, record.pid)
        _checkpoint_deadline(operation_deadline)
        alive = _safe_group_exists(group_exists, record.process_group_id)
        if identity is not None or alive:
            return False
        self.transition(
            _lease_from_record(record),
            record.context,
            "verified-exit",
            None,
        )
        return True

    def _persist_recovery_obligation(
        self,
        record: DurableProcessOwnershipRecordV2,
        *,
        observed_identity: ProcessIdentityV2 | None,
        identity_failure_code: str | None = None,
        pre_cont_sent: bool = False,
        pre_cont_errno: int | None = None,
        term_sent: bool = False,
        term_errno: int | None = None,
        post_cont_sent: bool = False,
        post_cont_errno: int | None = None,
        configured_timeout_seconds: float | None = None,
        elapsed_seconds: float | None = None,
    ) -> None:
        previous_attempt = 0
        if record.cleanup_obligation is not None:
            previous_attempt = int(record.cleanup_obligation["attempt"])
        cont_sent = pre_cont_sent or post_cont_sent
        cont_errno = (
            None
            if cont_sent
            else post_cont_errno
            if post_cont_errno is not None
            else pre_cont_errno
        )
        deadline_proof: dict[str, object] | None = None
        if configured_timeout_seconds is not None:
            configured_ns = max(1, int(configured_timeout_seconds * 1_000_000_000))
            elapsed_ns = max(
                configured_ns,
                int((elapsed_seconds or configured_timeout_seconds) * 1_000_000_000),
            )
            deadline_proof = {
                "schemaVersion": 2,
                "proofType": "operation-deadline-v2",
                "operation": "recover",
                "phase": "durable-process-ownership",
                "timeoutCode": "DURABLE_OWNERSHIP_RECOVERY_TIMEOUT",
                "deadlineKind": "phase",
                "configuredTimeoutNanoseconds": configured_ns,
                "elapsedMonotonicNanoseconds": elapsed_ns,
                "deadlineExceeded": True,
            }
        signal_sequence_sent = bool(
            pre_cont_sent and term_sent and post_cont_sent
        )
        is_signal_sequence_checkpoint = bool(
            signal_sequence_sent
            and identity_failure_code is None
            and configured_timeout_seconds is None
        )
        obligation = {
            "schemaVersion": 2,
            "obligationType": "transient-process-group-cleanup-v2",
            "obligationId": record.lease_id,
            "status": "pending",
            "operation": "recover",
            "phase": "durable-process-ownership",
            "processLabel": record.process_label,
            "pid": record.pid,
            "processGroupId": record.process_group_id,
            "reasonCode": (
                "DURABLE_PROCESS_OWNERSHIP_SIGNAL_SEQUENCE_SENT"
                if is_signal_sequence_checkpoint
                else "DURABLE_PROCESS_OWNERSHIP_RECONCILIATION_REQUIRED"
            ),
            "attempt": previous_attempt + 1,
            "termSent": term_sent,
            "contSent": cont_sent,
            "preContSent": pre_cont_sent,
            "postContSent": post_cont_sent,
            "termErrorErrno": term_errno,
            "contErrorErrno": cont_errno,
            "preContErrorErrno": pre_cont_errno,
            "postContErrorErrno": post_cont_errno,
            "observedAlive": True,
            "nextAction": (
                "reconcile-identity-without-repeat-signals"
                if signal_sequence_sent
                else "reconcile-identity-and-retry-term-cont"
            ),
            "automaticSignalAuthorized": False,
            "continuationAllowed": False,
            "expectedProcessIdentity": _identity_document(_record_identity(record)),
            "observedProcessIdentity": (
                None
                if observed_identity is None
                else _identity_document(observed_identity)
            ),
            "identityFailureCode": identity_failure_code,
            "deadlineProof": deadline_proof,
        }
        checked = validate_cleanup_obligation_v2(obligation)
        self.transition(
            _lease_from_record(record),
            record.context,
            "cleanup-required",
            checked,
        )

    def _complete_context(
        self, context: Mapping[str, object]
    ) -> dict[str, object]:
        if type(context) is not dict:
            _fail(
                "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                "context должен быть обычным объектом",
            )
        document = copy.deepcopy(dict(context))
        if set(document) == _GENERIC_SUPERVISOR_CONTEXT_KEYS:
            if (
                self.operation is None
                or self.phase is None
                or self.invocation_id is None
            ):
                _fail(
                    "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                    "общий context не связан с публичной операцией",
                )
            document.update(
                {
                    "operation": self.operation,
                    "phase": self.phase,
                    "invocationId": self.invocation_id,
                }
            )
        return _validate_complete_context(document)

    def _lock_home(self) -> int:
        _require_owned_nonwritable_directory(
            self.codex_home,
            code="DURABLE_OWNERSHIP_CODEX_HOME_UNSAFE",
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.codex_home, flags)
        except OSError as exc:
            raise DurableProcessOwnershipV2Error(
                "DURABLE_OWNERSHIP_CODEX_HOME_UNSAFE",
                "CODEX_HOME нельзя заблокировать",
            ) from exc
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=_HOME_LOCK_TIMEOUT_SECONDS,
                timeout_code=_HOME_LOCK_TIMEOUT_CODE,
            )
        except (
            finite_file_lock_v2.FileLockTimeoutV2,
            operation_deadline_v2.OperationDeadlineExceededV2,
        ):
            os.close(descriptor)
            raise
        except OSError as exc:
            os.close(descriptor)
            raise DurableProcessOwnershipV2Error(
                "DURABLE_OWNERSHIP_CODEX_HOME_UNSAFE",
                "CODEX_HOME нельзя заблокировать",
            ) from exc
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _ensure_ownership_directory(self) -> Path:
        manifests = self.codex_home / "install-manifests"
        root = ownership_directory_path_v2(self.codex_home)
        try:
            manifests.mkdir(mode=0o700, exist_ok=True)
            _require_private_directory(
                manifests,
                code="DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
            )
            root.mkdir(mode=0o700, exist_ok=True)
            _require_private_directory(
                root,
                code="DURABLE_OWNERSHIP_DIRECTORY_UNSAFE",
            )
            _fsync_directory(self.codex_home)
            _fsync_directory(manifests)
        except DurableProcessOwnershipV2Error:
            raise
        except OSError as exc:
            raise DurableProcessOwnershipV2Error(
                "DURABLE_OWNERSHIP_IO_FAILED",
                "не удалось создать частный каталог владения",
            ) from exc
        return root

    def _remove_empty_ownership_directory(self, root: Path) -> None:
        if any(root.iterdir()):
            return
        os.rmdir(root)
        _fsync_directory(root.parent)

    @staticmethod
    def _require_binding(
        record: DurableProcessOwnershipRecordV2,
        lease: TransientProcessLeaseV2,
        context: Mapping[str, object],
    ) -> None:
        if (
            record.lease_id != lease.lease_id
            or record.process_label != lease.label
            or record.pid != lease.pid
            or record.process_group_id != lease.process_group_id
            or record.session_id != lease.session_id
            or record.process_start_marker != lease.process_start_marker
            or record.context != context
        ):
            _fail(
                "DURABLE_OWNERSHIP_BINDING_MISMATCH",
                "переход относится к другой аренде или context",
            )


def ownership_directory_path_v2(codex_home: Path) -> Path:
    if not isinstance(codex_home, Path) or not codex_home.is_absolute():
        raise TypeError("codex_home must be an absolute Path")
    return codex_home / "install-manifests" / _DIRECTORY_NAME


def _record_identity(
    record: DurableProcessOwnershipRecordV2,
) -> ProcessIdentityV2:
    return ProcessIdentityV2(
        pid=record.pid,
        process_group_id=record.process_group_id,
        session_id=record.session_id,
        start_marker=record.process_start_marker,
    )


def _lease_from_record(
    record: DurableProcessOwnershipRecordV2,
) -> TransientProcessLeaseV2:
    return TransientProcessLeaseV2(
        lease_id=record.lease_id,
        label=record.process_label,
        pid=record.pid,
        process_group_id=record.process_group_id,
        session_id=record.session_id,
        process_start_marker=record.process_start_marker,
        process=object(),
    )


def _identity_document(identity: ProcessIdentityV2) -> dict[str, object]:
    return {
        "pid": identity.pid,
        "processGroupId": identity.process_group_id,
        "sessionId": identity.session_id,
        "startMarker": identity.start_marker,
    }


def _signal_sequence_already_sent(
    record: DurableProcessOwnershipRecordV2,
) -> bool:
    obligation = record.cleanup_obligation
    return bool(
        record.state == "CLEANUP_REQUIRED"
        and obligation is not None
        and obligation["preContSent"] is True
        and obligation["termSent"] is True
        and obligation["postContSent"] is True
    )


def _identity_failure(
    expected: ProcessIdentityV2,
    observed: ProcessIdentityV2 | None,
    *,
    group_alive: bool,
    after_term: bool,
) -> str | None:
    if observed is None:
        if not group_alive:
            return None
        return (
            "PROCESS_IDENTITY_UNAVAILABLE_AFTER_TERM"
            if after_term
            else "PROCESS_IDENTITY_UNAVAILABLE"
        )
    if observed != expected:
        return (
            "PROCESS_IDENTITY_CHANGED_AFTER_TERM"
            if after_term
            else "PROCESS_IDENTITY_MISMATCH"
        )
    if not group_alive:
        return "PROCESS_IDENTITY_PRESENT_AFTER_EXIT"
    return None


def _safe_read_identity(
    reader: Callable[[int], ProcessIdentityV2 | None], pid: int
) -> ProcessIdentityV2 | None:
    try:
        identity = reader(pid)
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except OSError:
        return None
    if identity is not None and not isinstance(identity, ProcessIdentityV2):
        raise TypeError("identity_reader must return ProcessIdentityV2 or None")
    return identity


def _safe_group_exists(reader: Callable[[int], bool], pgid: int) -> bool:
    try:
        result = reader(pgid)
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except OSError:
        return True
    if type(result) is not bool:
        raise TypeError("group_exists must return bool")
    return result


def _validate_recovery_arguments_v2(
    *,
    accepted_candidate_proof: object,
    candidate_termination_authorized: object,
    identity_reader: object,
    group_exists: object,
    killpg: object,
    monotonic: object,
    sleep: object,
    max_wait_seconds: object,
    poll_interval_seconds: object,
    context_kinds: object,
) -> tuple[
    Callable[[int], ProcessIdentityV2 | None],
    Callable[[int], bool],
]:
    """Проверить весь вызов до ожидания единственной recovery-блокировки."""

    if not callable(accepted_candidate_proof):
        raise TypeError("accepted_candidate_proof must be callable")
    if (
        candidate_termination_authorized is not None
        and not callable(candidate_termination_authorized)
    ):
        raise TypeError("candidate_termination_authorized must be callable")
    reader = (
        _default_identity_reader
        if identity_reader is None
        else identity_reader
    )
    exists = _default_group_exists if group_exists is None else group_exists
    for item, name in (
        (reader, "identity_reader"),
        (exists, "group_exists"),
        (killpg, "killpg"),
        (monotonic, "monotonic"),
        (sleep, "sleep"),
    ):
        if not callable(item):
            raise TypeError(f"{name} must be callable")
    if (
        isinstance(max_wait_seconds, bool)
        or not isinstance(max_wait_seconds, (int, float))
        or not 0 < float(max_wait_seconds) <= 30.0
    ):
        raise ValueError("max_wait_seconds must be in (0, 30]")
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not 0 < float(poll_interval_seconds) <= float(max_wait_seconds)
    ):
        raise ValueError(
            "poll_interval_seconds must be in (0, max_wait_seconds]"
        )
    if context_kinds is not None and (
        type(context_kinds) is not frozenset
        or not context_kinds
        or not context_kinds.issubset(
            {"candidate-dispatch-v2", "installer-transient-v2"}
        )
    ):
        raise ValueError("context_kinds must be null or a supported frozenset")
    assert callable(reader)
    assert callable(exists)
    return reader, exists


def _send_signal(
    killpg: Callable[[int, int], None], pgid: int, signum: int
) -> tuple[bool, int | None]:
    if signum not in {signal.SIGCONT, signal.SIGTERM}:
        raise AssertionError("only SIGCONT and SIGTERM are supported")
    try:
        killpg(pgid, signum)
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except OSError as exc:
        error_number = exc.errno if type(exc.errno) is int and exc.errno > 0 else errno.EIO
        return False, error_number
    return True, None


def _recovery_thread_lock_v2(codex_home: Path) -> Any:
    info = os.lstat(codex_home)
    key = (int(info.st_dev), int(info.st_ino))
    with _RECOVERY_THREAD_LOCKS_GUARD:
        lock = _RECOVERY_THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _RECOVERY_THREAD_LOCKS[key] = lock
        return lock


def _recovery_lock_remaining_seconds_v2(absolute_deadline: float) -> float:
    operation_deadline = (
        operation_deadline_v2.current_operation_deadline_v2()
    )
    if operation_deadline is not None:
        operation_deadline.checkpoint()
    remaining = absolute_deadline - time.monotonic()
    if operation_deadline is not None:
        remaining = min(
            remaining,
            operation_deadline.remaining_seconds(),
        )
    if remaining <= 0:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        raise finite_file_lock_v2.FileLockTimeoutV2(
            _RECOVERY_LOCK_TIMEOUT_CODE,
            _RECOVERY_LOCK_TIMEOUT_SECONDS,
        )
    return remaining


def _open_recovery_lock_v2(codex_home: Path) -> int:
    path = codex_home / _RECOVERY_LOCK_NAME
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(
                path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(path, flags)
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync_directory(codex_home)
        info = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
        ):
            _fail(
                "DURABLE_OWNERSHIP_RECOVERY_LOCK_INVALID",
                "файл блокировки восстановления изменён",
            )
        return descriptor
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


@contextmanager
def _durable_recovery_critical_section_v2(
    codex_home: Path,
) -> Iterator[bool]:
    """Сериализовать recovery в потоке и между процессами конечным ожиданием."""

    _require_owned_nonwritable_directory(
        codex_home,
        code="DURABLE_OWNERSHIP_CODEX_HOME_UNSAFE",
    )
    absolute_deadline = time.monotonic() + _RECOVERY_LOCK_TIMEOUT_SECONDS
    thread_lock = _recovery_thread_lock_v2(codex_home)
    thread_contended = not thread_lock.acquire(blocking=False)
    if thread_contended:
        wait_seconds = _recovery_lock_remaining_seconds_v2(
            absolute_deadline
        )
        acquired = thread_lock.acquire(timeout=wait_seconds)
        if not acquired:
            operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
            raise finite_file_lock_v2.FileLockTimeoutV2(
                _RECOVERY_LOCK_TIMEOUT_CODE,
                _RECOVERY_LOCK_TIMEOUT_SECONDS,
            )

    descriptor: int | None = None
    file_locked = False
    primary_error: BaseException | None = None
    try:
        descriptor = _open_recovery_lock_v2(codex_home)
        file_contended = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            file_locked = True
        except OSError as error:
            if error.errno not in {
                errno.EACCES,
                errno.EAGAIN,
                errno.EWOULDBLOCK,
            }:
                raise
            file_contended = True
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=True,
                    timeout_seconds=_recovery_lock_remaining_seconds_v2(
                        absolute_deadline
                    ),
                    timeout_code=_RECOVERY_LOCK_TIMEOUT_CODE,
                )
            except finite_file_lock_v2.FileLockTimeoutV2:
                operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
                raise
            file_locked = True
        operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
        yield thread_contended or file_contended
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            if descriptor is not None:
                try:
                    if file_locked:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                except BaseException as error:
                    cleanup_error = error
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
        finally:
            thread_lock.release()
        if cleanup_error is not None:
            if primary_error is not None:
                primary_error.add_note(
                    "recovery lock release also failed: "
                    + type(cleanup_error).__name__
                    + ": "
                    + str(cleanup_error)[:512]
                )
            else:
                raise DurableProcessOwnershipV2Error(
                    "DURABLE_OWNERSHIP_RECOVERY_LOCK_RELEASE_FAILED",
                    "не удалось освободить блокировку восстановления",
                ) from cleanup_error


def _read_monotonic(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("monotonic must return a finite number")
    result = float(value)
    if result < 0 or result == float("inf") or result != result:
        raise ValueError("monotonic must return a finite non-negative number")
    return result


def _checkpoint_deadline(
    deadline: operation_deadline_v2.OperationDeadlineV2 | None,
) -> None:
    if deadline is not None:
        deadline.checkpoint()


def _default_identity_reader(pid: int) -> ProcessIdentityV2 | None:
    try:
        first_group = os.getpgid(pid)
        first_session = os.getsid(pid)
        marker = system_process_start_marker_v2(pid)
        second_group = os.getpgid(pid)
        second_session = os.getsid(pid)
    except (ChildGuardV2Error, OSError):
        return None
    if (first_group, first_session) != (second_group, second_session):
        return None
    return ProcessIdentityV2(
        pid=pid,
        process_group_id=second_group,
        session_id=second_session,
        start_marker=marker,
    )


def _default_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        return True
    return True


def _validate_lease(lease: TransientProcessLeaseV2) -> None:
    if not isinstance(lease, TransientProcessLeaseV2):
        raise TypeError("lease must be TransientProcessLeaseV2")
    if _LEASE_ID.fullmatch(lease.lease_id) is None:
        _fail("DURABLE_OWNERSHIP_RECORD_INVALID", "leaseId неверен")
    _bounded_name(
        lease.label,
        "processLabel",
        code="DURABLE_OWNERSHIP_RECORD_INVALID",
    )
    if (
        type(lease.pid) is not int
        or lease.pid <= 0
        or lease.process_group_id != lease.pid
        or lease.session_id != lease.pid
        or type(lease.process_start_marker) is not str
        or not lease.process_start_marker
    ):
        _fail(
            "DURABLE_OWNERSHIP_RECORD_INVALID",
            "аренда не содержит полную личность лидера нового сеанса",
        )


def _validate_complete_context(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _fail(
            "DURABLE_OWNERSHIP_CONTEXT_INVALID",
            "context должен быть обычным объектом",
        )
    document = copy.deepcopy(value)
    if set(document) == _CANDIDATE_CONTEXT_KEYS:
        if (
            document.get("schemaVersion") != 2
            or document.get("contextKind") != "candidate-dispatch-v2"
        ):
            _fail(
                "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                "вид candidate context неверен",
            )
        patterns = {
            "operationId": _OPERATION_ID,
            "candidateId": _CANDIDATE_ID,
            "controllerStartId": _CONTROLLER_START_ID,
            "actionFingerprint": _SHA256,
            "dispatchReceiptFingerprint": _SHA256,
        }
        for name, pattern in patterns.items():
            item = document.get(name)
            if type(item) is not str or pattern.fullmatch(item) is None:
                _fail(
                    "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                    f"{name} candidate context неверен",
                )
        return document
    if set(document) == _GENERIC_CONTEXT_KEYS:
        if (
            document.get("schemaVersion") != 2
            or document.get("contextKind") != "installer-transient-v2"
        ):
            _fail(
                "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                "вид общего context неверен",
            )
        for name in ("processLabel", "operation", "phase"):
            _bounded_name(
                document.get(name),
                name,
                code="DURABLE_OWNERSHIP_CONTEXT_INVALID",
            )
        invocation_id = document.get("invocationId")
        if (
            type(invocation_id) is not str
            or _INVOCATION_ID.fullmatch(invocation_id) is None
        ):
            _fail(
                "DURABLE_OWNERSHIP_CONTEXT_INVALID",
                "invocationId общего context неверен",
            )
        return document
    _fail(
        "DURABLE_OWNERSHIP_CONTEXT_INVALID",
        "context имеет неполный или расширенный набор полей",
    )


def _bounded_name(value: object, name: str, *, code: str) -> str:
    if type(value) is not str or _SAFE_NAME.fullmatch(value) is None:
        _fail(code, f"{name} должен быть ограниченной служебной строкой")
    return value


def _read_record(path: Path) -> DurableProcessOwnershipRecordV2:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DurableProcessOwnershipV2Error(
            "DURABLE_OWNERSHIP_FILE_UNSAFE",
            "файл записи недоступен",
        ) from exc
    try:
        info = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_RECORD_BYTES
        ):
            _fail(
                "DURABLE_OWNERSHIP_FILE_UNSAFE",
                "файл записи не является частным обычным файлом",
            )
        chunks: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) > _MAX_RECORD_BYTES:
        _fail("DURABLE_OWNERSHIP_FILE_UNSAFE", "запись слишком велика")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DurableProcessOwnershipV2Error(
            "DURABLE_OWNERSHIP_RECORD_INVALID",
            "запись не является JSON",
        ) from exc
    if type(document) is not dict or canonical_json_bytes(document) != payload:
        _fail(
            "DURABLE_OWNERSHIP_RECORD_INVALID",
            "запись не является каноническим JSON-объектом",
        )
    return DurableProcessOwnershipRecordV2.from_mapping(document)


def _publish_new_record(
    path: Path, record: DurableProcessOwnershipRecordV2
) -> None:
    payload = canonical_json_bytes(record.to_document())
    if len(payload) > _MAX_RECORD_BYTES:
        _fail("DURABLE_OWNERSHIP_RECORD_INVALID", "запись слишком велика")
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.{os.urandom(8).hex()}.tmp"
    )
    descriptor: int | None = None
    linked = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        os.unlink(temporary)
        linked = False
        _fsync_directory(path.parent)
    except DurableProcessOwnershipV2Error:
        raise
    except FileExistsError as exc:
        raise DurableProcessOwnershipV2Error(
            "DURABLE_OWNERSHIP_CONFLICT",
            "запись с таким leaseId уже существует",
        ) from exc
    except OSError as exc:
        raise DurableProcessOwnershipV2Error(
            "DURABLE_OWNERSHIP_IO_FAILED",
            "не удалось атомарно опубликовать запись",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if _lexists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass
        if linked:
            _fsync_directory(path.parent)


def _replace_record(
    path: Path, record: DurableProcessOwnershipRecordV2
) -> None:
    payload = canonical_json_bytes(record.to_document())
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.{os.urandom(8).hex()}.tmp"
    )
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise DurableProcessOwnershipV2Error(
            "DURABLE_OWNERSHIP_IO_FAILED",
            "не удалось атомарно заменить запись",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if _lexists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            _fail(
                "DURABLE_OWNERSHIP_IO_FAILED",
                "не удалось полностью записать документ",
            )
        view = view[written:]


def _require_private_directory(path: Path, *, code: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DurableProcessOwnershipV2Error(
            code,
            f"частный каталог недоступен: {path}",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        _fail(code, f"каталог не является частным: {path}")


def _require_owned_nonwritable_directory(path: Path, *, code: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DurableProcessOwnershipV2Error(
            code,
            f"свой каталог недоступен: {path}",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        _fail(code, f"каталог доступен для чужой записи: {path}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlock_close(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _fail(code: str, message: str) -> None:
    raise DurableProcessOwnershipV2Error(code, message)


__all__ = [
    "DurableOwnershipRecoveryResultV2",
    "DurableProcessOwnershipRecordV2",
    "DurableProcessOwnershipStoreV2",
    "DurableProcessOwnershipV2Error",
    "OutstandingDurableProcessOwnershipV2",
    "ownership_directory_path_v2",
]
