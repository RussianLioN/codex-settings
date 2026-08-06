"""Ограниченный производственный сервер ``health`` протокола контроллера v2."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import socket
import sqlite3
import stat
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from .canonical_json import (
    CanonicalJsonError,
    MAX_SAFE_INTEGER,
    canonical_json_bytes,
    domain_fingerprint,
)
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .coordinator_selection_v2 import (
    CoordinatorSelectionV2,
    validate_coordinator_selection_document_v2,
)
from .lifecycle_controller_protocol_v2 import LifecycleControllerProtocolV2Error
from .schema_projection import APPLICATION_ID
from .state_store_v2 import (
    _QUIESCENCE_QUERIES,
    AcceptingControllerV2,
)


PROTOCOL_VERSION = 2
RELEASE = "0.2.0"
NAMESPACE = "codex-smart-subagents-v2"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_WORKERS = 16
HEALTH_DATABASE_DEADLINE_SECONDS = 0.25
_SOCKET_PATH_LIMIT = 100
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_SOCKETS: set[str] = set()
_LIFECYCLE_METHODS = frozenset(
    {
        "maintenance_begin",
        "maintenance_strengthen",
        "maintenance_status",
        "shutdown",
        "controller_accept",
        "controller_recover",
        "maintenance_resume",
    }
)
_REMOTE_CODES_BY_CATEGORY = {
    "CONFLICT": frozenset(
        {"COMMAND_REPLAY_CONFLICT", "CONTROLLER_OPERATION_CONFLICT"}
    ),
    "STALE": frozenset(
        {
            "CONTROL_EPOCH_MISMATCH",
            "CONTROLLER_INSTANCE_MISMATCH",
            "ACCOUNT_CONTEXT_CHANGED",
            "ACTIVATION_GATE_CHANGED",
            "START_REQUEST_STALE",
        }
    ),
    "UNAVAILABLE": frozenset(
        {
            "ADAPTIVE_ACTIVATION_UNCOMMITTED",
            "ACCOUNT_EVIDENCE_UNAVAILABLE",
            "EXTERNAL_PROCESS_STILL_RUNNING",
        }
    ),
    "INVALID": frozenset(
        {
            "INVALID_TRANSITION",
            "ACCOUNT_EVIDENCE_NOT_SUCCEEDED",
            "START_REQUEST_OWNERSHIP_MISMATCH",
        }
    ),
    "INTERNAL": frozenset({"INTERNAL_ERROR"}),
}


@dataclass
class ControllerHealthV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ControllerRegistrationReceiptV2:
    """Результат единственной разрешённой записи строки контроллера в БД."""

    database_path: Path
    cleanup: Callable[[], None]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.database_path, Path)
            or not self.database_path.is_absolute()
        ):
            raise ControllerHealthV2Error(
                "REGISTRATION_INVALID",
                "database_path must be an absolute Path",
            )
        if not callable(self.cleanup):
            raise ControllerHealthV2Error(
                "REGISTRATION_INVALID",
                "cleanup must be callable",
            )


ControllerRegistrarV2 = Callable[
    [AcceptingControllerV2], ControllerRegistrationReceiptV2
]
LifecycleHandlerV2 = Callable[[Mapping[str, object]], Mapping[str, object]]
LifecycleResponseObserverV2 = Callable[
    [Mapping[str, object], Mapping[str, object]], None
]


class ControllerHealthServerV2:
    """Владеет закрытым сокетом health и жизненного цикла контроллера v2."""

    def __init__(
        self,
        *,
        socket_path: Path,
        lock_path: Path,
        codex_home: Path,
        state_home: Path,
        database_id: str,
        activation_id: str,
        activation_fingerprint: str,
        compatibility_fingerprint: str,
        routing_policy_fingerprint: str,
        bundled_catalog_fingerprint: str,
        coordinator_selection: CoordinatorSelectionV2,
        instance_id: str,
        controller_start_id: str,
        control_epoch: int,
        registrar: ControllerRegistrarV2,
        clock: Callable[[], datetime] | None = None,
        io_timeout_seconds: float = 1.0,
    ) -> None:
        self.socket_path = _absolute_path(socket_path, "socket_path")
        self.lock_path = _absolute_path(lock_path, "lock_path")
        self.codex_home = _owned_codex_home_directory(codex_home).resolve()
        self.state_home = _private_directory(state_home, "state_home")
        if self.socket_path.parent != self.lock_path.parent:
            _fail("INVALID_CONFIGURATION", "socket and lock must share one directory")
        _private_directory(self.socket_path.parent, "runtime directory")
        if len(os.fsencode(self.socket_path)) >= _SOCKET_PATH_LIMIT:
            _fail("SOCKET_PATH_TOO_LONG", "Unix socket path is too long")
        _identifier(database_id, "db2_", 32, "database_id")
        _identifier(activation_id, "act2_", 64, "activation_id")
        _sha256(activation_fingerprint, "activation_fingerprint")
        _sha256(compatibility_fingerprint, "compatibility_fingerprint")
        _sha256(routing_policy_fingerprint, "routing_policy_fingerprint")
        _sha256(bundled_catalog_fingerprint, "bundled_catalog_fingerprint")
        if not isinstance(coordinator_selection, CoordinatorSelectionV2):
            _fail(
                "INVALID_CONFIGURATION",
                "coordinator_selection must be CoordinatorSelectionV2",
            )
        _identifier(instance_id, "ci2_", 32, "instance_id")
        _identifier(controller_start_id, "cs2_", 32, "controller_start_id")
        if type(control_epoch) is not int or not 1 <= control_epoch <= MAX_SAFE_INTEGER:
            _fail("INVALID_CONFIGURATION", "control_epoch is outside the safe range")
        if not callable(registrar):
            _fail("INVALID_CONFIGURATION", "registrar must be callable")
        if not callable(clock or _utc_now):
            _fail("INVALID_CONFIGURATION", "clock must be callable")
        if (
            type(io_timeout_seconds) not in {int, float}
            or type(io_timeout_seconds) is bool
            or not 0 < float(io_timeout_seconds) <= 1.0
        ):
            _fail(
                "INVALID_CONFIGURATION",
                "io_timeout_seconds must be greater than zero and at most one",
            )

        self.database_id = database_id
        self.activation_id = activation_id
        self.activation_fingerprint = activation_fingerprint
        self.compatibility_fingerprint = compatibility_fingerprint
        self.routing_policy_fingerprint = routing_policy_fingerprint
        self.bundled_catalog_fingerprint = bundled_catalog_fingerprint
        if (
            coordinator_selection.recompute_account_context_fingerprint(
                active_context_fingerprint=activation_fingerprint,
            )
            != coordinator_selection.account_context_fingerprint
        ):
            _fail(
                "INVALID_CONFIGURATION",
                "coordinator selection context differs from activation",
            )
        self.coordinator_selection = validate_coordinator_selection_document_v2(
            coordinator_selection.to_document()
        )
        self.instance_id = instance_id
        self.controller_start_id = controller_start_id
        self.control_epoch = control_epoch
        self.registrar = registrar
        self.clock = clock or _utc_now
        self.io_timeout_seconds = float(io_timeout_seconds)
        self.codex_home_hash = hashlib.sha256(
            str(self.codex_home).encode("utf-8")
        ).hexdigest()

        self._lifecycle_lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._coordinator_lock = threading.Lock()
        self._workers_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._worker_slots = threading.BoundedSemaphore(MAX_WORKERS)
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_WORKERS,
            thread_name_prefix="codex-smart-health-v2",
        )
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._listener: socket.socket | None = None
        self._lock_fd: int | None = None
        self._lock_created = False
        self._lock_identity: tuple[int, int, int, int, int, int, int] | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._active_socket_claimed = False
        self._registration: ControllerRegistrationReceiptV2 | None = None
        self._controller: AcceptingControllerV2 | None = None
        self._lifecycle_handler: LifecycleHandlerV2 | None = None
        self._lifecycle_response_observer: LifecycleResponseObserverV2 | None = None
        self._expected_control_epoch = control_epoch
        self._candidate_mode = False
        self._started = False
        self._closed = False

    def publish_coordinator_selection(
        self,
        selection: CoordinatorSelectionV2,
    ) -> None:
        """Атомарно публикует повторно доказанный выбор в живом health."""

        if not isinstance(selection, CoordinatorSelectionV2):
            _fail(
                "INVALID_CONFIGURATION",
                "coordinator selection refresh has another type",
            )
        if (
            selection.recompute_account_context_fingerprint(
                active_context_fingerprint=self.activation_fingerprint,
            )
            != selection.account_context_fingerprint
        ):
            _fail(
                "INVALID_CONFIGURATION",
                "refreshed coordinator selection context differs from activation",
            )
        document = validate_coordinator_selection_document_v2(
            selection.to_document()
        )
        with self._coordinator_lock:
            if self._closed:
                _fail("SERVER_CLOSED", "controller health server is closed")
            self.coordinator_selection = document

    def start(self) -> AcceptingControllerV2:
        """Связывает сокет, регистрирует БД и только после проверки открывает готовность."""

        with self._lifecycle_lock:
            if self._closed:
                _fail("SERVER_CLOSED", "controller health server is closed")
            if self._started:
                assert self._controller is not None
                return self._controller
            try:
                controller = self._claim_controller_binding()
                registration = self.registrar(controller)
                if type(registration) is not ControllerRegistrationReceiptV2:
                    _fail(
                        "REGISTRATION_INVALID",
                        "registrar must return ControllerRegistrationReceiptV2",
                    )
                self._registration = registration
                self._read_health_payload(registration.database_path, controller)
                self._controller = controller
                self._started = True
                self._ready.set()
                return controller
            except ChildGuardV2Error as exc:
                self._rollback_start()
                raise ControllerHealthV2Error(
                    "PROCESS_MARKER_UNAVAILABLE", str(exc)
                ) from exc
            except BaseException:
                self._rollback_start()
                raise

    def start_candidate(self, *, database_path: Path) -> AcceptingControllerV2:
        """Открыть унаследованный канал кандидата до ``controller_accept``.

        База уже должна находиться в непубликуемой служебной форме. Метод не
        объявляет health-готовность и не изменяет SQLite: единственным переходом
        остаётся долговечный ``controller_accept`` через привязанный обработчик.
        """

        _private_database(database_path)
        database_path = database_path.resolve(strict=True)
        with self._lifecycle_lock:
            if self._closed:
                _fail("SERVER_CLOSED", "controller health server is closed")
            if self._started:
                _fail("SERVER_ALREADY_STARTED", "candidate channel is already started")
            try:
                controller = self._claim_controller_binding()
                self._registration = ControllerRegistrationReceiptV2(
                    database_path=database_path,
                    cleanup=lambda: None,
                )
                self._controller = controller
                self._candidate_mode = True
                self._started = True
                return controller
            except BaseException:
                self._rollback_start()
                raise

    def _claim_controller_binding(self) -> AcceptingControllerV2:
        socket_info = self._claim_socket()
        process_marker = system_process_start_marker_v2(os.getpid())
        updated_at = self.clock()
        if (
            not isinstance(updated_at, datetime)
            or updated_at.tzinfo is None
            or updated_at.utcoffset() is None
        ):
            _fail("INVALID_TIME", "clock must return an aware datetime")
        return self._controller_binding(
            socket_info=socket_info,
            process_marker=process_marker,
            updated_at=updated_at.astimezone(timezone.utc),
        )

    def wait_until_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def bind_lifecycle_handler(
        self,
        handler: LifecycleHandlerV2,
        *,
        response_observer: LifecycleResponseObserverV2 | None = None,
    ) -> None:
        """Однократно подключает долговечный обработчик управляющих команд."""

        if not callable(handler):
            _fail("INVALID_CONFIGURATION", "lifecycle handler must be callable")
        if response_observer is not None and not callable(response_observer):
            _fail(
                "INVALID_CONFIGURATION",
                "lifecycle response observer must be callable",
            )
        with self._lifecycle_lock:
            if self._closed:
                _fail("SERVER_CLOSED", "controller protocol server is closed")
            if (
                self._lifecycle_handler is not None
                and self._lifecycle_handler != handler
            ):
                _fail(
                    "LIFECYCLE_HANDLER_ALREADY_BOUND",
                    "another lifecycle handler is already bound",
                )
            self._lifecycle_handler = handler
            self._lifecycle_response_observer = response_observer

    def serve_forever(self) -> None:
        listener = self._listener
        if not self._started or listener is None:
            _fail("SERVER_NOT_STARTED", "start must complete before serve_forever")
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop.is_set() or exc.errno in {errno.EBADF, errno.EINVAL}:
                    break
                raise
            connection.settimeout(self.io_timeout_seconds)
            if not self._worker_slots.acquire(blocking=False):
                connection.close()
                continue
            with self._workers_lock:
                self._connections.add(connection)
            try:
                self._executor.submit(self._handle_connection, connection)
            except RuntimeError:
                with self._workers_lock:
                    self._connections.discard(connection)
                self._worker_slots.release()
                connection.close()

    def close(self) -> None:
        with self._close_lock:
            with self._lifecycle_lock:
                if self._closed:
                    return
                self._closed = True
                self._stop.set()
                listener = self._listener
                self._listener = None
                if listener is not None:
                    try:
                        listener.close()
                    except OSError:
                        pass
                with self._workers_lock:
                    connections = list(self._connections)
                for connection in connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        connection.close()
                    except OSError:
                        pass

            # Принятый работник входит в lifecycle-блокировку для чтения
            # регистрации. Ожидание пула под той же блокировкой создало бы
            # взаимную блокировку между close и таким работником.
            self._executor.shutdown(wait=True, cancel_futures=True)
            with self._lifecycle_lock:
                cleanup_error = self._cleanup_registration()
                self._safe_remove_socket()
                self._release_lock()
                self._ready.clear()
                self._release_active_socket_claim()
                if cleanup_error is not None:
                    raise ControllerHealthV2Error(
                        "REGISTRATION_CLEANUP_FAILED", str(cleanup_error)
                    ) from cleanup_error

    def discard_created_lock(self) -> None:
        """Удаляет только неизменённый lock, созданный этим сервером."""

        with self._lifecycle_lock:
            if self._lock_fd is not None:
                _fail("SERVER_NOT_CLOSED", "controller lock ещё занят сервером")
            identity = self._lock_identity
            if not self._lock_created or identity is None:
                return
            try:
                info = os.lstat(self.lock_path)
            except FileNotFoundError:
                self._lock_created = False
                self._lock_identity = None
                return
            observed = (
                info.st_dev,
                info.st_ino,
                info.st_uid,
                info.st_gid,
                stat.S_IMODE(info.st_mode),
                info.st_nlink,
                info.st_size,
            )
            if stat.S_ISREG(info.st_mode) and observed == identity:
                os.unlink(self.lock_path)
                self._lock_created = False
                self._lock_identity = None

    def _claim_socket(self) -> os.stat_result:
        socket_key = str(self.socket_path)
        with _ACTIVE_LOCK:
            if socket_key in _ACTIVE_SOCKETS:
                _fail("CONTROLLER_ALREADY_RUNNING", "socket is already active")
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        lock_created = False
        lock_identity: tuple[int, int, int, int, int, int, int] | None = None
        try:
            lock_fd = os.open(
                self.lock_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            lock_created = True
        except FileExistsError:
            lock_fd = os.open(self.lock_path, flags)
        try:
            lock_info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.getuid()
                or lock_info.st_nlink != 1
            ):
                _fail("UNSAFE_LOCK", "controller lock has unexpected metadata")
            os.fchmod(lock_fd, 0o600)
            lock_info = os.fstat(lock_fd)
            lock_identity = (
                lock_info.st_dev,
                lock_info.st_ino,
                lock_info.st_uid,
                lock_info.st_gid,
                stat.S_IMODE(lock_info.st_mode),
                lock_info.st_nlink,
                lock_info.st_size,
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ControllerHealthV2Error(
                    "CONTROLLER_ALREADY_RUNNING", "controller lock is held"
                ) from exc
            self._remove_proven_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            bound_identity: tuple[int, int] | None = None
            try:
                listener.bind(str(self.socket_path))
                bound_info = os.lstat(self.socket_path)
                if (
                    not stat.S_ISSOCK(bound_info.st_mode)
                    or bound_info.st_uid != os.getuid()
                    or bound_info.st_nlink != 1
                ):
                    _fail("UNSAFE_SOCKET", "bound socket has unexpected metadata")
                bound_identity = (bound_info.st_dev, bound_info.st_ino)
                os.chmod(self.socket_path, 0o600)
                socket_info = os.lstat(self.socket_path)
                if (
                    not stat.S_ISSOCK(socket_info.st_mode)
                    or socket_info.st_uid != os.getuid()
                    or socket_info.st_nlink != 1
                    or stat.S_IMODE(socket_info.st_mode) != 0o600
                    or (socket_info.st_dev, socket_info.st_ino) != bound_identity
                ):
                    _fail("UNSAFE_SOCKET", "controller socket has unexpected metadata")
                listener.listen(32)
                listener.settimeout(0.05)
            except BaseException:
                listener.close()
                self._remove_socket_matching(bound_identity)
                raise
            self._lock_fd = lock_fd
            self._lock_created = lock_created
            self._lock_identity = lock_identity
            self._listener = listener
            self._socket_identity = (socket_info.st_dev, socket_info.st_ino)
            with _ACTIVE_LOCK:
                _ACTIVE_SOCKETS.add(socket_key)
                self._active_socket_claimed = True
            return socket_info
        except BaseException:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)
            if lock_created and lock_identity is not None:
                try:
                    info = os.lstat(self.lock_path)
                    if (
                        stat.S_ISREG(info.st_mode)
                        and (info.st_dev, info.st_ino)
                        == (lock_identity[0], lock_identity[1])
                        and info.st_uid == lock_identity[2]
                        and info.st_gid == lock_identity[3]
                        and stat.S_IMODE(info.st_mode) == lock_identity[4]
                        and info.st_nlink == lock_identity[5]
                        and info.st_size == lock_identity[6]
                    ):
                        os.unlink(self.lock_path)
                except FileNotFoundError:
                    pass
            raise

    def _remove_proven_stale_socket(self) -> None:
        try:
            first = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(first.st_mode)
            or first.st_uid != os.getuid()
            or first.st_nlink != 1
        ):
            _fail(
                "UNSAFE_EXISTING_SOCKET",
                "existing controller path is not a safe owned socket",
            )
        second = os.lstat(self.socket_path)
        if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
            _fail("SOCKET_CHANGED", "controller socket changed during stale check")
        os.unlink(self.socket_path)

    def _controller_binding(
        self,
        *,
        socket_info: os.stat_result,
        process_marker: str,
        updated_at: datetime,
    ) -> AcceptingControllerV2:
        projection = {
            "protocolVersion": 2,
            "release": RELEASE,
            "namespace": NAMESPACE,
            "codexHomeHash": self.codex_home_hash,
            "stateHome": str(self.state_home),
            "activationFingerprint": self.activation_fingerprint,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "routingPolicyFingerprint": self.routing_policy_fingerprint,
            "bundledCatalogFingerprint": self.bundled_catalog_fingerprint,
            "databaseId": self.database_id,
            "databaseSchemaVersion": 2,
        }
        return AcceptingControllerV2(
            controller_identity=domain_fingerprint(
                "codex-smart/controller-identity/v2", projection
            ),
            instance_id=self.instance_id,
            controller_start_id=self.controller_start_id,
            controller_pid=os.getpid(),
            controller_process_start_marker=process_marker,
            controller_process_group_id=os.getpgrp(),
            control_epoch=self.control_epoch,
            activation_id=self.activation_id,
            activation_fingerprint=self.activation_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
            routing_policy_fingerprint=self.routing_policy_fingerprint,
            bundled_catalog_fingerprint=self.bundled_catalog_fingerprint,
            socket_path=str(self.socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            socket_mode=f"0{stat.S_IMODE(socket_info.st_mode):03o}",
            updated_at=updated_at,
        )

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            with connection:
                response_observer: LifecycleResponseObserverV2 | None = None
                if _peer_uid(connection) != os.getuid():
                    _fail("PEER_FORBIDDEN", "controller client has another user id")
                request = _read_request(connection)
                with self._lifecycle_lock:
                    controller = self._controller
                    registration = self._registration
                    if controller is None or registration is None:
                        _fail(
                            "SERVER_NOT_STARTED",
                            "controller registration is unavailable",
                        )
                    if request.get("method") == "health":
                        if not self._ready.is_set():
                            _fail(
                                "CANDIDATE_NOT_ACCEPTED",
                                "candidate health is withheld before controller_accept",
                            )
                        _validate_health_request(
                            request,
                            codex_home_hash=self.codex_home_hash,
                        )
                        payload, control_epoch = self._read_health_payload(
                            registration.database_path,
                            controller,
                        )
                        response = self._health_response(
                            request=request,
                            payload=payload,
                            control_epoch=control_epoch,
                        )
                    else:
                        handler = self._lifecycle_handler
                        if handler is None:
                            _fail(
                                "METHOD_NOT_AVAILABLE",
                                "lifecycle handler is not bound",
                            )
                        try:
                            response = dict(handler(request))
                        except LifecycleControllerProtocolV2Error as exc:
                            response = _lifecycle_error_response(
                                request,
                                error=exc,
                                control_epoch=self._expected_control_epoch,
                            )
                        canonical_json_bytes(response)
                        if response.get("responseKind") == "SUCCESS":
                            response_epoch = response.get("controlEpoch")
                            if type(response_epoch) is not int:
                                _fail(
                                    "INVALID_LIFECYCLE_RESPONSE",
                                    "successful lifecycle response has no epoch",
                                )
                            self._expected_control_epoch = response_epoch
                            if self._candidate_mode and request.get("method") in {
                                "controller_accept",
                                "controller_recover",
                            }:
                                self._complete_candidate_registration(response)
                        response_observer = self._lifecycle_response_observer
                encoded = canonical_json_bytes(response) + b"\n"
                if len(encoded) > MAX_MESSAGE_BYTES:
                    _fail(
                        "RESPONSE_TOO_LARGE", "health response exceeds the size limit"
                    )
                connection.sendall(encoded)
                if response_observer is not None:
                    response_observer(request, response)
        except (ControllerHealthV2Error, OSError, UnicodeError, ValueError):
            pass
        finally:
            with self._workers_lock:
                self._connections.discard(connection)
            self._worker_slots.release()

    def _complete_candidate_registration(
        self,
        response: Mapping[str, object],
    ) -> None:
        controller = self._controller
        registration = self._registration
        payload = response.get("payload")
        if (
            controller is None
            or registration is None
            or not isinstance(payload, Mapping)
            or type(response.get("controlEpoch")) is not int
            or type(payload.get("instanceId")) is not str
            or payload.get("controllerStartId") != controller.controller_start_id
            or payload.get("controllerIdentity") != controller.controller_identity
        ):
            _fail(
                "CANDIDATE_ACCEPT_RESPONSE_INVALID",
                "candidate acceptance did not return its exact process identity",
            )
        accepted = replace(
            controller,
            instance_id=str(payload["instanceId"]),
            control_epoch=int(response["controlEpoch"]),
        )
        self._read_health_payload(registration.database_path, accepted)
        self._controller = accepted
        self._candidate_mode = False
        self._ready.set()

    def _read_health_payload(
        self,
        database_path: Path,
        controller: AcceptingControllerV2,
    ) -> tuple[dict[str, object], int]:
        database_deadline = time.monotonic() + HEALTH_DATABASE_DEADLINE_SECONDS
        database_info = _private_database(database_path)
        connection = sqlite3.connect(
            database_path,
            timeout=0.1,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.set_progress_handler(
                lambda: int(time.monotonic() >= database_deadline),
                1000,
            )
            connection.execute("pragma query_only=on")
            connection.execute("pragma busy_timeout=100")
            connection.execute("begin")
            application_id = int(
                connection.execute("pragma application_id").fetchone()[0]
            )
            user_version = int(connection.execute("pragma user_version").fetchone()[0])
            controller_rows = connection.execute(
                "select * from controller_state"
            ).fetchall()
            identity_rows = connection.execute(
                "select * from database_identity"
            ).fetchall()
            counts = {
                name: int(connection.execute(statement).fetchone()[0])
                for name, statement in _QUIESCENCE_QUERIES.items()
            }
            connection.execute("commit")
            if time.monotonic() >= database_deadline:
                _fail(
                    "DATABASE_DEADLINE_EXCEEDED",
                    "health database projection exceeded its deadline",
                )
        except sqlite3.Error as exc:
            raise ControllerHealthV2Error("DATABASE_UNAVAILABLE", str(exc)) from exc
        finally:
            connection.close()
        after = _private_database(database_path)
        if (database_info.st_dev, database_info.st_ino) != (after.st_dev, after.st_ino):
            _fail("DATABASE_CHANGED", "database inode changed while reading health")
        if application_id != APPLICATION_ID or user_version != 2:
            _fail("DATABASE_BINDING_MISMATCH", "database protocol metadata differs")
        if len(controller_rows) != 1 or len(identity_rows) != 1:
            _fail("DATABASE_BINDING_MISMATCH", "database singleton rows differ")
        row = dict(controller_rows[0])
        identity = dict(identity_rows[0])
        self._validate_database_binding(row, identity, controller)
        self._validate_live_process_and_socket(controller)
        if type(row["quiescent"]) is not int or row["quiescent"] not in {0, 1}:
            _fail("CONTROLLER_BINDING_MISMATCH", "quiescent flag is invalid")
        if bool(row["quiescent"]) and any(counts.values()):
            _fail("CONTROLLER_BINDING_MISMATCH", "quiescent row has active work")
        maintenance_modes = {"NONE": None, "DRAIN": "drain", "FREEZE": "freeze"}
        maintenance_mode = maintenance_modes.get(str(row["maintenance_mode"]))
        if str(row["maintenance_mode"]) not in maintenance_modes:
            _fail("CONTROLLER_BINDING_MISMATCH", "maintenance mode is invalid")
        with self._coordinator_lock:
            coordinator_selection = dict(self.coordinator_selection)
        return {
            "namespace": NAMESPACE,
            "controllerIdentity": row["controller_identity"],
            "instanceId": row["instance_id"],
            "controllerStartId": row["controller_start_id"],
            "pid": row["controller_pid"],
            "processStartMarker": row["controller_process_start_marker"],
            "processGroupId": row["controller_process_group_id"],
            "state": row["state"],
            "maintenanceMode": maintenance_mode,
            "operationId": row["operation_id"],
            "acceptingNewRoutes": bool(row["accepting_new_routes"]),
            "quiescent": bool(row["quiescent"]),
            "activationFingerprint": row["activation_fingerprint"],
            "compatibilityFingerprint": row["compatibility_fingerprint"],
            "routingPolicyFingerprint": row["routing_policy_fingerprint"],
            "bundledCatalogFingerprint": row["bundled_catalog_fingerprint"],
            "coordinatorSelection": coordinator_selection,
            "databaseId": row["database_id"],
            "databaseSchemaVersion": 2,
            "workCounts": counts,
        }, int(row["control_epoch"])

    def _validate_database_binding(
        self,
        row: dict[str, object],
        identity: dict[str, object],
        controller: AcceptingControllerV2,
    ) -> None:
        expected = {
            "singleton": 1,
            "database_id": self.database_id,
            "protocol_version": PROTOCOL_VERSION,
            "release": RELEASE,
            "controller_identity": controller.controller_identity,
            "instance_id": controller.instance_id,
            "controller_start_id": controller.controller_start_id,
            "controller_pid": controller.controller_pid,
            "controller_process_start_marker": controller.controller_process_start_marker,
            "controller_process_group_id": controller.controller_process_group_id,
            "control_epoch": self._expected_control_epoch,
            "activation_id": controller.activation_id,
            "activation_fingerprint": controller.activation_fingerprint,
            "compatibility_fingerprint": controller.compatibility_fingerprint,
            "routing_policy_fingerprint": controller.routing_policy_fingerprint,
            "bundled_catalog_fingerprint": controller.bundled_catalog_fingerprint,
            "socket_path": controller.socket_path,
            "socket_device": controller.socket_device,
            "socket_inode": controller.socket_inode,
            "socket_owner_uid": controller.socket_owner_uid,
            "socket_owner_gid": controller.socket_owner_gid,
            "socket_mode": controller.socket_mode,
            "lock_held": 1,
        }
        if any(row.get(name) != value for name, value in expected.items()):
            _fail("CONTROLLER_BINDING_MISMATCH", "controller database row diverges")
        live_states = {
            ("ACCEPTING", "NONE", True, False),
            ("DRAINING", "DRAIN", False, True),
            ("MAINTENANCE", "DRAIN", False, True),
            ("MAINTENANCE", "FREEZE", False, True),
        }
        lifecycle_shape = (
            row.get("state"),
            row.get("maintenance_mode"),
            row.get("accepting_new_routes") == 1,
            row.get("operation_id") is not None,
        )
        if lifecycle_shape not in live_states:
            _fail(
                "CONTROLLER_BINDING_MISMATCH",
                "controller lifecycle row is not live",
            )
        identity_expected = {
            "singleton": 1,
            "database_id": self.database_id,
            "schema_version": 2,
            "activation_id": controller.activation_id,
            "activation_fingerprint": controller.activation_fingerprint,
        }
        if any(
            identity.get(name) != value for name, value in identity_expected.items()
        ):
            _fail("DATABASE_BINDING_MISMATCH", "database identity row diverges")

    def _validate_live_process_and_socket(
        self,
        controller: AcceptingControllerV2,
    ) -> None:
        try:
            marker = system_process_start_marker_v2(controller.controller_pid)
        except ChildGuardV2Error as exc:
            raise ControllerHealthV2Error(
                "PROCESS_MARKER_UNAVAILABLE", str(exc)
            ) from exc
        if marker != controller.controller_process_start_marker:
            _fail("CONTROLLER_BINDING_MISMATCH", "process start marker diverges")
        info = os.lstat(self.socket_path)
        observed = (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            f"0{stat.S_IMODE(info.st_mode):03o}",
        )
        expected = (
            controller.socket_device,
            controller.socket_inode,
            controller.socket_owner_uid,
            controller.socket_owner_gid,
            controller.socket_mode,
        )
        if not stat.S_ISSOCK(info.st_mode) or observed != expected:
            _fail("CONTROLLER_BINDING_MISMATCH", "controller socket identity diverges")

    def _health_response(
        self,
        *,
        request: dict[str, object],
        payload: dict[str, object],
        control_epoch: int,
    ) -> dict[str, object]:
        projection: dict[str, object] = {
            "messageType": "response",
            "protocolVersion": PROTOCOL_VERSION,
            "release": RELEASE,
            "method": "health",
            "responseKind": "HEALTH",
            "commandId": None,
            "requestFingerprint": request["requestFingerprint"],
            "controlEpoch": control_epoch,
            "payload": payload,
        }
        return {
            **projection,
            "responseFingerprint": domain_fingerprint(
                "codex-smart/controller-response/v2", projection
            ),
            "extensions": {},
        }

    def _rollback_start(self) -> None:
        self._cleanup_registration()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        self._safe_remove_socket()
        self._release_lock()
        self._ready.clear()
        self._release_active_socket_claim()

    def _cleanup_registration(self) -> BaseException | None:
        registration = self._registration
        self._registration = None
        if registration is None:
            return None
        try:
            registration.cleanup()
        except BaseException as exc:  # cleanup must not prevent lock release
            return exc
        return None

    def _safe_remove_socket(self) -> None:
        identity = self._socket_identity
        self._socket_identity = None
        self._remove_socket_matching(identity)

    def _remove_socket_matching(self, identity: tuple[int, int] | None) -> None:
        if identity is None:
            return
        try:
            info = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == os.getuid()
            and (info.st_dev, info.st_ino) == identity
        ):
            os.unlink(self.socket_path)

    def _release_lock(self) -> None:
        lock_fd = self._lock_fd
        self._lock_fd = None
        if lock_fd is None:
            return
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    def _release_active_socket_claim(self) -> None:
        if not self._active_socket_claimed:
            return
        with _ACTIVE_LOCK:
            _ACTIVE_SOCKETS.discard(str(self.socket_path))
            self._active_socket_claimed = False


# Совместимое имя отражает расширенную поверхность, не ломая ранние импорты.
ControllerProtocolServerV2 = ControllerHealthServerV2


def _lifecycle_error_response(
    request: Mapping[str, object],
    *,
    error: LifecycleControllerProtocolV2Error,
    control_epoch: int,
) -> dict[str, object]:
    """Возвращает ошибку только для уже подтверждённого конверта запроса."""

    if error.code == "INVALID_REQUEST":
        _fail("INVALID_REQUEST", "invalid lifecycle request has no response")
    method = request.get("method")
    command_id = request.get("commandId")
    request_fingerprint = request.get("requestFingerprint")
    if (
        method not in _LIFECYCLE_METHODS
        or not _nullable_prefixed_hex(command_id, prefix="cc2_", suffix=32)
        or not _nullable_prefixed_hex(
            request_fingerprint,
            prefix="",
            suffix=64,
            nullable=False,
        )
        or type(control_epoch) is not int
        or not 1 <= control_epoch <= MAX_SAFE_INTEGER
    ):
        _fail("INVALID_REQUEST", "lifecycle error cannot be bound to request")
    category = error.category
    code = error.code
    if code not in _REMOTE_CODES_BY_CATEGORY.get(category, frozenset()):
        category = "INTERNAL"
        code = "INTERNAL_ERROR"
        message = (
            "внутренняя ошибка управляющего протокола"
        )
        retryable = False
    else:
        message = (
            error.message[:1024]
            or "отклонено управляющим протоколом"
        )
        retryable = error.retryable
    projection = {
        "messageType": "response",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "method": method,
        "responseKind": "ERROR",
        "commandId": command_id,
        "requestFingerprint": request_fingerprint,
        "controlEpoch": control_epoch,
        "payload": {
            "category": category,
            "code": code,
            "message": message,
            "retryable": retryable,
        },
    }
    return {
        **projection,
        "responseFingerprint": domain_fingerprint(
            "codex-smart/controller-response/v2", projection
        ),
        "extensions": {},
    }


def _nullable_prefixed_hex(
    value: object,
    *,
    prefix: str,
    suffix: int,
    nullable: bool = True,
) -> bool:
    if value is None:
        return nullable
    if type(value) is not str or not value.startswith(prefix):
        return False
    tail = value[len(prefix) :]
    return len(tail) == suffix and all(
        character in "0123456789abcdef" for character in tail
    )


def _read_request(connection: socket.socket) -> dict[str, object]:
    buffer = bytearray()
    while True:
        remaining = MAX_MESSAGE_BYTES + 1 - len(buffer)
        if remaining <= 0:
            _fail("MESSAGE_TOO_LARGE", "health request exceeds the size limit")
        chunk = connection.recv(min(65536, remaining))
        if not chunk:
            _fail("INVALID_REQUEST", "health request ended before newline")
        buffer.extend(chunk)
        if len(buffer) > MAX_MESSAGE_BYTES:
            _fail("MESSAGE_TOO_LARGE", "health request exceeds the size limit")
        newline = buffer.find(b"\n")
        if newline < 0:
            continue
        if newline != len(buffer) - 1:
            _fail("INVALID_REQUEST", "health request has trailing bytes")
        raw = bytes(buffer[:newline])
        break
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: _raise_json("floating values are forbidden"),
            parse_constant=lambda _value: _raise_json(
                "non-finite values are forbidden"
            ),
        )
        canonical_json_bytes(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        CanonicalJsonError,
        ValueError,
    ) as exc:
        raise ControllerHealthV2Error("INVALID_REQUEST", str(exc)) from exc
    if type(value) is not dict:
        _fail("INVALID_REQUEST", "health request must be an object")
    return value


def _validate_health_request(
    value: dict[str, object],
    *,
    codex_home_hash: str,
) -> None:
    expected_keys = {
        "messageType",
        "protocolVersion",
        "release",
        "codexHomeHash",
        "shellSessionId",
        "controllerIdentity",
        "instanceId",
        "controllerStartId",
        "commandId",
        "expectedControlEpoch",
        "operationId",
        "method",
        "params",
        "requestFingerprint",
        "extensions",
    }
    if set(value) != expected_keys:
        _fail("INVALID_REQUEST", "health request fields differ")
    constants = {
        "messageType": "request",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "codexHomeHash": codex_home_hash,
        "controllerIdentity": None,
        "instanceId": None,
        "controllerStartId": None,
        "commandId": None,
        "expectedControlEpoch": None,
        "operationId": None,
        "method": "health",
        "params": {},
    }
    if any(value[name] != expected for name, expected in constants.items()):
        _fail("INVALID_REQUEST", "health request envelope differs")
    shell_session_id = value["shellSessionId"]
    if type(shell_session_id) is not str or not 1 <= len(shell_session_id) <= 256:
        _fail("INVALID_REQUEST", "shellSessionId is invalid")
    if type(value["extensions"]) is not dict or len(value["extensions"]) > 128:
        _fail("INVALID_REQUEST", "health extensions are invalid")
    _sha256(value["requestFingerprint"], "requestFingerprint")
    projection = {
        key: item
        for key, item in value.items()
        if key not in {"requestFingerprint", "extensions"}
    }
    if value["requestFingerprint"] != domain_fingerprint(
        "codex-smart/controller-request/v2", projection
    ):
        _fail("INVALID_REQUEST", "health request fingerprint differs")


def _private_database(path: Path) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("REGISTRATION_INVALID", "database path must be absolute")
    try:
        parent_info = os.lstat(path.parent)
        info = os.lstat(path)
    except OSError as exc:
        raise ControllerHealthV2Error("DATABASE_UNAVAILABLE", str(exc)) from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        _fail("UNSAFE_DATABASE", "database file has unexpected metadata")
    return info


def _private_directory(path: Path, name: str) -> Path:
    absolute = _absolute_path(path, name)
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        raise ControllerHealthV2Error("INVALID_CONFIGURATION", str(exc)) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        _fail("INVALID_CONFIGURATION", f"{name} must be a private owned directory")
    return absolute


def _owned_codex_home_directory(path: Path) -> Path:
    absolute = _absolute_path(path, "codex_home")
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        raise ControllerHealthV2Error("INVALID_CONFIGURATION", str(exc)) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o755}
    ):
        _fail(
            "INVALID_CONFIGURATION",
            "codex_home must be owned and have mode 0700 or 0755",
        )
    return absolute


def _absolute_path(path: Path, name: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("INVALID_CONFIGURATION", f"{name} must be an absolute Path")
    return path


def _identifier(value: object, prefix: str, suffix: int, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != len(prefix) + suffix
        or not value.startswith(prefix)
        or any(
            character not in "0123456789abcdef" for character in value[len(prefix) :]
        )
    ):
        _fail("INVALID_CONFIGURATION", f"{name} is invalid")


def _sha256(value: object, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail("INVALID_CONFIGURATION", f"{name} is not a lowercase SHA-256")


def _peer_uid(connection: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    library = ctypes.CDLL(None, use_errno=True)
    getpeereid = getattr(library, "getpeereid", None)
    if getpeereid is None:
        _fail("PEER_CREDENTIALS_UNAVAILABLE", "getpeereid is unavailable")
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    result = getpeereid(
        connection.fileno(),
        ctypes.byref(uid),
        ctypes.byref(gid),
    )
    if result != 0:
        _fail("PEER_CREDENTIALS_FAILED", os.strerror(ctypes.get_errno()))
    return int(uid.value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _raise_json(message: str):
    raise ValueError(message)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fail(code: str, message: str):
    raise ControllerHealthV2Error(code, message)
