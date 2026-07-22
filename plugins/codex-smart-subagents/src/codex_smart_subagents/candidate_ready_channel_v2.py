"""Закрытый, восстанавливаемый канал регистрации контроллера-кандидата v2.

Канал не зависит от ``Popen`` и не ищет процесс через ``ps``. Единственная
точка повторного подключения — неизменяемое действие долговечного журнала:
путь сокета и хеш одноразового токена. Сам токен передаётся только дочернему
процессу, проверяется до публикации сокета и затем не отправляется по каналу.
"""

from __future__ import annotations

import copy
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import MutableMapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import quote

from .canonical_json import MAX_SAFE_INTEGER, canonical_json_bytes, domain_fingerprint
from .child_guard_v2 import system_process_start_marker_v2
from .durable_process_ownership_v2 import (
    DurableProcessOwnershipStoreV2,
    DurableProcessOwnershipV2Error,
)
from . import finite_file_lock_v2
from . import operation_deadline_v2
from . import operation_process_group_supervisor_v2
from .schema_projection import APPLICATION_ID
from .sqlite_deadline_v2 import (
    DeadlineAwareConnectionV2,
    connect_sqlite_with_deadline_v2,
)


_ACTION_KEYS = frozenset(
    {
        "actionKind",
        "candidateId",
        "controllerIdentity",
        "controllerStartId",
        "operationId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "argv",
        "argvFingerprint",
        "snapshotFingerprint",
        "privateReadyChannelPath",
        "readinessTokenHash",
        "readinessWindowMs",
        "processGroupPolicy",
    }
)
_DISPATCH_INTENT_KEYS = frozenset(
    {
        "schemaVersion",
        "receiptKind",
        "operationId",
        "candidateId",
        "controllerStartId",
        "actionFingerprint",
        "readinessTokenHash",
        "readinessWindowMs",
        "createdAtMonotonicMs",
        "absoluteDeadlineMonotonicMs",
        "receiptFingerprint",
    }
)
_REGISTRATION_KEYS = frozenset(
    {
        "candidateId",
        "controllerIdentity",
        "controllerStartId",
        "operationId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "argvFingerprint",
        "snapshotFingerprint",
        "privateReadyChannelPath",
        "privateReadyChannel",
        "readinessTokenHash",
        "readinessWindowMs",
        "processGroupPolicy",
        "pid",
        "processStartMarker",
        "processGroupId",
        "registrationFingerprint",
        "databaseLeaseProofFingerprint",
        "databaseOpened",
        "workingSocketPublished",
        "acceptingNewRoutes",
        "status",
        "exitProofFingerprint",
    }
)
_RESPONSE_KEYS = frozenset(
    {
        "protocolVersion",
        "responseKind",
        "candidateId",
        "controllerStartId",
        "operationId",
        "challengeNonce",
        "registration",
        "databaseLease",
        "workingControllerSocket",
        "responseFingerprint",
    }
)
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_SOCKET_PATH_LIMIT = 100
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIERS = {
    "candidateId": re.compile(r"^cand2_[0-9a-f]{32}$"),
    "controllerStartId": re.compile(r"^cs2_[0-9a-f]{32}$"),
    "operationId": re.compile(r"^op2_[0-9a-f]{32}$"),
    "activationId": re.compile(r"^act2_[0-9a-f]{64}$"),
    "databaseId": re.compile(r"^db2_[0-9a-f]{32}$"),
}
_CHALLENGE_DOMAIN = b"codex-smart/candidate-ready-challenge/v2\0"
_CANDIDATE_ARGV_DOMAIN = "codex-smart/controller-candidate-argv/v2"
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_REGISTRATION_RECEIPT_BYTES = 256 * 1024
_MAX_DISPATCH_INTENT_RECEIPT_BYTES = 16 * 1024
_MAX_CANDIDATE_SPAWN_WINDOW_MS = 30_000
_MAX_CANDIDATE_DISPATCH_ATTEMPTS = 8
_CANDIDATE_DISPATCH_LOCK_DIRECTORY = "candidate-dispatch-locks-v2"
_CANDIDATE_DISPATCH_LOCK_TIMEOUT_SECONDS = 30.0
_RETIRED_DISPATCH_DIRECTORY = "candidate-dispatch-retired-v2"
_READINESS_TOKEN_ENVIRONMENT = "CODEX_V2_CANDIDATE_READINESS_TOKEN"
_OWNERSHIP_GATE_FD_ENVIRONMENT = "CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD"
_REGISTRATION_RECEIPT_DOMAIN = (
    "codex-smart/controller-candidate-registration-receipt/v2"
)
_DISPATCH_INTENT_RECEIPT_DOMAIN = (
    "codex-smart/controller-candidate-dispatch-intent-receipt/v2"
)
_CANDIDATE_PROJECTION_DOMAIN = "codex-smart/controller-candidate/v2"
_SAFE_RUNTIME_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_CANDIDATE_DISPATCH_THREAD_LOCK = threading.Lock()


@dataclass
class CandidateReadyChannelV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class CandidateSpawnActionV2:
    """Проверенная неизменяемая часть шага ``controller_candidate_spawn``."""

    candidate_id: str
    controller_identity: str
    controller_start_id: str
    operation_id: str
    activation_id: str
    activation_fingerprint: str
    database_id: str
    argv: tuple[str, str, str]
    argv_fingerprint: str
    snapshot_fingerprint: str
    private_ready_channel_path: Path
    readiness_token_hash: str
    readiness_window_ms: int
    process_group_policy: str
    _dispatch_intent: CandidateDispatchIntentReceiptV2 | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CandidateSpawnActionV2":
        if type(value) is not dict or set(value) != _ACTION_KEYS:
            _fail(
                "CANDIDATE_ACTION_INVALID",
                "действие запуска имеет неполный или расширенный набор полей",
            )
        if value.get("actionKind") != "controller-candidate-spawn":
            _fail(
                "CANDIDATE_ACTION_INVALID", "actionKind не является запуском кандидата"
            )
        for name, pattern in _IDENTIFIERS.items():
            item = value.get(name)
            if type(item) is not str or pattern.fullmatch(item) is None:
                _fail("CANDIDATE_ACTION_INVALID", f"{name} имеет неверную форму")
        for name in (
            "controllerIdentity",
            "activationFingerprint",
            "argvFingerprint",
            "snapshotFingerprint",
            "readinessTokenHash",
        ):
            item = value.get(name)
            if type(item) is not str or _SHA256.fullmatch(item) is None:
                _fail("CANDIDATE_ACTION_INVALID", f"{name} не является SHA-256")
        argv = _validate_candidate_argv(value.get("argv"))
        expected_argv_fingerprint = domain_fingerprint(
            _CANDIDATE_ARGV_DOMAIN,
            {"argv": list(argv)},
        )
        if not hmac.compare_digest(
            str(value["argvFingerprint"]), expected_argv_fingerprint
        ):
            _fail(
                "CANDIDATE_ACTION_INVALID",
                "argvFingerprint не соответствует точному argv кандидата",
            )
        raw_path = value.get("privateReadyChannelPath")
        if (
            type(raw_path) is not str
            or not raw_path
            or not Path(raw_path).is_absolute()
        ):
            _fail(
                "CANDIDATE_ACTION_INVALID",
                "privateReadyChannelPath должен быть абсолютным путём",
            )
        readiness_window_ms = value.get("readinessWindowMs")
        if (
            type(readiness_window_ms) is not int
            or not 1 <= readiness_window_ms <= _MAX_CANDIDATE_SPAWN_WINDOW_MS
        ):
            _fail("CANDIDATE_ACTION_INVALID", "окно готовности имеет неверную форму")
        if value.get("processGroupPolicy") != "NEW_PRIVATE_GROUP":
            _fail("CANDIDATE_ACTION_INVALID", "политика группы процесса неверна")
        return cls(
            candidate_id=str(value["candidateId"]),
            controller_identity=str(value["controllerIdentity"]),
            controller_start_id=str(value["controllerStartId"]),
            operation_id=str(value["operationId"]),
            activation_id=str(value["activationId"]),
            activation_fingerprint=str(value["activationFingerprint"]),
            database_id=str(value["databaseId"]),
            argv=argv,
            argv_fingerprint=str(value["argvFingerprint"]),
            snapshot_fingerprint=str(value["snapshotFingerprint"]),
            private_ready_channel_path=Path(str(raw_path)).absolute(),
            readiness_token_hash=str(value["readinessTokenHash"]),
            readiness_window_ms=readiness_window_ms,
            process_group_policy="NEW_PRIVATE_GROUP",
        )

    def to_document(self) -> dict[str, Any]:
        return {
            "actionKind": "controller-candidate-spawn",
            "candidateId": self.candidate_id,
            "controllerIdentity": self.controller_identity,
            "controllerStartId": self.controller_start_id,
            "operationId": self.operation_id,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "databaseId": self.database_id,
            "argv": list(self.argv),
            "argvFingerprint": self.argv_fingerprint,
            "snapshotFingerprint": self.snapshot_fingerprint,
            "privateReadyChannelPath": str(self.private_ready_channel_path),
            "readinessTokenHash": self.readiness_token_hash,
            "readinessWindowMs": self.readiness_window_ms,
            "processGroupPolicy": self.process_group_policy,
        }

    @property
    def action_fingerprint(self) -> str:
        return domain_fingerprint(
            "codex-smart/step-action/v2",
            {"action": self.to_document()},
        )

    @property
    def dispatch_intent(self) -> CandidateDispatchIntentReceiptV2 | None:
        """Вернуть проверенную runtime-привязку, не входящую в action."""

        return self._dispatch_intent

    def with_dispatch_intent(
        self,
        receipt: CandidateDispatchIntentReceiptV2,
    ) -> CandidateSpawnActionV2:
        """Связать runtime-действие с отдельной долговечной квитанцией."""

        if not isinstance(receipt, CandidateDispatchIntentReceiptV2):
            raise TypeError("receipt must be CandidateDispatchIntentReceiptV2")
        receipt.validate_for(self)
        return CandidateSpawnActionV2(
            candidate_id=self.candidate_id,
            controller_identity=self.controller_identity,
            controller_start_id=self.controller_start_id,
            operation_id=self.operation_id,
            activation_id=self.activation_id,
            activation_fingerprint=self.activation_fingerprint,
            database_id=self.database_id,
            argv=self.argv,
            argv_fingerprint=self.argv_fingerprint,
            snapshot_fingerprint=self.snapshot_fingerprint,
            private_ready_channel_path=self.private_ready_channel_path,
            readiness_token_hash=self.readiness_token_hash,
            readiness_window_ms=self.readiness_window_ms,
            process_group_policy=self.process_group_policy,
            _dispatch_intent=receipt,
        )


@dataclass
class CandidateSpawnAuthorizationV2:
    """Одноразовая родительская авторизация передачи секрета в child env."""

    action_fingerprint: str
    readiness_token_hash: str
    _readiness_token: str = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    @classmethod
    def create(
        cls,
        *,
        action: CandidateSpawnActionV2,
        readiness_token: str,
    ) -> "CandidateSpawnAuthorizationV2":
        if not isinstance(action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        _validate_readiness_token(readiness_token)
        token_hash = hashlib.sha256(readiness_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(token_hash, action.readiness_token_hash):
            _fail(
                "CANDIDATE_SPAWN_TOKEN_MISMATCH",
                "секрет запуска не связан с долговечным действием",
            )
        return cls(
            action_fingerprint=action.action_fingerprint,
            readiness_token_hash=token_hash,
            _readiness_token=readiness_token,
        )

    def consume_for(self, action: CandidateSpawnActionV2) -> str:
        """Необратимо выдать секрет ровно одному точному spawn-action."""

        if not isinstance(action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        with self._lock:
            if self._consumed:
                _fail(
                    "CANDIDATE_SPAWN_TOKEN_CONSUMED",
                    "авторизация запуска уже была потреблена",
                )
            if not hmac.compare_digest(
                self.action_fingerprint, action.action_fingerprint
            ) or not hmac.compare_digest(
                self.readiness_token_hash, action.readiness_token_hash
            ):
                _fail(
                    "CANDIDATE_SPAWN_AUTHORIZATION_MISMATCH",
                    "авторизация относится к другому действию",
                )
            self._consumed = True
            token = self._readiness_token
            self._readiness_token = ""
            return token


@dataclass(frozen=True)
class CandidateDispatchIntentReceiptV2:
    """Неизменяемое намерение единственного запуска и его фактический срок."""

    operation_id: str
    candidate_id: str
    controller_start_id: str
    action_fingerprint: str
    readiness_token_hash: str
    readiness_window_ms: int
    created_at_monotonic_ms: int
    absolute_deadline_monotonic_ms: int
    receipt_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        action: CandidateSpawnActionV2,
        created_at_monotonic_ms: int,
    ) -> CandidateDispatchIntentReceiptV2:
        if not isinstance(action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        if type(created_at_monotonic_ms) is not int or created_at_monotonic_ms < 0:
            raise TypeError("created_at_monotonic_ms must be a non-negative int")
        absolute_deadline = created_at_monotonic_ms + action.readiness_window_ms
        if absolute_deadline > MAX_SAFE_INTEGER:
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "абсолютный монотонный срок выходит за безопасный диапазон",
            )
        unsigned = {
            "schemaVersion": 2,
            "receiptKind": "controller-candidate-dispatch-intent-v2",
            "operationId": action.operation_id,
            "candidateId": action.candidate_id,
            "controllerStartId": action.controller_start_id,
            "actionFingerprint": action.action_fingerprint,
            "readinessTokenHash": action.readiness_token_hash,
            "readinessWindowMs": action.readiness_window_ms,
            "createdAtMonotonicMs": created_at_monotonic_ms,
            "absoluteDeadlineMonotonicMs": absolute_deadline,
        }
        return cls.from_mapping(
            {
                **unsigned,
                "receiptFingerprint": domain_fingerprint(
                    _DISPATCH_INTENT_RECEIPT_DOMAIN,
                    unsigned,
                ),
            }
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> CandidateDispatchIntentReceiptV2:
        if type(value) is not dict or set(value) != _DISPATCH_INTENT_KEYS:
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "квитанция dispatch имеет неполный или расширенный набор полей",
            )
        if (
            value.get("schemaVersion") != 2
            or value.get("receiptKind") != "controller-candidate-dispatch-intent-v2"
        ):
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "вид или версия квитанции dispatch неверны",
            )
        for name in ("operationId", "candidateId", "controllerStartId"):
            item = value.get(name)
            if type(item) is not str or _IDENTIFIERS[name].fullmatch(item) is None:
                _fail(
                    "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                    f"{name} квитанции dispatch имеет неверную форму",
                )
        for name in (
            "actionFingerprint",
            "readinessTokenHash",
            "receiptFingerprint",
        ):
            item = value.get(name)
            if type(item) is not str or _SHA256.fullmatch(item) is None:
                _fail(
                    "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                    f"{name} квитанции dispatch не является SHA-256",
                )
        window = value.get("readinessWindowMs")
        created = value.get("createdAtMonotonicMs")
        deadline = value.get("absoluteDeadlineMonotonicMs")
        if (
            type(window) is not int
            or not 1 <= window <= _MAX_CANDIDATE_SPAWN_WINDOW_MS
            or type(created) is not int
            or not 0 <= created <= MAX_SAFE_INTEGER
            or type(deadline) is not int
            or not 1 <= deadline <= MAX_SAFE_INTEGER
            or deadline - created != window
        ):
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "монотонные границы квитанции dispatch неверны",
            )
        unsigned = copy.deepcopy(dict(value))
        receipt_fingerprint = str(unsigned.pop("receiptFingerprint"))
        if not hmac.compare_digest(
            receipt_fingerprint,
            domain_fingerprint(_DISPATCH_INTENT_RECEIPT_DOMAIN, unsigned),
        ):
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "fingerprint квитанции dispatch неверен",
            )
        return cls(
            operation_id=str(value["operationId"]),
            candidate_id=str(value["candidateId"]),
            controller_start_id=str(value["controllerStartId"]),
            action_fingerprint=str(value["actionFingerprint"]),
            readiness_token_hash=str(value["readinessTokenHash"]),
            readiness_window_ms=window,
            created_at_monotonic_ms=created,
            absolute_deadline_monotonic_ms=deadline,
            receipt_fingerprint=receipt_fingerprint,
        )

    def validate_for(self, action: CandidateSpawnActionV2) -> None:
        if not isinstance(action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        if (
            self.operation_id != action.operation_id
            or self.candidate_id != action.candidate_id
            or self.controller_start_id != action.controller_start_id
            or not hmac.compare_digest(
                self.action_fingerprint,
                action.action_fingerprint,
            )
            or not hmac.compare_digest(
                self.readiness_token_hash,
                action.readiness_token_hash,
            )
            or self.readiness_window_ms != action.readiness_window_ms
        ):
            _fail(
                "CANDIDATE_DISPATCH_BINDING_MISMATCH",
                "квитанция dispatch относится к другому действию",
            )

    def to_document(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "receiptKind": "controller-candidate-dispatch-intent-v2",
            "operationId": self.operation_id,
            "candidateId": self.candidate_id,
            "controllerStartId": self.controller_start_id,
            "actionFingerprint": self.action_fingerprint,
            "readinessTokenHash": self.readiness_token_hash,
            "readinessWindowMs": self.readiness_window_ms,
            "createdAtMonotonicMs": self.created_at_monotonic_ms,
            "absoluteDeadlineMonotonicMs": self.absolute_deadline_monotonic_ms,
            "receiptFingerprint": self.receipt_fingerprint,
        }


@dataclass(frozen=True)
class CandidateReadyReconnectV2:
    """Полностью проверенный ответ живого кандидата."""

    response: Mapping[str, Any]
    response_bytes: bytes
    registration: Mapping[str, Any]
    database_lease: Mapping[str, Any]
    working_controller_socket: Mapping[str, Any]


@dataclass
class CandidateReadyBootstrapV2:
    """Долговечное действие и потреблённый только дочерним процессом токен."""

    action: CandidateSpawnActionV2
    dispatch_intent: CandidateDispatchIntentReceiptV2
    readiness_token: str
    _consumed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        if not isinstance(
            self.dispatch_intent,
            CandidateDispatchIntentReceiptV2,
        ):
            raise TypeError("dispatch_intent must be CandidateDispatchIntentReceiptV2")
        self.dispatch_intent.validate_for(self.action)
        self.action = self.action.with_dispatch_intent(self.dispatch_intent)
        if type(self.readiness_token) is not str:
            raise TypeError("readiness_token must be str")
        if (
            hashlib.sha256(self.readiness_token.encode("utf-8")).hexdigest()
            != self.action.readiness_token_hash
        ):
            _fail(
                "CANDIDATE_READY_TOKEN_MISMATCH",
                "токен не связан с долговечным действием",
            )

    def consume(self) -> tuple[CandidateSpawnActionV2, str]:
        if self._consumed:
            _fail(
                "CANDIDATE_READY_TOKEN_CONSUMED",
                "токен готовности уже был потреблён",
            )
        self._consumed = True
        token = self.readiness_token
        self.readiness_token = ""
        return self.action, token


def candidate_controller_argv_v2(
    *,
    interpreter: Path,
    server_entrypoint: Path,
) -> tuple[str, str, str]:
    """Построить единственную каноническую команду candidate entrypoint."""

    for path, name in (
        (interpreter, "interpreter"),
        (server_entrypoint, "server_entrypoint"),
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise TypeError(f"{name} must be an absolute Path")
    try:
        executable = interpreter.resolve(strict=True)
        entrypoint = server_entrypoint.resolve(strict=True)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_ARGV_INVALID",
            "интерпретатор или candidate entrypoint недоступен",
        ) from exc
    if not executable.is_file() or not entrypoint.is_file():
        _fail(
            "CANDIDATE_ARGV_INVALID",
            "интерпретатор и candidate entrypoint должны быть файлами",
        )
    return (
        str(executable),
        str(entrypoint),
        "--serve-candidate-v2",
    )


def actual_candidate_controller_argv_v2() -> tuple[str, str, str]:
    """Нормализовать реальный argv уже работающего дочернего процесса."""

    if len(sys.argv) != 2 or sys.argv[1] != "--serve-candidate-v2":
        _fail(
            "CANDIDATE_ARGV_MISMATCH",
            "candidate entrypoint запущен с неожиданными аргументами",
        )
    return candidate_controller_argv_v2(
        interpreter=Path(sys.executable),
        server_entrypoint=Path(sys.argv[0]),
    )


def candidate_dispatch_intent_receipt_path_v2(
    *,
    codex_home: Path,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
) -> Path:
    """Получить единственный нормативный путь квитанции dispatch-intent."""

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    if not isinstance(codex_home, Path) or not codex_home.is_absolute():
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_INVALID",
            "CODEX_HOME должен быть абсолютным Path",
        )
    return (
        codex_home
        / "install-manifests"
        / "candidate-dispatch-intents-v2"
        / f"{parsed.operation_id}.{parsed.candidate_id}.json"
    )


def create_candidate_dispatch_intent_receipt_v2(
    *,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
    codex_home: Path,
    monotonic_ms: Callable[[], int] | None = None,
) -> CandidateDispatchIntentReceiptV2:
    """Атомарно зафиксировать фактический срок непосредственно перед Popen."""

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    clock = monotonic_ms or _system_monotonic_ms
    if not callable(clock):
        raise TypeError("monotonic_ms must be callable")
    created_at = clock()
    if type(created_at) is not int or created_at < 0:
        raise TypeError("monotonic_ms must return a non-negative int")
    receipt = CandidateDispatchIntentReceiptV2.create(
        action=parsed,
        created_at_monotonic_ms=created_at,
    )
    path = candidate_dispatch_intent_receipt_path_v2(
        codex_home=codex_home,
        action=parsed,
    )
    _require_owned_codex_home_v2(
        codex_home,
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    manifest_root = codex_home / "install-manifests"
    _require_private_directory(
        manifest_root,
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    try:
        path.parent.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DISPATCH_RECEIPT_INVALID",
            "не удалось создать каталог квитанций dispatch",
        ) from exc
    _require_private_directory(
        path.parent,
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    payload = canonical_json_bytes(receipt.to_document())
    if len(payload) > _MAX_DISPATCH_INTENT_RECEIPT_BYTES:
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_INVALID",
            "квитанция dispatch превысила предел",
        )
    if _lexists(path):
        load_candidate_dispatch_intent_receipt_v2(
            codex_home=codex_home,
            action=parsed,
        )
        _fail(
            "CANDIDATE_DISPATCH_ALREADY_EXISTS",
            "долговечное намерение запуска уже существует",
        )
    published = _publish_private_immutable_file_v2(
        path,
        payload,
        code="CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    if not published:
        load_candidate_dispatch_intent_receipt_v2(
            codex_home=codex_home,
            action=parsed,
        )
        _fail(
            "CANDIDATE_DISPATCH_ALREADY_EXISTS",
            "долговечное намерение запуска уже существует",
        )
    loaded = load_candidate_dispatch_intent_receipt_v2(
        codex_home=codex_home,
        action=parsed,
    )
    if loaded != receipt:
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_CHANGED",
            "опубликованная квитанция dispatch изменилась",
        )
    return loaded


def load_candidate_dispatch_intent_receipt_v2(
    *,
    codex_home: Path,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
) -> CandidateDispatchIntentReceiptV2:
    """Ограниченно прочитать и связать каноническую квитанцию dispatch."""

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    path = candidate_dispatch_intent_receipt_path_v2(
        codex_home=codex_home,
        action=parsed,
    )
    _require_owned_codex_home_v2(
        codex_home,
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    _require_private_directory(
        codex_home / "install-manifests",
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    _require_private_directory(
        path.parent,
        "CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    payload = _read_private_regular_file_bounded(
        path,
        limit=_MAX_DISPATCH_INTENT_RECEIPT_BYTES,
        code="CANDIDATE_DISPATCH_RECEIPT_INVALID",
    )
    try:
        document = _load_canonical_object(payload, "квитанция dispatch")
        receipt = CandidateDispatchIntentReceiptV2.from_mapping(document)
        receipt.validate_for(parsed)
    except CandidateReadyChannelV2Error as exc:
        if exc.code == "CANDIDATE_DISPATCH_BINDING_MISMATCH":
            raise
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DISPATCH_RECEIPT_INVALID",
            exc.message,
        ) from exc
    return receipt


def _retired_candidate_dispatch_receipt_path_v2(
    *,
    codex_home: Path,
    receipt: CandidateDispatchIntentReceiptV2,
) -> Path:
    return (
        codex_home
        / "install-manifests"
        / _RETIRED_DISPATCH_DIRECTORY
        / receipt.operation_id
        / receipt.candidate_id
        / f"{receipt.receipt_fingerprint}.json"
    )


def _retired_candidate_dispatch_partition_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
) -> Path:
    return (
        codex_home
        / "install-manifests"
        / _RETIRED_DISPATCH_DIRECTORY
        / action.operation_id
        / action.candidate_id
    )


@contextmanager
def _candidate_dispatch_critical_section_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
) -> Iterator[None]:
    """Сериализовать доказательство закрытия попытки и следующий spawn."""

    if not isinstance(action, CandidateSpawnActionV2):
        raise TypeError("action must be CandidateSpawnActionV2")
    _require_owned_codex_home_v2(
        codex_home,
        "CANDIDATE_DISPATCH_LOCK_INVALID",
    )
    manifest_root = codex_home / "install-manifests"
    _require_private_directory(
        manifest_root,
        "CANDIDATE_DISPATCH_LOCK_INVALID",
    )
    started_at = time.monotonic()
    absolute_deadline = started_at + _CANDIDATE_DISPATCH_LOCK_TIMEOUT_SECONDS
    process_wait = _candidate_dispatch_lock_remaining_seconds_v2(
        absolute_deadline
    )
    acquired = _CANDIDATE_DISPATCH_THREAD_LOCK.acquire(timeout=process_wait)
    if not acquired:
        operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
        _fail(
            "CANDIDATE_DISPATCH_LOCK_TIMEOUT",
            "внутрипроцессная блокировка запуска осталась занятой",
        )
    descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        lock_root = manifest_root / _CANDIDATE_DISPATCH_LOCK_DIRECTORY
        created_root = False
        try:
            lock_root.mkdir(mode=0o700)
            created_root = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_DISPATCH_LOCK_INVALID",
                "не удалось создать каталог блокировок запуска",
            ) from exc
        _require_private_directory(
            lock_root,
            "CANDIDATE_DISPATCH_LOCK_INVALID",
        )
        if created_root:
            _fsync_directory_v2(manifest_root)
        lock_path = lock_root / (
            f"{action.operation_id}.{action.candidate_id}.lock"
        )
        _publish_private_immutable_file_v2(
            lock_path,
            b"",
            code="CANDIDATE_DISPATCH_LOCK_INVALID",
        )
        flags = os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        try:
            descriptor = os.open(lock_path, flags)
            info = os.fstat(descriptor)
            named = os.lstat(lock_path)
        except OSError as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_DISPATCH_LOCK_INVALID",
                "файл блокировки запуска недоступен",
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
        ):
            _fail(
                "CANDIDATE_DISPATCH_LOCK_INVALID",
                "файл блокировки запуска изменён",
            )
        file_wait = _candidate_dispatch_lock_remaining_seconds_v2(
            absolute_deadline
        )
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=file_wait,
                timeout_code="CANDIDATE_DISPATCH_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_DISPATCH_LOCK_TIMEOUT",
                "межпроцессная блокировка запуска осталась занятой",
            ) from exc
        operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as close_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        "Candidate dispatch lock descriptor close also failed: "
                        f"{type(close_error).__name__}: {close_error}"
                    )
        finally:
            _CANDIDATE_DISPATCH_THREAD_LOCK.release()


def _candidate_dispatch_lock_remaining_seconds_v2(
    absolute_deadline: float,
) -> float:
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    if operation_deadline is not None:
        operation_deadline.checkpoint()
    remaining = absolute_deadline - time.monotonic()
    if operation_deadline is not None:
        remaining = min(remaining, operation_deadline.remaining_seconds())
    if remaining <= 0:
        _fail(
            "CANDIDATE_DISPATCH_LOCK_TIMEOUT",
            "срок ожидания блокировки запуска истёк",
        )
    return remaining


def _rename_no_replace_v2(source: Path, target: Path) -> bool:
    """Атомарно переместить файл, никогда не заменяя существующий target."""

    if not isinstance(source, Path) or not source.is_absolute():
        raise TypeError("source must be an absolute Path")
    if not isinstance(target, Path) or not target.is_absolute():
        raise TypeError("target must be an absolute Path")
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        at_fdcwd = -2
        no_replace = 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        at_fdcwd = -100
        no_replace = 1  # RENAME_NOREPLACE
    else:
        rename = None
        at_fdcwd = 0
        no_replace = 0
    if rename is None:
        _fail(
            "CANDIDATE_DISPATCH_RETIREMENT_UNSUPPORTED",
            "система не предоставляет атомарный rename без замены",
        )
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(target),
        no_replace,
    )
    if result == 0:
        return True
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        return False
    raise OSError(error_number, os.strerror(error_number), str(source), str(target))


def _load_retired_candidate_dispatch_receipts_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
) -> tuple[CandidateDispatchIntentReceiptV2, ...]:
    """Прочитать только точный закрытый раздел operation/candidate.

    Предрелизная плоская форма намеренно не сканируется и не поддерживается.
    """

    root = codex_home / "install-manifests" / _RETIRED_DISPATCH_DIRECTORY
    if not _lexists(root):
        return ()
    _require_private_directory(root, "CANDIDATE_DISPATCH_RETIREMENT_INVALID")
    operation_root = root / action.operation_id
    if not _lexists(operation_root):
        return ()
    _require_private_directory(
        operation_root,
        "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
    )
    partition = _retired_candidate_dispatch_partition_v2(
        codex_home=codex_home,
        action=action,
    )
    if not _lexists(partition):
        return ()
    _require_private_directory(
        partition,
        "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
    )
    paths: list[Path] = []
    try:
        with os.scandir(partition) as entries:
            for entry in entries:
                if len(paths) >= _MAX_CANDIDATE_DISPATCH_ATTEMPTS:
                    _fail(
                        "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
                        "раздел архивных dispatch-квитанций превысил предел",
                    )
                paths.append(Path(entry.path))
    except CandidateReadyChannelV2Error:
        raise
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
            "не удалось ограниченно прочитать раздел архивных dispatch-квитанций",
        ) from exc
    selected: list[CandidateDispatchIntentReceiptV2] = []
    for path in sorted(paths, key=lambda item: item.name):
        payload = _read_private_regular_file_bounded(
            path,
            limit=_MAX_DISPATCH_INTENT_RECEIPT_BYTES,
            code="CANDIDATE_DISPATCH_RETIREMENT_INVALID",
        )
        try:
            receipt = CandidateDispatchIntentReceiptV2.from_mapping(
                _load_canonical_object(payload, "архивная квитанция dispatch")
            )
        except CandidateReadyChannelV2Error as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
                exc.message,
            ) from exc
        receipt.validate_for(action)
        expected_name = f"{receipt.receipt_fingerprint}.json"
        if path.name != expected_name:
            _fail(
                "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
                "имя архивной квитанции dispatch не совпало с содержимым",
            )
        selected.append(receipt)
    return tuple(selected)


def _ensure_retired_candidate_dispatch_partition_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
) -> Path:
    parent = codex_home / "install-manifests"
    for name in (
        _RETIRED_DISPATCH_DIRECTORY,
        action.operation_id,
        action.candidate_id,
    ):
        child = parent / name
        created = False
        try:
            child.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_DISPATCH_RETIREMENT_FAILED",
                "не удалось создать закрытый раздел архивных dispatch-квитанций",
            ) from exc
        _require_private_directory(
            child,
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
        )
        if created:
            try:
                _fsync_directory_v2(parent)
            except OSError as exc:
                raise CandidateReadyChannelV2Error(
                    "CANDIDATE_DISPATCH_RETIREMENT_FAILED",
                    "не удалось синхронизировать каталог архивных dispatch-квитанций",
                ) from exc
        parent = child
    return parent


def _require_candidate_dispatch_retry_effect_absence_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    definition: Any,
    record: _CandidateSpawnJournalRecordV2,
    active_attempts: int,
) -> tuple[CandidateDispatchIntentReceiptV2, ...]:
    if active_attempts not in {0, 1}:
        raise ValueError("active_attempts must be 0 or 1")
    _validate_candidate_spawn_before_v2(
        definition.before,
        action=action,
        require_live_absence=True,
    )
    if _lexists(
        candidate_registration_receipt_path_v2(
            codex_home=codex_home,
            action=action,
        )
    ):
        _fail(
            "CANDIDATE_DISPATCH_RETRY_EFFECT_PRESENT",
            "кандидат уже оставил квитанцию регистрации",
        )
    steps = record.journal.get("steps")
    if type(steps) is not list or any(
        type(step) is dict
        and step.get("kind") in {"controller_accept", "controller_previous_accept"}
        and step.get("state") in {"INTENT_DURABLE", "COMPLETED"}
        for step in steps
    ):
        _fail(
            "CANDIDATE_DISPATCH_RETRY_EFFECT_PRESENT",
            "журнал уже содержит эффект принятия кандидата",
        )
    try:
        owned = DurableProcessOwnershipStoreV2(codex_home).load_all()
    except DurableProcessOwnershipV2Error as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DISPATCH_OWNERSHIP_INVALID",
            exc.message,
        ) from exc
    if owned:
        _fail(
            "CANDIDATE_DISPATCH_OWNERSHIP_OUTSTANDING",
            "долговечное владение процессом не разрешено",
        )
    retired = _load_retired_candidate_dispatch_receipts_v2(
        codex_home=codex_home,
        action=action,
    )
    if len(retired) + active_attempts >= _MAX_CANDIDATE_DISPATCH_ATTEMPTS:
        _fail(
            "CANDIDATE_DISPATCH_RETRY_LIMIT_REACHED",
            "исчерпан предел последовательных попыток dispatch",
        )
    return retired


def _require_closed_candidate_dispatch_attempt_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    definition: Any,
    record: _CandidateSpawnJournalRecordV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2,
    now_ms: int,
) -> tuple[CandidateDispatchIntentReceiptV2, ...]:
    try:
        _validate_dispatch_deadline_v2(
            dispatch_intent,
            now_ms=now_ms,
            expired_code="CANDIDATE_SPAWN_RECOVERY_EXPIRED",
        )
    except CandidateReadyChannelV2Error as exc:
        if exc.code not in {
            "CANDIDATE_SPAWN_RECOVERY_EXPIRED",
            "CANDIDATE_DISPATCH_MONOTONIC_ROLLBACK",
        }:
            raise
    else:
        _fail(
            "CANDIDATE_DISPATCH_RETRY_NOT_CLOSED",
            "действующая попытка dispatch ещё не достигла конечного состояния",
        )
    return _require_candidate_dispatch_retry_effect_absence_v2(
        codex_home=codex_home,
        action=action,
        definition=definition,
        record=record,
        active_attempts=1,
    )


def _retire_candidate_dispatch_intent_receipt_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2,
) -> Path:
    source = candidate_dispatch_intent_receipt_path_v2(
        codex_home=codex_home,
        action=action,
    )
    persisted = load_candidate_dispatch_intent_receipt_v2(
        codex_home=codex_home,
        action=action,
    )
    if persisted != dispatch_intent:
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_CHANGED",
            "активная квитанция dispatch изменилась перед архивированием",
        )
    target = _retired_candidate_dispatch_receipt_path_v2(
        codex_home=codex_home,
        receipt=dispatch_intent,
    )
    partition = _ensure_retired_candidate_dispatch_partition_v2(
        codex_home=codex_home,
        action=action,
    )
    if target.parent != partition:
        _fail(
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
            "путь архивной dispatch-квитанции вышел за точный раздел",
        )
    try:
        moved = _rename_no_replace_v2(source, target)
        if not moved:
            _fail(
                "CANDIDATE_DISPATCH_RETIREMENT_CONFLICT",
                "архивная dispatch-квитанция уже существует",
            )
        _fsync_directory_v2(source.parent)
        _fsync_directory_v2(target.parent)
    except CandidateReadyChannelV2Error:
        raise
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DISPATCH_RETIREMENT_FAILED",
            "не удалось атомарно архивировать dispatch-квитанцию",
        ) from exc
    payload = _read_private_regular_file_bounded(
        target,
        limit=_MAX_DISPATCH_INTENT_RECEIPT_BYTES,
        code="CANDIDATE_DISPATCH_RETIREMENT_INVALID",
    )
    if payload != canonical_json_bytes(dispatch_intent.to_document()):
        _fail(
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
            "архивная dispatch-квитанция изменилась",
        )
    return target


def spawn_candidate_controller_process_v2(
    *,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2,
    authorization: CandidateSpawnAuthorizationV2,
    codex_home: Path,
    state_home: Path,
    wrapper_path: Path,
    runtime_environment: Mapping[str, str] | None = None,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    monotonic_ms: Callable[[], int] | None = None,
    process_supervisor: Any | None = None,
) -> CandidateDispatchIntentReceiptV2:
    """Запустить кандидата без наследования среды и без PID как истины.

    Долговечная квитанция уже должна существовать. Возврат происходит только
    после успешного вызова ``Popen``; PID и готовность доказывает ready-канал.
    """

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    if not isinstance(authorization, CandidateSpawnAuthorizationV2):
        raise TypeError("authorization must be CandidateSpawnAuthorizationV2")
    if not isinstance(dispatch_intent, CandidateDispatchIntentReceiptV2):
        raise TypeError("dispatch_intent must be CandidateDispatchIntentReceiptV2")
    dispatch_intent.validate_for(parsed)
    persisted_dispatch = load_candidate_dispatch_intent_receipt_v2(
        codex_home=codex_home,
        action=parsed,
    )
    if persisted_dispatch != dispatch_intent:
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_CHANGED",
            "переданная квитанция dispatch не совпала с долговечной",
        )
    if not callable(popen_factory):
        raise TypeError("popen_factory must be callable")
    clock = monotonic_ms or _system_monotonic_ms
    if not callable(clock):
        raise TypeError("monotonic_ms must be callable")
    dispatch_observed_at = clock()
    if type(dispatch_observed_at) is not int or dispatch_observed_at < 0:
        raise TypeError("monotonic_ms must return a non-negative int")
    _validate_dispatch_deadline_v2(
        dispatch_intent,
        now_ms=dispatch_observed_at,
        expired_code="CANDIDATE_SPAWN_DEADLINE_EXPIRED",
    )
    canonical_argv = candidate_controller_argv_v2(
        interpreter=Path(parsed.argv[0]),
        server_entrypoint=Path(parsed.argv[1]),
    )
    if canonical_argv != parsed.argv:
        _fail(
            "CANDIDATE_SPAWN_ARGV_MISMATCH",
            "argv запуска не является точным каноническим argv действия",
        )
    private_codex_home = _owned_codex_home_v2(
        codex_home, "CANDIDATE_SPAWN_CODEX_HOME_INVALID"
    )
    private_state_home = _private_spawn_directory(
        state_home, "CANDIDATE_SPAWN_STATE_HOME_INVALID"
    )
    private_wrapper = _private_spawn_executable(wrapper_path)
    source_environment = (
        os.environ if runtime_environment is None else runtime_environment
    )
    if not isinstance(source_environment, Mapping) or not all(
        type(name) is str and type(value) is str
        for name, value in source_environment.items()
    ):
        raise TypeError("runtime_environment must be a string mapping")
    safe_environment: dict[str, str] = {}
    for name in _SAFE_RUNTIME_ENVIRONMENT:
        if name not in source_environment:
            continue
        value = source_environment[name]
        if "\0" in value or len(value.encode("utf-8")) > 32 * 1024:
            _fail(
                "CANDIDATE_SPAWN_ENVIRONMENT_INVALID",
                f"значение {name} в окружении небезопасно",
            )
        safe_environment[name] = value
    current_supervisor = (
        operation_process_group_supervisor_v2.
        current_process_group_supervisor_v2()
    )
    if (
        process_supervisor is not None
        and current_supervisor is not None
        and process_supervisor is not current_supervisor
    ):
        _fail(
            "CANDIDATE_PROCESS_SUPERVISOR_CONFLICT",
            "явный надзор отличается от надзора текущей операции",
        )
    supervisor = (
        current_supervisor if process_supervisor is None else process_supervisor
    )
    spawn_transient = getattr(supervisor, "spawn_transient", None)
    if not callable(spawn_transient):
        _fail(
            "CANDIDATE_PROCESS_SUPERVISOR_REQUIRED",
            "запуск кандидата разрешён только внутри единого надзора операции",
        )
    readiness_token = authorization.consume_for(parsed)
    try:
        gate_reader, gate_writer = os.pipe()
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_OWNERSHIP_GATE_FAILED",
            "не удалось создать стартовый канал владения",
        ) from exc
    safe_environment.update(
        {
            "CODEX_HOME": str(private_codex_home),
            "CODEX_V2_STATE_HOME": str(private_state_home),
            "CODEX_V2_WRAPPER_PATH": str(private_wrapper),
            "CODEX_V2_CANDIDATE_OPERATION_ID": parsed.operation_id,
            "CODEX_V2_CANDIDATE_CONTROLLER_START_ID": parsed.controller_start_id,
            _READINESS_TOKEN_ENVIRONMENT: readiness_token,
            _OWNERSHIP_GATE_FD_ENVIRONMENT: str(gate_reader),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    ownership_context = {
        "schemaVersion": 2,
        "contextKind": "candidate-dispatch-v2",
        "operationId": parsed.operation_id,
        "candidateId": parsed.candidate_id,
        "controllerStartId": parsed.controller_start_id,
        "actionFingerprint": parsed.action_fingerprint,
        "dispatchReceiptFingerprint": dispatch_intent.receipt_fingerprint,
    }
    process: Any | None = None
    reader_open = True
    writer_open = True
    try:
        lease = spawn_transient(
            label="candidate-controller",
            argv=parsed.argv,
            env=safe_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            pass_fds=(gate_reader,),
            restore_signals=True,
            umask=0o077,
            ownership_context=ownership_context,
        )
        os.close(gate_reader)
        reader_open = False
        DurableProcessOwnershipStoreV2(private_codex_home).publish(
            lease,
            ownership_context,
        )
        written = os.write(gate_writer, b"1")
        if written != 1:
            _fail(
                "CANDIDATE_OWNERSHIP_GATE_FAILED",
                "не удалось полностью отпустить стартовый канал",
            )
        os.close(gate_writer)
        writer_open = False
        process = lease.process
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        operation_process_group_supervisor_v2.ProcessGroupSupervisorV2Error,
        DurableProcessOwnershipV2Error,
    ) as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_SPAWN_FAILED",
            "операционная система отвергла запуск кандидата",
        ) from exc
    finally:
        if reader_open:
            try:
                os.close(gate_reader)
            except OSError:
                pass
        if writer_open:
            try:
                os.close(gate_writer)
            except OSError:
                pass
    assert process is not None
    waiter = getattr(process, "wait", None)
    if not callable(waiter):
        _fail(
            "CANDIDATE_SPAWN_HANDLE_INVALID",
            "Popen не вернул ожидаемый wait-интерфейс",
        )
    threading.Thread(
        target=_reap_candidate_process_v2,
        args=(process,),
        name="codex-smart-candidate-reaper-v2-" + parsed.candidate_id[-12:],
        daemon=True,
    ).start()
    return dispatch_intent


def await_candidate_ownership_gate_v2(
    environment: MutableMapping[str, str],
) -> None:
    """Не открывать SQLite/ready до долговечной публикации личности процесса."""

    if not isinstance(environment, MutableMapping) or not all(
        type(name) is str and type(value) is str
        for name, value in environment.items()
    ):
        raise TypeError("environment must be a mutable string mapping")
    raw_descriptor = environment.pop(_OWNERSHIP_GATE_FD_ENVIRONMENT, None)
    if type(raw_descriptor) is not str:
        _fail(
            "CANDIDATE_OWNERSHIP_GATE_MISSING",
            f"{_OWNERSHIP_GATE_FD_ENVIRONMENT} отсутствует",
        )
    try:
        descriptor = int(raw_descriptor, 10)
    except ValueError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_OWNERSHIP_GATE_INVALID",
            "дескриптор стартового канала неверен",
        ) from exc
    if descriptor < 3 or str(descriptor) != raw_descriptor:
        _fail(
            "CANDIDATE_OWNERSHIP_GATE_INVALID",
            "дескриптор стартового канала не является каноническим",
        )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISFIFO(info.st_mode):
            _fail(
                "CANDIDATE_OWNERSHIP_GATE_INVALID",
                "стартовый канал не является pipe",
            )
        release = os.read(descriptor, 2)
    except CandidateReadyChannelV2Error:
        raise
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_OWNERSHIP_GATE_INVALID",
            "стартовый канал недоступен",
        ) from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if release != b"1":
        _fail(
            "CANDIDATE_OWNERSHIP_GATE_NOT_RELEASED",
            "родитель не подтвердил долговечное владение процессом",
        )


def candidate_registration_receipt_path_v2(
    *,
    codex_home: Path,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
) -> Path:
    """Получить нормативный путь отдельной квитанции регистрации."""

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    if not isinstance(codex_home, Path) or not codex_home.is_absolute():
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "CODEX_HOME должен быть абсолютным Path",
        )
    return (
        codex_home
        / "install-manifests"
        / "candidate-registrations-v2"
        / f"{parsed.operation_id}.{parsed.candidate_id}.json"
    )


class CandidateReadyChannelServerV2:
    """Владелец отдельного сокета регистрации до ``controller_accept``."""

    def __init__(
        self,
        *,
        action: CandidateSpawnActionV2,
        dispatch_intent: CandidateDispatchIntentReceiptV2,
        readiness_token: str,
        database_path: Path,
        controller: Any,
        monotonic_ms: Callable[[], int] | None = None,
        peer_uid_provider: Callable[[socket.socket], int] | None = None,
        process_identity_provider: Callable[[], tuple[int, str, int]] | None = None,
        actual_argv_provider: Callable[[], tuple[str, str, str]] | None = None,
        io_timeout_seconds: float = 0.5,
    ) -> None:
        if not isinstance(action, CandidateSpawnActionV2):
            raise TypeError("action must be CandidateSpawnActionV2")
        if not isinstance(dispatch_intent, CandidateDispatchIntentReceiptV2):
            raise TypeError("dispatch_intent must be CandidateDispatchIntentReceiptV2")
        dispatch_intent.validate_for(action)
        if type(readiness_token) is not str or not 32 <= len(readiness_token) <= 256:
            _fail(
                "CANDIDATE_READY_TOKEN_INVALID", "токен готовности имеет неверную длину"
            )
        if "\0" in readiness_token:
            _fail("CANDIDATE_READY_TOKEN_INVALID", "токен готовности содержит NUL")
        if not isinstance(database_path, Path) or not database_path.is_absolute():
            _fail("CANDIDATE_DATABASE_INVALID", "путь базы должен быть абсолютным Path")
        if (
            type(io_timeout_seconds) not in {int, float}
            or type(io_timeout_seconds) is bool
            or not 0 < float(io_timeout_seconds) <= 1.0
        ):
            raise ValueError("io_timeout_seconds must be in (0, 1]")
        self.action = action
        self.dispatch_intent = dispatch_intent
        self.database_path = database_path.absolute()
        self.controller = controller
        self._token = readiness_token
        self._monotonic_ms = monotonic_ms or _system_monotonic_ms
        self._peer_uid = peer_uid_provider or _peer_uid
        self._process_identity = process_identity_provider or _system_process_identity
        self._actual_argv = actual_argv_provider or actual_candidate_controller_argv_v2
        self._io_timeout_seconds = float(io_timeout_seconds)
        self._listener: socket.socket | None = None
        self._listener_identity: tuple[int, int] | None = None
        self._lease_connection: DeadlineAwareConnectionV2 | None = None
        self._database_lease: dict[str, Any] | None = None
        self._working_socket: dict[str, Any] | None = None
        self._registration: dict[str, Any] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._registered = threading.Event()
        self._expired = threading.Event()
        self._failed = threading.Event()
        self._close_lock = threading.Lock()
        self._resource_lock = threading.Lock()
        self._state = "NEW"
        self._failure: CandidateReadyChannelV2Error | None = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def failure(self) -> CandidateReadyChannelV2Error | None:
        return self._failure

    def start(self) -> "CandidateReadyChannelServerV2":
        if self._state != "NEW":
            _fail("CANDIDATE_READY_STATE_INVALID", "канал уже запускался")
        actual_argv = self._actual_argv()
        if (
            type(actual_argv) is not tuple
            or actual_argv != self.action.argv
            or domain_fingerprint(
                _CANDIDATE_ARGV_DOMAIN,
                {"argv": list(actual_argv)},
            )
            != self.action.argv_fingerprint
        ):
            _fail(
                "CANDIDATE_ARGV_MISMATCH",
                "фактический argv процесса отличается от долговечного действия",
            )
        if (
            hashlib.sha256(self._token.encode("utf-8")).hexdigest()
            != self.action.readiness_token_hash
        ):
            _fail(
                "CANDIDATE_READY_TOKEN_MISMATCH",
                "токен не связан с долговечным действием",
            )
        _validate_dispatch_deadline_v2(
            self.dispatch_intent,
            now_ms=self._monotonic_ms(),
            expired_code="CANDIDATE_READY_DEADLINE_EXPIRED",
        )
        _require_private_ready_parent(self.action.private_ready_channel_path.parent)
        if (
            len(os.fsencode(self.action.private_ready_channel_path))
            >= _SOCKET_PATH_LIMIT
        ):
            _fail(
                "CANDIDATE_READY_PATH_TOO_LONG",
                "путь сокета готовности слишком длинный",
            )
        if _lexists(self.action.private_ready_channel_path):
            _fail(
                "CANDIDATE_READY_PATH_OCCUPIED", "путь сокета готовности уже существует"
            )
        try:
            self._bind_controller_identity()
            self._database_lease, self._lease_connection = _open_database_lease(
                self.database_path,
                action=self.action,
            )
            self._bind_ready_socket()
            self._registration = self._build_registration()
            self._state = "LISTENING"
            self._thread = threading.Thread(
                target=self._serve,
                name="codex-smart-candidate-ready-v2-" + self.action.candidate_id[-12:],
                daemon=True,
            )
            self._thread.start()
            self._token = ""
            return self
        except BaseException:
            self._cleanup_resources()
            raise

    def wait_until_registered(self, timeout: float) -> bool:
        if type(timeout) not in {int, float} or type(timeout) is bool or timeout < 0:
            raise ValueError("timeout must be non-negative")
        return self._registered.wait(float(timeout))

    def wait_until_expired(self, timeout: float) -> bool:
        if type(timeout) not in {int, float} or type(timeout) is bool or timeout < 0:
            raise ValueError("timeout must be non-negative")
        return self._expired.wait(float(timeout))

    def wait_until_failed(self, timeout: float) -> bool:
        if type(timeout) not in {int, float} or type(timeout) is bool or timeout < 0:
            raise ValueError("timeout must be non-negative")
        return self._failed.wait(float(timeout))

    def remaining_seconds(self) -> float:
        return max(
            0.0,
            (self.dispatch_intent.absolute_deadline_monotonic_ms - self._monotonic_ms())
            / 1000.0,
        )

    def mark_accepted(self) -> None:
        if self._expired.is_set() or self._failed.is_set():
            _fail("CANDIDATE_READY_NOT_ACCEPTABLE", "канал уже завершён с отказом")
        self._state = "ACCEPTED"
        self.close()

    def close(self) -> None:
        with self._close_lock:
            if self._state == "CLOSED":
                return
            if self._state not in {"EXPIRED", "FAILED", "ACCEPTED"}:
                self._state = "CLOSED"
            self._stop.set()
            listener = self._listener
            self._listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._cleanup_resources()

    def _bind_controller_identity(self) -> None:
        try:
            controller_identity = str(self.controller.controller_identity)
            controller_start_id = str(self.controller.controller_start_id)
            activation_id = str(self.controller.activation_id)
            activation_fingerprint = str(self.controller.activation_fingerprint)
            socket_path = Path(str(self.controller.socket_path))
            expected_socket = (
                int(self.controller.socket_device),
                int(self.controller.socket_inode),
                int(self.controller.socket_owner_uid),
                int(self.controller.socket_owner_gid),
                str(self.controller.socket_mode),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_CONTROLLER_INVALID",
                "контроллер не дал полную рабочую идентичность",
            ) from exc
        if (
            controller_identity != self.action.controller_identity
            or controller_start_id != self.action.controller_start_id
            or activation_id != self.action.activation_id
            or activation_fingerprint != self.action.activation_fingerprint
        ):
            _fail(
                "CANDIDATE_CONTROLLER_IDENTITY_MISMATCH",
                "контроллер отличается от долговечного действия",
            )
        pid, marker, process_group_id = self._process_identity()
        if (
            type(pid) is not int
            or type(marker) is not str
            or not marker
            or type(process_group_id) is not int
            or pid < 1
            or process_group_id < 1
            or pid != process_group_id
            or getattr(self.controller, "controller_pid", None) != pid
            or getattr(self.controller, "controller_process_start_marker", None)
            != marker
            or getattr(self.controller, "controller_process_group_id", None)
            != process_group_id
        ):
            _fail(
                "CANDIDATE_PROCESS_IDENTITY_MISMATCH",
                "процесс не является точно связанным владельцем частной группы",
            )
        live_socket = _socket_identity(
            socket_path, "CANDIDATE_CONTROLLER_SOCKET_INVALID"
        )
        observed_socket = (
            live_socket["device"],
            live_socket["inode"],
            live_socket["ownerUid"],
            live_socket["ownerGid"],
            live_socket["mode"],
        )
        if observed_socket != expected_socket:
            _fail(
                "CANDIDATE_CONTROLLER_SOCKET_INVALID",
                "рабочий сокет не совпал с идентичностью контроллера",
            )
        self._working_socket = live_socket

    def _bind_ready_socket(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        identity: tuple[int, int] | None = None
        try:
            listener.bind(str(self.action.private_ready_channel_path))
            os.chmod(self.action.private_ready_channel_path, 0o600)
            info = os.lstat(self.action.private_ready_channel_path)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                _fail("CANDIDATE_READY_SOCKET_UNSAFE", "сокет готовности небезопасен")
            identity = (info.st_dev, info.st_ino)
            listener.listen(8)
            listener.settimeout(0.05)
            self._listener = listener
            self._listener_identity = identity
        except BaseException:
            listener.close()
            _unlink_socket_if_exact(self.action.private_ready_channel_path, identity)
            raise

    def _build_registration(self) -> dict[str, Any]:
        assert self._listener_identity is not None
        assert self._database_lease is not None
        info = os.lstat(self.action.private_ready_channel_path)
        ready_identity = _identity_document(
            self.action.private_ready_channel_path, info
        )
        pid, marker, process_group_id = self._process_identity()
        base = {
            "candidateId": self.action.candidate_id,
            "controllerIdentity": self.action.controller_identity,
            "controllerStartId": self.action.controller_start_id,
            "operationId": self.action.operation_id,
            "activationId": self.action.activation_id,
            "activationFingerprint": self.action.activation_fingerprint,
            "databaseId": self.action.database_id,
            "argvFingerprint": self.action.argv_fingerprint,
            "snapshotFingerprint": self.action.snapshot_fingerprint,
            "privateReadyChannelPath": str(self.action.private_ready_channel_path),
            "privateReadyChannel": ready_identity,
            "readinessTokenHash": self.action.readiness_token_hash,
            "readinessWindowMs": self.action.readiness_window_ms,
            "processGroupPolicy": self.action.process_group_policy,
            "pid": pid,
            "processStartMarker": marker,
            "processGroupId": process_group_id,
            "databaseLeaseProofFingerprint": self._database_lease["proofFingerprint"],
            "databaseOpened": True,
            "workingSocketPublished": False,
            "acceptingNewRoutes": False,
            "status": "REGISTERED_READY",
            "exitProofFingerprint": None,
        }
        base["registrationFingerprint"] = domain_fingerprint(
            "codex-smart/candidate-registration/v2", base
        )
        return base

    def _serve(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    _validate_dispatch_deadline_v2(
                        self.dispatch_intent,
                        now_ms=self._monotonic_ms(),
                        expired_code="CANDIDATE_READY_DEADLINE_EXPIRED",
                    )
                except CandidateReadyChannelV2Error as exc:
                    if exc.code == "CANDIDATE_READY_DEADLINE_EXPIRED":
                        self._state = "EXPIRED"
                        self._stop.set()
                        break
                    raise
                listener = self._listener
                if listener is None:
                    break
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError as exc:
                    if self._stop.is_set() or exc.errno in {errno.EBADF, errno.EINVAL}:
                        break
                    raise
                self._handle_connection(connection)
        except CandidateReadyChannelV2Error as exc:
            self._failure = exc
            self._state = "FAILED"
            self._stop.set()
        except BaseException as exc:
            self._failure = CandidateReadyChannelV2Error(
                "CANDIDATE_READY_SERVER_FAILED", str(exc)
            )
            self._state = "FAILED"
            self._stop.set()
        finally:
            self._cleanup_resources()
            if self._state == "EXPIRED":
                self._expired.set()
            elif self._state == "FAILED":
                self._failed.set()

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            with connection:
                connection.settimeout(self._io_timeout_seconds)
                if self._peer_uid(connection) != os.getuid():
                    return
                try:
                    request_bytes = _receive_bounded(connection, _MAX_REQUEST_BYTES)
                    request = _load_canonical_object(request_bytes, "запрос готовности")
                    nonce = _verify_challenge(request, self.action)
                except (
                    CandidateReadyChannelV2Error,
                    OSError,
                    UnicodeError,
                    ValueError,
                ):
                    return
                try:
                    self._verify_live_bindings()
                except CandidateReadyChannelV2Error as exc:
                    error_response = {
                        "protocolVersion": 2,
                        "responseKind": "candidate-registration-error-v2",
                        "candidateId": self.action.candidate_id,
                        "controllerStartId": self.action.controller_start_id,
                        "operationId": self.action.operation_id,
                        "challengeNonce": nonce,
                        "errorCode": exc.code,
                    }
                    error_response["responseFingerprint"] = domain_fingerprint(
                        "codex-smart/candidate-ready-error/v2", error_response
                    )
                    connection.sendall(canonical_json_bytes(error_response))
                    raise
                assert self._registration is not None
                assert self._database_lease is not None
                assert self._working_socket is not None
                response = {
                    "protocolVersion": 2,
                    "responseKind": "candidate-registration-v2",
                    "candidateId": self.action.candidate_id,
                    "controllerStartId": self.action.controller_start_id,
                    "operationId": self.action.operation_id,
                    "challengeNonce": nonce,
                    "registration": copy.deepcopy(self._registration),
                    "databaseLease": copy.deepcopy(self._database_lease),
                    "workingControllerSocket": copy.deepcopy(self._working_socket),
                }
                response["responseFingerprint"] = domain_fingerprint(
                    "codex-smart/candidate-ready-response/v2", response
                )
                encoded = canonical_json_bytes(response)
                if len(encoded) > _MAX_RESPONSE_BYTES:
                    _fail("CANDIDATE_READY_RESPONSE_TOO_LARGE", "ответ превысил предел")
                connection.sendall(encoded)
                self._registered.set()
        except (OSError, TimeoutError):
            return

    def _verify_live_bindings(self) -> None:
        assert self._registration is not None
        assert self._database_lease is not None
        assert self._working_socket is not None
        ready = _socket_identity(
            self.action.private_ready_channel_path,
            "CANDIDATE_READY_SOCKET_CHANGED",
        )
        if ready != self._registration["privateReadyChannel"]:
            _fail("CANDIDATE_READY_SOCKET_CHANGED", "сокет регистрации изменился")
        working = _socket_identity(
            Path(self._working_socket["path"]),
            "CANDIDATE_CONTROLLER_SOCKET_CHANGED",
        )
        if working != self._working_socket:
            _fail("CANDIDATE_CONTROLLER_SOCKET_CHANGED", "рабочий сокет изменился")
        _verify_database_lease(self._database_lease, action=self.action)
        pid, marker, process_group_id = self._process_identity()
        if (
            pid != self._registration["pid"]
            or marker != self._registration["processStartMarker"]
            or process_group_id != self._registration["processGroupId"]
        ):
            _fail("CANDIDATE_PROCESS_CHANGED", "процесс кандидата изменился")

    def _cleanup_resources(self) -> None:
        with self._resource_lock:
            listener = self._listener
            self._listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            _unlink_socket_if_exact(
                self.action.private_ready_channel_path,
                self._listener_identity,
            )
            connection = self._lease_connection
            self._lease_connection = None
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback_for_cleanup_v2()
                except sqlite3.Error:
                    pass
                finally:
                    connection.close()


@dataclass(frozen=True)
class _CandidateSpawnJournalRecordV2:
    action: CandidateSpawnActionV2
    state: str
    step: Mapping[str, Any]
    journal: Mapping[str, Any]


def load_durable_candidate_spawn_action_v2(
    *,
    codex_home: Path,
    operation_id: str,
    controller_start_id: str,
    require_intent_durable: bool = False,
) -> CandidateSpawnActionV2:
    """Прочитать единственный immutable spawn-action из основного журнала.

    Читается нормативный путь, а не путь из окружения. Канонические байты,
    общий fingerprint журнала и отдельный fingerprint действия проверяются до
    того, как путь ready-сокета может повлиять на файловую систему.
    """

    if type(require_intent_durable) is not bool:
        raise TypeError("require_intent_durable must be bool")
    record = _load_candidate_spawn_journal_record_v2(
        codex_home=codex_home,
        operation_id=operation_id,
        controller_start_id=controller_start_id,
        allowed_states=(
            frozenset({"INTENT_DURABLE"})
            if require_intent_durable
            else frozenset({"INTENT_DURABLE", "COMPLETED"})
        ),
    )
    return record.action


def _load_candidate_spawn_journal_record_v2(
    *,
    codex_home: Path,
    operation_id: str,
    controller_start_id: str,
    allowed_states: frozenset[str],
) -> _CandidateSpawnJournalRecordV2:
    if not isinstance(codex_home, Path) or not codex_home.is_absolute():
        _fail("CANDIDATE_JOURNAL_INVALID", "CODEX_HOME должен быть абсолютным Path")
    if _IDENTIFIERS["operationId"].fullmatch(operation_id) is None:
        _fail("CANDIDATE_JOURNAL_INVALID", "operationId имеет неверную форму")
    if _IDENTIFIERS["controllerStartId"].fullmatch(controller_start_id) is None:
        _fail("CANDIDATE_JOURNAL_INVALID", "controllerStartId имеет неверную форму")
    if (
        not isinstance(allowed_states, frozenset)
        or not allowed_states
        or not allowed_states.issubset({"PLANNED", "INTENT_DURABLE", "COMPLETED"})
    ):
        raise TypeError("allowed_states is invalid")
    _require_owned_codex_home_v2(codex_home, "CANDIDATE_JOURNAL_INVALID")
    manifest_root = codex_home / "install-manifests"
    _require_private_directory(manifest_root, "CANDIDATE_JOURNAL_INVALID")
    journal_path = manifest_root / "codex-smart-subagents-v2.transaction.json"
    payload = _read_private_regular_file_bounded(
        journal_path,
        limit=_MAX_JOURNAL_BYTES,
        code="CANDIDATE_JOURNAL_INVALID",
    )
    journal = _load_canonical_object(payload, "основной журнал")
    projection = copy.deepcopy(journal)
    journal_fingerprint = projection.pop("journalFingerprint", None)
    if (
        type(journal_fingerprint) is not str
        or _SHA256.fullmatch(journal_fingerprint) is None
        or not hmac.compare_digest(
            journal_fingerprint,
            domain_fingerprint("codex-smart/operation-journal/v2", projection),
        )
        or journal.get("operationId") != operation_id
    ):
        _fail(
            "CANDIDATE_JOURNAL_INVALID", "fingerprint или operationId журнала неверен"
        )
    steps = journal.get("steps")
    if type(steps) is not list:
        _fail("CANDIDATE_JOURNAL_INVALID", "журнал не содержит шаги")
    candidates = [
        step
        for step in steps
        if type(step) is dict and step.get("kind") == "controller_candidate_spawn"
    ]
    if len(candidates) != 1:
        _fail(
            "CANDIDATE_JOURNAL_INVALID",
            "журнал должен содержать один шаг запуска кандидата",
        )
    step = candidates[0]
    if (
        step.get("state") not in allowed_states
        or type(step.get("stepId")) is not str
        or re.fullmatch(r"st2_[0-9a-f]{32}", str(step.get("stepId"))) is None
        or type(step.get("action")) is not dict
    ):
        _fail("CANDIDATE_JOURNAL_INVALID", "шаг запуска ещё не стал долговечным")
    expected_action_fingerprint = domain_fingerprint(
        "codex-smart/step-action/v2",
        {"action": copy.deepcopy(step["action"])},
    )
    if type(step.get("actionFingerprint")) is not str or not hmac.compare_digest(
        str(step["actionFingerprint"]), expected_action_fingerprint
    ):
        _fail("CANDIDATE_JOURNAL_INVALID", "fingerprint действия запуска неверен")
    try:
        action = CandidateSpawnActionV2.from_mapping(step["action"])
    except CandidateReadyChannelV2Error as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_JOURNAL_INVALID", exc.message
        ) from exc
    if (
        action.operation_id != operation_id
        or action.controller_start_id != controller_start_id
    ):
        _fail(
            "CANDIDATE_JOURNAL_INVALID",
            "действие не связано с ожидаемой операцией и запуском контроллера",
        )
    return _CandidateSpawnJournalRecordV2(
        action=action,
        state=str(step["state"]),
        step=copy.deepcopy(step),
        journal=copy.deepcopy(journal),
    )


def load_candidate_ready_bootstrap_v2(
    *,
    codex_home: Path,
    environment: MutableMapping[str, str],
    operation_id: str,
    controller_start_id: str,
) -> CandidateReadyBootstrapV2:
    """Потребить токен из среды и связать его с action основного журнала."""

    if not isinstance(environment, MutableMapping) or not all(
        type(name) is str and type(value) is str for name, value in environment.items()
    ):
        raise TypeError("environment must be a mutable string mapping")
    readiness_token = environment.pop(_READINESS_TOKEN_ENVIRONMENT, None)
    if type(readiness_token) is not str:
        _fail(
            "CANDIDATE_READY_TOKEN_MISSING",
            f"{_READINESS_TOKEN_ENVIRONMENT} отсутствует",
        )
    action = load_durable_candidate_spawn_action_v2(
        codex_home=codex_home,
        operation_id=operation_id,
        controller_start_id=controller_start_id,
        require_intent_durable=True,
    )
    dispatch_intent = load_candidate_dispatch_intent_receipt_v2(
        codex_home=codex_home,
        action=action,
    )
    return CandidateReadyBootstrapV2(
        action=action,
        dispatch_intent=dispatch_intent,
        readiness_token=readiness_token,
    )


def start_candidate_ready_channel_v2(
    *,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2 | None = None,
    readiness_token: str,
    database_path: Path,
    controller: Any,
    monotonic_ms: Callable[[], int] | None = None,
    peer_uid_provider: Callable[[socket.socket], int] | None = None,
    process_identity_provider: Callable[[], tuple[int, str, int]] | None = None,
    actual_argv_provider: Callable[[], tuple[str, str, str]] | None = None,
    io_timeout_seconds: float = 0.5,
) -> CandidateReadyChannelServerV2:
    """Проверить входы, открыть lease и опубликовать частный ready-сокет."""

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    resolved_dispatch = _resolve_dispatch_intent_v2(parsed, dispatch_intent)
    return CandidateReadyChannelServerV2(
        action=parsed,
        dispatch_intent=resolved_dispatch,
        readiness_token=readiness_token,
        database_path=database_path,
        controller=controller,
        monotonic_ms=monotonic_ms,
        peer_uid_provider=peer_uid_provider,
        process_identity_provider=process_identity_provider,
        actual_argv_provider=actual_argv_provider,
        io_timeout_seconds=io_timeout_seconds,
    ).start()


def reconnect_candidate_ready_channel_v2(
    *,
    action: Mapping[str, Any] | CandidateSpawnActionV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2 | None = None,
    timeout_seconds: float,
    process_start_marker_provider: Callable[
        [int], str
    ] = system_process_start_marker_v2,
    monotonic_ms: Callable[[], int] | None = None,
) -> CandidateReadyReconnectV2:
    """Повторно получить регистрацию только по долговечному действию.

    Секретный токен родителю не нужен после сбоя: хеш из действия служит
    ключом одноразового HMAC-вызова, а UID второй стороны проверяется отдельно.
    """

    parsed = (
        action
        if isinstance(action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(action)
    )
    resolved_dispatch = _resolve_dispatch_intent_v2(parsed, dispatch_intent)
    if (
        type(timeout_seconds) not in {int, float}
        or type(timeout_seconds) is bool
        or not 0 < float(timeout_seconds) <= 5.0
    ):
        raise ValueError("timeout_seconds must be in (0, 5]")
    if not callable(process_start_marker_provider):
        raise TypeError("process_start_marker_provider must be callable")
    clock = monotonic_ms or _system_monotonic_ms
    if not callable(clock):
        raise TypeError("monotonic_ms must be callable")
    _validate_dispatch_deadline_v2(
        resolved_dispatch,
        now_ms=clock(),
        expired_code="CANDIDATE_READY_DEADLINE_EXPIRED",
    )
    before = _socket_identity(
        parsed.private_ready_channel_path, "CANDIDATE_READY_SOCKET_UNSAFE"
    )
    nonce = os.urandom(32).hex()
    request = _challenge_document(parsed, nonce)
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    if operation_deadline is not None:
        operation_deadline.checkpoint()
        call_deadline = operation_deadline.child(
            phase="candidate-ready-reconnect",
            max_seconds=timeout_seconds,
            timeout_code="CANDIDATE_READY_RECONNECT_TIMEOUT",
        )
    else:
        call_deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="candidate-ready-reconnect",
            timeout_seconds=timeout_seconds,
            timeout_code="CANDIDATE_READY_RECONNECT_TIMEOUT",
        )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _set_candidate_socket_timeout(
            connection,
            deadline=call_deadline,
            local_cap_seconds=float(timeout_seconds),
        )
        connection.connect(str(parsed.private_ready_channel_path))
        if _peer_uid(connection) != os.getuid():
            _fail("CANDIDATE_READY_PEER_FORBIDDEN", "UID кандидата отличается")
        _set_candidate_socket_timeout(
            connection,
            deadline=call_deadline,
            local_cap_seconds=float(timeout_seconds),
        )
        connection.sendall(canonical_json_bytes(request))
        connection.shutdown(socket.SHUT_WR)
        response_bytes = _receive_bounded(
            connection,
            _MAX_RESPONSE_BYTES,
            deadline=call_deadline,
            local_cap_seconds=float(timeout_seconds),
        )
    except operation_deadline_v2.OperationDeadlineExceededV2 as exc:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_READY_AUTHENTICATION_FAILED",
            "кандидат не подтвердил долговечный вызов",
        ) from exc
    except CandidateReadyChannelV2Error:
        raise
    except (OSError, TimeoutError) as exc:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_READY_AUTHENTICATION_FAILED",
            "кандидат не подтвердил долговечный вызов",
        ) from exc
    finally:
        connection.close()
    if not response_bytes:
        _fail(
            "CANDIDATE_READY_AUTHENTICATION_FAILED",
            "кандидат отверг вызов готовности",
        )
    response = _load_canonical_object(response_bytes, "ответ готовности")
    try:
        after = _socket_identity(
            parsed.private_ready_channel_path,
            "CANDIDATE_READY_SOCKET_UNSAFE",
        )
    except CandidateReadyChannelV2Error as exc:
        if response_bytes:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_READY_RESPONSE_INVALID",
                "ready-сокет исчез после ответа кандидата",
            ) from exc
        raise
    if before != after:
        _fail("CANDIDATE_READY_SOCKET_CHANGED", "ready-сокет изменился при обмене")
    _verify_response(
        response,
        response_bytes=response_bytes,
        action=parsed,
        nonce=nonce,
        ready_identity=after,
        process_start_marker_provider=process_start_marker_provider,
    )
    return CandidateReadyReconnectV2(
        response=copy.deepcopy(response),
        response_bytes=response_bytes,
        registration=copy.deepcopy(response["registration"]),
        database_lease=copy.deepcopy(response["databaseLease"]),
        working_controller_socket=copy.deepcopy(response["workingControllerSocket"]),
    )


def build_controller_candidate_spawn_step_port_v2(
    *,
    candidate_spawn_action: Mapping[str, Any] | CandidateSpawnActionV2,
    codex_home: Path,
    state_home: Path,
    wrapper_path: Path,
    readiness_token: str | None,
    runtime_environment: Mapping[str, str] | None = None,
    reconnect_timeout_seconds: float = 1.0,
    poll_interval_seconds: float = 0.02,
    spawn_primitive: Callable[..., Any] = spawn_candidate_controller_process_v2,
    candidate_reconnect: Callable[..., Any] = reconnect_candidate_ready_channel_v2,
    accepted_controller_observer: Callable[[], Any] | None = None,
    process_start_marker_provider: Callable[
        [int], str
    ] = system_process_start_marker_v2,
    monotonic_ms: Callable[[], int] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> Any:
    """Собрать restart-safe порт шага ``controller_candidate_spawn``.

    До отдельной dispatch-квитанции состояние ``INTENT_DURABLE`` всё ещё
    доказуемо совпадает с before, поэтому восстановленный исполнитель с
    авторизацией вправе впервые запустить процесс. После квитанции наблюдатель
    переподключается до сохранённого срока. Закрытая без эффектов попытка может
    быть неизменно архивирована, после чего разрешена следующая попытка того же
    действия в пределах конечного счётчика.
    После принятия кандидата точная историческая проекция читается из отдельной
    неизменяемой квитанции и сверяется с ``observedAfter`` основного журнала.
    """

    from .installer_update_operation_v2 import UpdateStepPortV2
    from .lifecycle_constraint_matcher_v2 import (
        matches_controller_candidate_registration_v2,
    )
    from .lifecycle_operation_v2 import ProjectionV2, StepDefinitionV2

    action = (
        candidate_spawn_action
        if isinstance(candidate_spawn_action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(candidate_spawn_action)
    )
    if not isinstance(codex_home, Path) or not codex_home.is_absolute():
        raise TypeError("codex_home must be an absolute Path")
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise TypeError("state_home must be an absolute Path")
    if not isinstance(wrapper_path, Path) or not wrapper_path.is_absolute():
        raise TypeError("wrapper_path must be an absolute Path")
    if readiness_token is not None and type(readiness_token) is not str:
        raise TypeError("readiness_token must be str or None")
    if (
        type(reconnect_timeout_seconds) not in {int, float}
        or type(reconnect_timeout_seconds) is bool
        or not 0 < float(reconnect_timeout_seconds) <= 5.0
    ):
        raise ValueError("reconnect_timeout_seconds must be in (0, 5]")
    if (
        type(poll_interval_seconds) not in {int, float}
        or type(poll_interval_seconds) is bool
        or not 0 < float(poll_interval_seconds) <= 0.5
    ):
        raise ValueError("poll_interval_seconds must be in (0, 0.5]")
    for callback, name in (
        (spawn_primitive, "spawn_primitive"),
        (candidate_reconnect, "candidate_reconnect"),
        (process_start_marker_provider, "process_start_marker_provider"),
        (sleeper, "sleeper"),
        (popen_factory, "popen_factory"),
    ):
        if not callable(callback):
            raise TypeError(f"{name} must be callable")
    if accepted_controller_observer is not None and not callable(
        accepted_controller_observer
    ):
        raise TypeError("accepted_controller_observer must be callable or None")
    clock = monotonic_ms or _system_monotonic_ms
    if not callable(clock):
        raise TypeError("monotonic_ms must be callable")
    authorization = (
        None
        if readiness_token is None
        else CandidateSpawnAuthorizationV2.create(
            action=action,
            readiness_token=readiness_token,
        )
    )
    spawn_dispatched = False

    def load_dispatch_if_present() -> CandidateDispatchIntentReceiptV2 | None:
        path = candidate_dispatch_intent_receipt_path_v2(
            codex_home=codex_home,
            action=action,
        )
        if not _lexists(path):
            return None
        return load_candidate_dispatch_intent_receipt_v2(
            codex_home=codex_home,
            action=action,
        )

    def validate_definition(definition: Any) -> None:
        if not isinstance(definition, StepDefinitionV2):
            raise TypeError("definition must be StepDefinitionV2")
        if (
            definition.kind != "controller_candidate_spawn"
            or definition.command_id is not None
            or canonical_json_bytes(definition.action)
            != canonical_json_bytes(action.to_document())
        ):
            _fail(
                "CANDIDATE_SPAWN_DEFINITION_INVALID",
                "определение шага не связано с точным spawn-action",
            )
        _validate_candidate_spawn_before_v2(
            definition.before,
            action=action,
            require_live_absence=False,
        )
        _validate_expected_candidate_projection_v2(
            definition.expected_after,
            action=action,
        )

    def record_for(definition: Any) -> _CandidateSpawnJournalRecordV2:
        validate_definition(definition)
        record = _load_candidate_spawn_journal_record_v2(
            codex_home=codex_home,
            operation_id=action.operation_id,
            controller_start_id=action.controller_start_id,
            allowed_states=frozenset({"PLANNED", "INTENT_DURABLE", "COMPLETED"}),
        )
        if (
            record.action != action
            or record.step.get("before") != definition.before.to_document()
            or record.step.get("expectedAfter")
            != definition.expected_after.to_document()
        ):
            _fail(
                "CANDIDATE_SPAWN_JOURNAL_MISMATCH",
                "журнал не содержит точное определение порта запуска",
            )
        return record

    def projection_from_reconnect(
        definition: Any,
        reconnect: CandidateReadyReconnectV2,
    ) -> ProjectionV2:
        if not isinstance(reconnect, CandidateReadyReconnectV2):
            _fail(
                "CANDIDATE_SPAWN_RECONNECT_INVALID",
                "ready-канал вернул иной тип результата",
            )
        projection = _candidate_projection_from_registration_v2(
            definition.expected_after,
            reconnect.registration,
        )
        if not matches_controller_candidate_registration_v2(
            projection, definition.expected_after
        ):
            _fail(
                "CANDIDATE_SPAWN_RECONNECT_INVALID",
                "регистрация не удовлетворяет expectedAfter",
            )
        _persist_candidate_registration_receipt_v2(
            codex_home=codex_home,
            action=action,
            projection=projection,
            reconnect=reconnect,
        )
        return projection

    def observe(definition: Any) -> ProjectionV2:
        record = record_for(definition)
        if record.state == "PLANNED":
            if (
                load_dispatch_if_present() is not None
                or _lexists(action.private_ready_channel_path)
                or _lexists(
                    candidate_registration_receipt_path_v2(
                        codex_home=codex_home,
                        action=action,
                    )
                )
            ):
                _fail(
                    "CANDIDATE_SPAWN_EFFECT_BEFORE_INTENT",
                    "эффект запуска появился до долговечного intent",
                )
            _validate_candidate_spawn_before_v2(
                definition.before,
                action=action,
                require_live_absence=True,
            )
            return definition.before
        if record.state == "INTENT_DURABLE":
            dispatch_intent = load_dispatch_if_present()
            if dispatch_intent is None:
                _require_candidate_dispatch_retry_effect_absence_v2(
                    codex_home=codex_home,
                    action=action,
                    definition=definition,
                    record=record,
                    active_attempts=0,
                )
                return definition.before
            try:
                result = _reconnect_candidate_until_deadline_v2(
                    action=action,
                    dispatch_intent=dispatch_intent,
                    candidate_reconnect=candidate_reconnect,
                    reconnect_timeout_seconds=float(reconnect_timeout_seconds),
                    poll_interval_seconds=float(poll_interval_seconds),
                    process_start_marker_provider=process_start_marker_provider,
                    monotonic_ms=clock,
                    sleeper=sleeper,
                )
            except CandidateReadyChannelV2Error as exc:
                if exc.code not in {
                    "CANDIDATE_SPAWN_RECOVERY_EXPIRED",
                    "CANDIDATE_DISPATCH_MONOTONIC_ROLLBACK",
                }:
                    raise
                _require_closed_candidate_dispatch_attempt_v2(
                    codex_home=codex_home,
                    action=action,
                    definition=definition,
                    record=record,
                    dispatch_intent=dispatch_intent,
                    now_ms=clock(),
                )
                return definition.before
            return projection_from_reconnect(definition, result)
        dispatch_intent = load_dispatch_if_present()
        if dispatch_intent is None:
            _fail(
                "CANDIDATE_DISPATCH_RECEIPT_MISSING",
                "COMPLETED spawn не содержит долговечную dispatch-квитанцию",
            )
        if _lexists(action.private_ready_channel_path):
            result = _reconnect_candidate_until_deadline_v2(
                action=action,
                dispatch_intent=dispatch_intent,
                candidate_reconnect=candidate_reconnect,
                reconnect_timeout_seconds=float(reconnect_timeout_seconds),
                poll_interval_seconds=float(poll_interval_seconds),
                process_start_marker_provider=process_start_marker_provider,
                monotonic_ms=clock,
                sleeper=sleeper,
            )
            observed = projection_from_reconnect(definition, result)
        else:
            accept_completed = _journal_has_completed_candidate_accept_v2(
                record,
                expected_candidate=definition.expected_after,
            )
            accepted_controller = None
            if not accept_completed:
                if accepted_controller_observer is None:
                    _fail(
                        "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE",
                        "ready закрыт без доказанного controller_accept",
                    )
                accepted_controller = accepted_controller_observer()
                if not isinstance(accepted_controller, ProjectionV2):
                    _fail(
                        "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
                        "наблюдатель принятого контроллера вернул неверную проекцию",
                    )
            observed = _load_candidate_registration_receipt_v2(
                codex_home=codex_home,
                action=action,
                expected=definition.expected_after,
                process_start_marker_provider=process_start_marker_provider,
                accepted_controller=accepted_controller,
            )
        persisted_document = record.step.get("observedAfter")
        if type(persisted_document) is not dict:
            _fail(
                "CANDIDATE_SPAWN_PERSISTED_AFTER_INVALID",
                "COMPLETED spawn не содержит observedAfter",
            )
        try:
            persisted = ProjectionV2.from_document(persisted_document)
        except (TypeError, ValueError) as exc:
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_SPAWN_PERSISTED_AFTER_INVALID",
                "observedAfter запуска повреждён",
            ) from exc
        if persisted != observed:
            _fail(
                "CANDIDATE_SPAWN_PERSISTED_AFTER_CHANGED",
                "историческая квитанция не совпала с persisted observedAfter",
            )
        return observed

    def apply(definition: Any) -> None:
        nonlocal spawn_dispatched
        with _candidate_dispatch_critical_section_v2(
            codex_home=codex_home,
            action=action,
        ):
            record = record_for(definition)
            if record.state != "INTENT_DURABLE":
                _fail(
                    "CANDIDATE_SPAWN_INTENT_REQUIRED",
                    "Popen разрешён только после долговечного intent",
                )
            _validate_candidate_spawn_before_v2(
                definition.before,
                action=action,
                require_live_absence=True,
            )
            if spawn_dispatched:
                _fail(
                    "CANDIDATE_SPAWN_REPLAY_FORBIDDEN",
                    "этот экземпляр порта уже передал попытку запуска",
                )
            if authorization is None:
                _fail(
                    "CANDIDATE_SPAWN_AUTHORIZATION_REQUIRED",
                    "для Popen отсутствует сохранённая авторизация",
                )
            active_dispatch = load_dispatch_if_present()
            if active_dispatch is None:
                retired_dispatches = (
                    _require_candidate_dispatch_retry_effect_absence_v2(
                        codex_home=codex_home,
                        action=action,
                        definition=definition,
                        record=record,
                        active_attempts=0,
                    )
                )
                previous_dispatches = retired_dispatches
            else:
                retired_dispatches = _require_closed_candidate_dispatch_attempt_v2(
                    codex_home=codex_home,
                    action=action,
                    definition=definition,
                    record=record,
                    dispatch_intent=active_dispatch,
                    now_ms=clock(),
                )
                previous_dispatches = (*retired_dispatches, active_dispatch)
            fresh_created_at = clock()
            fresh_candidate = CandidateDispatchIntentReceiptV2.create(
                action=action,
                created_at_monotonic_ms=fresh_created_at,
            )
            if any(
                hmac.compare_digest(
                    previous.receipt_fingerprint,
                    fresh_candidate.receipt_fingerprint,
                )
                for previous in previous_dispatches
            ):
                _fail(
                    "CANDIDATE_DISPATCH_FRESHNESS_UNPROVEN",
                    "новая dispatch-квитанция совпала с прежней попыткой",
                )
            if active_dispatch is not None:
                _retire_candidate_dispatch_intent_receipt_v2(
                    codex_home=codex_home,
                    action=action,
                    dispatch_intent=active_dispatch,
                )
            dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
                action=action,
                codex_home=codex_home,
                monotonic_ms=lambda: fresh_created_at,
            )
            spawn_dispatched = True
            spawn_primitive(
                action=action,
                dispatch_intent=dispatch_intent,
                authorization=authorization,
                codex_home=codex_home,
                state_home=state_home,
                wrapper_path=wrapper_path,
                runtime_environment=runtime_environment,
                popen_factory=popen_factory,
                monotonic_ms=clock,
            )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, definition: observed == definition.before,
        matches_after=lambda observed, definition: (
            matches_controller_candidate_registration_v2(
                observed, definition.expected_after
            )
        ),
    )


def _validate_candidate_spawn_before_v2(
    projection: Any,
    *,
    action: CandidateSpawnActionV2,
    require_live_absence: bool,
) -> None:
    from .lifecycle_operation_v2 import ProjectionV2

    if not isinstance(projection, ProjectionV2):
        raise TypeError("spawn before must be ProjectionV2")
    value = dict(projection.value)
    if (
        projection.schema_id != "absence-proof-v2"
        or set(value)
        != {
            "proofId",
            "installationId",
            "operationId",
            "entries",
            "directorySyncCompleted",
            "proofFingerprint",
        }
        or type(value.get("proofId")) is not str
        or re.fullmatch(r"ap2_[0-9a-f]{32}", str(value.get("proofId"))) is None
        or type(value.get("installationId")) is not str
        or re.fullmatch(r"ins2_[0-9a-f]{32}", str(value.get("installationId"))) is None
        or value.get("operationId") != action.operation_id
        or value.get("directorySyncCompleted") is not True
    ):
        _fail(
            "CANDIDATE_SPAWN_BEFORE_INVALID",
            "before не является точным доказательством отсутствия",
        )
    proof_projection = copy.deepcopy(value)
    proof_fingerprint = proof_projection.pop("proofFingerprint")
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(value),
    }
    if (
        type(proof_fingerprint) is not str
        or not hmac.compare_digest(
            proof_fingerprint,
            domain_fingerprint("codex-smart/absence-proof/v2", proof_projection),
        )
        or not hmac.compare_digest(
            projection.value_fingerprint,
            domain_fingerprint("codex-smart/absence-proof-projection/v2", envelope),
        )
    ):
        _fail(
            "CANDIDATE_SPAWN_BEFORE_INVALID",
            "fingerprint доказательства отсутствия неверен",
        )
    entries = value.get("entries")
    if type(entries) is not list or len(entries) != 1 or type(entries[0]) is not dict:
        _fail(
            "CANDIDATE_SPAWN_BEFORE_INVALID",
            "доказательство должно содержать один ready-путь",
        )
    entry = entries[0]
    if set(entry) != {
        "path",
        "basename",
        "parentDevice",
        "parentInode",
        "absent",
    }:
        _fail(
            "CANDIDATE_SPAWN_BEFORE_INVALID",
            "запись отсутствия ready-пути имеет неверную форму",
        )
    parent = action.private_ready_channel_path.parent
    _require_private_ready_parent(parent)
    parent_info = os.lstat(parent)
    if (
        entry.get("path") != str(action.private_ready_channel_path)
        or entry.get("basename") != action.private_ready_channel_path.name
        or entry.get("parentDevice") != parent_info.st_dev
        or entry.get("parentInode") != parent_info.st_ino
        or entry.get("absent") is not True
        or (require_live_absence and _lexists(action.private_ready_channel_path))
    ):
        _fail(
            "CANDIDATE_SPAWN_BEFORE_CHANGED",
            "ready-путь или его родитель отличаются от before",
        )


def _validate_expected_candidate_projection_v2(
    projection: Any,
    *,
    action: CandidateSpawnActionV2,
) -> None:
    from .lifecycle_operation_v2 import ProjectionV2

    if not isinstance(projection, ProjectionV2):
        raise TypeError("expected_after must be ProjectionV2")
    expected_value = {
        **{
            name: value
            for name, value in action.to_document().items()
            if name not in {"actionKind", "argv"}
        },
        "privateReadyChannel": None,
        "pid": None,
        "processStartMarker": None,
        "processGroupId": None,
        "registrationFingerprint": None,
        "databaseLeaseProofFingerprint": None,
        "databaseOpened": False,
        "workingSocketPublished": False,
        "acceptingNewRoutes": False,
        "status": "EXPECTED_REGISTRATION",
        "exitProofFingerprint": None,
    }
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": expected_value,
    }
    if (
        projection.schema_id != "controller-candidate-v2"
        or dict(projection.value) != expected_value
        or not hmac.compare_digest(
            projection.value_fingerprint,
            domain_fingerprint(_CANDIDATE_PROJECTION_DOMAIN, envelope),
        )
    ):
        _fail(
            "CANDIDATE_SPAWN_EXPECTED_AFTER_INVALID",
            "expectedAfter не является точным ограничением регистрации",
        )


def _candidate_projection_from_registration_v2(
    template: Any,
    registration: Mapping[str, Any],
) -> Any:
    from .lifecycle_operation_v2 import ProjectionV2

    if not isinstance(template, ProjectionV2) or type(registration) is not dict:
        _fail(
            "CANDIDATE_SPAWN_RECONNECT_INVALID",
            "невозможно построить проекцию регистрации",
        )
    value = copy.deepcopy(dict(registration))
    envelope = {
        "schemaId": template.schema_id,
        "schemaSha256": template.schema_sha256,
        "value": value,
    }
    return ProjectionV2(
        schema_id=template.schema_id,
        schema_sha256=template.schema_sha256,
        value=value,
        value_fingerprint=domain_fingerprint(_CANDIDATE_PROJECTION_DOMAIN, envelope),
    )


def _reconnect_candidate_until_deadline_v2(
    *,
    action: CandidateSpawnActionV2,
    dispatch_intent: CandidateDispatchIntentReceiptV2,
    candidate_reconnect: Callable[..., Any],
    reconnect_timeout_seconds: float,
    poll_interval_seconds: float,
    process_start_marker_provider: Callable[[int], str],
    monotonic_ms: Callable[[], int],
    sleeper: Callable[[float], None],
) -> CandidateReadyReconnectV2:
    dispatch_intent.validate_for(action)
    last_error: CandidateReadyChannelV2Error | None = None
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    while True:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        now = monotonic_ms()
        try:
            remaining_ms = _validate_dispatch_deadline_v2(
                dispatch_intent,
                now_ms=now,
                expired_code="CANDIDATE_SPAWN_RECOVERY_EXPIRED",
            )
        except CandidateReadyChannelV2Error as exc:
            if exc.code != "CANDIDATE_SPAWN_RECOVERY_EXPIRED":
                raise
            raise CandidateReadyChannelV2Error(
                "CANDIDATE_SPAWN_RECOVERY_EXPIRED",
                "кандидат не опубликовал проверяемый ready-канал до срока",
            ) from last_error
        if _lexists(action.private_ready_channel_path):
            try:
                timeout_seconds = min(
                    reconnect_timeout_seconds,
                    max(0.001, remaining_ms / 1000.0),
                )
                if operation_deadline is not None:
                    timeout_seconds = (
                        operation_deadline.bounded_timeout_seconds(
                            local_cap_seconds=timeout_seconds
                        )
                    )
                result = candidate_reconnect(
                    action=action,
                    dispatch_intent=dispatch_intent,
                    timeout_seconds=timeout_seconds,
                    process_start_marker_provider=process_start_marker_provider,
                    monotonic_ms=monotonic_ms,
                )
                if not isinstance(result, CandidateReadyReconnectV2):
                    _fail(
                        "CANDIDATE_SPAWN_RECONNECT_INVALID",
                        "reconnect вернул иной тип",
                    )
                return result
            except CandidateReadyChannelV2Error as exc:
                if exc.code not in {
                    "CANDIDATE_READY_AUTHENTICATION_FAILED",
                    "CANDIDATE_READY_SOCKET_UNSAFE",
                }:
                    raise
                last_error = exc
        sleep_seconds = min(
            poll_interval_seconds, remaining_ms / 1000.0
        )
        if operation_deadline is not None:
            operation_deadline.checkpoint()
            sleep_seconds = min(
                sleep_seconds, operation_deadline.remaining_seconds()
            )
        sleeper(sleep_seconds)


def _persist_candidate_registration_receipt_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    projection: Any,
    reconnect: CandidateReadyReconnectV2,
) -> None:
    receipt_path = candidate_registration_receipt_path_v2(
        codex_home=codex_home,
        action=action,
    )
    receipt_root = receipt_path.parent
    _require_owned_codex_home_v2(
        codex_home,
        "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
    )
    _require_private_directory(
        codex_home / "install-manifests",
        "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
    )
    try:
        receipt_root.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "не удалось создать каталог квитанций регистрации",
        ) from exc
    _require_private_directory(receipt_root, "CANDIDATE_REGISTRATION_RECEIPT_INVALID")
    document = {
        "schemaVersion": 2,
        "receiptKind": "controller-candidate-registration-v2",
        "operationId": action.operation_id,
        "candidateId": action.candidate_id,
        "controllerStartId": action.controller_start_id,
        "actionFingerprint": action.action_fingerprint,
        "registrationProjection": projection.to_document(),
        "databaseLease": copy.deepcopy(dict(reconnect.database_lease)),
        "workingControllerSocket": copy.deepcopy(
            dict(reconnect.working_controller_socket)
        ),
    }
    document["receiptFingerprint"] = domain_fingerprint(
        _REGISTRATION_RECEIPT_DOMAIN, document
    )
    payload = canonical_json_bytes(document)
    if len(payload) > _MAX_REGISTRATION_RECEIPT_BYTES:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "квитанция регистрации превысила предел",
        )
    if _lexists(receipt_path):
        existing = _read_private_regular_file_bounded(
            receipt_path,
            limit=_MAX_REGISTRATION_RECEIPT_BYTES,
            code="CANDIDATE_REGISTRATION_RECEIPT_INVALID",
        )
        if existing != payload:
            _fail(
                "CANDIDATE_REGISTRATION_RECEIPT_CHANGED",
                "существующая квитанция регистрации отличается",
            )
        return
    _publish_private_immutable_file_v2(receipt_path, payload)
    existing = _read_private_regular_file_bounded(
        receipt_path,
        limit=_MAX_REGISTRATION_RECEIPT_BYTES,
        code="CANDIDATE_REGISTRATION_RECEIPT_INVALID",
    )
    if existing != payload:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_CHANGED",
            "опубликованная квитанция регистрации отличается",
        )


def _load_candidate_registration_receipt_v2(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    expected: Any,
    process_start_marker_provider: Callable[[int], str],
    accepted_controller: Any | None = None,
) -> Any:
    from .lifecycle_constraint_matcher_v2 import (
        matches_controller_candidate_registration_v2,
    )
    from .lifecycle_operation_v2 import ProjectionV2

    path = candidate_registration_receipt_path_v2(
        codex_home=codex_home,
        action=action,
    )
    _require_private_directory(path.parent, "CANDIDATE_REGISTRATION_RECEIPT_INVALID")
    payload = _read_private_regular_file_bounded(
        path,
        limit=_MAX_REGISTRATION_RECEIPT_BYTES,
        code="CANDIDATE_REGISTRATION_RECEIPT_INVALID",
    )
    document = _load_canonical_object(payload, "квитанция регистрации")
    if set(document) != {
        "schemaVersion",
        "receiptKind",
        "operationId",
        "candidateId",
        "controllerStartId",
        "actionFingerprint",
        "registrationProjection",
        "databaseLease",
        "workingControllerSocket",
        "receiptFingerprint",
    }:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "квитанция регистрации имеет неверную форму",
        )
    fingerprint_projection = copy.deepcopy(document)
    fingerprint = fingerprint_projection.pop("receiptFingerprint")
    if (
        document.get("schemaVersion") != 2
        or document.get("receiptKind") != "controller-candidate-registration-v2"
        or document.get("operationId") != action.operation_id
        or document.get("candidateId") != action.candidate_id
        or document.get("controllerStartId") != action.controller_start_id
        or document.get("actionFingerprint") != action.action_fingerprint
        or type(fingerprint) is not str
        or not hmac.compare_digest(
            fingerprint,
            domain_fingerprint(_REGISTRATION_RECEIPT_DOMAIN, fingerprint_projection),
        )
    ):
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "квитанция регистрации не связана с action",
        )
    raw_projection = document.get("registrationProjection")
    if type(raw_projection) is not dict:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "квитанция не содержит проекцию регистрации",
        )
    try:
        projection = ProjectionV2.from_document(raw_projection)
    except (TypeError, ValueError) as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "проекция регистрации повреждена",
        ) from exc
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    if not hmac.compare_digest(
        projection.value_fingerprint,
        domain_fingerprint(_CANDIDATE_PROJECTION_DOMAIN, envelope),
    ) or not matches_controller_candidate_registration_v2(projection, expected):
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "историческая проекция не удовлетворяет expectedAfter",
        )
    lease = document.get("databaseLease")
    working = document.get("workingControllerSocket")
    _verify_historical_registration_evidence_v2(
        registration=dict(projection.value),
        lease=lease,
        working=working,
        action=action,
        process_start_marker_provider=process_start_marker_provider,
    )
    if accepted_controller is not None:
        _validate_accepted_controller_successor_v2(
            registration=projection,
            working=working,
            accepted=accepted_controller,
        )
    return projection


def _validate_accepted_controller_successor_v2(
    *,
    registration: Any,
    working: object,
    accepted: Any,
) -> None:
    from .lifecycle_operation_v2 import ProjectionV2

    if (
        not isinstance(registration, ProjectionV2)
        or not isinstance(accepted, ProjectionV2)
        or registration.schema_id != "controller-candidate-v2"
        or accepted.schema_id != "controller-state-v2"
        or registration.schema_sha256 != accepted.schema_sha256
        or type(working) is not dict
    ):
        _fail(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            "принятый контроллер имеет неверную проекцию",
        )
    envelope = {
        "schemaId": accepted.schema_id,
        "schemaSha256": accepted.schema_sha256,
        "value": copy.deepcopy(dict(accepted.value)),
    }
    if not hmac.compare_digest(
        accepted.value_fingerprint,
        domain_fingerprint("codex-smart/controller-state/v2", envelope),
    ):
        _fail(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            "отпечаток принятого контроллера не совпал",
        )
    stable = {
        "controllerIdentity",
        "controllerStartId",
        "pid",
        "processStartMarker",
        "processGroupId",
        "activationId",
        "activationFingerprint",
        "databaseId",
    }
    if (
        any(
            registration.value.get(name) != accepted.value.get(name)
            for name in stable
        )
        or accepted.value.get("socket") != working
        or accepted.value.get("lockHeld") is not True
        or accepted.value.get("state") not in {"MAINTENANCE", "ACCEPTING"}
    ):
        _fail(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            "принятый контроллер не продолжает точную регистрацию кандидата",
        )


def _verify_historical_registration_evidence_v2(
    *,
    registration: Mapping[str, Any],
    lease: object,
    working: object,
    action: CandidateSpawnActionV2,
    process_start_marker_provider: Callable[[int], str],
) -> None:
    if type(registration) is not dict or set(registration) != _REGISTRATION_KEYS:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "историческая регистрация имеет неверную форму",
        )
    immutable = action.to_document()
    immutable.pop("actionKind")
    immutable.pop("argv")
    registration_projection = copy.deepcopy(dict(registration))
    registration_fingerprint = registration_projection.pop(
        "registrationFingerprint", None
    )
    ready = registration.get("privateReadyChannel")
    if (
        any(registration.get(name) != value for name, value in immutable.items())
        or type(registration_fingerprint) is not str
        or not hmac.compare_digest(
            registration_fingerprint,
            domain_fingerprint(
                "codex-smart/candidate-registration/v2",
                registration_projection,
            ),
        )
        or registration.get("status") != "REGISTERED_READY"
        or registration.get("databaseOpened") is not True
        or registration.get("workingSocketPublished") is not False
        or registration.get("acceptingNewRoutes") is not False
        or registration.get("exitProofFingerprint") is not None
        or not _historical_ready_identity_v2(
            ready, expected_path=action.private_ready_channel_path
        )
    ):
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "историческая регистрация не связана с action",
        )
    pid = registration.get("pid")
    marker = registration.get("processStartMarker")
    pgid = registration.get("processGroupId")
    try:
        current_marker = (
            process_start_marker_provider(pid) if type(pid) is int else None
        )
    except (OSError, ValueError) as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_REGISTRATION_PROCESS_CHANGED",
            "процесс принятого кандидата больше не подтверждается",
        ) from exc
    if (
        type(pid) is not int
        or pid < 1
        or type(pgid) is not int
        or pgid != pid
        or type(marker) is not str
        or not marker
        or current_marker != marker
    ):
        _fail(
            "CANDIDATE_REGISTRATION_PROCESS_CHANGED",
            "процесс принятого кандидата изменился",
        )
    if type(working) is not dict:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "рабочий socket отсутствует в квитанции",
        )
    observed_working = _socket_identity(
        Path(str(working.get("path"))),
        "CANDIDATE_REGISTRATION_WORKING_SOCKET_CHANGED",
    )
    if observed_working != working:
        _fail(
            "CANDIDATE_REGISTRATION_WORKING_SOCKET_CHANGED",
            "рабочий socket принятого кандидата изменился",
        )
    if type(lease) is not dict:
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "lease базы отсутствует в квитанции",
        )
    _verify_database_lease(lease, action=action)
    if registration.get("databaseLeaseProofFingerprint") != lease.get(
        "proofFingerprint"
    ):
        _fail(
            "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
            "регистрация не связана с lease базы",
        )


def _historical_ready_identity_v2(
    value: object,
    *,
    expected_path: Path,
) -> bool:
    if type(value) is not dict or set(value) != {
        "path",
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
        "mode",
    }:
        return False
    return bool(
        value.get("path") == str(expected_path)
        and type(value.get("device")) is int
        and value["device"] >= 0
        and type(value.get("inode")) is int
        and value["inode"] > 0
        and value.get("ownerUid") == os.getuid()
        and type(value.get("ownerGid")) is int
        and value.get("mode") == "0600"
    )


def _journal_has_completed_candidate_accept_v2(
    record: _CandidateSpawnJournalRecordV2,
    *,
    expected_candidate: Any,
) -> bool:
    steps = record.journal.get("steps")
    if type(steps) is not list:
        return False
    accepts = [
        step
        for step in steps
        if type(step) is dict and step.get("kind") == "controller_accept"
    ]
    if len(accepts) != 1:
        return False
    accept = accepts[0]
    action = accept.get("action")
    if type(action) is not dict:
        return False
    return bool(
        accept.get("state") == "COMPLETED"
        and accept.get("before") == expected_candidate.to_document()
        and action.get("actionKind") == "controller-command"
        and action.get("method") == "controller_accept"
        and action.get("operationId") == record.action.operation_id
        and accept.get("actionFingerprint")
        == domain_fingerprint(
            "codex-smart/step-action/v2",
            {"action": copy.deepcopy(action)},
        )
        and type(accept.get("observedAfter")) is dict
    )


def _publish_private_immutable_file_v2(
    path: Path,
    payload: bytes,
    *,
    code: str = "CANDIDATE_REGISTRATION_RECEIPT_INVALID",
) -> bool:
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.{os.urandom(8).hex()}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    linked = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail(
                    code,
                    "не удалось полностью записать квитанцию",
                )
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
            linked = True
        except FileExistsError:
            linked = False
        _fsync_directory_v2(path.parent)
    except CandidateReadyChannelV2Error:
        raise
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            code,
            "не удалось атомарно опубликовать квитанцию",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        if linked:
            _fsync_directory_v2(path.parent)
    return linked


def _fsync_directory_v2(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _challenge_document(action: CandidateSpawnActionV2, nonce: str) -> dict[str, Any]:
    unsigned = {
        "protocolVersion": 2,
        "method": "candidate_registration",
        "candidateId": action.candidate_id,
        "controllerStartId": action.controller_start_id,
        "operationId": action.operation_id,
        "nonce": nonce,
    }
    signature = hmac.new(
        bytes.fromhex(action.readiness_token_hash),
        _CHALLENGE_DOMAIN + canonical_json_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return {**unsigned, "challengeFingerprint": signature}


def _verify_challenge(
    request: Mapping[str, Any], action: CandidateSpawnActionV2
) -> str:
    expected_keys = {
        "protocolVersion",
        "method",
        "candidateId",
        "controllerStartId",
        "operationId",
        "nonce",
        "challengeFingerprint",
    }
    nonce = request.get("nonce")
    if (
        set(request) != expected_keys
        or request.get("protocolVersion") != 2
        or request.get("method") != "candidate_registration"
        or request.get("candidateId") != action.candidate_id
        or request.get("controllerStartId") != action.controller_start_id
        or request.get("operationId") != action.operation_id
        or type(nonce) is not str
        or _SHA256.fullmatch(nonce) is None
    ):
        _fail("CANDIDATE_READY_CHALLENGE_INVALID", "вызов имеет неверную форму")
    expected = _challenge_document(action, nonce)["challengeFingerprint"]
    supplied = request.get("challengeFingerprint")
    if type(supplied) is not str or not hmac.compare_digest(supplied, expected):
        _fail("CANDIDATE_READY_CHALLENGE_INVALID", "подпись вызова неверна")
    return nonce


def _verify_response(
    response: Mapping[str, Any],
    *,
    response_bytes: bytes,
    action: CandidateSpawnActionV2,
    nonce: str,
    ready_identity: Mapping[str, Any],
    process_start_marker_provider: Callable[[int], str],
) -> None:
    if set(response) != _RESPONSE_KEYS:
        _fail(
            "CANDIDATE_READY_RESPONSE_INVALID",
            "ответ имеет лишние или пропущенные поля",
        )
    projection = copy.deepcopy(dict(response))
    fingerprint = projection.pop("responseFingerprint", None)
    if (
        response.get("protocolVersion") != 2
        or response.get("responseKind") != "candidate-registration-v2"
        or response.get("candidateId") != action.candidate_id
        or response.get("controllerStartId") != action.controller_start_id
        or response.get("operationId") != action.operation_id
        or response.get("challengeNonce") != nonce
        or type(fingerprint) is not str
        or not hmac.compare_digest(
            fingerprint,
            domain_fingerprint("codex-smart/candidate-ready-response/v2", projection),
        )
        or canonical_json_bytes(response) != response_bytes
    ):
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "ответ не связан с вызовом")
    registration = response.get("registration")
    lease = response.get("databaseLease")
    working = response.get("workingControllerSocket")
    if type(registration) is not dict or set(registration) != _REGISTRATION_KEYS:
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "регистрация имеет неверную форму")
    immutable = action.to_document()
    immutable.pop("actionKind")
    immutable.pop("argv")
    if any(registration.get(name) != value for name, value in immutable.items()):
        _fail(
            "CANDIDATE_READY_RESPONSE_INVALID",
            "регистрация изменила долговечное действие",
        )
    registration_projection = copy.deepcopy(registration)
    registration_fingerprint = registration_projection.pop(
        "registrationFingerprint", None
    )
    if (
        type(registration_fingerprint) is not str
        or not hmac.compare_digest(
            registration_fingerprint,
            domain_fingerprint(
                "codex-smart/candidate-registration/v2", registration_projection
            ),
        )
        or registration.get("privateReadyChannel") != ready_identity
        or registration.get("status") != "REGISTERED_READY"
        or registration.get("databaseOpened") is not True
        or registration.get("workingSocketPublished") is not False
        or registration.get("acceptingNewRoutes") is not False
        or registration.get("exitProofFingerprint") is not None
    ):
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "регистрация не является точной")
    pid = registration.get("pid")
    marker = registration.get("processStartMarker")
    pgid = registration.get("processGroupId")
    if (
        type(pid) is not int
        or type(marker) is not str
        or not marker
        or type(pgid) is not int
        or pid < 1
        or pid != pgid
        or process_start_marker_provider(pid) != marker
    ):
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "процесс кандидата не подтверждён")
    if (
        type(working) is not dict
        or _socket_identity(
            Path(str(working.get("path"))),
            "CANDIDATE_CONTROLLER_SOCKET_INVALID",
        )
        != working
    ):
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "рабочий сокет не подтверждён")
    if type(lease) is not dict:
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "lease базы отсутствует")
    _verify_database_lease(lease, action=action)
    if registration.get("databaseLeaseProofFingerprint") != lease.get(
        "proofFingerprint"
    ):
        _fail("CANDIDATE_READY_RESPONSE_INVALID", "регистрация не связана с lease базы")


def _open_database_lease(
    path: Path,
    *,
    action: CandidateSpawnActionV2,
) -> tuple[dict[str, Any], DeadlineAwareConnectionV2]:
    before = _private_database(path)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    connection: DeadlineAwareConnectionV2 | None = None
    try:
        connection = connect_sqlite_with_deadline_v2(
            uri,
            uri=True,
            timeout=0.1,
            busy_timeout_ms=100,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.execute("pragma query_only=on")
        journal_mode_row = connection.execute("pragma journal_mode").fetchone()
        journal_mode = (
            ""
            if journal_mode_row is None
            else str(journal_mode_row[0]).lower()
        )
        if journal_mode != "wal":
            failure = CandidateReadyChannelV2Error(
                "CANDIDATE_DATABASE_JOURNAL_MODE_INVALID",
                "база кандидата не использует WAL до открытия lease",
            )
            _cleanup_failed_database_lease_v2(connection, failure)
            connection = None
            raise failure
        connection.execute("begin")
        application_id = int(connection.execute("pragma application_id").fetchone()[0])
        user_version = int(connection.execute("pragma user_version").fetchone()[0])
        query_only = int(connection.execute("pragma query_only").fetchone()[0])
        rows = connection.execute(
            "select database_id,schema_version,activation_id,activation_fingerprint "
            "from database_identity"
        ).fetchall()
    except operation_deadline_v2.OperationDeadlineExceededV2 as primary:
        if connection is not None:
            _cleanup_failed_database_lease_v2(connection, primary)
        raise
    except sqlite3.Error as exc:
        failure = CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_LEASE_FAILED", str(exc)
        )
        if connection is not None:
            _cleanup_failed_database_lease_v2(connection, failure)
        raise failure from exc
    assert connection is not None
    try:
        after = _private_database(path)
    except BaseException as primary:
        _cleanup_failed_database_lease_v2(connection, primary)
        raise
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        failure = CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_CHANGED",
            "база изменилась при открытии lease",
        )
        _cleanup_failed_database_lease_v2(connection, failure)
        raise failure
    expected_identity = (
        action.database_id,
        2,
        action.activation_id,
        action.activation_fingerprint,
    )
    if (
        application_id != APPLICATION_ID
        or user_version != 2
        or query_only != 1
        or len(rows) != 1
        or tuple(rows[0]) != expected_identity
    ):
        failure = CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_BINDING_MISMATCH",
            "база не связана с активацией",
        )
        _cleanup_failed_database_lease_v2(connection, failure)
        raise failure
    projection = {
        "leaseKind": "sqlite-read-only-v2",
        "databaseId": action.database_id,
        "path": str(path),
        "device": before.st_dev,
        "inode": before.st_ino,
        "ownerUid": before.st_uid,
        "ownerGid": before.st_gid,
        "mode": f"0{stat.S_IMODE(before.st_mode):03o}",
        "applicationId": application_id,
        "userVersion": user_version,
        "activationId": action.activation_id,
        "activationFingerprint": action.activation_fingerprint,
        "journalMode": journal_mode,
        "queryOnly": True,
        "transactionOpen": True,
    }
    projection["proofFingerprint"] = domain_fingerprint(
        "codex-smart/sqlite-read-only-lease/v2", projection
    )
    return projection, connection


def _cleanup_failed_database_lease_v2(
    connection: DeadlineAwareConnectionV2,
    primary: BaseException,
) -> None:
    """Закрыть невыданный lease, не маскируя исходный отказ или общий срок."""

    try:
        if connection.in_transaction:
            connection.rollback_for_cleanup_v2()
    except BaseException as cleanup_error:
        primary.add_note(
            "Candidate database lease rollback also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
    try:
        connection.close()
    except BaseException as cleanup_error:
        primary.add_note(
            "Candidate database lease close also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )


def _verify_database_lease(
    lease: Mapping[str, Any],
    *,
    action: CandidateSpawnActionV2,
) -> None:
    expected_keys = {
        "leaseKind",
        "databaseId",
        "path",
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
        "mode",
        "applicationId",
        "userVersion",
        "activationId",
        "activationFingerprint",
        "journalMode",
        "queryOnly",
        "transactionOpen",
        "proofFingerprint",
    }
    if type(lease) is not dict or set(lease) != expected_keys:
        _fail("CANDIDATE_DATABASE_LEASE_INVALID", "lease имеет неверную форму")
    projection = copy.deepcopy(dict(lease))
    proof = projection.pop("proofFingerprint", None)
    if (
        lease.get("leaseKind") != "sqlite-read-only-v2"
        or lease.get("databaseId") != action.database_id
        or lease.get("activationId") != action.activation_id
        or lease.get("activationFingerprint") != action.activation_fingerprint
        or lease.get("applicationId") != APPLICATION_ID
        or lease.get("userVersion") != 2
        or lease.get("journalMode") != "wal"
        or lease.get("queryOnly") is not True
        or lease.get("transactionOpen") is not True
        or type(proof) is not str
        or not hmac.compare_digest(
            proof,
            domain_fingerprint("codex-smart/sqlite-read-only-lease/v2", projection),
        )
    ):
        _fail("CANDIDATE_DATABASE_LEASE_INVALID", "lease не связан с действием")
    raw_path = lease.get("path")
    if type(raw_path) is not str or not Path(raw_path).is_absolute():
        _fail("CANDIDATE_DATABASE_LEASE_INVALID", "путь lease неверен")
    info = _private_database(Path(raw_path))
    observed = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        f"0{stat.S_IMODE(info.st_mode):03o}",
    )
    expected = (
        lease.get("device"),
        lease.get("inode"),
        lease.get("ownerUid"),
        lease.get("ownerGid"),
        lease.get("mode"),
    )
    if observed != expected:
        _fail("CANDIDATE_DATABASE_CHANGED", "файл базы отличается от lease")
    uri = "file:" + quote(raw_path, safe="/") + "?mode=ro"
    try:
        connection = connect_sqlite_with_deadline_v2(
            uri,
            uri=True,
            timeout=0.1,
            busy_timeout_ms=100,
            isolation_level=None,
        )
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except sqlite3.Error as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_LEASE_INVALID", str(exc)
        ) from exc
    try:
        connection.execute("pragma query_only=on")
        identity = connection.execute(
            "select database_id,schema_version,activation_id,activation_fingerprint "
            "from database_identity"
        ).fetchall()
        metadata = (
            int(connection.execute("pragma application_id").fetchone()[0]),
            int(connection.execute("pragma user_version").fetchone()[0]),
            int(connection.execute("pragma query_only").fetchone()[0]),
            str(connection.execute("pragma journal_mode").fetchone()[0]).lower(),
        )
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except sqlite3.Error as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_LEASE_INVALID", str(exc)
        ) from exc
    finally:
        connection.close()
    if (
        metadata != (APPLICATION_ID, 2, 1, "wal")
        or len(identity) != 1
        or tuple(identity[0])
        != (
            action.database_id,
            2,
            action.activation_id,
            action.activation_fingerprint,
        )
    ):
        _fail("CANDIDATE_DATABASE_LEASE_INVALID", "содержимое базы изменилось")


def _private_database(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_DATABASE_INVALID", str(exc)
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("CANDIDATE_DATABASE_INVALID", "файл базы небезопасен")
    return info


def _validate_candidate_argv(value: object) -> tuple[str, str, str]:
    if type(value) is not list or len(value) != 3:
        _fail(
            "CANDIDATE_ACTION_INVALID",
            "argv кандидата должен содержать ровно три элемента",
        )
    if not all(
        type(item) is str
        and item
        and "\0" not in item
        and len(item.encode("utf-8")) <= 4096
        for item in value
    ):
        _fail("CANDIDATE_ACTION_INVALID", "argv кандидата содержит неверную строку")
    interpreter, entrypoint, mode = value
    for item, name in (
        (interpreter, "interpreter"),
        (entrypoint, "server entrypoint"),
    ):
        if not Path(item).is_absolute() or os.path.normpath(item) != item:
            _fail(
                "CANDIDATE_ACTION_INVALID",
                f"{name} в argv должен быть нормализованным абсолютным путём",
            )
    if mode != "--serve-candidate-v2":
        _fail("CANDIDATE_ACTION_INVALID", "режим candidate entrypoint неверен")
    return interpreter, entrypoint, mode


def _socket_identity(path: Path, code: str) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "путь сокета должен быть абсолютным")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(code, str(exc)) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail(code, "метаданные сокета небезопасны")
    return _identity_document(path, info)


def _identity_document(path: Path, info: os.stat_result) -> dict[str, Any]:
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
    }


def _require_private_ready_parent(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_READY_PARENT_UNSAFE", str(exc)
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail(
            "CANDIDATE_READY_PARENT_UNSAFE", "родитель ready-сокета не является частным"
        )


def _require_private_directory(path: Path, code: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(code, str(exc)) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail(code, f"каталог небезопасен: {path}")


def _read_private_regular_file_bounded(
    path: Path,
    *,
    limit: int,
    code: str,
) -> bytes:
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(code, str(exc)) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            _fail(code, f"файл небезопасен: {path}")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        if len(payload) > limit:
            _fail(code, f"файл превышает предел: {path}")
        return payload
    finally:
        os.close(descriptor)


def _receive_bounded(
    connection: socket.socket,
    limit: int,
    *,
    deadline: operation_deadline_v2.OperationDeadlineV2 | None = None,
    local_cap_seconds: float | None = None,
) -> bytes:
    if (deadline is None) != (local_cap_seconds is None):
        raise ValueError(
            "deadline and local_cap_seconds must be provided together"
        )
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        if deadline is not None:
            assert local_cap_seconds is not None
            _set_candidate_socket_timeout(
                connection,
                deadline=deadline,
                local_cap_seconds=local_cap_seconds,
            )
        block = connection.recv(min(64 * 1024, remaining))
        if deadline is not None:
            deadline.checkpoint()
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    payload = b"".join(chunks)
    if len(payload) > limit:
        _fail("CANDIDATE_READY_MESSAGE_TOO_LARGE", "сообщение превысило предел")
    return payload


def _set_candidate_socket_timeout(
    connection: socket.socket,
    *,
    deadline: operation_deadline_v2.OperationDeadlineV2,
    local_cap_seconds: float,
) -> None:
    deadline.checkpoint()
    connection.settimeout(
        deadline.bounded_timeout_seconds(
            local_cap_seconds=local_cap_seconds,
        )
    )


def _load_canonical_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_READY_JSON_INVALID", f"{label}: {exc}"
        ) from exc
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        _fail("CANDIDATE_READY_JSON_INVALID", f"{label} не является каноническим JSON")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate key: {name}")
        result[name] = value
    return result


def _system_process_identity() -> tuple[int, str, int]:
    pid = os.getpid()
    return pid, system_process_start_marker_v2(pid), os.getpgrp()


def _system_monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


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
        _fail("CANDIDATE_READY_PEER_UNAVAILABLE", "getpeereid недоступен")
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        _fail("CANDIDATE_READY_PEER_UNAVAILABLE", os.strerror(ctypes.get_errno()))
    return int(uid.value)


def _unlink_socket_if_exact(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == identity:
        os.unlink(path)


def _lexists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _validate_readiness_token(value: object) -> str:
    if (
        type(value) is not str
        or not 32 <= len(value) <= 256
        or "\0" in value
        or len(value.encode("utf-8")) > 1024
    ):
        _fail(
            "CANDIDATE_SPAWN_TOKEN_INVALID",
            "секрет запуска имеет неверную форму",
        )
    return value


def _resolve_dispatch_intent_v2(
    action: CandidateSpawnActionV2,
    explicit: CandidateDispatchIntentReceiptV2 | None,
) -> CandidateDispatchIntentReceiptV2:
    if explicit is not None and not isinstance(
        explicit,
        CandidateDispatchIntentReceiptV2,
    ):
        raise TypeError("dispatch_intent must be CandidateDispatchIntentReceiptV2")
    attached = action.dispatch_intent
    if explicit is not None and attached is not None and explicit != attached:
        _fail(
            "CANDIDATE_DISPATCH_BINDING_MISMATCH",
            "явная и bootstrap-квитанции dispatch различаются",
        )
    result = explicit if explicit is not None else attached
    if result is None:
        _fail(
            "CANDIDATE_DISPATCH_RECEIPT_REQUIRED",
            "ready-каналу требуется проверенная dispatch-квитанция",
        )
    result.validate_for(action)
    return result


def _validate_dispatch_deadline_v2(
    dispatch_intent: CandidateDispatchIntentReceiptV2,
    *,
    now_ms: object,
    expired_code: str,
) -> int:
    if not isinstance(dispatch_intent, CandidateDispatchIntentReceiptV2):
        raise TypeError("dispatch_intent must be CandidateDispatchIntentReceiptV2")
    if type(now_ms) is not int or now_ms < 0:
        raise TypeError("monotonic clock must return a non-negative int")
    if now_ms < dispatch_intent.created_at_monotonic_ms:
        _fail(
            "CANDIDATE_DISPATCH_MONOTONIC_ROLLBACK",
            "монотонные часы откатились относительно dispatch-квитанции",
        )
    remaining_ms = dispatch_intent.absolute_deadline_monotonic_ms - now_ms
    if remaining_ms <= 0:
        _fail(expired_code, "абсолютный срок готовности кандидата истёк")
    return remaining_ms


def _owned_codex_home_v2(path: Path, code: str) -> Path:
    _require_owned_codex_home_v2(path, code)
    return path.absolute()


def _require_owned_codex_home_v2(path: Path, code: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "CODEX_HOME должен быть абсолютным Path")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            code,
            f"CODEX_HOME недоступен: {path}",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o755}
    ):
        _fail(
            code,
            "CODEX_HOME должен принадлежать пользователю и иметь режим 0700 или 0755",
        )


def _private_spawn_directory(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "путь должен быть абсолютным Path")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(code, f"каталог недоступен: {path}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail(code, f"каталог не является частным: {path}")
    return path.absolute()


def _private_spawn_executable(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(
            "CANDIDATE_SPAWN_WRAPPER_INVALID",
            "wrapper должен быть абсолютным Path",
        )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CandidateReadyChannelV2Error(
            "CANDIDATE_SPAWN_WRAPPER_INVALID",
            f"wrapper недоступен: {path}",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in {0o500, 0o700}
        or not os.access(path, os.X_OK)
    ):
        _fail(
            "CANDIDATE_SPAWN_WRAPPER_INVALID",
            "wrapper имеет небезопасную идентичность",
        )
    return path.absolute()


def _reap_candidate_process_v2(process: Any) -> None:
    """Только освобождает ресурс Popen; не наблюдает готовность процесса."""

    try:
        process.wait()
    except BaseException:
        return


def _fail(code: str, message: str) -> None:
    raise CandidateReadyChannelV2Error(code, message)


__all__ = [
    "CandidateDispatchIntentReceiptV2",
    "CandidateReadyBootstrapV2",
    "CandidateReadyChannelServerV2",
    "CandidateReadyChannelV2Error",
    "CandidateReadyReconnectV2",
    "CandidateSpawnActionV2",
    "CandidateSpawnAuthorizationV2",
    "actual_candidate_controller_argv_v2",
    "await_candidate_ownership_gate_v2",
    "build_controller_candidate_spawn_step_port_v2",
    "candidate_controller_argv_v2",
    "candidate_dispatch_intent_receipt_path_v2",
    "candidate_registration_receipt_path_v2",
    "create_candidate_dispatch_intent_receipt_v2",
    "load_candidate_ready_bootstrap_v2",
    "load_candidate_dispatch_intent_receipt_v2",
    "load_durable_candidate_spawn_action_v2",
    "reconnect_candidate_ready_channel_v2",
    "spawn_candidate_controller_process_v2",
    "start_candidate_ready_channel_v2",
]
