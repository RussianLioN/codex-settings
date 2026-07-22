"""Частный командный канал между MCP-переходником и контроллером v2."""

from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import json
import os
import re
import secrets
import socket
import stat
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical_json import CanonicalJsonError, canonical_json_bytes, domain_fingerprint
from .mcp_contracts_v2 import (
    MCPContractV2Error,
    TOOL_NAMES,
    get_tool_definitions_v2,
    validate_tool_input_v2,
    validate_tool_output_v2,
)


PROTOCOL_VERSION = 2
RELEASE = "0.2.0"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_WORKERS = 16
_SOCKET_PATH_LIMIT = 100
_COMMAND_ID = re.compile(r"^csc2_[0-9a-f]{32}$")
_SHELL_SESSION_ID = re.compile(r"^cas2_[A-Za-z0-9_-]{32,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_DOMAIN = "codex-smart/private-command-request/v2"
_RESPONSE_DOMAIN = "codex-smart/private-command-response/v2"
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_SOCKETS: set[str] = set()
_REMOTE_ERRORS = {
    "INVALID_PARAMS": "Параметры команды отклонены.",
    "HANDLER_FAILED": "Обработчик команды завершился с ошибкой.",
    "INVALID_RESULT": "Обработчик вернул ответ вне договора.",
    "RESPONSE_TOO_LARGE": "Ответ команды превысил допустимый размер.",
}


@dataclass
class ControllerCommandV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


ControllerCommandHandlerV2 = Callable[[str, str, dict[str, Any]], Mapping[str, Any]]


def get_private_command_schemas_v2(
    *,
    routing_input_schema: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Возвращает самодостаточные закрытые схемы частного канала."""

    definitions = get_tool_definitions_v2(routing_input_schema=routing_input_schema)
    by_name = {item["name"]: item for item in definitions}
    request_by_method: dict[str, Any] = {}
    response_by_method: dict[str, Any] = {}
    for method in TOOL_NAMES:
        request_by_method[method] = _request_schema(
            method,
            by_name[method]["inputSchema"],
        )
        response_by_method[method] = _success_response_schema(
            method,
            by_name[method]["outputSchema"],
        )
    return {
        "requestByMethod": request_by_method,
        "successResponseByMethod": response_by_method,
        "errorResponse": _error_response_schema(),
    }


class ControllerCommandServerV2:
    """Владеет частным сокетом и передаёт четыре команды доверенному обработчику."""

    def __init__(
        self,
        *,
        socket_path: Path,
        lock_path: Path,
        handler: ControllerCommandHandlerV2,
        routing_input_validator: Callable[[Mapping[str, Any]], Any] | None = None,
        io_timeout_seconds: float = 1.0,
    ) -> None:
        self.socket_path = _absolute_path(socket_path, "socket_path")
        self.lock_path = _absolute_path(lock_path, "lock_path")
        if self.socket_path.parent != self.lock_path.parent:
            _fail("INVALID_CONFIGURATION", "socket and lock must share one directory")
        _private_directory(self.socket_path.parent, "runtime directory")
        if len(os.fsencode(self.socket_path)) >= _SOCKET_PATH_LIMIT:
            _fail("SOCKET_PATH_TOO_LONG", "Unix socket path is too long")
        if not callable(handler):
            _fail("INVALID_CONFIGURATION", "handler must be callable")
        if routing_input_validator is not None and not callable(
            routing_input_validator
        ):
            _fail(
                "INVALID_CONFIGURATION",
                "routing_input_validator must be callable",
            )
        _bounded_timeout(io_timeout_seconds, maximum=1.0, name="io_timeout_seconds")

        self.handler = handler
        self.routing_input_validator = routing_input_validator
        self.io_timeout_seconds = float(io_timeout_seconds)
        self._lifecycle_lock = threading.RLock()
        self._workers_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._worker_slots = threading.BoundedSemaphore(MAX_WORKERS)
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_WORKERS,
            thread_name_prefix="codex-smart-command-v2",
        )
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._listener: socket.socket | None = None
        self._lock_fd: int | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._active_socket_claimed = False
        self._started = False
        self._closed = False

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                _fail("SERVER_CLOSED", "command server is closed")
            if self._started:
                return
            try:
                self._claim_socket()
            except BaseException:
                self._rollback_start()
                raise
            self._started = True
            self._ready.set()

    def wait_until_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def serve_forever(self) -> None:
        listener = self._listener
        if not self._started or listener is None or not self._ready.is_set():
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
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._safe_remove_socket()
            self._release_lock()
            self._ready.clear()
            self._release_active_socket_claim()

    def _claim_socket(self) -> None:
        socket_key = str(self.socket_path)
        with _ACTIVE_LOCK:
            if socket_key in _ACTIVE_SOCKETS:
                _fail("ALREADY_RUNNING", "command socket is already active")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(self.lock_path, flags, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.getuid()
                or lock_info.st_nlink != 1
            ):
                _fail("UNSAFE_LOCK", "command lock has unexpected metadata")
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ControllerCommandV2Error(
                    "ALREADY_RUNNING", "command lock is held"
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
                    _fail("UNSAFE_SOCKET", "command socket has unexpected metadata")
                listener.listen(32)
                listener.settimeout(0.05)
            except BaseException:
                listener.close()
                self._remove_socket_matching(bound_identity)
                raise
            self._lock_fd = lock_fd
            self._listener = listener
            self._socket_identity = (socket_info.st_dev, socket_info.st_ino)
            with _ACTIVE_LOCK:
                _ACTIVE_SOCKETS.add(socket_key)
                self._active_socket_claimed = True
        except BaseException:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)
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
                "existing command path is not a safe owned socket",
            )
        if _socket_accepts_connections(self.socket_path):
            _fail("ALREADY_RUNNING", "existing command socket accepts connections")
        second = os.lstat(self.socket_path)
        if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
            _fail("SOCKET_CHANGED", "command socket changed during stale check")
        os.unlink(self.socket_path)

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            with connection:
                if _peer_uid(connection) != os.getuid():
                    return
                request = _read_message(
                    connection,
                    invalid_code="INVALID_REQUEST",
                    incomplete_code="INVALID_REQUEST",
                )
                envelope = _validate_request_envelope(request)
                try:
                    arguments = validate_tool_input_v2(
                        envelope["method"],
                        envelope["params"],
                        routing_input_validator=self.routing_input_validator,
                    )
                except MCPContractV2Error:
                    response = _error_response(envelope, "INVALID_PARAMS")
                else:
                    response = self._invoke_handler(envelope, arguments)
                encoded = canonical_json_bytes(response) + b"\n"
                if len(encoded) > MAX_MESSAGE_BYTES:
                    encoded = (
                        canonical_json_bytes(
                            _error_response(envelope, "RESPONSE_TOO_LARGE")
                        )
                        + b"\n"
                    )
                connection.sendall(encoded)
        except (
            CanonicalJsonError,
            ControllerCommandV2Error,
            OSError,
            UnicodeError,
            ValueError,
        ):
            pass
        finally:
            with self._workers_lock:
                self._connections.discard(connection)
            self._worker_slots.release()

    def _invoke_handler(
        self,
        envelope: dict[str, Any],
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            candidate = self.handler(
                envelope["shellSessionId"],
                envelope["method"],
                copy.deepcopy(arguments),
            )
        except Exception:
            return _error_response(envelope, "HANDLER_FAILED")
        try:
            result = validate_tool_output_v2(envelope["method"], candidate)
        except (MCPContractV2Error, TypeError, ValueError):
            return _error_response(envelope, "INVALID_RESULT")
        if result["owner"]["shellSessionId"] != envelope["shellSessionId"]:
            return _error_response(envelope, "INVALID_RESULT")
        return _success_response(envelope, result)

    def _rollback_start(self) -> None:
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


class ControllerCommandClientV2:
    """Проверяет вызов и пересылает его единственному владельцу контроллера."""

    def __init__(
        self,
        *,
        socket_path: Path,
        shell_session_id: str,
        routing_input_validator: Callable[[Mapping[str, Any]], Any] | None = None,
        connect_timeout_seconds: float = 1.0,
        call_timeout_seconds: float = 65.0,
    ) -> None:
        self.socket_path = _absolute_path(socket_path, "socket_path")
        _private_directory(self.socket_path.parent, "runtime directory")
        if len(os.fsencode(self.socket_path)) >= _SOCKET_PATH_LIMIT:
            _fail("SOCKET_PATH_TOO_LONG", "Unix socket path is too long")
        _shell_session_id(shell_session_id)
        if routing_input_validator is not None and not callable(
            routing_input_validator
        ):
            _fail(
                "INVALID_CONFIGURATION",
                "routing_input_validator must be callable",
            )
        _bounded_timeout(
            connect_timeout_seconds,
            maximum=1.0,
            name="connect_timeout_seconds",
        )
        _bounded_timeout(
            call_timeout_seconds,
            maximum=65.0,
            name="call_timeout_seconds",
        )
        self.routing_input_validator = routing_input_validator
        self.shell_session_id = shell_session_id
        self.connect_timeout_seconds = float(connect_timeout_seconds)
        self.call_timeout_seconds = float(call_timeout_seconds)

    def call(self, method: str, arguments: Any) -> dict[str, Any]:
        if method not in TOOL_NAMES:
            _fail("UNKNOWN_METHOD", "unknown private command method")
        try:
            oversized_arguments = (
                len(canonical_json_bytes(arguments)) > MAX_MESSAGE_BYTES
            )
        except CanonicalJsonError:
            oversized_arguments = False
        if oversized_arguments:
            _fail("MESSAGE_TOO_LARGE", "command request exceeds the size limit")
        try:
            params = validate_tool_input_v2(
                method,
                arguments,
                routing_input_validator=self.routing_input_validator,
            )
        except MCPContractV2Error as exc:
            raise ControllerCommandV2Error(
                "INVALID_PARAMS", "command parameters were rejected"
            ) from exc
        command_id = "csc2_" + secrets.token_hex(16)
        request = _request(self.shell_session_id, command_id, method, params)
        encoded = canonical_json_bytes(request) + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            _fail("MESSAGE_TOO_LARGE", "command request exceeds the size limit")

        try:
            _safe_socket(self.socket_path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.connect_timeout_seconds)
                connection.connect(str(self.socket_path))
                if _peer_uid(connection) != os.getuid():
                    _fail("TRANSPORT_FAILURE", "controller has another user id")
                connection.settimeout(self.call_timeout_seconds)
                connection.sendall(encoded)
                response = _read_message(
                    connection,
                    invalid_code="INVALID_RESPONSE",
                    incomplete_code="TRANSPORT_FAILURE",
                )
        except ControllerCommandV2Error:
            raise
        except TimeoutError as exc:
            raise ControllerCommandV2Error(
                "TRANSPORT_TIMEOUT", "private command timed out"
            ) from exc
        except OSError as exc:
            raise ControllerCommandV2Error(
                "TRANSPORT_FAILURE", "private command transport failed"
            ) from exc

        value = _validate_response_envelope(
            response,
            command_id=command_id,
            method=method,
            request_fingerprint=request["requestFingerprint"],
        )
        if value["responseKind"] == "ERROR":
            payload = value["payload"]
            raise ControllerCommandV2Error(payload["code"], payload["message"])
        try:
            result = validate_tool_output_v2(method, value["payload"])
        except MCPContractV2Error as exc:
            raise ControllerCommandV2Error(
                "INVALID_RESPONSE", "private command result is invalid"
            ) from exc
        if result["owner"]["shellSessionId"] != self.shell_session_id:
            _fail("INVALID_RESPONSE", "private command result owner differs")
        return result


def _request(
    shell_session_id: str,
    command_id: str,
    method: str,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    projection = {
        "messageType": "request",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "commandId": command_id,
        "shellSessionId": shell_session_id,
        "method": method,
        "params": copy.deepcopy(dict(params)),
    }
    return {
        **projection,
        "requestFingerprint": domain_fingerprint(_REQUEST_DOMAIN, projection),
    }


def _success_response(
    request: Mapping[str, Any], result: Mapping[str, Any]
) -> dict[str, Any]:
    return _response_envelope(request, "SUCCESS", result)


def _error_response(request: Mapping[str, Any], code: str) -> dict[str, Any]:
    return _response_envelope(
        request,
        "ERROR",
        {"code": code, "message": _REMOTE_ERRORS[code]},
    )


def _response_envelope(
    request: Mapping[str, Any],
    response_kind: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    projection = {
        "messageType": "response",
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "commandId": request["commandId"],
        "method": request["method"],
        "responseKind": response_kind,
        "requestFingerprint": request["requestFingerprint"],
        "payload": copy.deepcopy(dict(payload)),
    }
    return {
        **projection,
        "responseFingerprint": domain_fingerprint(_RESPONSE_DOMAIN, projection),
    }


def _validate_request_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "messageType",
        "protocolVersion",
        "release",
        "commandId",
        "shellSessionId",
        "method",
        "params",
        "requestFingerprint",
    }
    if type(value) is not dict or set(value) != expected:
        _fail("INVALID_REQUEST", "private command request fields differ")
    if (
        value["messageType"] != "request"
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["release"] != RELEASE
        or value["method"] not in TOOL_NAMES
        or type(value["params"]) is not dict
        or type(value["commandId"]) is not str
        or _COMMAND_ID.fullmatch(value["commandId"]) is None
        or type(value["shellSessionId"]) is not str
        or _SHELL_SESSION_ID.fullmatch(value["shellSessionId"]) is None
        or type(value["requestFingerprint"]) is not str
        or _SHA256.fullmatch(value["requestFingerprint"]) is None
    ):
        _fail("INVALID_REQUEST", "private command request envelope differs")
    projection = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "requestFingerprint"
    }
    if value["requestFingerprint"] != domain_fingerprint(_REQUEST_DOMAIN, projection):
        _fail("INVALID_REQUEST", "private command request fingerprint differs")
    return copy.deepcopy(value)


def _validate_response_envelope(
    value: Mapping[str, Any],
    *,
    command_id: str,
    method: str,
    request_fingerprint: str,
) -> dict[str, Any]:
    expected = {
        "messageType",
        "protocolVersion",
        "release",
        "commandId",
        "method",
        "responseKind",
        "requestFingerprint",
        "payload",
        "responseFingerprint",
    }
    if type(value) is not dict or set(value) != expected:
        _fail("INVALID_RESPONSE", "private command response fields differ")
    if (
        value["messageType"] != "response"
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["release"] != RELEASE
        or value["commandId"] != command_id
        or value["method"] != method
        or value["responseKind"] not in {"SUCCESS", "ERROR"}
        or value["requestFingerprint"] != request_fingerprint
        or type(value["payload"]) is not dict
        or type(value["responseFingerprint"]) is not str
        or _SHA256.fullmatch(value["responseFingerprint"]) is None
    ):
        _fail("INVALID_RESPONSE", "private command response envelope differs")
    projection = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "responseFingerprint"
    }
    if value["responseFingerprint"] != domain_fingerprint(_RESPONSE_DOMAIN, projection):
        _fail("INVALID_RESPONSE", "private command response fingerprint differs")
    if value["responseKind"] == "ERROR":
        payload = value["payload"]
        code = payload.get("code")
        if (
            set(payload) != {"code", "message"}
            or code not in _REMOTE_ERRORS
            or payload["message"] != _REMOTE_ERRORS[code]
        ):
            _fail("INVALID_RESPONSE", "private command error differs")
    return copy.deepcopy(value)


def _read_message(
    connection: socket.socket,
    *,
    invalid_code: str,
    incomplete_code: str,
) -> dict[str, Any]:
    buffer = bytearray()
    while True:
        remaining = MAX_MESSAGE_BYTES + 1 - len(buffer)
        if remaining <= 0:
            _fail("MESSAGE_TOO_LARGE", "private command message exceeds the limit")
        chunk = connection.recv(min(65536, remaining))
        if not chunk:
            _fail(incomplete_code, "private command message ended before newline")
        buffer.extend(chunk)
        if len(buffer) > MAX_MESSAGE_BYTES:
            _fail("MESSAGE_TOO_LARGE", "private command message exceeds the limit")
        newline = buffer.find(b"\n")
        if newline < 0:
            continue
        if newline != len(buffer) - 1:
            _fail(invalid_code, "private command message has trailing bytes")
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
        raise ControllerCommandV2Error(invalid_code, str(exc)) from exc
    if type(value) is not dict:
        _fail(invalid_code, "private command message must be an object")
    return value


def _request_schema(method: str, params_schema: Mapping[str, Any]) -> dict[str, Any]:
    embedded, definitions = _embedded_schema("params", params_schema)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": [
            "messageType",
            "protocolVersion",
            "release",
            "commandId",
            "shellSessionId",
            "method",
            "params",
            "requestFingerprint",
        ],
        "properties": {
            "messageType": {"const": "request"},
            "protocolVersion": {"const": 2},
            "release": {"const": RELEASE},
            "commandId": {"type": "string", "pattern": _COMMAND_ID.pattern},
            "shellSessionId": {
                "type": "string",
                "pattern": _SHELL_SESSION_ID.pattern,
            },
            "method": {"const": method},
            "params": embedded,
            "requestFingerprint": {"type": "string", "pattern": _SHA256.pattern},
        },
        "additionalProperties": False,
        "$defs": definitions,
    }


def _success_response_schema(
    method: str, payload_schema: Mapping[str, Any]
) -> dict[str, Any]:
    embedded, definitions = _embedded_schema("payload", payload_schema)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": [
            "messageType",
            "protocolVersion",
            "release",
            "commandId",
            "method",
            "responseKind",
            "requestFingerprint",
            "payload",
            "responseFingerprint",
        ],
        "properties": {
            "messageType": {"const": "response"},
            "protocolVersion": {"const": 2},
            "release": {"const": RELEASE},
            "commandId": {"type": "string", "pattern": _COMMAND_ID.pattern},
            "method": {"const": method},
            "responseKind": {"const": "SUCCESS"},
            "requestFingerprint": {"type": "string", "pattern": _SHA256.pattern},
            "payload": embedded,
            "responseFingerprint": {"type": "string", "pattern": _SHA256.pattern},
        },
        "additionalProperties": False,
        "$defs": definitions,
    }


def _error_response_schema() -> dict[str, Any]:
    error_variants = [
        {
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": {"const": code},
                "message": {"const": message},
            },
            "additionalProperties": False,
        }
        for code, message in _REMOTE_ERRORS.items()
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": [
            "messageType",
            "protocolVersion",
            "release",
            "commandId",
            "method",
            "responseKind",
            "requestFingerprint",
            "payload",
            "responseFingerprint",
        ],
        "properties": {
            "messageType": {"const": "response"},
            "protocolVersion": {"const": 2},
            "release": {"const": RELEASE},
            "commandId": {"type": "string", "pattern": _COMMAND_ID.pattern},
            "method": {"enum": list(TOOL_NAMES)},
            "responseKind": {"const": "ERROR"},
            "requestFingerprint": {"type": "string", "pattern": _SHA256.pattern},
            "payload": {"oneOf": error_variants},
            "responseFingerprint": {"type": "string", "pattern": _SHA256.pattern},
        },
        "additionalProperties": False,
    }


def _embedded_schema(
    name: str, schema: Mapping[str, Any]
) -> tuple[dict[str, str], dict[str, Any]]:
    value = copy.deepcopy(dict(schema))
    value.pop("$schema", None)
    value.pop("$id", None)

    def rewrite(candidate: Any) -> None:
        if type(candidate) is dict:
            reference = candidate.get("$ref")
            if type(reference) is str and reference.startswith("#"):
                candidate["$ref"] = f"#/$defs/{name}" + reference[1:]
            for child in candidate.values():
                rewrite(child)
        elif type(candidate) is list:
            for child in candidate:
                rewrite(child)

    rewrite(value)
    return {"$ref": f"#/$defs/{name}"}, {name: value}


def _safe_socket(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ControllerCommandV2Error(
            "TRANSPORT_FAILURE", "private command socket is unavailable"
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("TRANSPORT_FAILURE", "private command socket is unsafe")
    return info


def _socket_accepts_connections(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.05)
        try:
            probe.connect(str(path))
        except (ConnectionRefusedError, FileNotFoundError):
            return False
        except OSError:
            return True
        return True


def _private_directory(path: Path, name: str) -> Path:
    absolute = _absolute_path(path, name)
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        raise ControllerCommandV2Error("INVALID_CONFIGURATION", str(exc)) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        _fail("INVALID_CONFIGURATION", f"{name} must be a private owned directory")
    return absolute


def _absolute_path(path: Path, name: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("INVALID_CONFIGURATION", f"{name} must be an absolute Path")
    return path


def _shell_session_id(value: Any) -> None:
    if type(value) is not str or _SHELL_SESSION_ID.fullmatch(value) is None:
        _fail(
            "INVALID_SHELL_SESSION",
            "shell_session_id does not match the cas2 contract",
        )


def _bounded_timeout(value: Any, *, maximum: float, name: str) -> None:
    if (
        type(value) not in {int, float}
        or type(value) is bool
        or not 0 < float(value) <= maximum
    ):
        _fail(
            "INVALID_CONFIGURATION",
            f"{name} must be greater than zero and at most {maximum}",
        )


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
        _fail("TRANSPORT_FAILURE", "peer credentials are unavailable")
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    result = getpeereid(
        connection.fileno(),
        ctypes.byref(uid),
        ctypes.byref(gid),
    )
    if result != 0:
        _fail("TRANSPORT_FAILURE", "peer credentials could not be read")
    return int(uid.value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _raise_json(message: str) -> None:
    raise ValueError(message)


def _fail(code: str, message: str) -> None:
    raise ControllerCommandV2Error(code, message)


__all__ = [
    "MAX_MESSAGE_BYTES",
    "ControllerCommandClientV2",
    "ControllerCommandHandlerV2",
    "ControllerCommandServerV2",
    "ControllerCommandV2Error",
    "get_private_command_schemas_v2",
]
