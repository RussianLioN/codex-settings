"""Local Unix-socket controller transport with peer and namespace checks."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
import socket
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import RequestContext, sha256_text
from .service import ServiceError, SmartService
from .store import StoreError


PROTOCOL_VERSION = 1
RELEASE = "0.1.0"
MAX_MESSAGE_BYTES = 1024 * 1024
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_SOCKETS: set[str] = set()


@dataclass
class ControllerAlreadyRunning(RuntimeError):
    socket_path: Path

    def __str__(self) -> str:
        return f"controller already owns {self.socket_path}"


@dataclass
class WireProtocolError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RuntimePaths:
    base_dir: Path
    namespace: str
    namespace_dir: Path
    run_dir: Path
    socket_path: Path
    lock_path: Path

    @classmethod
    def for_codex_home(
        cls,
        codex_home: str,
        *,
        state_home: Path | None = None,
    ) -> "RuntimePaths":
        canonical = str(Path(codex_home).expanduser().resolve())
        namespace = sha256_text(canonical)[:16]
        root = (
            state_home.expanduser()
            if state_home is not None
            else Path(
                os.environ.get(
                    "XDG_STATE_HOME",
                    str(Path.home() / ".local" / "state"),
                )
            ).expanduser()
        )
        base_dir = root / "codex-as"
        namespace_dir = base_dir / "ns" / namespace
        runtime_namespace = sha256_text(str(root.resolve()))[:8]
        run_dir = Path("/tmp") / (
            f"codex-as-{os.getuid()}-{runtime_namespace}"
        )
        socket_path = run_dir / f"{namespace}.sock"
        lock_path = run_dir / f"{namespace}.lock"
        if len(os.fsencode(socket_path)) >= 100:
            raise WireProtocolError(
                "SOCKET_PATH_TOO_LONG",
                f"Unix socket path is too long: {socket_path}",
            )
        return cls(
            base_dir=base_dir,
            namespace=namespace,
            namespace_dir=namespace_dir,
            run_dir=run_dir,
            socket_path=socket_path,
            lock_path=lock_path,
        )


class ControllerServer:
    def __init__(
        self,
        *,
        paths: RuntimePaths,
        service: SmartService,
        codex_home_hash: str,
    ) -> None:
        self.paths = paths
        self.service = service
        self.codex_home_hash = codex_home_hash
        self._closed = False
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._socket_inode: int | None = None
        self._lock_fd: int | None = None
        self._socket: socket.socket | None = None
        self._claim()

    def wait_until_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def serve_forever(self) -> None:
        listener = self._socket
        if listener is None:
            raise RuntimeError("controller socket is not initialized")
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop.is_set() or exc.errno in {errno.EBADF, errno.EINVAL}:
                    break
                raise
            worker = threading.Thread(
                target=self._handle_connection,
                args=(connection,),
                daemon=True,
            )
            with self._workers_lock:
                self._workers.add(worker)
            worker.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        listener = self._socket
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._workers_lock:
            workers = list(self._workers)
        for worker in workers:
            worker.join(timeout=1)
        self._safe_remove_socket()
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None
        with _ACTIVE_LOCK:
            _ACTIVE_SOCKETS.discard(str(self.paths.socket_path))

    def _claim(self) -> None:
        self._prepare_run_dir()
        socket_key = str(self.paths.socket_path)
        with _ACTIVE_LOCK:
            if socket_key in _ACTIVE_SOCKETS:
                raise ControllerAlreadyRunning(self.paths.socket_path)
        lock_fd = os.open(
            self.paths.lock_path,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(lock_fd)
            raise ControllerAlreadyRunning(self.paths.socket_path) from exc

        try:
            self._remove_proven_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.paths.socket_path))
            os.chmod(self.paths.socket_path, 0o600)
            info = os.lstat(self.paths.socket_path)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                raise WireProtocolError(
                    "UNSAFE_SOCKET",
                    "controller socket has unexpected metadata",
                )
            listener.listen(32)
            listener.settimeout(0.2)
            self._socket_inode = info.st_ino
            self._socket = listener
            self._lock_fd = lock_fd
            with _ACTIVE_LOCK:
                _ACTIVE_SOCKETS.add(socket_key)
            self._ready.set()
        except Exception:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
            raise

    def _prepare_run_dir(self) -> None:
        for directory in (self.paths.base_dir, self.paths.run_dir):
            if directory.is_symlink():
                raise WireProtocolError(
                    "UNSAFE_RUN_DIR",
                    f"run directory is a symlink: {directory}",
                )
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
            info = directory.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise WireProtocolError(
                    "UNSAFE_RUN_DIR",
                    f"run directory has unexpected metadata: {directory}",
                )

    def _remove_proven_stale_socket(self) -> None:
        try:
            first = os.lstat(self.paths.socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(first.st_mode)
            or first.st_uid != os.getuid()
            or first.st_nlink != 1
        ):
            raise WireProtocolError(
                "UNSAFE_EXISTING_SOCKET",
                "existing controller path is not a safe owned socket",
            )
        second = os.lstat(self.paths.socket_path)
        if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
            raise WireProtocolError(
                "SOCKET_CHANGED",
                "controller socket changed during stale check",
            )
        os.unlink(self.paths.socket_path)

    def _safe_remove_socket(self) -> None:
        if self._socket_inode is None:
            return
        try:
            info = os.lstat(self.paths.socket_path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_ino == self._socket_inode
        ):
            os.unlink(self.paths.socket_path)

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            with connection:
                try:
                    if _peer_uid(connection) != os.getuid():
                        raise WireProtocolError(
                            "PEER_FORBIDDEN",
                            "controller client has another user id",
                        )
                    stream = connection.makefile("rwb", buffering=0)
                    raw = stream.readline(MAX_MESSAGE_BYTES + 1)
                    if not raw or len(raw) > MAX_MESSAGE_BYTES:
                        raise WireProtocolError(
                            "MESSAGE_TOO_LARGE",
                            "controller request exceeds the size limit",
                        )
                    try:
                        request = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise WireProtocolError(
                            "INVALID_JSON",
                            "controller request is not valid JSON",
                        ) from exc
                    response = self._dispatch(request)
                    envelope = {"ok": True, "result": response}
                except (
                    WireProtocolError,
                    ServiceError,
                    StoreError,
                    ValueError,
                ) as exc:
                    envelope = {
                        "ok": False,
                        "error": {
                            "code": getattr(
                                exc,
                                "code",
                                "INVALID_REQUEST",
                            ),
                            "message": getattr(exc, "message", str(exc)),
                        },
                    }
                encoded = (
                    json.dumps(
                        envelope,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                connection.sendall(encoded)
        except OSError:
            pass
        finally:
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def _dispatch(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise WireProtocolError("INVALID_REQUEST", "request must be an object")
        required = {
            "protocolVersion",
            "release",
            "codexHomeHash",
            "shellSessionId",
            "method",
            "params",
        }
        if set(request) != required:
            raise WireProtocolError(
                "INVALID_REQUEST",
                "request envelope has unexpected fields",
            )
        if request["protocolVersion"] != PROTOCOL_VERSION:
            raise WireProtocolError(
                "PROTOCOL_MISMATCH",
                "controller protocol version does not match",
            )
        if request["release"] != RELEASE:
            raise WireProtocolError(
                "RELEASE_MISMATCH",
                "controller release does not match",
            )
        if request["codexHomeHash"] != self.codex_home_hash:
            raise WireProtocolError(
                "CODEX_HOME_FORBIDDEN",
                "controller namespace does not match CODEX_HOME",
            )
        shell_session_id = request["shellSessionId"]
        method = request["method"]
        params = request["params"]
        if not isinstance(shell_session_id, str) or not shell_session_id:
            raise WireProtocolError(
                "INVALID_REQUEST",
                "shellSessionId must be a non-empty string",
            )
        if not isinstance(method, str) or not isinstance(params, dict):
            raise WireProtocolError(
                "INVALID_REQUEST",
                "method and params have invalid types",
            )

        if method == "health":
            if params:
                raise WireProtocolError(
                    "INVALID_REQUEST",
                    "health does not accept parameters",
                )
            return {
                "protocolVersion": PROTOCOL_VERSION,
                "release": RELEASE,
                "namespace": self.paths.namespace,
            }
        if method == "issue_turn_binding":
            if set(params) != {"context"} or not isinstance(
                params["context"], dict
            ):
                raise WireProtocolError(
                    "INVALID_REQUEST",
                    "issue_turn_binding requires one context object",
                )
            context = RequestContext.from_wire(params["context"])
            if context.shell_session_id != shell_session_id:
                raise WireProtocolError(
                    "SESSION_FORBIDDEN",
                    "context belongs to another shell session",
                )
            if sha256_text(context.codex_home) != self.codex_home_hash:
                raise WireProtocolError(
                    "CODEX_HOME_FORBIDDEN",
                    "context belongs to another CODEX_HOME",
                )
            return {
                "turnBinding": self.service.store.issue_turn_binding(context)
            }
        if method == "smart_plan":
            binding = params.get("turnBinding")
            if not isinstance(binding, str):
                raise WireProtocolError(
                    "INVALID_REQUEST",
                    "smart_plan requires turnBinding",
                )
            context = self.service.store.context_for_turn_binding(
                binding,
                shell_session_id=shell_session_id,
                codex_home_hash=self.codex_home_hash,
            )
            return self.service.smart_plan(params, context)
        if method in {"smart_start", "smart_wait", "smart_cancel"}:
            route_id = params.get("routeId")
            if not isinstance(route_id, str):
                raise WireProtocolError(
                    "INVALID_REQUEST",
                    f"{method} requires routeId",
                )
            context = self.service.store.context_for_route(
                route_id,
                shell_session_id=shell_session_id,
                codex_home_hash=self.codex_home_hash,
            )
            handler = getattr(self.service, method)
            return handler(params, context)
        raise WireProtocolError("UNKNOWN_METHOD", f"unknown method: {method}")


class ControllerClient:
    def __init__(
        self,
        *,
        socket_path: Path,
        codex_home_hash: str,
        shell_session_id: str,
        timeout: float = 65,
    ) -> None:
        self.socket_path = socket_path
        self.codex_home_hash = codex_home_hash
        self.shell_session_id = shell_session_id
        self.timeout = timeout

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request = {
            "protocolVersion": PROTOCOL_VERSION,
            "release": RELEASE,
            "codexHomeHash": self.codex_home_hash,
            "shellSessionId": self.shell_session_id,
            "method": method,
            "params": params,
        }
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            if _peer_uid(connection) != os.getuid():
                raise WireProtocolError(
                    "PEER_FORBIDDEN",
                    "controller server has another user id",
                )
            with connection.makefile("rwb", buffering=0) as stream:
                stream.write(
                    json.dumps(
                        request,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                raw = stream.readline(MAX_MESSAGE_BYTES + 1)
        except OSError as exc:
            raise WireProtocolError(
                "CONTROLLER_UNAVAILABLE",
                str(exc),
            ) from exc
        finally:
            connection.close()
        if not raw or len(raw) > MAX_MESSAGE_BYTES:
            raise WireProtocolError(
                "INVALID_RESPONSE",
                "controller response is missing or too large",
            )
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise WireProtocolError(
                "INVALID_RESPONSE",
                "controller response is not valid JSON",
            ) from exc
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise WireProtocolError(
                "INVALID_RESPONSE",
                "controller response envelope is invalid",
            )
        if not response["ok"]:
            error = response.get("error", {})
            raise WireProtocolError(
                str(error.get("code", "CONTROLLER_ERROR")),
                str(error.get("message", "controller request failed")),
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise WireProtocolError(
                "INVALID_RESPONSE",
                "controller result must be an object",
            )
        return result


def _peer_uid(connection: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)

    libc = ctypes.CDLL(None, use_errno=True)
    getpeereid = getattr(libc, "getpeereid", None)
    if getpeereid is None:
        raise WireProtocolError(
            "PEER_CREDENTIALS_UNAVAILABLE",
            "getpeereid is unavailable",
        )
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    result = getpeereid(
        connection.fileno(),
        ctypes.byref(uid),
        ctypes.byref(gid),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise WireProtocolError(
            "PEER_CREDENTIALS_FAILED",
            os.strerror(error),
        )
    return int(uid.value)
