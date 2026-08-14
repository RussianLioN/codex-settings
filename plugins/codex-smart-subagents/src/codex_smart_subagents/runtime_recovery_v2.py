"""Планирование и точное восстановление каталогов попыток версии 2."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


_ARTIFACT_ID = re.compile(r"^ra2_[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^att2_[0-9a-f]{32}$")
_MARKER_NAME = ".codex-smart-attempt-v2.json"
_MARKER_KIND = "codex-smart-attempt-runtime/v2"
_ARTIFACT_KIND = "attempt_runtime_v2"


@dataclass
class RuntimeRecoveryV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RuntimeRecoveryActionV2:
    kind: str
    artifact_id: str
    attempt_id: str
    path: Path


@dataclass(frozen=True)
class RuntimeRecoveryReportV2:
    ok: bool
    applied: bool
    actions: tuple[RuntimeRecoveryActionV2, ...]
    blockers: tuple[str, ...]


class RuntimeArtifactStoreV2(Protocol):
    def runtime_artifacts(self) -> list[dict[str, Any]]: ...

    def seal_runtime_artifact(
        self,
        artifact_id: str,
        *,
        terminal: bool,
    ) -> Mapping[str, Any]: ...


class RuntimeRecoveryV2:
    """Сначала строит полный план, затем удаляет только доказанные остатки."""

    def __init__(
        self,
        *,
        store: RuntimeArtifactStoreV2,
        attempts_root: Path,
        remover: Callable[[Path, Path], None] | None = None,
    ) -> None:
        if not callable(getattr(store, "runtime_artifacts", None)) or not callable(
            getattr(store, "seal_runtime_artifact", None)
        ):
            raise TypeError("store must provide runtime artifact operations")
        if remover is None:
            remover = remove_attempt_tree_v2
        if not callable(remover):
            raise TypeError("remover must be callable")
        self.store = store
        self.attempts_root = _private_attempts_root(attempts_root)
        self.remover = remover

    def run(self, *, apply: bool) -> RuntimeRecoveryReportV2:
        if type(apply) is not bool:
            raise TypeError("apply must be bool")
        actions, blockers = self._plan()
        if blockers or not apply:
            return RuntimeRecoveryReportV2(
                ok=not blockers,
                applied=False,
                actions=tuple(actions),
                blockers=tuple(blockers),
            )
        for action in actions:
            self._apply(action)
        return RuntimeRecoveryReportV2(
            ok=True,
            applied=bool(actions),
            actions=tuple(actions),
            blockers=(),
        )

    def _plan(self) -> tuple[list[RuntimeRecoveryActionV2], list[str]]:
        try:
            raw_records = self.store.runtime_artifacts()
        except Exception as exc:
            raise RuntimeRecoveryV2Error(
                "RUNTIME_ARTIFACT_STORE_UNAVAILABLE",
                str(exc),
            ) from exc
        if type(raw_records) is not list:
            raise RuntimeRecoveryV2Error(
                "RUNTIME_ARTIFACT_STORE_INVALID",
                "runtime artifact list must be an exact list",
            )
        actions: list[RuntimeRecoveryActionV2] = []
        blockers: list[str] = []
        registered_paths: set[Path] = set()
        seen_artifacts: set[str] = set()
        for raw in raw_records:
            parsed = self._parse_record(raw)
            if parsed is None:
                blockers.append("RUNTIME_ARTIFACT_RECORD_INVALID")
                continue
            artifact_id, attempt_id, path, state, device, inode = parsed
            if artifact_id in seen_artifacts or path in registered_paths:
                blockers.append("RUNTIME_ARTIFACT_RECORD_CONFLICT")
                continue
            seen_artifacts.add(artifact_id)
            registered_paths.add(path)
            try:
                info = path.lstat()
            except FileNotFoundError:
                if state in {"RESERVED", "ACTIVE"}:
                    actions.append(
                        RuntimeRecoveryActionV2(
                            kind="MARK_MISSING",
                            artifact_id=artifact_id,
                            attempt_id=attempt_id,
                            path=path,
                        )
                    )
                continue
            except OSError:
                blockers.append("ATTEMPT_RUNTIME_UNAVAILABLE")
                continue
            if (
                path.is_symlink()
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                blockers.append("ARTIFACT_IDENTITY_MISMATCH")
                continue
            if not _marker_matches(
                path,
                artifact_id=artifact_id,
                attempt_id=attempt_id,
            ):
                blockers.append("ATTEMPT_MARKER_INVALID")
                continue
            if state == "ACTIVE":
                if device != info.st_dev or inode != info.st_ino:
                    blockers.append("ARTIFACT_IDENTITY_MISMATCH")
                    continue
                kind = "REMOVE_ACTIVE"
            elif state == "RESERVED":
                if device is not None or inode is not None:
                    blockers.append("RUNTIME_ARTIFACT_RECORD_INVALID")
                    continue
                kind = "ADOPT_AND_REMOVE"
            else:
                blockers.append("TERMINAL_ARTIFACT_PRESENT")
                continue
            actions.append(
                RuntimeRecoveryActionV2(
                    kind=kind,
                    artifact_id=artifact_id,
                    attempt_id=attempt_id,
                    path=path,
                )
            )
        try:
            actual = sorted(
                self.attempts_root.iterdir(),
                key=lambda item: item.name.encode("utf-8"),
            )
        except OSError as exc:
            raise RuntimeRecoveryV2Error(
                "ATTEMPTS_ROOT_UNAVAILABLE",
                str(exc),
            ) from exc
        for path in actual:
            if path not in registered_paths:
                blockers.append("UNREGISTERED_ATTEMPT_RUNTIME")
        return actions, list(dict.fromkeys(blockers))

    def _parse_record(
        self,
        raw: object,
    ) -> tuple[str, str, Path, str, int | None, int | None] | None:
        if not isinstance(raw, Mapping):
            return None
        try:
            artifact_id = raw["artifactId"]
            kind = raw["kind"]
            raw_path = raw["path"]
            allowed_root = raw["allowedRoot"]
            state = raw["state"]
            device = raw["device"]
            inode = raw["inode"]
        except KeyError:
            return None
        if (
            not isinstance(artifact_id, str)
            or _ARTIFACT_ID.fullmatch(artifact_id) is None
            or kind != _ARTIFACT_KIND
            or not isinstance(raw_path, str)
            or not isinstance(allowed_root, str)
            or allowed_root != str(self.attempts_root)
            or state not in {"RESERVED", "ACTIVE", "TERMINAL", "MISSING"}
            or (device is not None and (type(device) is not int or device < 0))
            or (inode is not None and (type(inode) is not int or inode <= 0))
        ):
            return None
        path = Path(raw_path)
        prefix = "attempt-"
        if (
            not path.is_absolute()
            or path.parent != self.attempts_root
            or not path.name.startswith(prefix)
        ):
            return None
        attempt_id = path.name[len(prefix) :]
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            return None
        if state == "ACTIVE" and (device is None or inode is None):
            return None
        if state != "ACTIVE" and (device is not None or inode is not None):
            return None
        return artifact_id, attempt_id, path, state, device, inode

    def _apply(self, action: RuntimeRecoveryActionV2) -> None:
        if action.kind == "MARK_MISSING":
            sealed = self.store.seal_runtime_artifact(
                action.artifact_id,
                terminal=True,
            )
            if sealed.get("state") != "MISSING":
                raise RuntimeRecoveryV2Error(
                    "RUNTIME_ARTIFACT_SEAL_MISMATCH",
                    "missing artifact did not become MISSING",
                )
            return
        if action.kind == "ADOPT_AND_REMOVE":
            active = self.store.seal_runtime_artifact(
                action.artifact_id,
                terminal=False,
            )
            _require_active_identity(active, action)
        elif action.kind == "REMOVE_ACTIVE":
            records = self.store.runtime_artifacts()
            matching = [
                item
                for item in records
                if isinstance(item, Mapping)
                and item.get("artifactId") == action.artifact_id
            ]
            if len(matching) != 1:
                raise RuntimeRecoveryV2Error(
                    "RUNTIME_ARTIFACT_RECORD_CONFLICT",
                    "active artifact disappeared before cleanup",
                )
            _require_active_identity(matching[0], action)
        else:
            raise RuntimeRecoveryV2Error(
                "RUNTIME_RECOVERY_ACTION_INVALID",
                action.kind,
            )
        if not _marker_matches(
            action.path,
            artifact_id=action.artifact_id,
            attempt_id=action.attempt_id,
        ):
            raise RuntimeRecoveryV2Error(
                "ATTEMPT_MARKER_INVALID",
                "attempt marker changed before cleanup",
            )
        self.remover(action.path, self.attempts_root)
        terminal = self.store.seal_runtime_artifact(
            action.artifact_id,
            terminal=True,
        )
        if terminal.get("state") != "MISSING":
            raise RuntimeRecoveryV2Error(
                "RUNTIME_ARTIFACT_SEAL_MISMATCH",
                "removed artifact did not become MISSING",
            )


def write_attempt_marker_v2(
    attempt_root: Path,
    *,
    artifact_id: str,
    attempt_id: str,
) -> Path:
    """Создаёт один закрытый маркер после резервирования пути в базе."""

    if _ARTIFACT_ID.fullmatch(artifact_id) is None:
        raise RuntimeRecoveryV2Error("ARTIFACT_ID_INVALID", "invalid artifact id")
    if _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise RuntimeRecoveryV2Error("ATTEMPT_ID_INVALID", "invalid attempt id")
    _private_attempt_directory(attempt_root)
    marker = attempt_root / _MARKER_NAME
    payload = json.dumps(
        {
            "artifactId": artifact_id,
            "attemptId": attempt_id,
            "kind": _MARKER_KIND,
            "schemaVersion": 2,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(marker, 0o600)
        _fsync_directory(attempt_root)
    except OSError as exc:
        raise RuntimeRecoveryV2Error("ATTEMPT_MARKER_UNAVAILABLE", str(exc)) from exc
    return marker


def prepare_attempts_root_v2(state_home: Path) -> Path:
    """Создаёт либо подтверждает единый частный корень каталогов попыток."""

    if not isinstance(state_home, Path) or not state_home.is_absolute():
        raise RuntimeRecoveryV2Error(
            "STATE_HOME_UNSAFE",
            "state home must be an absolute Path",
        )
    try:
        if state_home.resolve(strict=True) != state_home:
            raise RuntimeRecoveryV2Error(
                "STATE_HOME_UNSAFE",
                "state home must be canonical",
            )
    except OSError as exc:
        raise RuntimeRecoveryV2Error("STATE_HOME_UNSAFE", str(exc)) from exc
    try:
        _private_attempt_directory(state_home)
    except RuntimeRecoveryV2Error as exc:
        raise RuntimeRecoveryV2Error("STATE_HOME_UNSAFE", exc.message) from exc
    target = state_home / "attempt-runtimes-v2"
    try:
        target.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise RuntimeRecoveryV2Error(
            "ATTEMPTS_ROOT_UNAVAILABLE",
            str(exc),
        ) from exc
    return _private_attempts_root(target)


def remove_attempt_tree_v2(path: Path, attempts_root: Path) -> None:
    """Удаляет только прямой частный каталог попытки с допустимым именем."""

    attempts_root = _private_attempts_root(attempts_root)
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.parent != attempts_root
        or not path.name.startswith("attempt-")
        or _ATTEMPT_ID.fullmatch(path.name.removeprefix("attempt-")) is None
    ):
        raise RuntimeRecoveryV2Error(
            "ATTEMPT_CLEANUP_PATH_MISMATCH",
            "attempt path is outside the owned root",
        )
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeRecoveryV2Error("ATTEMPT_CLEANUP_FAILED", str(exc)) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeRecoveryV2Error(
            "ATTEMPT_CLEANUP_PATH_MISMATCH",
            "attempt directory identity is unsafe",
        )
    try:
        for current, directories, filenames in os.walk(
            path,
            topdown=False,
            followlinks=False,
        ):
            current_path = Path(current)
            current_info = current_path.lstat()
            if (
                current_path.is_symlink()
                or not stat.S_ISDIR(current_info.st_mode)
                or current_info.st_uid != os.getuid()
            ):
                raise RuntimeRecoveryV2Error(
                    "ATTEMPT_CLEANUP_PATH_MISMATCH",
                    "attempt subtree contains an unsafe directory",
                )
            current_path.chmod(0o700)
            for name in filenames:
                item = current_path / name
                item_info = item.lstat()
                if item_info.st_uid != os.getuid():
                    raise RuntimeRecoveryV2Error(
                        "ATTEMPT_CLEANUP_PATH_MISMATCH",
                        "attempt subtree contains a foreign file",
                    )
                item.unlink()
            for name in directories:
                item = current_path / name
                if item.is_symlink():
                    item.unlink()
                else:
                    item.chmod(0o700)
                    item.rmdir()
        path.rmdir()
        _fsync_directory(attempts_root)
    except RuntimeRecoveryV2Error:
        raise
    except OSError as exc:
        raise RuntimeRecoveryV2Error("ATTEMPT_CLEANUP_FAILED", str(exc)) from exc


def _marker_matches(path: Path, *, artifact_id: str, attempt_id: str) -> bool:
    marker = path / _MARKER_NAME
    try:
        info = marker.lstat()
        if (
            marker.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= 1024
        ):
            return False
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return bool(
        type(value) is dict
        and set(value) == {"artifactId", "attemptId", "kind", "schemaVersion"}
        and value.get("schemaVersion") == 2
        and value.get("kind") == _MARKER_KIND
        and value.get("artifactId") == artifact_id
        and value.get("attemptId") == attempt_id
    )


def _require_active_identity(
    record: Mapping[str, Any],
    action: RuntimeRecoveryActionV2,
) -> None:
    try:
        info = action.path.lstat()
    except OSError as exc:
        raise RuntimeRecoveryV2Error("ARTIFACT_IDENTITY_MISMATCH", str(exc)) from exc
    if (
        record.get("state") != "ACTIVE"
        or record.get("path") != str(action.path)
        or action.path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or record.get("device") != info.st_dev
        or record.get("inode") != info.st_ino
    ):
        raise RuntimeRecoveryV2Error(
            "ARTIFACT_IDENTITY_MISMATCH",
            "runtime artifact changed before cleanup",
        )


def _private_attempts_root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise RuntimeRecoveryV2Error(
            "ATTEMPTS_ROOT_INVALID",
            "attempts root must be an absolute Path",
        )
    _private_attempt_directory(path)
    return path


def _private_attempt_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeRecoveryV2Error("ATTEMPTS_ROOT_INVALID", str(exc)) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeRecoveryV2Error(
            "ATTEMPTS_ROOT_INVALID",
            "attempt directory must be private and owned",
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
