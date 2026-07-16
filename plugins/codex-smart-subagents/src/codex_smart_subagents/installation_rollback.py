"""Доказанный откат установки без управления маршрутами или контроллером."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import quote

from .controller import RuntimePaths, WireProtocolError
from .state import RouteState, is_terminal


SCHEMA_VERSION = 1
INSTALLATION_NAME = "codex-smart-subagents-v2"
MARKETPLACE_NAME = "codex-settings-adaptive"
PLUGIN_NAME = "codex-smart-subagents"
PLUGIN_ID = f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"


class RollbackError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class RollbackPreflight:
    smart_mode_disabled: bool
    controller_stopped: bool
    active_routes: int
    active_attempts: int
    probe_ok: bool = True
    blockers: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return (
            self.probe_ok
            and self.smart_mode_disabled
            and self.controller_stopped
            and self.active_routes == 0
            and self.active_attempts == 0
            and not self.blockers
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "smartModeDisabled": self.smart_mode_disabled,
            "controllerStopped": self.controller_stopped,
            "activeRoutes": self.active_routes,
            "activeAttempts": self.active_attempts,
            "probeOk": self.probe_ok,
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class RollbackContext:
    codex_home: Path
    codex_binary: Path
    state_home: Path
    manifest_path: Path
    owned_root: Path
    marketplace_root: Path
    launcher_path: Path
    admin_path: Path
    highfd_path: Path
    config_path: Path
    manifest: Mapping[str, Any]

    @classmethod
    def from_installation(
        cls,
        *,
        codex_home: Path,
        codex_binary: Path,
        state_home: Path,
    ) -> "RollbackContext":
        for name, value in (
            ("codex_home", codex_home),
            ("codex_binary", codex_binary),
            ("state_home", state_home),
        ):
            if not value.is_absolute():
                raise RollbackError(
                    "ROLLBACK_INVALID_PATH",
                    f"{name} должен быть абсолютным путём",
                )
        codex_home = codex_home.resolve()
        codex_binary = codex_binary.resolve()
        state_home = state_home.resolve()
        if not codex_home.is_dir() or codex_home.is_symlink():
            raise RollbackError(
                "ROLLBACK_UNSAFE_CODEX_HOME",
                f"нет безопасного CODEX_HOME: {codex_home}",
            )
        try:
            binary_info = codex_binary.stat()
        except OSError as exc:
            raise RollbackError(
                "ROLLBACK_CODEX_BINARY_MISSING",
                f"не найден Codex: {codex_binary}",
            ) from exc
        if (
            not stat.S_ISREG(binary_info.st_mode)
            or not os.access(codex_binary, os.X_OK)
        ):
            raise RollbackError(
                "ROLLBACK_CODEX_BINARY_MISSING",
                f"Codex не является исполняемым файлом: {codex_binary}",
            )
        manifest_path = (
            codex_home
            / "install-manifests"
            / f"{INSTALLATION_NAME}.json"
        )
        manifest = load_manifest(manifest_path)
        if manifest.get("codexHome") != str(codex_home):
            raise RollbackError(
                "ROLLBACK_MANIFEST_MISMATCH",
                "CODEX_HOME не совпадает с манифестом",
            )
        if manifest.get("codexBinary") != str(codex_binary):
            raise RollbackError(
                "ROLLBACK_MANIFEST_MISMATCH",
                "исполняемый Codex не совпадает с манифестом",
            )
        owned_root = codex_home / INSTALLATION_NAME
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, Mapping):
            raise RollbackError(
                "ROLLBACK_MANIFEST_MISMATCH",
                "в манифесте нет карты артефактов",
            )
        launcher_path = _manifest_artifact_path(
            artifacts,
            "launcher",
        )
        admin_path = _manifest_artifact_path(
            artifacts,
            "admin",
        )
        highfd_path = _manifest_artifact_path(
            artifacts,
            "highfd",
        )
        if (
            launcher_path.name != "codex-smart"
            or admin_path.name != "codex-smart-subagents-admin"
            or highfd_path.name != "codex-highfd"
            or len(
                {
                    launcher_path.parent,
                    admin_path.parent,
                    highfd_path.parent,
                }
            )
            != 1
        ):
            raise RollbackError(
                "ROLLBACK_MANIFEST_MISMATCH",
                "оболочки в манифесте имеют неверные пути",
            )
        if _manifest_artifact_path(
            artifacts,
            "ownedTree",
        ) != owned_root:
            raise RollbackError(
                "ROLLBACK_MANIFEST_MISMATCH",
                "принадлежащее дерево в манифесте имеет неверный путь",
            )
        return cls(
            codex_home=codex_home,
            codex_binary=codex_binary,
            state_home=state_home,
            manifest_path=manifest_path,
            owned_root=owned_root,
            marketplace_root=owned_root / "marketplace",
            launcher_path=launcher_path,
            admin_path=admin_path,
            highfd_path=highfd_path,
            config_path=codex_home / "config.toml",
            manifest=manifest,
        )

    @property
    def manifest_root(self) -> Path:
        return self.manifest_path.parent

    @property
    def lock_path(self) -> Path:
        return self.manifest_root / f"{INSTALLATION_NAME}.lock"

    @property
    def installed_plugin_root(self) -> Path:
        return self.marketplace_root / "plugins" / PLUGIN_NAME

    @property
    def launcher_target(self) -> Path:
        return self.installed_plugin_root / "bin" / "codex-smart"

    @property
    def admin_target(self) -> Path:
        return (
            self.installed_plugin_root
            / "bin"
            / "codex-smart-subagents-admin"
        )

    @property
    def runtime_paths(self) -> RuntimePaths:
        try:
            return RuntimePaths.for_codex_home(
                str(self.codex_home),
                state_home=self.state_home,
            )
        except (OSError, ValueError, WireProtocolError) as exc:
            raise RollbackError(
                "ROLLBACK_INVALID_RUNTIME_PATHS",
                "не удалось вычислить безопасные пути контроллера",
            ) from exc

    @property
    def database_path(self) -> Path:
        return (
            self.runtime_paths.namespace_dir
            / "state"
            / "smart-subagents.sqlite3"
        )

    @property
    def quarantine_path(self) -> Path:
        return self.runtime_paths.namespace_dir / "quarantine-state"

    @property
    def backups_path(self) -> Path:
        return self.codex_home / "backups" / INSTALLATION_NAME


def probe_rollback_preflight(
    context: RollbackContext,
    *,
    environment: Mapping[str, str] | None = None,
) -> RollbackPreflight:
    source = os.environ if environment is None else environment
    blockers: list[str] = []
    smart_value = source.get("CODEX_SMART_ENABLED", "0")
    smart_disabled = smart_value == "0"
    if not smart_disabled:
        blockers.append("SMART_MODE_ENABLED")

    controller_stopped = _controller_lock_is_free(context)
    if context.runtime_paths.socket_path.exists():
        controller_stopped = False
    if not controller_stopped:
        blockers.append("CONTROLLER_ACTIVE")

    active_routes = 0
    active_attempts = 0
    probe_ok = True
    if context.database_path.exists():
        try:
            active_routes, active_attempts = _active_database_counts(
                context.database_path
            )
        except (OSError, sqlite3.Error, ValueError):
            active_routes = -1
            active_attempts = -1
            probe_ok = False
            blockers.append("STATE_PROBE_FAILED")
    if active_routes > 0:
        blockers.append("ACTIVE_ROUTES")
    if active_attempts > 0:
        blockers.append("ACTIVE_ATTEMPTS")
    return RollbackPreflight(
        smart_mode_disabled=smart_disabled,
        controller_stopped=controller_stopped,
        active_routes=active_routes,
        active_attempts=active_attempts,
        probe_ok=probe_ok,
        blockers=tuple(blockers),
    )


def plan_rollback(
    context: RollbackContext,
    *,
    preflight: RollbackPreflight,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    _verify_ownership(context, extra_environment)
    return {
        "status": "planned",
        "ready": preflight.ready,
        "preflight": preflight.to_wire(),
        "actions": [
            f"выполнить codex plugin remove {PLUGIN_ID}",
            (
                "выполнить codex plugin marketplace remove "
                f"{MARKETPLACE_NAME}"
            ),
            f"удалить проверенную ссылку {context.launcher_path}",
            f"удалить проверенную ссылку {context.admin_path}",
            f"удалить проверенное дерево {context.owned_root}",
            f"удалить манифест {context.manifest_path}",
            "сохранить базу, карантин и резервные копии",
        ],
        "retained": _retained_paths(context),
    }


def apply_rollback(
    context: RollbackContext,
    *,
    preflight: RollbackPreflight,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not preflight.ready:
        raise RollbackError(
            "ROLLBACK_PREFLIGHT_REQUIRED",
            "внешний допуск не подтвердил выключенный режим и остановку работ",
        )
    _verify_ownership(context, extra_environment)
    with installation_lock(context.lock_path):
        with controller_rollback_guard(context):
            guarded = _probe_locked_preflight(
                context,
                extra_environment=extra_environment,
            )
            if not guarded.ready:
                raise RollbackError(
                    "ROLLBACK_PREFLIGHT_STALE",
                    (
                        "состояние изменилось после внешнего допуска: "
                        + ", ".join(guarded.blockers)
                    ),
                )
            manifest = load_manifest(context.manifest_path)
            if manifest != context.manifest:
                raise RollbackError(
                    "ROLLBACK_MANIFEST_CHANGED",
                    "манифест изменился после внешней проверки",
                )
            _verify_ownership(context, extra_environment)
            current_config = _capture_current_config(context)
            plugin_removed = False
            marketplace_removed = False
            try:
                _codex_json(
                    context,
                    ["plugin", "remove", PLUGIN_ID, "--json"],
                    "CODEX_PLUGIN_REMOVE_FAILED",
                    extra_environment,
                )
                plugin_removed = True
                _codex_json(
                    context,
                    [
                        "plugin",
                        "marketplace",
                        "remove",
                        MARKETPLACE_NAME,
                        "--json",
                    ],
                    "CODEX_MARKETPLACE_REMOVE_FAILED",
                    extra_environment,
                )
                marketplace_removed = True
                _restore_absent_config_if_safe(context, manifest)
                retained_cache = _remove_empty_plugin_cache_namespace(context)
                retained_smoke = _remove_empty_smoke_state(context)
                retained_trash = _retire_verified_paths(context, manifest)
            except BaseException:
                _repair_failed_rollback(
                    context,
                    current_config=current_config,
                    plugin_removed=plugin_removed,
                    marketplace_removed=marketplace_removed,
                    extra_environment=extra_environment,
                )
                raise
    retained = _retained_paths(context)
    return {
        "status": "rolled_back",
        "retainedBackup": str(
            manifest.get("backup", {}).get("directory", "")
        ),
        "retainedDatabase": retained["database"],
        "retainedQuarantine": retained["quarantine"],
        "retainedBackups": retained["backups"],
        "retainedTrash": retained_trash,
        "retainedCache": retained_cache,
        "retainedSmokeState": retained_smoke,
    }


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_MANIFEST_MISSING",
            f"нет манифеста установки: {path}",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RollbackError(
            "ROLLBACK_MANIFEST_UNSAFE",
            f"манифест имеет небезопасные свойства: {path}",
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RollbackError(
            "ROLLBACK_MANIFEST_INVALID",
            f"манифест повреждён: {path}",
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != SCHEMA_VERSION
        or document.get("installation") != INSTALLATION_NAME
        or document.get("pluginId") != PLUGIN_ID
        or document.get("marketplaceName") != MARKETPLACE_NAME
    ):
        raise RollbackError(
            "ROLLBACK_MANIFEST_INVALID",
            "идентичность манифеста не совпадает с этой версией",
        )
    return document


def verify_manifest_artifacts(
    context: RollbackContext,
    manifest: Mapping[str, Any],
) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return [
            {
                "code": "ROLLBACK_MANIFEST_INVALID",
                "message": "в манифесте нет карты артефактов",
            }
        ]
    tree = artifacts.get("ownedTree")
    if not isinstance(tree, Mapping) or tree.get("path") != str(
        context.owned_root
    ):
        problems.append(
            {
                "code": "ROLLBACK_MANIFEST_MISMATCH",
                "message": "неверный путь принадлежащего дерева",
            }
        )
    else:
        try:
            actual = tree_digest(context.owned_root)
        except RollbackError as exc:
            problems.append({"code": exc.code, "message": exc.message})
        else:
            if actual != tree.get("sha256"):
                problems.append(
                    {
                        "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                        "message": str(context.owned_root),
                    }
                )

    launcher = artifacts.get("launcher")
    if not isinstance(launcher, Mapping) or launcher.get("path") != str(
        context.launcher_path
    ):
        problems.append(
            {
                "code": "ROLLBACK_MANIFEST_MISMATCH",
                "message": "неверный путь codex-smart",
            }
        )
    elif not context.launcher_path.is_symlink():
        problems.append(
            {
                "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                "message": str(context.launcher_path),
            }
        )
    else:
        target = os.readlink(context.launcher_path)
        if (
            target != launcher.get("target")
            or Path(target) != context.launcher_target
        ):
            problems.append(
                {
                    "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                    "message": str(context.launcher_path),
                }
            )
        else:
            try:
                digest = file_digest(context.launcher_target)
            except RollbackError as exc:
                problems.append({"code": exc.code, "message": exc.message})
            else:
                if digest != launcher.get("targetSha256"):
                    problems.append(
                        {
                            "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                            "message": str(context.launcher_path),
                        }
                    )

    highfd = artifacts.get("highfd")
    if not isinstance(highfd, Mapping) or highfd.get("path") != str(
        context.highfd_path
    ):
        problems.append(
            {
                "code": "ROLLBACK_MANIFEST_MISMATCH",
                "message": "неверный путь codex-highfd",
            }
        )
    elif context.highfd_path.is_symlink() or not context.highfd_path.is_file():
        problems.append(
            {
                "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                "message": str(context.highfd_path),
            }
        )
    else:
        try:
            digest = file_digest(context.highfd_path)
        except RollbackError as exc:
            problems.append({"code": exc.code, "message": exc.message})
        else:
            if (
                digest != highfd.get("sha256")
                or stat.S_IMODE(context.highfd_path.stat().st_mode) != 0o755
            ):
                problems.append(
                    {
                        "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                        "message": str(context.highfd_path),
                    }
                )
    admin = artifacts.get("admin")
    if not isinstance(admin, Mapping) or admin.get("path") != str(
        context.admin_path
    ):
        problems.append(
            {
                "code": "ROLLBACK_MANIFEST_MISMATCH",
                "message": "неверный путь административной команды",
            }
        )
    elif not context.admin_path.is_symlink():
        problems.append(
            {
                "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                "message": str(context.admin_path),
            }
        )
    else:
        target = os.readlink(context.admin_path)
        if (
            target != admin.get("target")
            or Path(target) != context.admin_target
        ):
            problems.append(
                {
                    "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                    "message": str(context.admin_path),
                }
            )
        else:
            try:
                digest = file_digest(context.admin_target)
            except RollbackError as exc:
                problems.append({"code": exc.code, "message": exc.message})
            else:
                if digest != admin.get("targetSha256"):
                    problems.append(
                        {
                            "code": "ARTIFACT_FINGERPRINT_MISMATCH",
                            "message": str(context.admin_path),
                        }
                    )
    return problems


def file_digest(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_ARTIFACT_UNAVAILABLE",
            f"не удалось прочитать {path}: {exc}",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise RollbackError(
            "ROLLBACK_UNSAFE_ARTIFACT",
            f"ожидался обычный файл: {path}",
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise RollbackError(
            "ROLLBACK_ARTIFACT_UNAVAILABLE",
            f"нет безопасного каталога: {root}",
        )
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = b"d"
            value = b""
        elif stat.S_ISREG(info.st_mode):
            kind = b"x" if info.st_mode & stat.S_IXUSR else b"f"
            value = bytes.fromhex(file_digest(path))
        else:
            raise RollbackError(
                "ROLLBACK_UNSAFE_ARTIFACT",
                f"дерево содержит ссылку или особый файл: {path}",
            )
        digest.update(kind)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(value)
    return digest.hexdigest()


def _verify_ownership(
    context: RollbackContext,
    extra_environment: Mapping[str, str] | None,
) -> None:
    manifest = load_manifest(context.manifest_path)
    if manifest != context.manifest:
        raise RollbackError(
            "ROLLBACK_MANIFEST_CHANGED",
            "манифест изменился после загрузки",
        )
    conflicts = verify_manifest_artifacts(context, manifest)
    if conflicts:
        raise RollbackError(
            "ROLLBACK_OWNERSHIP_CONFLICT",
            "; ".join(
                f"{problem['code']}: {problem['message']}"
                for problem in conflicts
            ),
        )
    _verify_backup_ownership(context, manifest)
    plugins = [
        item
        for item in _list_plugins(context, extra_environment)
        if item.get("pluginId") == PLUGIN_ID
    ]
    marketplaces = [
        item
        for item in _list_marketplaces(context, extra_environment)
        if item.get("name") == MARKETPLACE_NAME
    ]
    if (
        len(plugins) != 1
        or len(marketplaces) != 1
        or Path(str(marketplaces[0].get("root", ""))).resolve()
        != context.marketplace_root
    ):
        raise RollbackError(
            "ROLLBACK_OWNERSHIP_CONFLICT",
            "состояние расширения или рынка не совпадает с манифестом",
        )


def _verify_backup_ownership(
    context: RollbackContext,
    manifest: Mapping[str, Any],
) -> None:
    backup = manifest.get("backup")
    if not isinstance(backup, Mapping):
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "манифест не содержит резервную копию",
        )
    raw_directory = backup.get("directory")
    if not isinstance(raw_directory, str) or not Path(
        raw_directory
    ).is_absolute():
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "каталог резервной копии имеет неверный путь",
        )
    directory = Path(raw_directory)
    if directory.parent != context.backups_path:
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "резервная копия находится вне управляемого каталога",
        )
    try:
        info = directory.lstat()
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "каталог резервной копии отсутствует",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "каталог резервной копии имеет небезопасные свойства",
        )

    config_existed = backup.get("configExisted")
    if type(config_existed) is not bool:
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "неверен признак прежнего config.toml",
        )
    if config_existed:
        config_path = Path(str(backup.get("config", "")))
        if (
            config_path != directory / "config.toml"
            or file_digest(config_path) != backup.get("configSha256")
            or not _is_private_backup_file(config_path)
        ):
            raise RollbackError(
                "ROLLBACK_BACKUP_CONFLICT",
                "резервная копия config.toml изменилась",
            )
    elif not _is_empty_private_marker(directory / "config.absent"):
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "маркер отсутствующего config.toml повреждён",
        )

    prior = backup.get("highfd")
    if not isinstance(prior, Mapping) or type(
        prior.get("existed")
    ) is not bool:
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "неверны сведения о прежнем codex-highfd",
        )
    if prior["existed"]:
        highfd_path = Path(str(prior.get("path", "")))
        mode = prior.get("mode")
        if (
            highfd_path != directory / "codex-highfd"
            or file_digest(highfd_path) != prior.get("sha256")
            or not _is_private_backup_file(highfd_path)
            or type(mode) is not int
            or mode & ~0o777
        ):
            raise RollbackError(
                "ROLLBACK_BACKUP_CONFLICT",
                "резервная копия codex-highfd изменилась",
            )
    elif not _is_empty_private_marker(directory / "codex-highfd.absent"):
        raise RollbackError(
            "ROLLBACK_BACKUP_CONFLICT",
            "маркер отсутствующего codex-highfd повреждён",
        )


def _is_private_backup_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def _is_empty_private_marker(path: Path) -> bool:
    return (
        _is_private_backup_file(path)
        and path.stat().st_size == 0
    )


def _controller_lock_is_free(context: RollbackContext) -> bool:
    path = context.runtime_paths.lock_path
    if not path.exists():
        return True
    if path.is_symlink() or not path.is_file():
        return False
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


@contextmanager
def controller_rollback_guard(
    context: RollbackContext,
) -> Iterator[None]:
    paths = context.runtime_paths
    run_dir = paths.run_dir
    if not os.path.lexists(run_dir):
        try:
            os.mkdir(run_dir, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RollbackError(
                "ROLLBACK_UNSAFE_CONTROLLER_RUNTIME",
                f"не удалось создать каталог блокировки: {run_dir}",
            ) from exc
    try:
        run_info = run_dir.lstat()
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_UNSAFE_CONTROLLER_RUNTIME",
            f"не удалось проверить каталог блокировки: {run_dir}",
        ) from exc
    if (
        not stat.S_ISDIR(run_info.st_mode)
        or run_info.st_uid != os.getuid()
        or stat.S_IMODE(run_info.st_mode) & 0o077
    ):
        raise RollbackError(
            "ROLLBACK_UNSAFE_CONTROLLER_RUNTIME",
            f"каталог блокировки имеет небезопасные свойства: {run_dir}",
        )
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(paths.lock_path, flags, 0o600)
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_UNSAFE_CONTROLLER_LOCK",
            f"не удалось открыть блокировку: {paths.lock_path}",
        ) from exc
    locked = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise RollbackError(
                "ROLLBACK_UNSAFE_CONTROLLER_LOCK",
                "файл блокировки контроллера имеет небезопасные свойства",
            )
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise RollbackError(
                "ROLLBACK_UNSAFE_CONTROLLER_LOCK",
                "не удалось ограничить права файла блокировки",
            )
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as exc:
            raise RollbackError(
                "ROLLBACK_CONTROLLER_ACTIVE",
                "контроллер захватил блокировку после внешнего допуска",
            ) from exc
        locked = True
        if os.path.lexists(paths.socket_path):
            raise RollbackError(
                "ROLLBACK_CONTROLLER_ACTIVE",
                "сокет контроллера существует после захвата блокировки",
            )
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _probe_locked_preflight(
    context: RollbackContext,
    *,
    extra_environment: Mapping[str, str] | None,
) -> RollbackPreflight:
    source = dict(os.environ)
    if extra_environment:
        source.update(extra_environment)
    blockers: list[str] = []
    smart_disabled = source.get("CODEX_SMART_ENABLED", "0") == "0"
    if not smart_disabled:
        blockers.append("SMART_MODE_ENABLED")
    controller_stopped = not os.path.lexists(
        context.runtime_paths.socket_path
    )
    if not controller_stopped:
        blockers.append("CONTROLLER_ACTIVE")
    active_routes = 0
    active_attempts = 0
    probe_ok = True
    if context.database_path.exists():
        try:
            active_routes, active_attempts = _active_database_counts(
                context.database_path
            )
        except (OSError, sqlite3.Error, ValueError):
            active_routes = -1
            active_attempts = -1
            probe_ok = False
            blockers.append("STATE_PROBE_FAILED")
    if active_routes > 0:
        blockers.append("ACTIVE_ROUTES")
    if active_attempts > 0:
        blockers.append("ACTIVE_ATTEMPTS")
    return RollbackPreflight(
        smart_mode_disabled=smart_disabled,
        controller_stopped=controller_stopped,
        active_routes=active_routes,
        active_attempts=active_attempts,
        probe_ok=probe_ok,
        blockers=tuple(blockers),
    )


def _active_database_counts(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("unsafe database") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("unsafe database")
    terminals = tuple(
        state.value for state in RouteState if is_terminal(state)
    )
    placeholders = ",".join("?" for _ in terminals)
    uri = f"file:{quote(str(path))}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        route_row = connection.execute(
            f"select count(*) from routes where state not in ({placeholders})",
            terminals,
        ).fetchone()
        attempt_row = connection.execute(
            "select count(*) from attempts where state = 'RUNNING'"
        ).fetchone()
        if route_row is None or attempt_row is None:
            raise ValueError("missing counts")
        return int(route_row[0]), int(attempt_row[0])
    finally:
        connection.close()


def _capture_current_config(
    context: RollbackContext,
) -> tuple[bool, bytes]:
    if context.config_path.is_symlink():
        raise RollbackError(
            "ROLLBACK_OWNERSHIP_CONFLICT",
            "config.toml стал символической ссылкой",
        )
    if not context.config_path.exists():
        return (False, b"")
    if not context.config_path.is_file():
        raise RollbackError(
            "ROLLBACK_OWNERSHIP_CONFLICT",
            "config.toml не является обычным файлом",
        )
    return (True, context.config_path.read_bytes())


def _repair_failed_rollback(
    context: RollbackContext,
    *,
    current_config: tuple[bool, bytes],
    plugin_removed: bool,
    marketplace_removed: bool,
    extra_environment: Mapping[str, str] | None,
) -> None:
    if marketplace_removed and context.marketplace_root.is_dir():
        _codex_best_effort(
            context,
            [
                "plugin",
                "marketplace",
                "add",
                str(context.marketplace_root),
                "--json",
            ],
            extra_environment,
        )
    if plugin_removed and context.marketplace_root.is_dir():
        _codex_best_effort(
            context,
            ["plugin", "add", PLUGIN_ID, "--json"],
            extra_environment,
        )
    existed, data = current_config
    if existed:
        if context.config_path.is_symlink():
            raise RollbackError(
                "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
                "config.toml стал символической ссылкой",
            )
        if not context.config_path.exists():
            _atomic_write(context.config_path, data, mode=0o600)
            return
        if not context.config_path.is_file():
            raise RollbackError(
                "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
                "config.toml перестал быть обычным файлом",
            )
        if context.config_path.read_bytes() != data:
            raise RollbackError(
                "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
                (
                    "config.toml изменился параллельно; "
                    "новые данные не перезаписаны"
                ),
            )
        return
    if context.config_path.is_symlink():
        raise RollbackError(
            "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
            "config.toml стал символической ссылкой",
        )
    if not context.config_path.exists():
        return
    if not context.config_path.is_file():
        raise RollbackError(
            "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
            "config.toml перестал быть обычным файлом",
        )
    if not context.config_path.read_bytes().strip():
        context.config_path.unlink()
        return
    raise RollbackError(
        "ROLLBACK_CONFIG_CHANGED_DURING_REPAIR",
        "непустой config.toml сохранён для ручной проверки",
    )


def _retire_verified_paths(
    context: RollbackContext,
    manifest: Mapping[str, Any],
) -> str:
    _prepare_private_directory(context.manifest_root)
    trash = (
        context.manifest_root
        / f".{INSTALLATION_NAME}.rollback-{secrets.token_hex(6)}"
    )
    _prepare_private_directory(trash)
    launcher_trash = trash / "codex-smart"
    admin_trash = trash / "codex-smart-subagents-admin"
    highfd_trash = trash / "codex-highfd"
    owned_trash = trash / "owned"
    manifest_trash = trash / "manifest.json"
    moved: list[tuple[Path, Path]] = []
    installed_highfd = context.highfd_path.read_bytes()
    backup = manifest.get("backup")
    prior = backup.get("highfd") if isinstance(backup, Mapping) else None
    if not isinstance(prior, Mapping):
        raise RollbackError(
            "ROLLBACK_OWNERSHIP_CONFLICT",
            "манифест не содержит резервную копию codex-highfd",
        )
    try:
        if prior.get("existed") is True:
            prior_path = Path(str(prior.get("path", "")))
            if file_digest(prior_path) != prior.get("sha256"):
                raise RollbackError(
                    "ROLLBACK_OWNERSHIP_CONFLICT",
                    "резервная копия codex-highfd изменилась",
                )
            prior_mode = prior.get("mode")
            if type(prior_mode) is not int or prior_mode & ~0o777:
                raise RollbackError(
                    "ROLLBACK_OWNERSHIP_CONFLICT",
                    "режим прежнего codex-highfd повреждён",
                )
            _atomic_write(
                context.highfd_path,
                prior_path.read_bytes(),
                mode=prior_mode,
            )
        else:
            os.replace(context.highfd_path, highfd_trash)
            moved.append((highfd_trash, context.highfd_path))
        os.replace(context.launcher_path, launcher_trash)
        moved.append((launcher_trash, context.launcher_path))
        os.replace(context.admin_path, admin_trash)
        moved.append((admin_trash, context.admin_path))
        _make_tree_removable(context.owned_root)
        os.replace(context.owned_root, owned_trash)
        moved.append((owned_trash, context.owned_root))
        os.replace(context.manifest_path, manifest_trash)
        moved.append((manifest_trash, context.manifest_path))
    except BaseException:
        for source, target in reversed(moved):
            if os.path.lexists(source):
                os.replace(source, target)
        if prior.get("existed") is True:
            _atomic_write(
                context.highfd_path,
                installed_highfd,
                mode=0o755,
            )
        if context.owned_root.is_dir():
            _seal_private_tree(context.owned_root)
        if trash.is_dir():
            _make_tree_removable(trash)
            shutil.rmtree(trash)
        raise
    try:
        if owned_trash.is_dir():
            _make_tree_removable(owned_trash)
        shutil.rmtree(trash)
    except OSError:
        return str(trash)
    return ""


def _restore_absent_config_if_safe(
    context: RollbackContext,
    manifest: Mapping[str, Any],
) -> None:
    backup = manifest.get("backup")
    if not isinstance(backup, Mapping):
        return
    if backup.get("configExisted") is not False:
        return
    if context.config_path.is_symlink() or not context.config_path.is_file():
        return
    try:
        empty = not context.config_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return
    if empty:
        context.config_path.unlink()


def _remove_empty_plugin_cache_namespace(
    context: RollbackContext,
) -> str:
    path = (
        context.codex_home
        / "plugins"
        / "cache"
        / MARKETPLACE_NAME
    )
    return _remove_empty_directory(path)


def _remove_empty_smoke_state(context: RollbackContext) -> str:
    return _remove_empty_directory(
        context.codex_home / "adaptive-subagents-smoke-state"
    )


def _remove_empty_directory(path: Path) -> str:
    if not os.path.lexists(path):
        return ""
    if path.is_symlink() or not path.is_dir():
        return str(path)
    try:
        path.rmdir()
    except OSError:
        return str(path)
    return ""


def _retained_paths(context: RollbackContext) -> dict[str, str]:
    return {
        "database": (
            str(context.database_path)
            if context.database_path.exists()
            else ""
        ),
        "quarantine": (
            str(context.quarantine_path)
            if context.quarantine_path.exists()
            else ""
        ),
        "backups": (
            str(context.backups_path)
            if context.backups_path.exists()
            else ""
        ),
    }


def _list_marketplaces(
    context: RollbackContext,
    extra_environment: Mapping[str, str] | None,
) -> list[dict[str, Any]]:
    document = _codex_json(
        context,
        ["plugin", "marketplace", "list", "--json"],
        "CODEX_MARKETPLACE_LIST_FAILED",
        extra_environment,
    )
    value = document.get("marketplaces")
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in value
    ):
        raise RollbackError(
            "CODEX_MARKETPLACE_LIST_INVALID",
            "Codex вернул неверный список рынков",
        )
    return value


def _list_plugins(
    context: RollbackContext,
    extra_environment: Mapping[str, str] | None,
) -> list[dict[str, Any]]:
    document = _codex_json(
        context,
        ["plugin", "list", "--json"],
        "CODEX_PLUGIN_LIST_FAILED",
        extra_environment,
    )
    value = document.get("installed")
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in value
    ):
        raise RollbackError(
            "CODEX_PLUGIN_LIST_INVALID",
            "Codex вернул неверный список расширений",
        )
    return value


def _codex_json(
    context: RollbackContext,
    arguments: Sequence[str],
    error_code: str,
    extra_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    result = _run_process(
        [str(context.codex_binary), *arguments],
        _command_environment(context, extra_environment),
        timeout=30,
    )
    if result.returncode != 0:
        raise RollbackError(error_code, _bounded_error(result))
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RollbackError(
            error_code,
            f"Codex вернул не-JSON: {result.stdout[:500]!r}",
        ) from exc
    if not isinstance(document, dict):
        raise RollbackError(error_code, "Codex вернул JSON не в виде объекта")
    return document


def _codex_best_effort(
    context: RollbackContext,
    arguments: Sequence[str],
    extra_environment: Mapping[str, str] | None,
) -> None:
    try:
        _run_process(
            [str(context.codex_binary), *arguments],
            _command_environment(context, extra_environment),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, RollbackError):
        return


def _run_process(
    arguments: Sequence[str],
    environment: Mapping[str, str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(environment),
            timeout=timeout,
            check=False,
            shell=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RollbackError(
            "ROLLBACK_PROCESS_START_FAILED",
            f"не удалось выполнить {arguments[0]}: {exc}",
        ) from exc


def _command_environment(
    context: RollbackContext,
    extra: Mapping[str, str] | None,
) -> dict[str, str]:
    environment: dict[str, str] = {
        "CODEX_HOME": str(context.codex_home),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "PATH": os.environ.get(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        ),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if "TMPDIR" in os.environ:
        environment["TMPDIR"] = os.environ["TMPDIR"]
    if extra:
        environment.update(extra)
    return environment


@contextmanager
def installation_lock(path: Path) -> Iterator[None]:
    _prepare_private_directory(path.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RollbackError(
            "ROLLBACK_UNSAFE_INSTALL_LOCK",
            f"не удалось безопасно открыть блокировку: {path}",
        ) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise RollbackError(
                "ROLLBACK_UNSAFE_INSTALL_LOCK",
                f"блокировка имеет небезопасные свойства: {path}",
            )
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise RollbackError(
                "ROLLBACK_UNSAFE_INSTALL_LOCK",
                f"не удалось ограничить права блокировки: {path}",
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    _prepare_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if temporary.exists():
            temporary.unlink()
        raise


def _prepare_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise RollbackError(
            "ROLLBACK_UNSAFE_PATH",
            f"каталог не должен быть ссылкой: {path}",
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    if not path.is_dir():
        raise RollbackError(
            "ROLLBACK_UNSAFE_PATH",
            f"ожидался каталог: {path}",
        )


def _seal_private_tree(root: Path) -> None:
    for path in sorted(
        root.rglob("*"),
        key=lambda item: (len(item.parts), item.as_posix()),
        reverse=True,
    ):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            os.chmod(path, 0o500)
        elif stat.S_ISREG(info.st_mode):
            os.chmod(
                path,
                0o500 if info.st_mode & stat.S_IXUSR else 0o400,
            )
        else:
            raise RollbackError(
                "ROLLBACK_UNSAFE_ARTIFACT",
                f"дерево содержит особый файл: {path}",
            )
    os.chmod(root, 0o500)


def _make_tree_removable(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bounded_error(result: subprocess.CompletedProcess[str]) -> str:
    return (
        result.stderr.strip()[:1000]
        or result.stdout.strip()[:1000]
        or f"код завершения {result.returncode}"
    )


def _manifest_artifact_path(
    artifacts: Mapping[str, Any],
    name: str,
) -> Path:
    artifact = artifacts.get(name)
    raw = artifact.get("path") if isinstance(artifact, Mapping) else None
    if not isinstance(raw, str) or not Path(raw).is_absolute():
        raise RollbackError(
            "ROLLBACK_MANIFEST_MISMATCH",
            f"артефакт {name} не имеет абсолютного пути",
        )
    return Path(raw)
