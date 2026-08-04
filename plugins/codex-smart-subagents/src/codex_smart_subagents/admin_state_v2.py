"""Доказательство установленного состояния для административных команд v2."""

from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayLayout,
    GatewayRuntimeBindingV2,
    GatewayState,
)
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .execution_recovery_v2 import observe_process_identity_v2
from .production_runtime_v2 import (
    accepting_controller_from_binding_v2,
    database_identity_from_binding_v2,
)
from .schema_projection import APPLICATION_ID, database_schema_fingerprint
from .state_store_v2 import SmartStoreV2


EXIT_ARGUMENT = 2
EXIT_UNSAFE = 4
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_RECEIPT_KEYS = frozenset(
    {
        "schemaVersion",
        "kind",
        "sourceDigest",
        "installationId",
        "activationId",
        "codexHome",
        "codexBinary",
        "stateHome",
        "marketplacePath",
        "registeredMarketplacePath",
        "links",
        "marketplaceName",
        "pluginId",
        "extensions",
    }
)


@dataclass
class AdminV2Error(RuntimeError):
    exit_code: int
    code: str
    message: str
    data: dict[str, Any]

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class AdminConfigV2:
    codex_home: Path
    layout: GatewayLayout
    installer_receipt_path: Path

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "AdminConfigV2":
        raw_home = environ.get("CODEX_HOME", str(Path.home() / ".codex"))
        home = Path(raw_home).expanduser()
        if not home.is_absolute():
            raise AdminV2Error(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "CODEX_HOME должен быть абсолютным путём.",
                {},
            )
        try:
            info = home.lstat()
        except OSError as exc:
            raise AdminV2Error(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "CODEX_HOME недоступен.",
                {},
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CODEX_HOME_INVALID",
                "CODEX_HOME не прошёл проверку свойств.",
                {},
            )
        home = home.absolute()
        layout = GatewayLayout.for_codex_home(home)
        return cls(
            codex_home=home,
            layout=layout,
            installer_receipt_path=(
                layout.manifest_root / "codex-smart-subagents-v2.installer.json"
            ),
        )


@dataclass(frozen=True)
class ProvenAdminStateV2:
    config: AdminConfigV2
    receipt: Mapping[str, Any]
    binding: GatewayRuntimeBindingV2


@dataclass(frozen=True)
class ControllerStopReportV2:
    stopped: bool
    signaled: bool
    reason_code: str
    pid: int


def load_proven_state_v2(config: AdminConfigV2) -> ProvenAdminStateV2:
    receipt = _require_installer_receipt(config)
    resolver = ActivationResolver(layout=config.layout, wrapper=Path(__file__))
    try:
        decision = resolver.resolve_persisted_activation()
    except Exception as exc:
        reason = getattr(exc, "code", "ACTIVATION_PROOF_FAILED")
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Принятая активация версии 2 не прошла проверку.",
            {"reasonCode": str(reason)},
        ) from exc
    binding = decision.runtime_binding
    if decision.state is not GatewayState.READY or binding is None:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Принятая активация версии 2 не прошла проверку.",
            {"reasonCode": decision.reason_code},
        )
    try:
        expected_codex_binary = (
            decision.source_drift.lexical_path
            if decision.source_drift is not None
            else decision.executable
        )
        _verify_receipt_binding(
            config,
            receipt,
            expected_codex_binary,
            binding,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Квитанция установщика расходится с принятой активацией.",
            {"reasonCode": "INSTALLER_RECEIPT_MISMATCH"},
        ) from exc
    return ProvenAdminStateV2(config=config, receipt=receipt, binding=binding)


def probe_live_controller_v2(proven: ProvenAdminStateV2) -> tuple[bool, str]:
    try:
        decision = ActivationResolver(
            layout=proven.config.layout,
            wrapper=Path(__file__),
        ).resolve()
    except Exception as exc:
        return False, str(getattr(exc, "code", "CONTROLLER_PROBE_FAILED"))
    binding = decision.runtime_binding
    if (
        decision.state is GatewayState.READY
        and binding is not None
        and binding.activation_id == proven.binding.activation_id
        and binding.control_epoch == proven.binding.control_epoch
    ):
        return True, "READY"
    return False, str(decision.reason_code)


@contextmanager
def open_readonly_database_v2(
    proven: ProvenAdminStateV2,
) -> Iterator[sqlite3.Connection]:
    path = proven.binding.database_path
    before = _private_database(path)
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro",
            uri=True,
            timeout=2,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "База версии 2 недоступна для подтверждённого чтения.",
            {"reasonCode": "DATABASE_UNAVAILABLE"},
        ) from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("pragma query_only=ON")
        quick = [tuple(row) for row in connection.execute("pragma quick_check")]
        foreign = [
            tuple(row) for row in connection.execute("pragma foreign_key_check")
        ]
        application_id = int(connection.execute("pragma application_id").fetchone()[0])
        user_version = int(connection.execute("pragma user_version").fetchone()[0])
        fingerprint = database_schema_fingerprint(connection, version=2).fingerprint
        identity = connection.execute("select * from database_identity").fetchall()
        controller = connection.execute("select * from controller_state").fetchall()
        if (
            quick != [("ok",)]
            or foreign
            or application_id != APPLICATION_ID
            or user_version != 2
            or fingerprint
            != proven.binding.database_identity_row.get("schema_fingerprint")
            or len(identity) != 1
            or dict(identity[0]) != dict(proven.binding.database_identity_row)
            or len(controller) != 1
            or dict(controller[0]) != dict(proven.binding.controller_row)
        ):
            raise AdminV2Error(
                EXIT_UNSAFE,
                "V2_STATE_UNCONFIRMED",
                "База версии 2 изменилась после доказательства активации.",
                {"reasonCode": "DATABASE_PROOF_MISMATCH"},
            )
        yield connection
        after = _private_database(path)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise AdminV2Error(
                EXIT_UNSAFE,
                "V2_STATE_UNCONFIRMED",
                "База версии 2 была заменена во время чтения.",
                {"reasonCode": "DATABASE_CHANGED"},
            )
    except sqlite3.Error as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "База версии 2 не прошла проверку.",
            {"reasonCode": "DATABASE_PROOF_FAILED"},
        ) from exc
    finally:
        connection.close()


@contextmanager
def open_runtime_store_v2(
    proven: ProvenAdminStateV2,
) -> Iterator[SmartStoreV2]:
    try:
        store = SmartStoreV2(
            proven.binding.database_path,
            database_identity=database_identity_from_binding_v2(proven.binding),
            controller=accepting_controller_from_binding_v2(proven.binding),
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "База версии 2 не открылась через производственное хранилище.",
            {"reasonCode": str(getattr(exc, "code", "DATABASE_OPEN_FAILED"))},
        ) from exc
    try:
        yield store
    finally:
        store.close()


def require_controller_stopped_v2(proven: ProvenAdminStateV2) -> None:
    row = proven.binding.controller_row
    pid = row.get("controller_pid")
    marker = row.get("controller_process_start_marker")
    if type(pid) is not int or pid <= 0 or type(marker) is not str or not marker:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Идентичность процесса контроллера не подтверждена.",
            {},
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Невозможно доказать остановку контроллера.",
            {},
        ) from exc
    try:
        observed = system_process_start_marker_v2(pid)
    except ChildGuardV2Error as exc:
        if exc.code == "PROCESS_NOT_RUNNING":
            return
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Невозможно проверить системный маркер контроллера.",
            {},
        ) from exc
    if observed == marker:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_ACTIVE",
            "Применение восстановления разрешено только после остановки контроллера.",
            {},
        )


def stop_live_controller_v2(
    proven: ProvenAdminStateV2,
    *,
    timeout_seconds: float = 10.0,
    process_observer: Callable[[int, str], str] | None = None,
    signal_sender: Callable[[int, int], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> ControllerStopReportV2:
    """Останавливает только дважды подтверждённый процесс контроллера."""

    if (
        type(timeout_seconds) not in {int, float}
        or timeout_seconds <= 0
        or timeout_seconds > 60
    ):
        raise ValueError("timeout_seconds должен находиться в диапазоне (0, 60]")
    row = proven.binding.controller_row
    pid = row.get("controller_pid")
    marker = row.get("controller_process_start_marker")
    if type(pid) is not int or pid <= 0 or type(marker) is not str or not marker:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Идентичность процесса контроллера не подтверждена.",
            {},
        )
    observer = process_observer or observe_process_identity_v2
    sender = signal_sender or os.kill
    clock = monotonic or time.monotonic
    pause = sleeper or time.sleep

    for _ in range(2):
        observation = _observe_controller_identity_v2(observer, pid, marker)
        if observation in {"ABSENT", "REUSED"}:
            return ControllerStopReportV2(
                stopped=True,
                signaled=False,
                reason_code="CONTROLLER_ALREADY_STOPPED",
                pid=pid,
            )
        if observation != "EXACT":
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CONTROLLER_STATE_UNKNOWN",
                "Невозможно доказать идентичность процесса контроллера.",
                {"reasonCode": observation},
            )

    try:
        sender(pid, signal.SIGTERM)
    except ProcessLookupError:
        return ControllerStopReportV2(
            stopped=True,
            signaled=False,
            reason_code="CONTROLLER_STOPPED",
            pid=pid,
        )
    except (PermissionError, OSError) as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STOP_FAILED",
            "Не удалось отправить сигнал подтверждённому контроллеру.",
            {},
        ) from exc

    deadline = clock() + float(timeout_seconds)
    while True:
        observation = _observe_controller_identity_v2(observer, pid, marker)
        if observation in {"ABSENT", "REUSED"}:
            return ControllerStopReportV2(
                stopped=True,
                signaled=True,
                reason_code="CONTROLLER_STOPPED",
                pid=pid,
            )
        if observation != "EXACT":
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CONTROLLER_STATE_UNKNOWN",
                "Невозможно доказать остановку процесса контроллера.",
                {"reasonCode": observation},
            )
        remaining = deadline - clock()
        if remaining <= 0:
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CONTROLLER_STOP_TIMEOUT",
                "Контроллер не остановился за отведённое время.",
                {"pid": pid},
            )
        pause(min(0.05, remaining))


def _observe_controller_identity_v2(
    observer: Callable[[int, str], str],
    pid: int,
    marker: str,
) -> str:
    try:
        observation = observer(pid, marker)
    except Exception as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Невозможно проверить системную идентичность контроллера.",
            {},
        ) from exc
    if observation not in {"EXACT", "ABSENT", "REUSED", "UNVERIFIABLE"}:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_STATE_UNKNOWN",
            "Проверка контроллера вернула неизвестное состояние.",
            {},
        )
    return observation


@contextmanager
def exclusive_controller_lock_v2(proven: ProvenAdminStateV2) -> Iterator[None]:
    path = proven.binding.state_home / "controller.lock"
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "CONTROLLER_LOCK_UNAVAILABLE",
            "Файл блокировки контроллера недоступен.",
            {},
        ) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CONTROLLER_LOCK_INVALID",
                "Файл блокировки контроллера не прошёл проверку свойств.",
                {},
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AdminV2Error(
                EXIT_UNSAFE,
                "CONTROLLER_ACTIVE",
                "Контроллер удерживает рабочую блокировку.",
                {},
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _private_database(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Файл базы версии 2 недоступен.",
            {"reasonCode": "DATABASE_UNAVAILABLE"},
        ) from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Файл базы версии 2 не прошёл проверку свойств.",
            {"reasonCode": "DATABASE_INVALID"},
        )
    return info


def _require_installer_receipt(config: AdminConfigV2) -> dict[str, Any]:
    try:
        value = _read_private_json(config.installer_receipt_path)
    except FileNotFoundError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Состояние версии 2 не подтверждено.",
            {"reasonCode": "INSTALLER_RECEIPT_MISSING"},
        ) from exc
    except OSError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Состояние версии 2 не подтверждено.",
            {"reasonCode": "INSTALLER_RECEIPT_UNAVAILABLE"},
        ) from exc
    except ValueError as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Состояние версии 2 не подтверждено.",
            {"reasonCode": "INSTALLER_RECEIPT_INVALID"},
        ) from exc
    if not _installer_receipt_valid(value, codex_home=config.codex_home):
        raise AdminV2Error(
            EXIT_UNSAFE,
            "V2_STATE_UNCONFIRMED",
            "Состояние версии 2 не подтверждено.",
            {"reasonCode": "INSTALLER_RECEIPT_INVALID"},
        )
    return dict(value)


def _verify_receipt_binding(
    config: AdminConfigV2,
    receipt: Mapping[str, Any],
    expected_codex_binary: Path,
    binding: GatewayRuntimeBindingV2,
) -> None:
    marketplace_link = config.layout.marketplace_link
    expected_plugin_bin = (
        marketplace_link / "plugins" / "codex-smart-subagents" / "bin"
    )
    if (
        receipt["activationId"] != binding.activation_id
        or receipt["stateHome"] != str(binding.state_home)
        or receipt["marketplacePath"] != str(marketplace_link)
        or receipt["registeredMarketplacePath"] != str(binding.marketplace_path)
        or receipt["codexBinary"] != str(expected_codex_binary)
        or marketplace_link.resolve(strict=True)
        != binding.marketplace_path.resolve(strict=True)
    ):
        raise ValueError("installer receipt binding differs")
    observed_names: set[str] = set()
    for raw in receipt["links"]:
        link = Path(str(raw["path"]))
        target = Path(str(raw["target"]))
        name = link.name
        if name not in {"codex-smart", "codex-smart-subagents-admin"}:
            raise ValueError("installer receipt contains another link")
        if target != expected_plugin_bin / name or name in observed_names:
            raise ValueError("installer receipt link target differs")
        info = link.lstat()
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or os.readlink(link) != str(target)
        ):
            raise ValueError("installed operator link differs")
        target_info = target.lstat()
        expected_resolved_parent = (
            binding.marketplace_path / "plugins" / "codex-smart-subagents" / "bin"
        ).resolve(strict=True)
        if (
            not stat.S_ISREG(target_info.st_mode)
            or target_info.st_uid != os.getuid()
            or not os.access(target, os.X_OK)
            or target.resolve(strict=True).parent != expected_resolved_parent
        ):
            raise ValueError("installed operator target differs")
        observed_names.add(name)
    if observed_names != {"codex-smart", "codex-smart-subagents-admin"}:
        raise ValueError("installer receipt links are incomplete")


def _read_private_json(path: Path) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > 64 * 1024
        ):
            raise ValueError("неверные свойства закрытого файла")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise ValueError("закрытый файл изменился при чтении")
        return json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("закрытый файл не содержит JSON") from exc
    finally:
        os.close(descriptor)


def _installer_receipt_valid(value: object, *, codex_home: Path) -> bool:
    if type(value) is not dict or set(value) != _RECEIPT_KEYS:
        return False
    links = value.get("links")
    paths: list[str] = []
    targets: list[str] = []
    if type(links) is not list or len(links) != 2:
        return False
    for link in links:
        if (
            type(link) is not dict
            or set(link) != {"path", "target"}
            or not _absolute_text(link.get("path"))
            or not _absolute_text(link.get("target"))
        ):
            return False
        paths.append(str(link["path"]))
        targets.append(str(link["target"]))
    return bool(
        value.get("schemaVersion") == 2
        and value.get("kind") == "codex-smart-installer-receipt/v2"
        and isinstance(value.get("sourceDigest"), str)
        and _SHA256.fullmatch(str(value["sourceDigest"]))
        and isinstance(value.get("installationId"), str)
        and _INSTALLATION_ID.fullmatch(str(value["installationId"]))
        and isinstance(value.get("activationId"), str)
        and _ACTIVATION_ID.fullmatch(str(value["activationId"]))
        and value.get("codexHome") == str(codex_home)
        and _absolute_text(value.get("codexBinary"))
        and _absolute_text(value.get("stateHome"))
        and _absolute_text(value.get("marketplacePath"))
        and _absolute_text(value.get("registeredMarketplacePath"))
        and len(set(paths)) == 2
        and len(set(targets)) == 2
        and value.get("marketplaceName") == "codex-settings-adaptive"
        and value.get("pluginId")
        == "codex-smart-subagents@codex-settings-adaptive"
        and value.get("extensions") == {}
    )


def _absolute_text(value: object) -> bool:
    return bool(
        type(value) is str
        and value.startswith("/")
        and "\x00" not in value
        and len(value.encode("utf-8")) <= 4096
    )


__all__ = [
    "AdminConfigV2",
    "AdminV2Error",
    "ControllerStopReportV2",
    "ProvenAdminStateV2",
    "exclusive_controller_lock_v2",
    "load_proven_state_v2",
    "open_readonly_database_v2",
    "open_runtime_store_v2",
    "probe_live_controller_v2",
    "require_controller_stopped_v2",
    "stop_live_controller_v2",
]
