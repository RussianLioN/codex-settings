"""Привязка события хода и MCP к доказанной активации версии 2."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from codex_smart_subagents.activation_gateway_v2 import (
    ActivationResolver,
    GatewayDecision,
    GatewayLayout,
    GatewayRuntimeBindingV2,
    GatewayState,
)
from codex_smart_subagents.canonical_json import (
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents import finite_file_lock_v2, operation_deadline_v2
from codex_smart_subagents.state_store_v2 import RequestContextV2
from codex_smart_subagents.mcp_runtime_proof_v2 import (
    USER_MCP_POLICY_PROOF_ENV_V2,
    require_bundled_mcp_manifest_v2,
    verify_mcp_runtime_attestation_v2,
    verify_user_mcp_policy_proof_v2,
)
from integration_runtime import (
    HOOK_TOTAL_BUDGET_SECONDS,
    IntegrationError,
    SESSION_PATTERN,
    request_context,
)


MAX_RECORD_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_BASE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_RECORD_FIELDS = {
    "schemaVersion",
    "shellSessionId",
    "sessionId",
    "turnId",
    "codexHome",
    "repoRoot",
    "baseSha",
    "worktreeFingerprint",
    "continuationCount",
    "recordFingerprint",
}
_LEGACY_RECORD_FIELDS = _RECORD_FIELDS - {"continuationCount"}
_DELEGATE_TERMINAL_ROUTE_STATES = frozenset(
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
_DELEGATE_PENDING_ROUTE_STATES = frozenset(
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
    }
)


class IntegrationV2Error(RuntimeError):
    """Санитизированная ошибка границы интеграции версии 2."""


@dataclass(frozen=True)
class IntegrationConfigV2:
    shell_session_id: str
    codex_home: Path
    state_home: Path
    gateway_path: Path
    launch_activation_id: str
    launch_gate_fingerprint: str
    catalog_path: Path

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "IntegrationConfigV2":
        if environ.get("CODEX_SMART_LAUNCHER_ACTIVE") != "1":
            raise IntegrationV2Error("шлюз умного режима версии 2 не активен")
        shell_session_id = environ.get("CODEX_ADAPTIVE_SESSION_ID", "")
        if SESSION_PATTERN.fullmatch(shell_session_id) is None:
            raise IntegrationV2Error("идентификатор сеанса оболочки неверен")
        activation_id = environ.get("CODEX_SMART_ACTIVATION_ID", "")
        gate_fingerprint = environ.get("CODEX_SMART_GATE_FINGERPRINT", "")
        if _ACTIVATION_ID.fullmatch(activation_id) is None:
            raise IntegrationV2Error("идентификатор активации неверен")
        if _SHA256.fullmatch(gate_fingerprint) is None:
            raise IntegrationV2Error("отпечаток шлюза активации неверен")

        codex_home = _absolute_directory(
            environ.get("CODEX_HOME", ""),
            "CODEX_HOME",
            private=False,
        )
        state_home = _absolute_directory(
            environ.get("CODEX_SMART_STATE_HOME", ""),
            "CODEX_SMART_STATE_HOME",
            private=True,
        )
        gateway_path = _absolute_file(
            environ.get("CODEX_SMART_GATEWAY_PATH", ""),
            "CODEX_SMART_GATEWAY_PATH",
            executable=True,
        )
        catalog_path = _absolute_file(
            environ.get("CODEX_ADAPTIVE_CATALOG", ""),
            "CODEX_ADAPTIVE_CATALOG",
            executable=False,
        )
        return cls(
            shell_session_id=shell_session_id,
            codex_home=codex_home,
            state_home=state_home,
            gateway_path=gateway_path,
            launch_activation_id=activation_id,
            launch_gate_fingerprint=gate_fingerprint,
            catalog_path=catalog_path,
        )


@dataclass(frozen=True)
class HookTurnContextV2:
    shell_session_id: str
    session_id: str
    turn_id: str
    codex_home: str
    repo_root: str
    base_sha: str
    worktree_fingerprint: str
    continuation_count: int = 0

    def __post_init__(self) -> None:
        if SESSION_PATTERN.fullmatch(self.shell_session_id) is None:
            raise IntegrationV2Error("идентификатор сеанса оболочки неверен")
        for value, name in (
            (self.session_id, "sessionId"),
            (self.turn_id, "turnId"),
            (self.codex_home, "codexHome"),
            (self.repo_root, "repoRoot"),
        ):
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
                raise IntegrationV2Error(f"поле {name} неверно")
        for value, name in (
            (self.codex_home, "codexHome"),
            (self.repo_root, "repoRoot"),
        ):
            if not Path(value).is_absolute():
                raise IntegrationV2Error(f"поле {name} не является абсолютным путём")
        if _BASE_SHA.fullmatch(self.base_sha) is None:
            raise IntegrationV2Error("baseSha неверен")
        if _SHA256.fullmatch(self.worktree_fingerprint) is None:
            raise IntegrationV2Error("worktreeFingerprint неверен")
        if (
            type(self.continuation_count) is not int
            or not 0 <= self.continuation_count <= 2
        ):
            raise IntegrationV2Error("continuationCount неверен")

    def value_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "shellSessionId": self.shell_session_id,
            "sessionId": self.session_id,
            "turnId": self.turn_id,
            "codexHome": self.codex_home,
            "repoRoot": self.repo_root,
            "baseSha": self.base_sha,
            "worktreeFingerprint": self.worktree_fingerprint,
            "continuationCount": self.continuation_count,
        }

    def value(self) -> dict[str, Any]:
        projection = self.value_without_fingerprint()
        return {
            **projection,
            "recordFingerprint": domain_fingerprint(
                "codex-smart/hook-turn-context/v2",
                projection,
            ),
        }

    @classmethod
    def from_value(cls, value: Any) -> "HookTurnContextV2":
        if type(value) is not dict:
            raise IntegrationV2Error("запись контекста хода имеет неверную форму")
        fields = frozenset(value)
        if fields not in {
            frozenset(_RECORD_FIELDS),
            frozenset(_LEGACY_RECORD_FIELDS),
        }:
            raise IntegrationV2Error("запись контекста хода имеет неверную форму")
        if value["schemaVersion"] != 2:
            raise IntegrationV2Error("версия записи контекста хода не поддерживается")
        record = cls(
            shell_session_id=value["shellSessionId"],
            session_id=value["sessionId"],
            turn_id=value["turnId"],
            codex_home=value["codexHome"],
            repo_root=value["repoRoot"],
            base_sha=value["baseSha"],
            worktree_fingerprint=value["worktreeFingerprint"],
            continuation_count=value.get("continuationCount", 0),
        )
        if "continuationCount" in value:
            expected_fingerprint = record.value()["recordFingerprint"]
        else:
            projection = record.value_without_fingerprint()
            projection.pop("continuationCount")
            expected_fingerprint = domain_fingerprint(
                "codex-smart/hook-turn-context/v2",
                projection,
            )
        if value["recordFingerprint"] != expected_fingerprint:
            raise IntegrationV2Error("отпечаток записи контекста хода не совпал")
        return record


class TurnContextStoreV2:
    """Частная однофайловая передача контекста от события к MCP-процессу."""

    def __init__(self, config: IntegrationConfigV2) -> None:
        self.config = config
        self.directory = config.state_home / "coordination"
        token = hashlib.sha256(config.shell_session_id.encode("utf-8")).hexdigest()[:32]
        self.path = self.directory / f"turn-{token}.json"
        self.lock_path = self.directory / f"turn-{token}.lock"

    def save(self, record: HookTurnContextV2) -> None:
        if record.shell_session_id != self.config.shell_session_id:
            raise IntegrationV2Error("запись принадлежит другому сеансу оболочки")
        if Path(record.codex_home) != self.config.codex_home:
            raise IntegrationV2Error("запись относится к другому CODEX_HOME")
        self._prepare_directory()
        descriptor = self._open_lock()
        acquired = False
        try:
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=True,
                    timeout_seconds=HOOK_TOTAL_BUDGET_SECONDS,
                    timeout_code="TURN_CONTEXT_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise IntegrationV2Error(str(error)) from error
            acquired = True
            encoded = canonical_json_bytes(record.value())
            if len(encoded) > MAX_RECORD_BYTES:
                raise IntegrationV2Error("запись контекста хода превышает предел")
            temporary = self.directory / (
                f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}"
            )
            output = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.write(output, encoded)
                os.fsync(output)
            finally:
                os.close(output)
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            _fsync_directory(self.directory)
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def load(self) -> HookTurnContextV2:
        self._prepare_directory()
        descriptor = self._open_lock()
        acquired = False
        try:
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=False,
                    timeout_seconds=HOOK_TOTAL_BUDGET_SECONDS,
                    timeout_code="TURN_CONTEXT_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise IntegrationV2Error(str(error)) from error
            acquired = True
            raw = _read_private_file(self.path)
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrationV2Error("запись контекста хода повреждена") from exc
        record = HookTurnContextV2.from_value(value)
        if raw != canonical_json_bytes(value):
            raise IntegrationV2Error("запись контекста хода неканонична")
        if record.shell_session_id != self.config.shell_session_id:
            raise IntegrationV2Error("запись принадлежит другому сеансу оболочки")
        if Path(record.codex_home) != self.config.codex_home:
            raise IntegrationV2Error("запись относится к другому CODEX_HOME")
        return record

    def update(
        self,
        mutator: Callable[[HookTurnContextV2], HookTurnContextV2],
        *,
        deadline: float | None = None,
    ) -> HookTurnContextV2:
        """Атомарно обновляет счётчик и другие поля одного хода."""

        if not callable(mutator):
            raise IntegrationV2Error("обновитель контекста хода неверен")
        if deadline is None:
            deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS
        _remaining_hook_budget(deadline)
        self._prepare_directory()
        descriptor = self._open_lock()
        acquired = False
        try:
            remaining = _remaining_hook_budget(deadline)
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=True,
                    timeout_seconds=remaining,
                    timeout_code="TURN_CONTEXT_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise IntegrationV2Error(str(error)) from error
            acquired = True
            _remaining_hook_budget(deadline)
            current = self._decode(_read_private_file(self.path))
            _remaining_hook_budget(deadline)
            updated = mutator(current)
            _remaining_hook_budget(deadline)
            if not isinstance(updated, HookTurnContextV2):
                raise IntegrationV2Error("обновитель вернул неверную запись")
            self._validate_identity(updated)
            if updated != current:
                self._write_unlocked(updated)
                _remaining_hook_budget(deadline)
            return updated
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _decode(self, raw: bytes) -> HookTurnContextV2:
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrationV2Error("запись контекста хода повреждена") from exc
        record = HookTurnContextV2.from_value(value)
        if raw != canonical_json_bytes(value):
            raise IntegrationV2Error("запись контекста хода неканонична")
        self._validate_identity(record)
        return record

    def _validate_identity(self, record: HookTurnContextV2) -> None:
        if record.shell_session_id != self.config.shell_session_id:
            raise IntegrationV2Error("запись принадлежит другому сеансу оболочки")
        if Path(record.codex_home) != self.config.codex_home:
            raise IntegrationV2Error("запись относится к другому CODEX_HOME")

    def _write_unlocked(self, record: HookTurnContextV2) -> None:
        encoded = canonical_json_bytes(record.value())
        if len(encoded) > MAX_RECORD_BYTES:
            raise IntegrationV2Error("запись контекста хода превышает предел")
        temporary = self.directory / (
            f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        )
        output = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(output, encoded)
            os.fsync(output)
        finally:
            os.close(output)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)
        _fsync_directory(self.directory)

    def _prepare_directory(self) -> None:
        _verify_private_directory(self.config.state_home)
        if self.directory.exists() or self.directory.is_symlink():
            _verify_private_directory(self.directory)
        else:
            self.directory.mkdir(mode=0o700)
            _verify_private_directory(self.directory)

    def _open_lock(self) -> int:
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            os.close(descriptor)
            raise IntegrationV2Error("небезопасная блокировка контекста хода")
        return descriptor


ResolverFactory = Callable[[IntegrationConfigV2], Any]


class FreshActivationProviderV2:
    """При каждом обращении повторяет полный READY-проход шлюза."""

    def __init__(
        self,
        config: IntegrationConfigV2,
        *,
        resolver_factory: ResolverFactory | None = None,
    ) -> None:
        self.config = config
        self.store = TurnContextStoreV2(config)
        self.resolver_factory = resolver_factory or self._default_resolver

    def request_context(self) -> RequestContextV2:
        record = self.store.load()
        decision = self._decision()
        binding = decision.runtime_binding
        assert binding is not None
        return RequestContextV2(
            shell_session_id=record.shell_session_id,
            session_id=record.session_id,
            turn_id=record.turn_id,
            codex_home=record.codex_home,
            repo_root=record.repo_root,
            base_sha=record.base_sha,
            worktree_fingerprint=record.worktree_fingerprint,
            activation_fingerprint=binding.activation_fingerprint,
            compatibility_fingerprint=binding.compatibility_fingerprint,
            issued_control_epoch=binding.control_epoch,
        )

    def activation_gate(self) -> dict[str, Any]:
        decision = self._decision()
        return copy.deepcopy(dict(decision.activation_gate or {}))

    def runtime_binding(self) -> GatewayRuntimeBindingV2:
        decision = self._decision()
        binding = decision.runtime_binding
        assert binding is not None
        return binding

    def _decision(self) -> GatewayDecision:
        try:
            resolver = self.resolver_factory(self.config)
            decision = resolver.resolve()
        except Exception as exc:
            raise IntegrationV2Error("не удалось повторно доказать активацию") from exc
        if (
            not isinstance(decision, GatewayDecision)
            or decision.state is not GatewayState.READY
            or decision.runtime_binding is None
        ):
            raise IntegrationV2Error("активация версии 2 больше не готова")
        if (
            decision.activation_id != self.config.launch_activation_id
            or decision.gate_fingerprint != self.config.launch_gate_fingerprint
        ):
            raise IntegrationV2Error("активация изменилась после запуска корневого сеанса")
        binding = decision.runtime_binding
        if (
            binding.state_home != self.config.state_home
            or decision.catalog_path != self.config.catalog_path
        ):
            raise IntegrationV2Error("пути доказанной активации изменились после запуска")
        return decision

    @staticmethod
    def _default_resolver(config: IntegrationConfigV2) -> ActivationResolver:
        return ActivationResolver(
            layout=GatewayLayout.for_codex_home(config.codex_home),
            wrapper=config.gateway_path,
        )


def capture_hook_turn_context_v2(
    payload: dict[str, Any],
    config: IntegrationConfigV2,
    *,
    deadline: float | None = None,
) -> HookTurnContextV2:
    """Использует тот же ограниченный снимок Git, что и проверенный путь v1."""

    try:
        legacy_config = _LegacyConfigAdapter(config)
        context = request_context(payload, legacy_config, deadline=deadline)
    except (IntegrationError, OSError, ValueError) as exc:
        raise IntegrationV2Error("не удалось зафиксировать контекст хода") from exc
    return HookTurnContextV2(
        shell_session_id=context.shell_session_id,
        session_id=context.session_id,
        turn_id=context.turn_id,
        codex_home=context.codex_home,
        repo_root=context.repo_root,
        base_sha=context.base_sha,
        worktree_fingerprint=context.worktree_fingerprint,
    )


def require_mcp_contract_v2(plugin_root: Path) -> None:
    """Доказывает, что установленный MCP-сервер обязателен и полон."""

    try:
        require_bundled_mcp_manifest_v2(Path(plugin_root))
    except Exception as exc:
        raise IntegrationV2Error("обязательный MCP не доказал полный договор") from exc


def require_live_mcp_runtime_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
) -> None:
    """Требует неизменную base policy и живой bundled MCP этого сеанса."""

    try:
        verify_user_mcp_policy_proof_v2(
            config.codex_home,
            environ.get(USER_MCP_POLICY_PROOF_ENV_V2),
        )
        verify_mcp_runtime_attestation_v2(environ)
    except Exception as exc:
        raise IntegrationV2Error(
            "живой bundled MCP текущего сеанса не доказан"
        ) from exc


def require_live_controller_v2(
    config: IntegrationConfigV2,
    *,
    deadline: float,
    resolver_factory: ResolverFactory | None = None,
) -> None:
    """Повторяет полный READY-проход контроллера в общем сроке хука."""

    remaining = _remaining_hook_budget(deadline)
    current = operation_deadline_v2.current_operation_deadline_v2()
    operation_deadline = current or operation_deadline_v2.OperationDeadlineV2.start(
        operation="user-prompt-controller-check",
        timeout_seconds=remaining,
        timeout_code="USER_PROMPT_CONTROLLER_DEADLINE",
    )
    try:
        with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
            operation_deadline.checkpoint()
            FreshActivationProviderV2(
                config,
                resolver_factory=resolver_factory,
            ).runtime_binding()
            operation_deadline.checkpoint()
        _remaining_hook_budget(deadline)
    except Exception as exc:
        raise IntegrationV2Error(
            "живой контроллер текущей активации не доказан"
        ) from exc


def durable_smart_plan_exists_v2(
    config: IntegrationConfigV2,
    record: HookTurnContextV2,
    *,
    resolver_factory: ResolverFactory | None = None,
    deadline: float | None = None,
) -> bool:
    """Совместимый ответ о наличии маршрута для доказанного хода."""

    return (
        durable_smart_turn_state_v2(
            config,
            record,
            resolver_factory=resolver_factory,
            deadline=deadline,
        )
        != "MISSING"
    )


def durable_smart_turn_state_v2(
    config: IntegrationConfigV2,
    record: HookTurnContextV2,
    *,
    resolver_factory: ResolverFactory | None = None,
    deadline: float | None = None,
) -> str:
    """Читает полный исход умного хода из доказанной базы."""

    if deadline is None:
        deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS
    _remaining_hook_budget(deadline)
    provider = FreshActivationProviderV2(
        config,
        resolver_factory=resolver_factory,
    )
    operation_deadline = (
        operation_deadline_v2.current_operation_deadline_v2()
    )
    if operation_deadline is None:
        operation_deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="stop-smart-turn-check",
            timeout_seconds=_remaining_hook_budget(deadline),
            timeout_code="STOP_SMART_PLAN_DEADLINE",
        )
    with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
        operation_deadline.checkpoint()
        database_path = provider.runtime_binding().database_path
        operation_deadline.checkpoint()
    _remaining_hook_budget(deadline)
    before = _private_database_identity(database_path)
    try:
        timeout = min(0.15, _remaining_hook_budget(deadline))
        connection = sqlite3.connect(
            database_path.as_uri() + "?mode=ro",
            uri=True,
            timeout=timeout,
        )
        try:
            connection.execute("pragma query_only=on")
            connection.set_progress_handler(
                lambda: int(time.monotonic() >= deadline),
                1_000,
            )
            rows = connection.execute(
                "select disposition,state from routes "
                "where shell_session_id=? and session_id=? and turn_id=? limit 2",
                (
                    record.shell_session_id,
                    record.session_id,
                    record.turn_id,
                ),
            ).fetchall()
            _remaining_hook_budget(deadline)
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise IntegrationV2Error("не удалось прочитать состояние smart_plan") from exc
    after = _private_database_identity(database_path)
    _remaining_hook_budget(deadline)
    if after != before:
        raise IntegrationV2Error("база smart_plan изменилась при проверке")
    if not rows:
        return "MISSING"
    if len(rows) != 1:
        raise IntegrationV2Error("ход содержит несколько маршрутов smart_plan")
    disposition, state = rows[0]
    if type(disposition) is not str or type(state) is not str:
        raise IntegrationV2Error("состояние smart_plan имеет неверный тип")
    normalized_disposition = disposition.lower()
    if normalized_disposition == "direct" and state == "DIRECT":
        return "DIRECT"
    if normalized_disposition == "clarify" and state == "CLARIFY":
        return "CLARIFY"
    if normalized_disposition != "delegate":
        raise IntegrationV2Error("решение smart_plan расходится с маршрутом")
    if state in _DELEGATE_TERMINAL_ROUTE_STATES:
        return "DELEGATE_TERMINAL"
    if state in _DELEGATE_PENDING_ROUTE_STATES:
        return "DELEGATE_PENDING"
    raise IntegrationV2Error("состояние делегированного маршрута неизвестно")


@dataclass(frozen=True)
class _LegacyConfigAdapter:
    shell_session_id: str
    codex_home: str

    def __init__(self, config: IntegrationConfigV2) -> None:
        object.__setattr__(self, "shell_session_id", config.shell_session_id)
        object.__setattr__(self, "codex_home", str(config.codex_home))


def _absolute_directory(raw: str, name: str, *, private: bool) -> Path:
    if not raw:
        raise IntegrationV2Error(f"{name} не задан")
    path = Path(raw)
    if not path.is_absolute():
        raise IntegrationV2Error(f"{name} должен быть абсолютным путём")
    try:
        path = path.resolve(strict=True)
        info = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error(f"{name} недоступен") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise IntegrationV2Error(f"{name} не является каталогом текущего пользователя")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise IntegrationV2Error(f"{name} должен иметь права 0700")
    return path


def _absolute_file(raw: str, name: str, *, executable: bool) -> Path:
    if not raw:
        raise IntegrationV2Error(f"{name} не задан")
    path = Path(raw)
    if not path.is_absolute():
        raise IntegrationV2Error(f"{name} должен быть абсолютным путём")
    try:
        path = path.resolve(strict=True)
        info = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error(f"{name} недоступен") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or (executable and not os.access(path, os.X_OK))
    ):
        raise IntegrationV2Error(f"{name} не является допустимым файлом")
    return path


def _verify_private_directory(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error("частный каталог состояния недоступен") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise IntegrationV2Error("частный каталог состояния небезопасен")


def _read_private_file(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error("запись контекста хода отсутствует") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > MAX_RECORD_BYTES
    ):
        raise IntegrationV2Error("запись контекста хода небезопасна")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise IntegrationV2Error("запись контекста хода изменилась при чтении")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_RECORD_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RECORD_BYTES:
                raise IntegrationV2Error("запись контекста хода превышает предел")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _private_database_identity(path: Path) -> tuple[int, int]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error("доказанная база smart_plan недоступна") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise IntegrationV2Error("доказанная база smart_plan неверна")
    return info.st_dev, info.st_ino


def _remaining_hook_budget(deadline: float) -> float:
    if type(deadline) not in {int, float}:
        raise IntegrationV2Error("абсолютный срок хука неверен")
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise IntegrationV2Error("истёк абсолютный срок хука")
    return remaining


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "FreshActivationProviderV2",
    "HOOK_TOTAL_BUDGET_SECONDS",
    "HookTurnContextV2",
    "IntegrationConfigV2",
    "IntegrationV2Error",
    "TurnContextStoreV2",
    "capture_hook_turn_context_v2",
    "durable_smart_plan_exists_v2",
    "durable_smart_turn_state_v2",
    "require_mcp_contract_v2",
    "require_live_controller_v2",
    "require_live_mcp_runtime_v2",
]
