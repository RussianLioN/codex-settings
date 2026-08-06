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
    refresh_activation_journal_absence_v2,
    require_pinned_controller_health_v2,
)
from codex_smart_subagents.canonical_json import (
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents import finite_file_lock_v2, operation_deadline_v2
from codex_smart_subagents.state_store_v2 import (
    RequestContextV2,
    canonical_activation_gate_v2,
)
from codex_smart_subagents.schema_projection import (
    APPLICATION_ID,
    SchemaProjectionError,
    database_schema_fingerprint,
)
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
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_CONTROLLER_INSTANCE_ID = re.compile(r"^ci2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_CONTROLLER_RELEASE = "0.2.0"
_CONTROLLER_NAMESPACE = "codex-smart-subagents-v2"
_LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)
_STOP_MANIFEST_FIELDS = {
    "schemaVersion",
    "installationId",
    "release",
    "pluginId",
    "marketplaceName",
    "stateHome",
    "sourceLocator",
    "codexSnapshot",
    "activeActivation",
    "previousActivation",
    "interfaceEvidence",
    "routingPolicyFingerprint",
    "bundledCatalogFingerprint",
    "artifacts",
    "originalBackup",
    "lastCommittedOperation",
    "databaseSchemaVersion",
    "extensions",
}
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
class PinnedResumeBindingV2:
    """Минимальная доказанная привязка для начального хука сеанса."""

    database_path: Path
    compatibility_fingerprint: str


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

    def load(self, *, deadline: float | None = None) -> HookTurnContextV2:
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
                    exclusive=False,
                    timeout_seconds=remaining,
                    timeout_code="TURN_CONTEXT_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise IntegrationV2Error(str(error)) from error
            acquired = True
            _remaining_hook_budget(deadline)
            raw = _read_private_file(self.path)
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        _remaining_hook_budget(deadline)
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

    def runtime_binding(
        self,
        *,
        deadline: float | None = None,
    ) -> GatewayRuntimeBindingV2:
        if deadline is None:
            decision = self._decision()
        else:
            operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
            if operation_deadline is None:
                operation_deadline = operation_deadline_v2.OperationDeadlineV2.start(
                    operation="fresh-activation-resolve",
                    timeout_seconds=_remaining_hook_budget(deadline),
                    timeout_code="FRESH_ACTIVATION_DEADLINE",
                )
            with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
                operation_deadline.checkpoint()
                decision = self._decision()
                operation_deadline.checkpoint()
            _remaining_hook_budget(deadline)
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


def require_current_user_mcp_policy_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
) -> None:
    """Проверяет неизменную политику до ленивого запуска MCP в Codex."""

    try:
        verify_user_mcp_policy_proof_v2(
            config.codex_home,
            environ.get(USER_MCP_POLICY_PROOF_ENV_V2),
        )
    except Exception as exc:
        raise IntegrationV2Error(
            "пользовательская политика MCP изменилась после запуска"
        ) from exc


def require_live_mcp_runtime_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
) -> None:
    """Требует неизменную base policy и живой bundled MCP этого сеанса."""

    require_current_user_mcp_policy_v2(config, environ)
    try:
        verify_mcp_runtime_attestation_v2(environ)
    except Exception as exc:
        raise IntegrationV2Error(
            "живой bundled MCP текущего сеанса не доказан"
        ) from exc


def require_live_controller_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
    *,
    deadline: float,
    absence_checker=refresh_activation_journal_absence_v2,
    health_checker=require_pinned_controller_health_v2,
) -> None:
    """Проверяет закреплённый шлюз и живой контроллер в коротком сроке хука.

    Полный READY-проход выполняется загрузчиком перед ``execve`` и повторяется
    поставщиком контроллера непосредственно перед каждой командой MCP.
    """

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
            gate = _launch_gate_from_environ_v2(config, environ)
            layout = GatewayLayout.for_codex_home(config.codex_home)
            absence_checker(
                gate["journalAbsenceProof"],
                expected_journal=layout.journal_path,
            )
            operation_deadline.checkpoint()
            health_checker(
                codex_home=config.codex_home,
                state_home=config.state_home,
                activation_id=config.launch_activation_id,
            )
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


def durable_stop_smart_turn_state_v2(
    config: IntegrationConfigV2,
    record: HookTurnContextV2,
    *,
    environ: Mapping[str, str],
    deadline: float | None = None,
    absence_checker: Callable[..., Any] | None = None,
    health_checker: Callable[..., Any] | None = None,
) -> str:
    """Читает состояние Stop через закреплённый запуск без полного resolve()."""

    if deadline is None:
        deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS
    (
        database_path,
        gate,
        layout,
        absence_checker,
        health_checker,
        _,
    ) = _pinned_stop_database_path_v2(
        config,
        environ,
        deadline=deadline,
        absence_checker=absence_checker,
        health_checker=health_checker,
    )
    route_state = _route_state_from_database_v2(
        database_path,
        record,
        deadline=deadline,
    )
    _require_stop_transition_guard_v2(
        config,
        gate=gate,
        layout=layout,
        absence_checker=absence_checker,
        health_checker=health_checker,
    )
    _remaining_hook_budget(deadline)
    return route_state


def pinned_resume_binding_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
    *,
    deadline: float,
) -> PinnedResumeBindingV2:
    """Доказывает закреплённую базу без ожидания живого контроллера.

    SessionStart только готовит аренду и не разрешает работу с маршрутом.
    Живой контроллер повторно и обязательно проверяется UserPromptSubmit до
    привязки первого хода, поэтому сетевое обращение здесь создавало лишь
    недетерминированный риск исчерпать двухсекундный срок обработчика.
    """

    database_path, _, _, _, _, pinned = _pinned_stop_database_path_v2(
        config,
        environ,
        deadline=deadline,
        absence_checker=None,
        health_checker=_defer_resume_controller_health_v2,
    )
    return PinnedResumeBindingV2(
        database_path=database_path,
        compatibility_fingerprint=pinned["compatibility_fingerprint"],
    )


def _defer_resume_controller_health_v2(**_kwargs: object) -> None:
    """Откладывает живую проверку до обязательного UserPromptSubmit."""


def _pinned_stop_database_path_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
    *,
    deadline: float,
    absence_checker: Callable[..., Any] | None,
    health_checker: Callable[..., Any] | None,
) -> tuple[
    Path,
    dict[str, Any],
    GatewayLayout,
    Callable[..., Any],
    Callable[..., Any],
    dict[str, str],
]:
    _remaining_hook_budget(deadline)
    if absence_checker is None:
        absence_checker = refresh_activation_journal_absence_v2
    if health_checker is None:
        health_checker = require_pinned_controller_health_v2
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    if operation_deadline is None:
        operation_deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="stop-smart-turn-check",
            timeout_seconds=_remaining_hook_budget(deadline),
            timeout_code="STOP_SMART_PLAN_DEADLINE",
        )
    try:
        with operation_deadline_v2.scoped_current_deadline_v2(operation_deadline):
            gate = _launch_gate_from_environ_v2(config, environ)
            layout = GatewayLayout.for_codex_home(config.codex_home)
            operation_deadline.checkpoint()
            absence_checker(
                gate["journalAbsenceProof"],
                expected_journal=layout.journal_path,
            )
            operation_deadline.checkpoint()
            health_checker(
                codex_home=config.codex_home,
                state_home=config.state_home,
                activation_id=config.launch_activation_id,
            )
            operation_deadline.checkpoint()
            manifest = _read_private_json_document_v2(
                layout.manifest_path,
                error="манифест закреплённой активации недоступен",
            )
            pinned = _manifest_pinned_bindings_v2(
                config,
                manifest,
                gate=gate,
                layout=layout,
            )
            receipt = _read_pinned_commit_receipt_v2(
                layout,
                manifest=manifest,
            )
            database_id = pinned["database_id"]
            database_path = (
                config.state_home
                / "databases"
                / database_id
                / "smart-subagents.sqlite3"
            )
            database_binding = _verify_pinned_database_rows_v2(
                config,
                database_path,
                pinned=pinned,
                deadline=deadline,
            )
            _verify_pinned_commit_receipt_v2(
                receipt,
                manifest=manifest,
                gate=gate,
                layout=layout,
                pinned=pinned,
                database_binding=database_binding,
            )
            operation_deadline.checkpoint()
    except Exception as exc:
        raise IntegrationV2Error(
            "закреплённая база smart_plan текущей активации не доказана"
        ) from exc
    _remaining_hook_budget(deadline)
    return database_path, gate, layout, absence_checker, health_checker, pinned


def _require_stop_transition_guard_v2(
    config: IntegrationConfigV2,
    *,
    gate: Mapping[str, Any],
    layout: GatewayLayout,
    absence_checker: Callable[..., Any],
    health_checker: Callable[..., Any],
) -> None:
    """Повторно доказывает, что установка не сменилась после чтения базы."""

    try:
        absence_checker(
            gate["journalAbsenceProof"],
            expected_journal=layout.journal_path,
        )
        health_checker(
            codex_home=config.codex_home,
            state_home=config.state_home,
            activation_id=config.launch_activation_id,
        )
    except Exception as exc:
        raise IntegrationV2Error(
            "закреплённая активация изменилась после чтения smart_plan"
        ) from exc


def _launch_gate_from_environ_v2(
    config: IntegrationConfigV2,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    raw_gate = environ.get("CODEX_SMART_ACTIVATION_GATE", "")
    if (
        type(raw_gate) is not str
        or not raw_gate
        or len(raw_gate.encode("utf-8")) > MAX_RECORD_BYTES
    ):
        raise IntegrationV2Error("шлюз запуска отсутствует")
    try:
        parsed_gate = json.loads(raw_gate)
    except json.JSONDecodeError as exc:
        raise IntegrationV2Error("шлюз запуска повреждён") from exc
    if type(parsed_gate) is not dict:
        raise IntegrationV2Error("шлюз запуска имеет неверную форму")
    if canonical_json_bytes(parsed_gate).decode("utf-8") != raw_gate:
        raise IntegrationV2Error("шлюз запуска неканоничен")
    gate = canonical_activation_gate_v2(parsed_gate)
    if gate["gateFingerprint"] != config.launch_gate_fingerprint:
        raise IntegrationV2Error("отпечаток шлюза запуска изменился")
    return gate


def _manifest_pinned_bindings_v2(
    config: IntegrationConfigV2,
    manifest: Mapping[str, Any],
    *,
    gate: Mapping[str, Any],
    layout: GatewayLayout,
) -> dict[str, str]:
    if type(manifest) is not dict:
        raise IntegrationV2Error("манифест активации имеет неверную форму")
    if frozenset(manifest) != frozenset(_STOP_MANIFEST_FIELDS):
        raise IntegrationV2Error("манифест активации имеет неверную форму")
    active = manifest.get("activeActivation")
    if type(active) is not dict:
        raise IntegrationV2Error("активная активация в манифесте отсутствует")
    interface = manifest.get("interfaceEvidence")
    if type(interface) is not dict:
        raise IntegrationV2Error("доказательство интерфейса в манифесте отсутствует")
    database_id = active.get("databaseId")
    activation_fingerprint = config.launch_activation_id.removeprefix("act2_")
    compatibility_fingerprint = interface.get("compatibilityFingerprint")
    routing_policy_fingerprint = manifest.get("routingPolicyFingerprint")
    bundled_catalog_fingerprint = manifest.get("bundledCatalogFingerprint")
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("release") != _CONTROLLER_RELEASE
        or manifest.get("pluginId") != "codex-smart-subagents"
        or manifest.get("marketplaceName") != "codex-settings-adaptive"
        or manifest.get("stateHome") != str(config.state_home)
        or manifest.get("databaseSchemaVersion") != 2
        or type(manifest.get("installationId")) is not str
        or re.fullmatch(r"ins2_[0-9a-f]{32}", manifest["installationId"]) is None
        or type(manifest.get("lastCommittedOperation")) is not str
        or re.fullmatch(r"op2_[0-9a-f]{32}", manifest["lastCommittedOperation"])
        is None
        or active.get("activationId") != config.launch_activation_id
        or active.get("activationFingerprint") != activation_fingerprint
        or type(database_id) is not str
        or _DATABASE_ID.fullmatch(database_id) is None
        or type(compatibility_fingerprint) is not str
        or _SHA256.fullmatch(compatibility_fingerprint) is None
        or type(routing_policy_fingerprint) is not str
        or _SHA256.fullmatch(routing_policy_fingerprint) is None
        or type(bundled_catalog_fingerprint) is not str
        or _SHA256.fullmatch(bundled_catalog_fingerprint) is None
    ):
        raise IntegrationV2Error("манифест не совпал с закреплённым запуском")
    manifest_semantic = domain_fingerprint(
        "codex-smart/manifest-semantic/v2",
        {key: value for key, value in manifest.items() if key != "extensions"},
    )
    if gate.get("manifestSemanticFingerprint") != manifest_semantic:
        raise IntegrationV2Error("манифест не совпал с закреплённым шлюзом")
    receipt = _read_pinned_commit_receipt_v2(layout, manifest=manifest)
    if receipt.get("receiptFingerprint") != gate.get("activationReceiptFingerprint"):
        raise IntegrationV2Error("commit-квитанция не совпала с закреплённым шлюзом")
    return {
        "database_id": database_id,
        "activation_fingerprint": activation_fingerprint,
        "compatibility_fingerprint": compatibility_fingerprint,
        "routing_policy_fingerprint": routing_policy_fingerprint,
        "bundled_catalog_fingerprint": bundled_catalog_fingerprint,
    }


def _read_pinned_commit_receipt_v2(
    layout: GatewayLayout,
    *,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    receipt_path = (
        layout.receipts_root
        / manifest["installationId"]
        / f"{manifest['lastCommittedOperation']}.commit.json"
    )
    receipt = _read_private_json_document_v2(
        receipt_path,
        error="commit-квитанция закреплённой активации недоступна",
    )
    if _read_private_file(receipt_path) != canonical_json_bytes(receipt):
        raise IntegrationV2Error("commit-квитанция неканонична")
    return receipt


def _verify_pinned_database_rows_v2(
    config: IntegrationConfigV2,
    database_path: Path,
    *,
    pinned: Mapping[str, str],
    deadline: float,
) -> dict[str, Any]:
    _remaining_hook_budget(deadline)
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    if operation_deadline is None:
        operation_deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="stop-smart-plan-database-check",
            timeout_seconds=_remaining_hook_budget(deadline),
            timeout_code="STOP_SMART_PLAN_DEADLINE",
        )
    operation_deadline.checkpoint()
    before = _private_database_identity(database_path)
    connection: sqlite3.Connection | None = None
    try:
        sqlite_timeout = operation_deadline.bounded_timeout_seconds(
            local_cap_seconds=0.05
        )
        connection = sqlite3.connect(
            database_path.as_uri() + "?mode=ro",
            uri=True,
            timeout=sqlite_timeout,
        )
        connection.row_factory = sqlite3.Row
        busy_timeout_ms = operation_deadline.bounded_timeout_ms(local_cap_ms=50)
        connection.execute(f"pragma busy_timeout={busy_timeout_ms}")
        connection.set_progress_handler(
            lambda: int(
                operation_deadline.remaining_nanoseconds() <= 0
                or time.monotonic() >= deadline
            ),
            1000,
        )
        operation_deadline.checkpoint()
        connection.execute("pragma query_only=on")
        application_id = int(connection.execute("pragma application_id").fetchone()[0])
        user_version = int(connection.execute("pragma user_version").fetchone()[0])
        if application_id != APPLICATION_ID or user_version != 2:
            raise IntegrationV2Error("метаданные базы smart_plan неверны")
        operation_deadline.checkpoint()
        quick = connection.execute("pragma quick_check").fetchall()
        if [tuple(row) for row in quick] != [("ok",)]:
            raise IntegrationV2Error("quick_check базы smart_plan не прошёл")
        operation_deadline.checkpoint()
        integrity = connection.execute("pragma integrity_check").fetchall()
        if [tuple(row) for row in integrity] != [("ok",)]:
            raise IntegrationV2Error("integrity_check базы smart_plan не прошёл")
        operation_deadline.checkpoint()
        if connection.execute("pragma foreign_key_check").fetchone() is not None:
            raise IntegrationV2Error("foreign_key_check базы smart_plan не прошёл")
        operation_deadline.checkpoint()
        schema = database_schema_fingerprint(connection, version=2)
        operation_deadline.checkpoint()
        identity_rows = connection.execute("select * from database_identity").fetchall()
        controller_rows = connection.execute("select * from controller_state").fetchall()
        operation_deadline.checkpoint()
    except (
        sqlite3.Error,
        SchemaProjectionError,
        ValueError,
        operation_deadline_v2.OperationDeadlineExceededV2,
    ) as exc:
        raise IntegrationV2Error("база smart_plan не прошла проверку схемы") from exc
    finally:
        if connection is not None:
            connection.set_progress_handler(None, 0)
            connection.close()
    if len(identity_rows) != 1 or len(controller_rows) != 1:
        raise IntegrationV2Error("база smart_plan не содержит одиночной привязки")
    identity = dict(identity_rows[0])
    controller = dict(controller_rows[0])
    _verify_pinned_database_identity_row_v2(config, identity, pinned=pinned)
    if identity.get("schema_fingerprint") != schema.fingerprint:
        raise IntegrationV2Error("фактическая схема базы smart_plan расходится")
    _verify_pinned_controller_row_v2(config, controller, pinned=pinned)
    after = _private_database_identity(database_path)
    if after != before:
        raise IntegrationV2Error("база smart_plan изменилась при проверке")
    return _database_binding_projection_v2(database_path, identity, before)


def _verify_pinned_database_identity_row_v2(
    config: IntegrationConfigV2,
    identity: Mapping[str, Any],
    *,
    pinned: Mapping[str, str],
) -> None:
    required = {
        "database_id",
        "schema_version",
        "schema_fingerprint",
        "schema_artifact_sha256",
        "activation_binding_nonce",
        "activation_id",
        "activation_fingerprint",
    }
    if not required.issubset(identity):
        raise IntegrationV2Error("строка identity базы smart_plan неполна")
    if (
        identity.get("database_id") != pinned["database_id"]
        or identity.get("schema_version") != 2
        or type(identity.get("schema_fingerprint")) is not str
        or _SHA256.fullmatch(identity["schema_fingerprint"]) is None
        or type(identity.get("schema_artifact_sha256")) is not str
        or _SHA256.fullmatch(identity["schema_artifact_sha256"]) is None
        or type(identity.get("activation_binding_nonce")) is not str
        or _SHA256.fullmatch(identity["activation_binding_nonce"]) is None
        or identity.get("activation_id") != config.launch_activation_id
        or identity.get("activation_fingerprint") != pinned["activation_fingerprint"]
    ):
        raise IntegrationV2Error("привязка базы smart_plan расходится с запуском")


def _database_binding_projection_v2(
    database_path: Path,
    identity: Mapping[str, Any],
    file_identity: tuple[int, int],
) -> dict[str, Any]:
    info = os.lstat(database_path)
    if (info.st_dev, info.st_ino) != file_identity:
        raise IntegrationV2Error("база smart_plan изменилась при построении привязки")
    identity_value = {
        "databaseId": identity["database_id"],
        "activationBindingNonce": identity["activation_binding_nonce"],
        "activationId": identity["activation_id"],
        "activationFingerprint": identity["activation_fingerprint"],
    }
    identity_fingerprint = domain_fingerprint(
        "codex-smart/database-identity/v2",
        identity_value,
    )
    binding_value = {
        "path": str(database_path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "databaseId": identity["database_id"],
        "databaseIdentity": identity_value,
        "databaseIdentityFingerprint": identity_fingerprint,
        "activationIdentity": {
            "activationId": identity["activation_id"],
            "activationFingerprint": identity["activation_fingerprint"],
        },
        "databaseVersion": _CONTROLLER_RELEASE,
        "schemaVersion": 2,
        "userVersion": 2,
        "schemaFingerprint": identity["schema_fingerprint"],
        "schemaArtifactSha256": identity["schema_artifact_sha256"],
    }
    binding = {
        "schemaId": "database-binding-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": binding_value,
    }
    binding["valueFingerprint"] = domain_fingerprint(
        "codex-smart/database-binding/v2",
        binding,
    )
    return binding


def _verify_pinned_commit_receipt_v2(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    gate: Mapping[str, Any],
    layout: GatewayLayout,
    pinned: Mapping[str, str],
    database_binding: Mapping[str, Any],
) -> None:
    required = {
        "schemaVersion",
        "receiptKind",
        "installationId",
        "operationId",
        "frozenJournalFingerprint",
        "manifest",
        "manifestDocument",
        "transitionLineage",
        "activation",
        "databaseBinding",
        "journalAbsenceTarget",
        "controllerIdentity",
        "completedStepIds",
        "receiptFingerprint",
        "completedAt",
    }
    if type(receipt) is not dict or frozenset(receipt) != frozenset(required):
        raise IntegrationV2Error("commit-квитанция имеет неверную форму")
    if (
        receipt.get("schemaVersion") != 2
        or receipt.get("receiptKind") != "activation-commit"
        or receipt.get("installationId") != manifest["installationId"]
        or receipt.get("operationId") != manifest["lastCommittedOperation"]
        or type(receipt.get("frozenJournalFingerprint")) is not str
        or _SHA256.fullmatch(receipt["frozenJournalFingerprint"]) is None
        or type(receipt.get("controllerIdentity")) is not str
        or _SHA256.fullmatch(receipt["controllerIdentity"]) is None
        or type(receipt.get("receiptFingerprint")) is not str
        or _SHA256.fullmatch(receipt["receiptFingerprint"]) is None
        or type(receipt.get("completedAt")) is not str
        or not receipt.get("completedAt")
    ):
        raise IntegrationV2Error("commit-квитанция расходится с манифестом")
    steps = receipt["completedStepIds"]
    if (
        type(steps) is not list
        or not steps
        or len(steps) != len(set(steps))
        or any(
            type(item) is not str or re.fullmatch(r"st2_[0-9a-f]{32}", item) is None
            for item in steps
        )
    ):
        raise IntegrationV2Error("шаги commit-квитанции неверны")
    lineage = receipt["transitionLineage"]
    if type(lineage) is not dict or "lineageFingerprint" not in lineage:
        raise IntegrationV2Error("lineage commit-квитанции неверен")
    lineage_projection = {
        key: value for key, value in lineage.items() if key != "lineageFingerprint"
    }
    if lineage["lineageFingerprint"] != domain_fingerprint(
        "codex-smart/activation-transition-lineage/v2",
        lineage_projection,
    ):
        raise IntegrationV2Error("lineage commit-квитанции не совпал")
    unsigned = {key: value for key, value in receipt.items() if key != "receiptFingerprint"}
    expected_receipt = domain_fingerprint(
        "codex-smart/activation-commit-receipt/v2",
        unsigned,
    )
    if (
        receipt["receiptFingerprint"] != expected_receipt
        or receipt["receiptFingerprint"] != gate.get("activationReceiptFingerprint")
    ):
        raise IntegrationV2Error("отпечаток commit-квитанции не совпал")
    if receipt["manifestDocument"] != manifest:
        raise IntegrationV2Error("документ манифеста в commit-квитанции не совпал")
    _verify_typed_projection_v2(
        receipt["manifest"],
        schema_id="manifest-v2",
        domain="codex-smart/journal-state/v2",
    )
    _verify_typed_projection_v2(
        receipt["activation"],
        schema_id="activation-v2",
        domain="codex-smart/journal-state/v2",
    )
    _verify_typed_projection_v2(
        receipt["databaseBinding"],
        schema_id="database-binding-v2",
        domain="codex-smart/database-binding/v2",
    )
    _verify_typed_projection_v2(
        receipt["journalAbsenceTarget"],
        schema_id="absence-proof-v2",
        domain="codex-smart/absence-proof-projection/v2",
    )
    if receipt["databaseBinding"] != database_binding:
        raise IntegrationV2Error("databaseBinding commit-квитанции не совпал с БД")
    if receipt["journalAbsenceTarget"] != gate["journalAbsenceProof"]:
        raise IntegrationV2Error("absence proof commit-квитанции не совпал")
    _verify_receipt_manifest_projection_v2(
        receipt["manifest"],
        manifest=manifest,
        layout=layout,
        manifest_semantic=gate["manifestSemanticFingerprint"],
    )
    _verify_receipt_activation_projection_v2(
        receipt["activation"],
        manifest=manifest,
        pinned=pinned,
        database_binding=database_binding,
    )


def _verify_typed_projection_v2(
    value: Any,
    *,
    schema_id: str,
    domain: str,
) -> None:
    if (
        type(value) is not dict
        or frozenset(value) != {"schemaId", "schemaSha256", "value", "valueFingerprint"}
        or value.get("schemaId") != schema_id
        or value.get("schemaSha256") != _LIFECYCLE_SCHEMA_SHA256
        or type(value.get("value")) is not dict
        or type(value.get("valueFingerprint")) is not str
        or _SHA256.fullmatch(value["valueFingerprint"]) is None
    ):
        raise IntegrationV2Error("typed projection commit-квитанции неверен")
    projection = {
        "schemaId": value["schemaId"],
        "schemaSha256": value["schemaSha256"],
        "value": value["value"],
    }
    if value["valueFingerprint"] != domain_fingerprint(domain, projection):
        raise IntegrationV2Error("typed projection commit-квитанции не совпал")


def _verify_receipt_manifest_projection_v2(
    value: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    layout: GatewayLayout,
    manifest_semantic: str,
) -> None:
    active = manifest["activeActivation"]
    expected_value = {
        "file": _file_projection_v2(layout.manifest_path),
        "schemaVersion": 2,
        "installationId": manifest["installationId"],
        "release": _CONTROLLER_RELEASE,
        "pluginId": manifest["pluginId"],
        "stateHome": manifest["stateHome"],
        "activeActivationId": active["activationId"],
        "previousActivationId": (
            None
            if manifest["previousActivation"] is None
            else manifest["previousActivation"]["activationId"]
        ),
        "lastCommittedOperation": manifest["lastCommittedOperation"],
        "sourceLocatorFingerprint": hashlib.sha256(
            canonical_json_bytes(manifest["sourceLocator"])
        ).hexdigest(),
        "artifactsFingerprint": hashlib.sha256(
            canonical_json_bytes(manifest["artifacts"])
        ).hexdigest(),
        "semanticFingerprint": manifest_semantic,
    }
    expected = _journal_projection_v2("manifest-v2", expected_value)
    if value != expected:
        raise IntegrationV2Error("manifest projection commit-квитанции не совпал")


def _verify_receipt_activation_projection_v2(
    value: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    pinned: Mapping[str, str],
    database_binding: Mapping[str, Any],
) -> None:
    activation_value = value["value"]
    required = {
        "directory",
        "activationFile",
        "activationId",
        "activationFingerprint",
        "generationId",
        "release",
        "databaseId",
        "databaseIdentityFingerprint",
        "marketplaceTreeSha256",
        "generationTreeSha256",
    }
    if not required.issubset(activation_value):
        raise IntegrationV2Error("activation projection commit-квитанции неполон")
    if (
        activation_value.get("activationId") != manifest["activeActivation"]["activationId"]
        or activation_value.get("activationFingerprint")
        != pinned["activation_fingerprint"]
        or activation_value.get("generationId")
        != manifest["activeActivation"].get("generationId")
        or activation_value.get("release") != _CONTROLLER_RELEASE
        or activation_value.get("databaseId") != pinned["database_id"]
        or activation_value.get("databaseIdentityFingerprint")
        != database_binding["value"]["databaseIdentityFingerprint"]
    ):
        raise IntegrationV2Error("activation projection commit-квитанции не совпал")


def _file_projection_v2(path: Path) -> dict[str, Any]:
    info = os.lstat(path)
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _hash_file_v2(path),
    }


def _hash_file_v2(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(descriptor)


def _journal_projection_v2(schema_id: str, value: dict[str, Any]) -> dict[str, Any]:
    projection = {
        "schemaId": schema_id,
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    projection["valueFingerprint"] = domain_fingerprint(
        "codex-smart/journal-state/v2",
        projection,
    )
    return projection


def _verify_pinned_controller_row_v2(
    config: IntegrationConfigV2,
    controller: Mapping[str, Any],
    *,
    pinned: Mapping[str, str],
) -> None:
    required = {
        "database_id",
        "protocol_version",
        "release",
        "controller_identity",
        "instance_id",
        "controller_start_id",
        "controller_pid",
        "controller_process_start_marker",
        "controller_process_group_id",
        "activation_id",
        "activation_fingerprint",
        "compatibility_fingerprint",
        "routing_policy_fingerprint",
        "bundled_catalog_fingerprint",
        "control_epoch",
        "state",
        "maintenance_mode",
        "reason_code",
        "operation_id",
        "socket_path",
        "socket_device",
        "socket_inode",
        "socket_owner_uid",
        "socket_owner_gid",
        "socket_mode",
        "lock_held",
        "accepting_new_routes",
    }
    if not required.issubset(controller):
        raise IntegrationV2Error("строка контроллера smart_plan неполна")
    expected_identity = _controller_identity_fingerprint_v2(config, pinned=pinned)
    if (
        controller.get("database_id") != pinned["database_id"]
        or controller.get("protocol_version") != 2
        or controller.get("release") != _CONTROLLER_RELEASE
        or controller.get("controller_identity") != expected_identity
        or type(controller.get("instance_id")) is not str
        or _CONTROLLER_INSTANCE_ID.fullmatch(controller["instance_id"]) is None
        or type(controller.get("controller_start_id")) is not str
        or _CONTROLLER_START_ID.fullmatch(controller["controller_start_id"]) is None
        or type(controller.get("controller_pid")) is not int
        or controller.get("controller_pid") <= 0
        or type(controller.get("controller_process_start_marker")) is not str
        or not controller.get("controller_process_start_marker")
        or type(controller.get("controller_process_group_id")) is not int
        or controller.get("controller_process_group_id") <= 0
        or controller.get("activation_id") != config.launch_activation_id
        or controller.get("activation_fingerprint") != pinned["activation_fingerprint"]
        or controller.get("compatibility_fingerprint")
        != pinned["compatibility_fingerprint"]
        or controller.get("routing_policy_fingerprint")
        != pinned["routing_policy_fingerprint"]
        or controller.get("bundled_catalog_fingerprint")
        != pinned["bundled_catalog_fingerprint"]
        or type(controller.get("control_epoch")) is not int
        or controller.get("control_epoch") < 1
        or controller.get("state") != "ACCEPTING"
        or controller.get("maintenance_mode") != "NONE"
        or controller.get("reason_code") != "NONE"
        or controller.get("operation_id") is not None
        or controller.get("lock_held") != 1
        or controller.get("accepting_new_routes") != 1
    ):
        raise IntegrationV2Error("привязка базы smart_plan расходится с запуском")
    _verify_pinned_controller_socket_row_v2(config, controller)


def _controller_identity_fingerprint_v2(
    config: IntegrationConfigV2,
    *,
    pinned: Mapping[str, str],
) -> str:
    projection = {
        "protocolVersion": 2,
        "release": _CONTROLLER_RELEASE,
        "namespace": _CONTROLLER_NAMESPACE,
        "codexHomeHash": hashlib.sha256(
            str(config.codex_home.resolve()).encode("utf-8")
        ).hexdigest(),
        "stateHome": str(config.state_home),
        "activationFingerprint": pinned["activation_fingerprint"],
        "compatibilityFingerprint": pinned["compatibility_fingerprint"],
        "routingPolicyFingerprint": pinned["routing_policy_fingerprint"],
        "bundledCatalogFingerprint": pinned["bundled_catalog_fingerprint"],
        "databaseId": pinned["database_id"],
        "databaseSchemaVersion": 2,
    }
    return domain_fingerprint("codex-smart/controller-identity/v2", projection)


def _verify_pinned_controller_socket_row_v2(
    config: IntegrationConfigV2,
    controller: Mapping[str, Any],
) -> None:
    socket_path_value = controller.get("socket_path")
    if type(socket_path_value) is not str:
        raise IntegrationV2Error("сокет контроллера smart_plan неверен")
    socket_path = Path(socket_path_value)
    if socket_path != config.state_home / "controller.sock":
        raise IntegrationV2Error("сокет контроллера smart_plan расходится с запуском")
    try:
        socket_info = os.lstat(socket_path)
    except OSError as exc:
        raise IntegrationV2Error("сокет контроллера smart_plan недоступен") from exc
    observed = (
        socket_info.st_dev,
        socket_info.st_ino,
        socket_info.st_uid,
        socket_info.st_gid,
        f"0{stat.S_IMODE(socket_info.st_mode):03o}",
    )
    expected = (
        controller.get("socket_device"),
        controller.get("socket_inode"),
        controller.get("socket_owner_uid"),
        controller.get("socket_owner_gid"),
        controller.get("socket_mode"),
    )
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != os.getuid()
        or stat.S_IMODE(socket_info.st_mode) != 0o600
        or observed != expected
    ):
        raise IntegrationV2Error("сокет контроллера smart_plan расходится с запуском")


def _route_state_from_database_v2(
    database_path: Path,
    record: HookTurnContextV2,
    *,
    deadline: float,
) -> str:
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


def _read_private_json_document_v2(path: Path, *, error: str) -> dict[str, Any]:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise IntegrationV2Error(error) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > 4 * 1024 * 1024
    ):
        raise IntegrationV2Error(error)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise IntegrationV2Error(error)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, 4 * 1024 * 1024 + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 4 * 1024 * 1024:
                raise IntegrationV2Error(error)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationV2Error(error) from exc
    if type(value) is not dict:
        raise IntegrationV2Error(error)
    return value


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
    "PinnedResumeBindingV2",
    "TurnContextStoreV2",
    "capture_hook_turn_context_v2",
    "durable_smart_plan_exists_v2",
    "durable_smart_turn_state_v2",
    "durable_stop_smart_turn_state_v2",
    "pinned_resume_binding_v2",
    "require_current_user_mcp_policy_v2",
    "require_mcp_contract_v2",
    "require_live_controller_v2",
    "require_live_mcp_runtime_v2",
]
