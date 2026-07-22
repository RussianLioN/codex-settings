"""Shared runtime contract for plugin entrypoints and lifecycle hooks."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from codex_smart_subagents.catalog import Catalog
from codex_smart_subagents.controller import ControllerClient, RuntimePaths
from codex_smart_subagents.identity import RequestContext, sha256_text


STATE_SCHEMA_VERSION = 1
MAX_HOOK_INPUT_BYTES = 64 * 1024
MAX_ADDITIONAL_CONTEXT_BYTES = 2048
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
TERMINAL_ROUTE_STATES = {
    "SUCCEEDED",
    "CANDIDATE_READY",
    "QUARANTINED",
    "CANCELLED",
    "FAILED",
    "STALE",
    "SKIPPED",
}
CHILD_MARKERS = (
    "CODEX_ADAPTIVE_CHILD",
    "CODEX_SMART_SUBAGENT_CHILD",
)
HOOK_TOTAL_BUDGET_SECONDS = 1.75
HOOK_CONTROLLER_TIMEOUT_SECONDS = 0.3
MCP_PLAN_TIMEOUT_SECONDS = 420.0
MCP_SHORT_TIMEOUT_SECONDS = 10.0
MCP_WAIT_GRACE_SECONDS = 5.0
COORDINATION_LOCK_TIMEOUT_SECONDS = 5.0
COORDINATION_LOCK_POLL_INTERVAL_SECONDS = 0.05


class IntegrationError(RuntimeError):
    """A sanitized integration-boundary error."""


def _acquire_coordination_lock(descriptor: int) -> None:
    """Получить локальную блокировку до одного монотонного срока."""

    deadline = time.monotonic() + COORDINATION_LOCK_TIMEOUT_SECONDS
    busy_errors = {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}
    while True:
        if time.monotonic() >= deadline:
            raise IntegrationError(
                "срок ожидания блокировки координации истёк"
            ) from None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as error:
            if error.errno not in busy_errors:
                raise
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IntegrationError(
                "срок ожидания блокировки координации истёк"
            ) from None
        time.sleep(min(COORDINATION_LOCK_POLL_INTERVAL_SECONDS, remaining))


@dataclass(frozen=True)
class IntegrationConfig:
    shell_session_id: str
    codex_home: str
    codex_home_hash: str
    catalog_path: Path | None
    paths: RuntimePaths

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        require_catalog: bool,
    ) -> "IntegrationConfig":
        shell_session_id = environ.get("CODEX_ADAPTIVE_SESSION_ID", "")
        if not SESSION_PATTERN.fullmatch(shell_session_id):
            raise IntegrationError(
                "CODEX_ADAPTIVE_SESSION_ID отсутствует или имеет неверный формат"
            )

        raw_codex_home = environ.get("CODEX_HOME", "")
        if not raw_codex_home:
            raise IntegrationError("CODEX_HOME должен быть задан явно")
        codex_home_path = Path(raw_codex_home)
        if not codex_home_path.is_absolute():
            raise IntegrationError("CODEX_HOME должен быть абсолютным путём")
        codex_home = str(codex_home_path.resolve())

        raw_state_home = environ.get("XDG_STATE_HOME", "")
        state_home = None
        if raw_state_home:
            state_home = Path(raw_state_home)
            if not state_home.is_absolute():
                raise IntegrationError(
                    "XDG_STATE_HOME должен быть абсолютным путём"
                )
            state_home = state_home.resolve()

        catalog_path: Path | None = None
        raw_catalog = environ.get("CODEX_ADAPTIVE_CATALOG", "")
        if raw_catalog:
            catalog_path = Path(raw_catalog)
            if not catalog_path.is_absolute():
                raise IntegrationError(
                    "CODEX_ADAPTIVE_CATALOG должен быть абсолютным путём"
                )
            catalog_path = catalog_path.resolve()
        if require_catalog:
            if catalog_path is None or not catalog_path.is_file():
                raise IntegrationError(
                    "CODEX_ADAPTIVE_CATALOG не указывает на каталог политики"
                )

        return cls(
            shell_session_id=shell_session_id,
            codex_home=codex_home,
            codex_home_hash=sha256_text(codex_home),
            catalog_path=catalog_path,
            paths=RuntimePaths.for_codex_home(
                codex_home,
                state_home=state_home,
            ),
        )


class CoordinationStore:
    """Small per-shell coordination record; it is not authoritative route state."""

    def __init__(self, config: IntegrationConfig) -> None:
        self.config = config
        self.directory = config.paths.namespace_dir / "coordination"
        token = hashlib.sha256(
            config.shell_session_id.encode("utf-8")
        ).hexdigest()[:32]
        self.path = self.directory / f"{token}.json"
        self.lock_path = self.directory / f"{token}.lock"

    def load(self) -> dict[str, Any] | None:
        self._prepare_directory()
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        if len(raw) > MAX_HOOK_INPUT_BYTES:
            raise IntegrationError("запись координации превышает предел")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IntegrationError("запись координации повреждена") from exc
        self._validate(value)
        return value

    def save(self, value: dict[str, Any]) -> None:
        self._validate(value)
        self._prepare_directory()
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_HOOK_INPUT_BYTES:
            raise IntegrationError("запись координации превышает предел")
        temporary = self.directory / (
            f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)

    def clear(self) -> None:
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise IntegrationError("небезопасная запись координации")
        self.path.unlink()

    def update(
        self,
        mutator: Callable[
            [dict[str, Any] | None],
            dict[str, Any] | None,
        ],
    ) -> dict[str, Any] | None:
        self._prepare_directory()
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        acquired = False
        try:
            _acquire_coordination_lock(descriptor)
            acquired = True
            current = self.load()
            updated = mutator(current)
            if updated is None:
                self.clear()
            else:
                self.save(updated)
            return updated
        finally:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _prepare_directory(self) -> None:
        for directory in (
            self.config.paths.base_dir,
            self.config.paths.namespace_dir,
            self.directory,
        ):
            if directory.is_symlink():
                raise IntegrationError("каталог состояния является ссылкой")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
            info = directory.stat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
            ):
                raise IntegrationError("небезопасный каталог состояния")

    def _validate(self, value: Any) -> None:
        required = {
            "schemaVersion",
            "shellSessionId",
            "sessionId",
            "turnId",
            "turnBinding",
            "catalogGeneration",
            "planCalled",
            "routeId",
            "disposition",
            "routeState",
            "afterSequence",
            "continuationCount",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise IntegrationError("запись координации имеет неверную схему")
        if value["schemaVersion"] != STATE_SCHEMA_VERSION:
            raise IntegrationError("версия записи координации не поддерживается")
        string_fields = required - {
            "schemaVersion",
            "planCalled",
            "afterSequence",
            "continuationCount",
        }
        if not all(isinstance(value[name], str) for name in string_fields):
            raise IntegrationError("строковые поля координации повреждены")
        if value["shellSessionId"] != self.config.shell_session_id:
            raise IntegrationError("запись принадлежит другому сеансу")
        if type(value["planCalled"]) is not bool:
            raise IntegrationError("признак планирования повреждён")
        for name in ("afterSequence", "continuationCount"):
            if type(value[name]) is not int or value[name] < 0:
                raise IntegrationError("счётчик координации повреждён")


def environment_is_active(environ: Mapping[str, str]) -> bool:
    if not environ.get("CODEX_ADAPTIVE_SESSION_ID"):
        return False
    return not any(
        environ.get(name, "").lower() in {"1", "true", "yes"}
        for name in CHILD_MARKERS
    )


def controller_client(config: IntegrationConfig) -> ControllerClient:
    return ControllerClient(
        socket_path=config.paths.socket_path,
        codex_home_hash=config.codex_home_hash,
        shell_session_id=config.shell_session_id,
        timeout=HOOK_CONTROLLER_TIMEOUT_SECONDS,
    )


class MCPControllerClient:
    """Choose a bounded controller timeout for each public MCP method."""

    def __init__(
        self,
        config: IntegrationConfig,
        *,
        client_factory: Callable[..., ControllerClient] = ControllerClient,
    ) -> None:
        self.config = config
        self.client_factory = client_factory

    def call(
        self,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        timeout = MCP_SHORT_TIMEOUT_SECONDS
        if method == "smart_plan":
            timeout = MCP_PLAN_TIMEOUT_SECONDS
        elif method == "smart_wait":
            requested = params.get("timeoutSeconds")
            if (
                type(requested) is not int
                or not 0 <= requested <= 60
            ):
                raise IntegrationError(
                    "timeoutSeconds должен быть целым числом от 0 до 60"
                )
            timeout = requested + MCP_WAIT_GRACE_SECONDS
        client = self.client_factory(
            socket_path=self.config.paths.socket_path,
            codex_home_hash=self.config.codex_home_hash,
            shell_session_id=self.config.shell_session_id,
            timeout=timeout,
        )
        return client.call(method, params)


def mcp_controller_client(config: IntegrationConfig) -> MCPControllerClient:
    return MCPControllerClient(config)


def request_context(
    payload: dict[str, Any],
    config: IntegrationConfig,
    *,
    deadline: float | None = None,
) -> RequestContext:
    _validate_hook_payload(payload, "UserPromptSubmit")
    repo_root, base_sha, fingerprint = _git_identity(
        payload["cwd"],
        deadline=deadline,
    )
    return RequestContext(
        shell_session_id=config.shell_session_id,
        session_id=payload["session_id"],
        turn_id=payload["turn_id"],
        codex_home=config.codex_home,
        repo_root=repo_root,
        base_sha=base_sha,
        worktree_fingerprint=fingerprint,
    )


def catalog_routing_context(
    config: IntegrationConfig,
) -> tuple[str, dict[str, str]]:
    if config.catalog_path is None:
        raise IntegrationError("каталог политики не задан")
    catalog = Catalog.load(config.catalog_path)
    identifiers = {
        "scopeDefault": catalog.opaque_id("scope", "default"),
        "artifactReport": catalog.opaque_id("artifact", "report"),
        "artifactCandidate": catalog.opaque_id("artifact", "candidate"),
    }
    for alias in sorted(catalog.validation):
        identifiers[f"validation.{alias}"] = catalog.opaque_id(
            "validation",
            alias,
        )
    return catalog.generation, identifiers


def read_hook_input(stream: Any) -> dict[str, Any]:
    raw = stream.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_HOOK_INPUT_BYTES:
        raise IntegrationError("вход события отсутствует или слишком велик")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrationError("вход события не является JSON") from exc
    if not isinstance(payload, dict):
        raise IntegrationError("вход события должен быть объектом")
    return payload


def write_hook_output(stream: Any, response: dict[str, Any] | None) -> None:
    if response is None:
        return
    stream.write(
        json.dumps(
            response,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream.flush()


def hook_context(event: str, text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_ADDITIONAL_CONTEXT_BYTES:
        raise IntegrationError("добавочный контекст события слишком велик")
    return {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": text,
        },
    }


def _validate_hook_payload(payload: dict[str, Any], event: str) -> None:
    if payload.get("hook_event_name") != event:
        raise IntegrationError("получено событие другого типа")
    for name in ("session_id", "turn_id", "cwd"):
        if not isinstance(payload.get(name), str) or not payload[name]:
            raise IntegrationError(f"поле события {name} отсутствует")
    cwd = Path(payload["cwd"])
    if not cwd.is_absolute() or not cwd.is_dir():
        raise IntegrationError("cwd события должен быть существующим каталогом")


def _git_identity(
    cwd: str,
    *,
    deadline: float | None = None,
) -> tuple[str, str, str]:
    deadline = (
        time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS
        if deadline is None
        else deadline
    )
    git = _git_binary()
    identity = _run_git(
        git,
        cwd,
        "rev-parse",
        "--show-toplevel",
        "HEAD",
        timeout_seconds=_budgeted_timeout(
            deadline,
            reserve_seconds=1.25,
            maximum_seconds=0.4,
        ),
    ).decode("utf-8").splitlines()
    if len(identity) != 2:
        raise IntegrationError("Git вернул неполную идентичность")
    repo_root, base_sha = identity
    status_bytes = _run_git(
        git,
        repo_root,
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
        timeout_seconds=_budgeted_timeout(
            deadline,
            reserve_seconds=0.65,
            maximum_seconds=0.65,
        ),
    )
    if not re.fullmatch(r"[0-9a-f]{40,64}", base_sha):
        raise IntegrationError("HEAD репозитория имеет неверный формат")
    return (
        str(Path(repo_root).resolve()),
        base_sha,
        hashlib.sha256(status_bytes).hexdigest(),
    )


def _git_binary() -> str:
    for candidate in ("/usr/bin/git", "/opt/homebrew/bin/git"):
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise IntegrationError("доверенный исполняемый файл Git не найден")


def _run_git(
    git: str,
    cwd: str,
    *args: str,
    timeout_seconds: float = 1.2,
) -> bytes:
    try:
        result = subprocess.run(
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.untrackedCache=false",
                "-C",
                cwd,
                *args,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=timeout_seconds,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
                "LC_ALL": "C",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IntegrationError("не удалось определить состояние Git") from exc
    return result.stdout


def _budgeted_timeout(
    deadline: float,
    *,
    reserve_seconds: float,
    maximum_seconds: float,
) -> float:
    remaining = deadline - time.monotonic() - reserve_seconds
    if remaining <= 0.05:
        raise IntegrationError("бюджет времени события исчерпан")
    return min(maximum_seconds, remaining)
