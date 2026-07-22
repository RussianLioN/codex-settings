"""Подготовка точного дочернего запуска по ``child-profile-v1``."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import quote

from .canonical_json import domain_fingerprint
from .child_profile_runtime_v1 import (
    ChildProfileDomainsV1,
    materialize_child_profile_v1,
    secret_fingerprint_v1,
)
from .child_runner import (
    ChildRuntimeLayout,
    ChildTelemetryConfig,
    remove_staged_auth,
    stage_auth_file,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_DEFAULT_ARGV_DOMAIN = "codex-smart/argv/v2"


@dataclass
class ChildLaunchV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ChildAttemptResourceV2(Protocol):
    """Ресурс одной попытки, владеющий её приёмником и аттестацией."""

    @property
    def telemetry_config(self) -> ChildTelemetryConfig: ...

    def attest(
        self,
        prepared: "PreparedChildLaunchV2",
        jsonl_events: list[dict[str, Any]],
        permission_probe_id: str,
    ) -> Any: ...

    def close(self) -> None: ...


class ChildLaunchCompletionV2(Protocol):
    """Завершает сохраняемое действие после успешного дочернего процесса."""

    def complete(self, child_result: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class PreparedChildLaunchV2:
    executable: Path
    argv: tuple[str, ...]
    environment: Mapping[str, str] = field(repr=False)
    stdin: bytes = field(repr=False)
    argv_fingerprint: str
    snapshot_sha256: str
    snapshot_identity_fingerprint: str
    model: str
    reasoning_effort: str
    permission_profile_id: str
    argv_domain: str
    environment_domain: str
    secret_domain: str
    non_secret_environment: Mapping[str, str]
    environment_fingerprint: str
    secret_sha256: str
    compatibility_fingerprint: str
    account_context_fingerprint: str
    expected_cli_version: str
    role: str
    attempt_resource: ChildAttemptResourceV2 = field(repr=False, compare=False)
    staged_auth_path: Path | None = field(default=None, repr=False)
    completion: ChildLaunchCompletionV2 | None = field(
        default=None,
        repr=False,
        compare=False,
    )


def child_argv_fingerprint_v2(
    *,
    argv: Sequence[str],
    argv_domain: str = _DEFAULT_ARGV_DOMAIN,
) -> str:
    """Отпечатывает только точный список аргументов в договорном домене."""

    if (
        not isinstance(argv_domain, str)
        or not argv_domain
        or "\0" in argv_domain
        or len(argv_domain.encode("utf-8")) > 256
    ):
        _fail("ARGV_DOMAIN_INVALID", "неверный домен отпечатка аргументов")
    if isinstance(argv, (str, bytes)) or not argv:
        _fail("ARGV_INVALID", "аргументы должны быть непустой последовательностью")
    exact_argv = list(argv)
    if any(
        not isinstance(value, str)
        or not value
        or "\0" in value
        or len(value.encode("utf-8")) > 64 * 1024
        for value in exact_argv
    ):
        _fail("ARGV_INVALID", "аргументы содержат недопустимое значение")
    return domain_fingerprint(argv_domain, exact_argv)


def require_child_environment_integrity_v2(
    prepared: PreparedChildLaunchV2,
) -> None:
    """Проверяет фактическую среду против раздельных отпечатков среды и секрета."""

    non_secret = _environment_mapping(prepared.non_secret_environment)
    actual = _environment_mapping(prepared.environment)
    if "OTEL_EXPORTER_OTLP_HEADERS" in non_secret:
        _fail("SECRET_ENVIRONMENT_LEAK", "секрет попал в несекретную проекцию")
    if set(actual) != set(non_secret) | {"OTEL_EXPORTER_OTLP_HEADERS"}:
        _fail("ENVIRONMENT_FINGERPRINT_MISMATCH", "фактическая среда не замкнута")
    if any(actual[name] != value for name, value in non_secret.items()):
        _fail("ENVIRONMENT_FINGERPRINT_MISMATCH", "значение среды было изменено")
    raw_headers = actual["OTEL_EXPORTER_OTLP_HEADERS"]
    observed_environment, observed_secret = child_environment_fingerprints_v1(
        non_secret_environment=non_secret,
        raw_otel_headers=raw_headers,
        environment_domain=prepared.environment_domain,
        secret_domain=prepared.secret_domain,
    )
    if observed_secret != prepared.secret_sha256:
        _fail("SECRET_FINGERPRINT_MISMATCH", "секрет запуска был изменён")
    if observed_environment != prepared.environment_fingerprint:
        _fail("ENVIRONMENT_FINGERPRINT_MISMATCH", "отпечаток среды не совпал")
    if any(raw_headers in argument for argument in prepared.argv):
        _fail("SECRET_ARGV_LEAK", "секрет попал в аргументы запуска")


def child_environment_fingerprints_v1(
    *,
    non_secret_environment: Mapping[str, str],
    raw_otel_headers: str,
    environment_domain: str,
    secret_domain: str,
) -> tuple[str, str]:
    """Возвращает ``(environmentFingerprint, secretSha256)``."""

    non_secret = _environment_mapping(non_secret_environment)
    if "OTEL_EXPORTER_OTLP_HEADERS" in non_secret:
        _fail("SECRET_ENVIRONMENT_LEAK", "секрет попал в несекретную проекцию")
    secret_sha256 = secret_fingerprint_v1(secret_domain, raw_otel_headers)
    environment_fingerprint = domain_fingerprint(
        environment_domain,
        {
            "variables": non_secret,
            "secretBindings": {
                "OTEL_EXPORTER_OTLP_HEADERS": secret_sha256,
            },
        },
    )
    return environment_fingerprint, secret_sha256


def prepare_child_launch_v2(
    *,
    executable: Path,
    snapshot_sha256: str,
    snapshot_identity_fingerprint: str,
    pair: Mapping[str, str],
    allowed_pairs: Sequence[Mapping[str, str]],
    runtime: ChildRuntimeLayout,
    snapshot_root: Path,
    output_schema: Path,
    profile: Mapping[str, Any],
    profile_domain: str,
    expected_profile_fingerprint: str,
    domains: ChildProfileDomainsV1,
    compatibility_fingerprint: str,
    account_context_fingerprint: str,
    expected_cli_version: str,
    attempt_resource: ChildAttemptResourceV2,
    auth_file: Path,
    prompt: str,
    workspace_root: Path | None = None,
    completion: ChildLaunchCompletionV2 | None = None,
) -> PreparedChildLaunchV2:
    """Материализует профиль, закрытую среду и частную аутентификацию."""

    try:
        telemetry = _attempt_telemetry_config(attempt_resource)
        return _prepare_child_launch_v2(
            executable=executable,
            snapshot_sha256=snapshot_sha256,
            snapshot_identity_fingerprint=snapshot_identity_fingerprint,
            pair=pair,
            allowed_pairs=allowed_pairs,
            runtime=runtime,
            snapshot_root=snapshot_root,
            output_schema=output_schema,
            profile=profile,
            profile_domain=profile_domain,
            expected_profile_fingerprint=expected_profile_fingerprint,
            domains=domains,
            compatibility_fingerprint=compatibility_fingerprint,
            account_context_fingerprint=account_context_fingerprint,
            expected_cli_version=expected_cli_version,
            telemetry=telemetry,
            attempt_resource=attempt_resource,
            auth_file=auth_file,
            prompt=prompt,
            workspace_root=workspace_root,
            completion=completion,
        )
    except BaseException as exc:
        close = getattr(attempt_resource, "close", None)
        if not callable(close):
            raise
        try:
            close()
        except Exception as cleanup_error:
            raise ChildLaunchV2Error(
                "ATTEMPT_RESOURCE_CLEANUP_FAILED",
                f"{cleanup_error}; preceding error: {exc}",
            ) from cleanup_error
        raise


def _prepare_child_launch_v2(
    *,
    executable: Path,
    snapshot_sha256: str,
    snapshot_identity_fingerprint: str,
    pair: Mapping[str, str],
    allowed_pairs: Sequence[Mapping[str, str]],
    runtime: ChildRuntimeLayout,
    snapshot_root: Path,
    output_schema: Path,
    profile: Mapping[str, Any],
    profile_domain: str,
    expected_profile_fingerprint: str,
    domains: ChildProfileDomainsV1,
    compatibility_fingerprint: str,
    account_context_fingerprint: str,
    expected_cli_version: str,
    telemetry: ChildTelemetryConfig,
    attempt_resource: ChildAttemptResourceV2,
    auth_file: Path,
    prompt: str,
    workspace_root: Path | None,
    completion: ChildLaunchCompletionV2 | None,
) -> PreparedChildLaunchV2:

    executable = _private_snapshot(executable, snapshot_sha256)
    _require_sha256(snapshot_identity_fingerprint, "SNAPSHOT_IDENTITY_INVALID")
    _require_sha256(compatibility_fingerprint, "COMPATIBILITY_INVALID")
    _require_sha256(account_context_fingerprint, "ACCOUNT_CONTEXT_INVALID")
    if (
        not isinstance(expected_cli_version, str)
        or not expected_cli_version
        or "\0" in expected_cli_version
        or len(expected_cli_version.encode("utf-8")) > 128
    ):
        _fail("CLI_VERSION_INVALID", "неверная ожидаемая версия Codex")
    selected = _exact_pair(pair)
    allowed = [_exact_pair(item) for item in allowed_pairs]
    keys = [(item["model"], item["reasoningEffort"]) for item in allowed]
    if len(keys) != len(set(keys)):
        _fail("POLICY_PAIRS_INVALID", "политика содержит повтор пары")
    if (selected["model"], selected["reasoningEffort"]) not in set(keys):
        _fail("PAIR_NOT_ALLOWED", "точная пара отсутствует в политике")
    _require_sha256(expected_profile_fingerprint, "PROFILE_FINGERPRINT_INVALID")
    if type(profile) is not dict:
        _fail("PROFILE_INVALID", "профиль должен быть точным объектом")
    try:
        observed_profile_fingerprint = domain_fingerprint(profile_domain, profile)
    except (TypeError, ValueError) as exc:
        _fail("PROFILE_FINGERPRINT_INVALID", str(exc))
    if observed_profile_fingerprint != expected_profile_fingerprint:
        _fail("PROFILE_FINGERPRINT_MISMATCH", "профиль отличается от политики")

    runtime = _private_runtime_layout(runtime)
    snapshot_root = _private_directory(
        snapshot_root,
        code="SNAPSHOT_ROOT_UNSAFE",
        writable=False,
    )
    schema = _private_schema(output_schema)
    if not isinstance(prompt, str) or not prompt or "\0" in prompt:
        _fail("PROMPT_INVALID", "задание должно быть непустой строкой")
    stdin = prompt.encode("utf-8")
    if len(stdin) > 64 * 1024:
        _fail("PROMPT_INVALID", "задание превышает 64 КиБ")

    role = profile.get("role") if isinstance(profile, Mapping) else None
    if not isinstance(role, str):
        _fail("PROFILE_INVALID", "профиль не содержит роли")
    if role == "writer":
        if workspace_root is None:
            _fail("WORKSPACE_ROOT_REQUIRED", "писателю нужен рабочий корень")
        workspace = _private_directory(
            workspace_root,
            code="WORKSPACE_ROOT_UNSAFE",
            writable=True,
        )
    elif workspace_root is not None:
        _fail("WORKSPACE_ROOT_FORBIDDEN", "рабочий корень разрешён только писателю")
    else:
        workspace = None
    if completion is not None and not callable(getattr(completion, "complete", None)):
        _fail("COMPLETION_INVALID", "завершитель запуска не предоставляет complete()")
    if (role == "writer") != (completion is not None):
        _fail(
            "COMPLETION_ROLE_MISMATCH",
            "завершитель обязателен только для роли автора",
        )

    raw_headers = f"{telemetry.header_name}={quote(telemetry.token, safe='')}"
    slot_values = {
        "snapshotRoot": os.fspath(snapshot_root),
        "codexHome": os.fspath(runtime.codex_home),
        "codexSqliteHome": os.fspath(runtime.sqlite_home),
        "home": os.fspath(runtime.home),
        "tmpDir": os.fspath(runtime.tmpdir),
        "otelEndpoint": telemetry.endpoint,
    }
    if workspace is not None:
        slot_values["workspaceRoot"] = os.fspath(workspace)
    trusted_context = {
        "schemaVersion": 1,
        "contractVersion": "codex-trusted-launch-context-v1",
        "role": role,
        "compatibilityFingerprint": compatibility_fingerprint,
        "selectedPair": selected,
        "resultSchemaPath": os.fspath(schema),
        "workDir": os.fspath(runtime.work_dir),
        "environmentSlotValues": slot_values,
        "secretSlotFingerprints": {
            "otelHeaders": secret_fingerprint_v1(domains.secret, raw_headers)
        },
    }
    try:
        binding = materialize_child_profile_v1(
            profile=profile,
            trusted_context=trusted_context,
            snapshot_path=os.fspath(executable),
            raw_otel_headers=raw_headers,
            domains=domains,
        )
    except Exception as exc:
        if isinstance(exc, ChildLaunchV2Error):
            raise
        _fail("PROFILE_MATERIALIZATION_FAILED", str(exc))

    staged_auth: Path | None = None
    try:
        staged_auth = stage_auth_file(auth_file, runtime.codex_home)
        prepared = PreparedChildLaunchV2(
            executable=executable,
            argv=binding.argv,
            environment=binding.exec_environment,
            stdin=stdin,
            argv_fingerprint=binding.argv_fingerprint,
            snapshot_sha256=snapshot_sha256,
            snapshot_identity_fingerprint=snapshot_identity_fingerprint,
            model=selected["model"],
            reasoning_effort=selected["reasoningEffort"],
            permission_profile_id=binding.permission_profile_id,
            argv_domain=domains.argv,
            environment_domain=domains.environment,
            secret_domain=domains.secret,
            non_secret_environment=binding.non_secret_environment,
            environment_fingerprint=binding.environment_fingerprint,
            secret_sha256=binding.secret_sha256,
            compatibility_fingerprint=compatibility_fingerprint,
            account_context_fingerprint=account_context_fingerprint,
            expected_cli_version=expected_cli_version,
            role=role,
            attempt_resource=attempt_resource,
            staged_auth_path=staged_auth,
            completion=completion,
        )
        require_child_environment_integrity_v2(prepared)
        return prepared
    except BaseException:
        if staged_auth is not None:
            remove_staged_auth(staged_auth)
        raise


def cleanup_prepared_child_launch_v2(prepared: PreparedChildLaunchV2) -> None:
    """Идемпотентно закрывает аутентификацию и ресурс одной попытки."""

    failures: list[str] = []
    try:
        if prepared.staged_auth_path is not None:
            codex_home = prepared.non_secret_environment.get("CODEX_HOME")
            if (
                not isinstance(codex_home, str)
                or prepared.staged_auth_path != Path(codex_home) / "auth.json"
            ):
                _fail(
                    "AUTH_CLEANUP_PATH_MISMATCH",
                    "путь аутентификации не принадлежит дочернему CODEX_HOME",
                )
            remove_staged_auth(prepared.staged_auth_path)
    except Exception as exc:
        failures.append(str(exc))
    try:
        prepared.attempt_resource.close()
    except Exception as exc:
        failures.append(str(exc))
    if failures:
        _fail("LAUNCH_CLEANUP_FAILED", "; ".join(failures))


def _attempt_telemetry_config(
    resource: ChildAttemptResourceV2,
) -> ChildTelemetryConfig:
    if not callable(getattr(resource, "attest", None)) or not callable(
        getattr(resource, "close", None)
    ):
        _fail(
            "ATTEMPT_RESOURCE_INVALID",
            "ресурс попытки не реализует attest/close",
        )
    try:
        telemetry = resource.telemetry_config
    except Exception as exc:
        raise ChildLaunchV2Error(
            "ATTEMPT_RESOURCE_INVALID",
            str(exc),
        ) from exc
    if not isinstance(telemetry, ChildTelemetryConfig):
        _fail(
            "ATTEMPT_RESOURCE_INVALID",
            "ресурс попытки вернул неверную настройку телеметрии",
        )
    return telemetry


def _environment_mapping(value: Mapping[str, str]) -> dict[str, str]:
    try:
        result = dict(value)
    except (TypeError, ValueError) as exc:
        raise ChildLaunchV2Error(
            "ENVIRONMENT_FINGERPRINT_MISMATCH",
            "среда не является отображением строк",
        ) from exc
    if any(
        not isinstance(name, str)
        or not name
        or "=" in name
        or "\0" in name
        or not isinstance(item, str)
        or "\0" in item
        for name, item in result.items()
    ):
        _fail("ENVIRONMENT_FINGERPRINT_MISMATCH", "среда содержит неверное значение")
    return result


def _private_snapshot(path: Path, expected_sha256: str) -> Path:
    _require_sha256(expected_sha256, "SNAPSHOT_SHA256_INVALID")
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        _fail("SNAPSHOT_UNSAFE", "снимок должен быть абсолютным обычным файлом")
    try:
        info = candidate.lstat()
    except OSError as exc:
        _fail("SNAPSHOT_UNSAFE", str(exc))
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o500
    ):
        _fail("SNAPSHOT_UNSAFE", "неверные свойства частного снимка")
    digest = hashlib.sha256()
    try:
        with candidate.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        _fail("SNAPSHOT_UNSAFE", str(exc))
    if digest.hexdigest() != expected_sha256:
        _fail("SNAPSHOT_SHA256_MISMATCH", "содержимое снимка изменилось")
    return candidate


def _private_runtime_layout(runtime: ChildRuntimeLayout) -> ChildRuntimeLayout:
    if not isinstance(runtime, ChildRuntimeLayout):
        _fail("RUNTIME_UNSAFE", "ожидалась структура частного запуска")
    root = _private_directory(runtime.root, code="RUNTIME_UNSAFE", writable=True)
    expected = {
        "home": root / "home",
        "tmpdir": root / "tmp",
        "codex_home": root / "codex-home",
        "sqlite_home": root / "sqlite-home",
        "work_dir": root / "work",
    }
    for name, expected_path in expected.items():
        observed = getattr(runtime, name)
        if observed != expected_path:
            _fail("RUNTIME_UNSAFE", f"неверный путь {name}")
        _private_directory(observed, code="RUNTIME_UNSAFE", writable=True)
    return runtime


def _private_directory(path: Path, *, code: str, writable: bool) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        _fail(code, "каталог должен быть абсолютным и не ссылкой")
    try:
        info = candidate.lstat()
    except OSError as exc:
        _fail(code, str(exc))
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or (writable and mode != 0o700)
        or (not writable and mode & 0o222)
    ):
        _fail(code, "неверные свойства частного каталога")
    return candidate


def _private_schema(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        _fail("OUTPUT_SCHEMA_UNSAFE", "схема должна быть абсолютным файлом")
    try:
        info = candidate.lstat()
    except OSError as exc:
        _fail("OUTPUT_SCHEMA_UNSAFE", str(exc))
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
        or not 0 < info.st_size <= 1024 * 1024
    ):
        _fail("OUTPUT_SCHEMA_UNSAFE", "неверные свойства схемы")
    return candidate


def _exact_pair(value: Mapping[str, str]) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"model", "reasoningEffort"}:
        _fail("PAIR_INVALID", "пара должна иметь ровно два поля")
    model = value["model"]
    effort = value["reasoningEffort"]
    if any(
        not isinstance(item, str)
        or not item
        or len(item.encode("utf-8")) > 128
        or any(character in item for character in "\0\n\r")
        for item in (model, effort)
    ):
        _fail("PAIR_INVALID", "значение пары небезопасно")
    return {"model": model, "reasoningEffort": effort}


def _require_sha256(value: str, code: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(code, "ожидался строчный SHA-256")


def _fail(code: str, message: str) -> None:
    raise ChildLaunchV2Error(code, message)
