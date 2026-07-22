"""Точная материализация договора ``child-profile-v1`` во время запуска."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .canonical_json import canonical_json_v1, domain_fingerprint


_MAX_TEXT_BYTES = 4_096
_MAX_ARG_BYTES = 65_536
_MAX_ARGV_ITEMS = 512
_SECRET_ENVIRONMENT_NAME = "OTEL_EXPORTER_OTLP_HEADERS"
_SECRET_SLOT_NAME = "otelHeaders"
_PROFILE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_PERMISSION_ARGUMENT_SLOTS = (
    "permissionDescriptionConfig",
    "permissionFilesystemConfig",
    "permissionNetworkConfig",
)
_PERMISSION_DESCRIPTIONS = {
    "classifier": "Adaptive child classifier",
    "reader": "Adaptive child reader",
    "writer": "Adaptive child writer",
}


@dataclass
class ChildProfileRuntimeError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ChildProfileDomainsV1:
    argv: str
    environment: str
    secret: str

    def __post_init__(self) -> None:
        for name, value in (
            ("argv", self.argv),
            ("environment", self.environment),
            ("secret", self.secret),
        ):
            if not _bounded_string(value, 256):
                _fail("DOMAIN_INVALID", f"неверный домен {name}")


@dataclass(frozen=True)
class MaterializedChildProfileV1:
    role: str
    compatibility_fingerprint: str
    permission_profile_id: str
    result_schema_id: str
    arguments: Mapping[str, str]
    argv: tuple[str, ...]
    non_secret_environment: Mapping[str, str]
    exec_environment: Mapping[str, str] = field(repr=False)
    argv_fingerprint: str
    environment_fingerprint: str
    secret_sha256: str

    def contract_value(self) -> dict[str, Any]:
        """Возвращает точную несекретную проекцию договора запуска."""

        return {
            "schemaVersion": 1,
            "contractVersion": "codex-child-launch-v1",
            "role": self.role,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "arguments": dict(self.arguments),
            "concreteArgv": list(self.argv),
            "nonSecretEnvironment": dict(self.non_secret_environment),
            "argvFingerprint": self.argv_fingerprint,
            "environmentFingerprint": self.environment_fingerprint,
            "secretSha256": self.secret_sha256,
        }


def materialize_child_profile_v1(
    *,
    profile: Mapping[str, Any],
    trusted_context: Mapping[str, Any],
    snapshot_path: str,
    raw_otel_headers: str,
    domains: ChildProfileDomainsV1,
) -> MaterializedChildProfileV1:
    """Замыкает доверенный контекст и профиль в точный запуск.

    Сырой заголовок телеметрии добавляется только в фактическую среду процесса;
    аргументы и сохраняемая договорная проекция содержат лишь его отпечаток.
    """

    normalized_profile = _profile(profile)
    normalized_context = _trusted_context(trusted_context, normalized_profile)
    if not _bounded_string(snapshot_path, _MAX_TEXT_BYTES, absolute=True):
        _fail("SNAPSHOT_PATH_INVALID", "путь снимка должен быть абсолютным")
    if not _bounded_string(raw_otel_headers, _MAX_TEXT_BYTES):
        _fail("OTEL_HEADERS_INVALID", "неверное секретное значение телеметрии")

    secret_sha256 = secret_fingerprint_v1(domains.secret, raw_otel_headers)
    trusted_secret_sha256 = normalized_context["secretSlotFingerprints"][
        _SECRET_SLOT_NAME
    ]
    if secret_sha256 != trusted_secret_sha256:
        _fail("SECRET_FINGERPRINT_MISMATCH", "секрет не совпадает с контекстом")

    non_secret_environment = _materialize_environment(
        normalized_profile,
        normalized_context["environmentSlotValues"],
    )
    arguments = {
        "snapshotPath": snapshot_path,
        "model": normalized_context["selectedPair"]["model"],
        "workDir": normalized_context["workDir"],
        "resultSchemaPath": normalized_context["resultSchemaPath"],
        "reasoningEffort": normalized_context["selectedPair"]["reasoningEffort"],
        **_permission_profile_arguments(
            normalized_profile,
            normalized_context["environmentSlotValues"],
        ),
        "otelExporterConfig": _otel_exporter_config(
            normalized_context["environmentSlotValues"]["otelEndpoint"]
        ),
    }
    argv = _materialize_argv(
        normalized_profile,
        arguments,
        non_secret_environment,
    )
    environment_projection = {
        "variables": non_secret_environment,
        "secretBindings": {_SECRET_ENVIRONMENT_NAME: secret_sha256},
    }
    exec_environment = dict(non_secret_environment)
    exec_environment[_SECRET_ENVIRONMENT_NAME] = raw_otel_headers
    return MaterializedChildProfileV1(
        role=normalized_profile["role"],
        compatibility_fingerprint=normalized_context["compatibilityFingerprint"],
        permission_profile_id=normalized_profile["permissionProfileId"],
        result_schema_id=normalized_profile["resultSchemaId"],
        arguments=MappingProxyType(arguments),
        argv=tuple(argv),
        non_secret_environment=MappingProxyType(non_secret_environment),
        exec_environment=MappingProxyType(exec_environment),
        argv_fingerprint=domain_fingerprint(domains.argv, argv),
        environment_fingerprint=domain_fingerprint(
            domains.environment,
            environment_projection,
        ),
        secret_sha256=secret_sha256,
    )


def secret_fingerprint_v1(domain: str, raw_value: str) -> str:
    """Отпечатывает секретные байты без канонического JSON-обрамления."""

    if not _bounded_string(domain, 256):
        _fail("DOMAIN_INVALID", "неверный домен секрета")
    if not _bounded_string(raw_value, _MAX_TEXT_BYTES):
        _fail("OTEL_HEADERS_INVALID", "неверное секретное значение телеметрии")
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + raw_value.encode("utf-8")
    ).hexdigest()


def _profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "contractVersion",
        "role",
        "permissionProfileId",
        "sandboxMode",
        "resultSchemaId",
        "argvTemplate",
        "environmentTemplate",
        "disabledFeatures",
        "negativeProbeIds",
    }
    if type(profile) is not dict or set(profile) != required:
        _fail("PROFILE_INVALID", "неверная форма профиля")
    if (
        profile["schemaVersion"] != 1
        or profile["contractVersion"] != "codex-child-profile-v1"
        or not _bounded_string(profile["role"], 128)
        or _PROFILE_NAME.fullmatch(profile["permissionProfileId"]) is None
        or not _bounded_string(profile["sandboxMode"], 128)
        or not _bounded_string(profile["resultSchemaId"], 128)
        or profile["role"] not in _PERMISSION_DESCRIPTIONS
    ):
        _fail("PROFILE_INVALID", "неверные метаданные профиля")
    argv_template = profile["argvTemplate"]
    if (
        type(argv_template) is not list
        or not argv_template
        or len(argv_template) > _MAX_ARGV_ITEMS
    ):
        _fail("PROFILE_INVALID", "неверный шаблон аргументов")
    for item in argv_template:
        if type(item) is not dict:
            _fail("PROFILE_INVALID", "неверный элемент шаблона аргументов")
        if set(item) == {"literal"}:
            if not _bounded_string(item["literal"], _MAX_ARG_BYTES):
                _fail("PROFILE_INVALID", "неверный литерал аргумента")
            continue
        if set(item) != {"slot", "prefix", "encoding"}:
            _fail("PROFILE_INVALID", "неизвестный элемент шаблона аргументов")
        if (
            item["slot"]
            not in {
                "snapshotPath",
                "model",
                "workDir",
                "resultSchemaPath",
                "reasoningEffort",
                "otelExporterConfig",
                "shellEnvironmentSet",
                *_PERMISSION_ARGUMENT_SLOTS,
            }
            or type(item["prefix"]) is not str
            or item["encoding"] not in {"raw", "json-string", "canonical-json"}
        ):
            _fail("PROFILE_INVALID", "неверная привязка аргумента")
    permission_items = [
        item for item in argv_template if item.get("slot") in _PERMISSION_ARGUMENT_SLOTS
    ]
    expected_default = "default_permissions=" + canonical_json_v1(
        profile["permissionProfileId"]
    )
    if (
        tuple(item["slot"] for item in permission_items) != _PERMISSION_ARGUMENT_SLOTS
        or sum(item.get("literal") == expected_default for item in argv_template) != 1
        or any(
            item != {"slot": slot, "prefix": "", "encoding": "raw"}
            for slot, item in zip(_PERMISSION_ARGUMENT_SLOTS, permission_items)
        )
    ):
        _fail(
            "PROFILE_PERMISSION_TABLE_MISSING",
            "профиль не содержит точную таблицу разрешений",
        )
    environment_template = profile["environmentTemplate"]
    if type(environment_template) is not dict or not environment_template:
        _fail("PROFILE_INVALID", "неверный шаблон среды")
    for name, source in environment_template.items():
        if (
            not _bounded_string(name, 256)
            or "=" in name
            or type(source) is not dict
            or set(source) not in ({"literal"}, {"slot"}, {"secretSlot"})
        ):
            _fail("PROFILE_INVALID", "неверная привязка среды")
        value = next(iter(source.values()))
        if not _bounded_string(value, _MAX_TEXT_BYTES):
            _fail("PROFILE_INVALID", "неверное значение шаблона среды")
        if "secretSlot" in source and (
            name != _SECRET_ENVIRONMENT_NAME
            or source["secretSlot"] != _SECRET_SLOT_NAME
        ):
            _fail("PROFILE_INVALID", "неизвестная секретная привязка")
    disabled = profile["disabledFeatures"]
    if (
        type(disabled) is not list
        or len(disabled) != len(set(disabled))
        or any(not _bounded_string(value, 128) for value in disabled)
    ):
        _fail("PROFILE_INVALID", "неверный перечень выключенных возможностей")
    if type(profile["negativeProbeIds"]) is not list:
        _fail("PROFILE_INVALID", "неверный перечень отрицательных проб")
    return profile


def _trusted_context(
    trusted_context: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "contractVersion",
        "role",
        "compatibilityFingerprint",
        "selectedPair",
        "resultSchemaPath",
        "workDir",
        "environmentSlotValues",
        "secretSlotFingerprints",
    }
    if type(trusted_context) is not dict or set(trusted_context) != required:
        _fail("TRUSTED_CONTEXT_INVALID", "неверная форма доверенного контекста")
    if (
        trusted_context["schemaVersion"] != 1
        or trusted_context["contractVersion"] != "codex-trusted-launch-context-v1"
        or trusted_context["role"] != profile["role"]
        or not _sha256(trusted_context["compatibilityFingerprint"])
        or not _bounded_string(
            trusted_context["resultSchemaPath"],
            _MAX_TEXT_BYTES,
            absolute=True,
        )
        or not _bounded_string(
            trusted_context["workDir"],
            _MAX_TEXT_BYTES,
            absolute=True,
        )
    ):
        _fail("TRUSTED_CONTEXT_INVALID", "неверные метаданные контекста")
    pair = trusted_context["selectedPair"]
    if (
        type(pair) is not dict
        or set(pair) != {"model", "reasoningEffort"}
        or not _bounded_string(pair["model"], 128)
        or not _bounded_string(pair["reasoningEffort"], 128)
    ):
        _fail("TRUSTED_CONTEXT_INVALID", "неверная выбранная пара")
    expected_slots = {
        source["slot"]
        for source in profile["environmentTemplate"].values()
        if set(source) == {"slot"}
    }
    slots = trusted_context["environmentSlotValues"]
    if type(slots) is not dict or set(slots) != expected_slots:
        _fail("TRUSTED_CONTEXT_INVALID", "неполный набор значений среды")
    for slot, value in slots.items():
        if not _bounded_string(
            value,
            _MAX_TEXT_BYTES,
            absolute=slot != "otelEndpoint",
        ):
            _fail("TRUSTED_CONTEXT_INVALID", f"неверное значение среды {slot}")
    expected_secret_slots = {
        source["secretSlot"]
        for source in profile["environmentTemplate"].values()
        if set(source) == {"secretSlot"}
    }
    secrets = trusted_context["secretSlotFingerprints"]
    if (
        type(secrets) is not dict
        or set(secrets) != expected_secret_slots
        or any(not _sha256(value) for value in secrets.values())
    ):
        _fail("TRUSTED_CONTEXT_INVALID", "неверные отпечатки секретов")
    return trusted_context


def _materialize_environment(
    profile: Mapping[str, Any],
    slot_values: Mapping[str, str],
) -> dict[str, str]:
    environment: dict[str, str] = {}
    found_secret = False
    for name, source in profile["environmentTemplate"].items():
        if "literal" in source:
            environment[name] = source["literal"]
        elif "slot" in source:
            environment[name] = slot_values[source["slot"]]
        else:
            found_secret = True
    if not found_secret or _SECRET_ENVIRONMENT_NAME in environment:
        _fail("PROFILE_INVALID", "профиль не отделил секрет телеметрии")
    return environment


def _materialize_argv(
    profile: Mapping[str, Any],
    arguments: Mapping[str, str],
    non_secret_environment: Mapping[str, str],
) -> list[str]:
    argv: list[str] = []
    for item in profile["argvTemplate"]:
        if "literal" in item:
            argv.append(item["literal"])
            continue
        slot = item["slot"]
        if slot == "shellEnvironmentSet":
            if item["encoding"] != "canonical-json":
                _fail("PROFILE_INVALID", "неверная кодировка среды в аргументах")
            value = canonical_json_v1(dict(non_secret_environment))
        else:
            value = arguments[slot]
            if item["encoding"] == "json-string":
                value = canonical_json_v1(value)
            elif item["encoding"] != "raw":
                _fail("PROFILE_INVALID", "неверная кодировка аргумента")
        concrete = item["prefix"] + value
        if not _bounded_string(concrete, _MAX_ARG_BYTES):
            _fail("ARGV_INVALID", "получен недопустимый аргумент")
        argv.append(concrete)
    for feature in profile["disabledFeatures"]:
        argv.extend(("--disable", feature))
    if len(argv) > _MAX_ARGV_ITEMS:
        _fail("ARGV_INVALID", "слишком много аргументов")
    return argv


def _otel_exporter_config(endpoint: str) -> str:
    """Строит несекретную настройку конечного OTLP/HTTP пути журналов."""

    if not _bounded_string(endpoint, _MAX_TEXT_BYTES):
        _fail("OTEL_ENDPOINT_INVALID", "неверный базовый endpoint телеметрии")
    final_endpoint = endpoint.rstrip("/") + "/v1/logs"
    if len(final_endpoint.encode("utf-8")) > _MAX_TEXT_BYTES:
        _fail("OTEL_ENDPOINT_INVALID", "конечный endpoint телеметрии слишком длинный")
    return (
        "otel.exporter={ otlp-http = { endpoint="
        + canonical_json_v1(final_endpoint)
        + ', protocol="json", headers={} } }'
    )


def _permission_profile_arguments(
    profile: Mapping[str, Any],
    environment_slots: Mapping[str, str],
) -> dict[str, str]:
    """Строит замкнутую таблицу разрешений из доверенных путей запуска."""

    name = profile["permissionProfileId"]
    role = profile["role"]
    snapshot_root = environment_slots["snapshotRoot"]
    workspace_root = environment_slots.get("workspaceRoot")
    if role == "writer":
        if not _bounded_string(workspace_root, _MAX_TEXT_BYTES, absolute=True):
            _fail(
                "PROFILE_PERMISSION_TABLE_INVALID",
                "писателю нужен доверенный рабочий корень",
            )
    elif workspace_root is not None:
        _fail(
            "PROFILE_PERMISSION_TABLE_INVALID",
            "рабочий корень разрешён только писателю",
        )
    entries = [
        canonical_json_v1(":root") + "=" + canonical_json_v1("deny"),
        canonical_json_v1(":minimal") + "=" + canonical_json_v1("read"),
        canonical_json_v1(":tmpdir") + "=" + canonical_json_v1("write"),
        canonical_json_v1(":workspace_roots")
        + "={"
        + canonical_json_v1(".")
        + "="
        + canonical_json_v1("write")
        + "}",
        canonical_json_v1(snapshot_root) + "=" + canonical_json_v1("read"),
    ]
    if workspace_root is not None:
        entries.append(
            canonical_json_v1(workspace_root) + "=" + canonical_json_v1("write")
        )
    prefix = f"permissions.{name}"
    return {
        "permissionDescriptionConfig": (
            prefix + ".description=" + canonical_json_v1(_PERMISSION_DESCRIPTIONS[role])
        ),
        "permissionFilesystemConfig": (
            prefix + ".filesystem={" + ",".join(entries) + "}"
        ),
        "permissionNetworkConfig": prefix + ".network.enabled=false",
    }


def _bounded_string(value: Any, limit: int, *, absolute: bool = False) -> bool:
    return (
        type(value) is str
        and bool(value)
        and "\0" not in value
        and (not absolute or value.startswith("/"))
        and len(value.encode("utf-8")) <= limit
    )


def _sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _fail(code: str, message: str) -> None:
    raise ChildProfileRuntimeError(code, message)
