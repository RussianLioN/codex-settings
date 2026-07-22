"""Получение защитной проекции встроенного каталога из снимка Codex."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical_json import domain_fingerprint
from .codex_binary_snapshot import (
    FIXED_PROCESS_PATH,
    SnapshotCommand,
    SnapshotCommandExecutor,
    SnapshotSubprocessExecutor,
)
from .evidence import build_interface_evidence, verify_interface_evidence
from .operation_deadline_v2 import OperationDeadlineExceededV2
from .policy_bundle_v2 import PolicyBundleV2


_MAX_OUTPUT_BYTES = 1024 * 1024
_MAX_MODELS = 256
_MAX_EFFORTS = 32
_MACHINE_SCHEMA_IDS = (
    "account-evidence-v1",
    "boundary-result-v1",
    "child-jsonl-v1",
    "child-profile-v1",
    "config-requirements-normalized-v1",
    "config-requirements-vector-recipe-v1",
    "interface-evidence-v1",
    "otel-logs-v1",
    "reader-result-v1",
    "routing-policy-v2",
    "writer-result-v1",
)
_APP_SERVER_OPTIONS = ("--strict-config", "--listen")
_EXEC_OPTIONS = (
    "--strict-config",
    "--model",
    "--skip-git-repo-check",
    "--ephemeral",
    "--ignore-user-config",
    "--ignore-rules",
    "--output-schema",
    "--json",
)


@dataclass
class InterfaceProbeV1Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class BundledCatalogEvidenceV1:
    projection: dict[str, Any]
    fingerprint: str


@dataclass(frozen=True)
class InterfaceEvidenceObservationV1:
    interface_evidence: dict[str, Any]
    bundled_catalog: BundledCatalogEvidenceV1


def probe_codex_interface_v1(
    *,
    subject: Mapping[str, Any],
    contract_root: Path,
    policy_bundle: PolicyBundleV2,
    executor: SnapshotCommandExecutor | None = None,
) -> InterfaceEvidenceObservationV1:
    """Проверяет требуемую поверхность снимка и строит InterfaceEvidence."""

    try:
        snapshot = Path(str(subject["snapshotPath"]))
    except (KeyError, TypeError, ValueError) as exc:
        _fail("INTERFACE_SUBJECT_INVALID", str(exc))
    runner = executor or SnapshotSubprocessExecutor()
    bundled = probe_bundled_catalog_v1(snapshot, executor=runner)
    _require_help_options(
        snapshot,
        ("app-server", "--help"),
        _APP_SERVER_OPTIONS,
        executor=runner,
    )
    _require_help_options(
        snapshot,
        ("exec", "--help"),
        _EXEC_OPTIONS,
        executor=runner,
    )
    schema_root = contract_root.expanduser() / "schemas"
    machine_schemas: dict[str, dict[str, str]] = {}
    for name in _MACHINE_SCHEMA_IDS:
        path = schema_root / f"{name}.schema.json"
        try:
            payload = path.read_bytes()
        except OSError as exc:
            _fail("INTERFACE_SCHEMA_MISSING", str(exc))
        machine_schemas[name] = {
            "schemaId": name,
            "schemaSha256": hashlib.sha256(payload).hexdigest(),
        }
    semantic = {
        "extensionRelease": "0.2.0",
        "contractVersion": "codex-interface-v1",
        "platformAdapter": "darwin-arm64-v1",
        "commands": ["app-server"],
        "options": ["--json"],
        "appServerMethods": ["model/list"],
        "machineSchemas": machine_schemas,
        "probeBudgets": {"full": 300},
        "negativeProbeIds": ["unknown-event"],
        "arg0AdapterVersion": "arg0-v1",
        "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
        "bundledCatalogFingerprint": bundled.fingerprint,
        "childProfiles": dict(policy_bundle.child_profile_fingerprints),
    }
    try:
        evidence = verify_interface_evidence(
            build_interface_evidence(
                subject=copy.deepcopy(dict(subject)),
                semantic=semantic,
            )
        )
    except OperationDeadlineExceededV2:
        raise
    except Exception as exc:
        _fail("INTERFACE_EVIDENCE_INVALID", str(exc))
    return InterfaceEvidenceObservationV1(
        interface_evidence=evidence,
        bundled_catalog=bundled,
    )


def probe_bundled_catalog_v1(
    executable: Path,
    *,
    executor: SnapshotCommandExecutor | None = None,
) -> BundledCatalogEvidenceV1:
    """Запускает только `debug models --bundled` у проверенного снимка."""

    candidate = executable.expanduser()
    if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
        _fail("BUNDLED_CATALOG_EXECUTABLE_INVALID", "путь снимка должен быть абсолютным")
    runner = executor or SnapshotSubprocessExecutor()
    command = SnapshotCommand(
        argv=(str(candidate), "debug", "models", "--bundled"),
        cwd=candidate.parent,
        environment={
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PROCESS_PATH,
        },
        timeout_seconds=10,
        max_output_bytes=_MAX_OUTPUT_BYTES,
    )
    try:
        result = runner.run(command)
    except OperationDeadlineExceededV2:
        raise
    except Exception as exc:
        _fail("BUNDLED_CATALOG_PROCESS_FAILED", str(exc))
    if (
        result.exit_code != 0
        or result.stderr
        or not result.stdout
        or len(result.stdout) > _MAX_OUTPUT_BYTES
    ):
        _fail(
            "BUNDLED_CATALOG_PROCESS_FAILED",
            "команда завершилась ошибкой или нарушила границы вывода",
        )
    try:
        raw = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("BUNDLED_CATALOG_JSON_INVALID", str(exc))
    projection = project_bundled_catalog_v1(raw)
    return BundledCatalogEvidenceV1(
        projection=projection,
        fingerprint=domain_fingerprint(
            "codex-smart/bundled-catalog/v1",
            projection,
        ),
    )


def project_bundled_catalog_v1(value: Any) -> dict[str, Any]:
    """Нормализует только защищённые поля, игнорируя описательные добавления."""

    if type(value) is not dict or type(value.get("models")) is not list:
        _fail("BUNDLED_CATALOG_INVALID", "корень не содержит массив models")
    raw_models = value["models"]
    if not 1 <= len(raw_models) <= _MAX_MODELS:
        _fail("BUNDLED_CATALOG_INVALID", "число моделей вне договора")

    models: list[dict[str, Any]] = []
    model_names: set[str] = set()
    for raw_model in raw_models:
        if type(raw_model) is not dict:
            _fail("BUNDLED_CATALOG_INVALID", "запись модели не является объектом")
        model = _bounded_identity(raw_model.get("slug"), maximum=128, field="slug")
        if model in model_names:
            _fail("BUNDLED_CATALOG_INVALID", "модель повторена")
        model_names.add(model)
        raw_efforts = raw_model.get("supported_reasoning_levels")
        if type(raw_efforts) is not list or not 1 <= len(raw_efforts) <= _MAX_EFFORTS:
            _fail("BUNDLED_CATALOG_INVALID", "уровни рассуждения вне договора")
        efforts: list[str] = []
        effort_names: set[str] = set()
        for raw_effort in raw_efforts:
            if type(raw_effort) is not dict:
                _fail("BUNDLED_CATALOG_INVALID", "уровень рассуждения не является объектом")
            effort = _bounded_identity(
                raw_effort.get("effort"),
                maximum=32,
                field="effort",
            )
            if effort in effort_names:
                _fail("BUNDLED_CATALOG_INVALID", "уровень рассуждения повторен")
            effort_names.add(effort)
            efforts.append(effort)
        models.append(
            {
                "model": model,
                "reasoningEfforts": sorted(efforts, key=lambda item: item.encode("utf-8")),
            }
        )
    models.sort(key=lambda item: item["model"].encode("utf-8"))
    return copy.deepcopy({"models": models})


def _require_help_options(
    executable: Path,
    arguments: tuple[str, ...],
    required: tuple[str, ...],
    *,
    executor: SnapshotCommandExecutor,
) -> None:
    command = SnapshotCommand(
        argv=(str(executable), *arguments),
        cwd=executable.parent,
        environment={
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PROCESS_PATH,
        },
        timeout_seconds=10,
        max_output_bytes=_MAX_OUTPUT_BYTES,
    )
    try:
        result = executor.run(command)
    except OperationDeadlineExceededV2:
        raise
    except Exception as exc:
        _fail("INTERFACE_HELP_FAILED", str(exc))
    if (
        result.exit_code != 0
        or result.stderr
        or not result.stdout
        or len(result.stdout) > _MAX_OUTPUT_BYTES
    ):
        _fail("INTERFACE_HELP_FAILED", "справка нарушила границы процесса")
    try:
        text = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        _fail("INTERFACE_HELP_INVALID", str(exc))
    for option in required:
        if option not in text:
            _fail("INTERFACE_OPTION_MISSING", option)


def _bounded_identity(value: Any, *, maximum: int, field: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character in value for character in "\0\r\n")
    ):
        _fail("BUNDLED_CATALOG_INVALID", f"неверное поле {field}")
    return value


def _fail(code: str, message: str) -> None:
    raise InterfaceProbeV1Error(code, message)
