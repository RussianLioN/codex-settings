"""Strict public installer command boundary for lifecycle protocol v2."""

from __future__ import annotations

import argparse
import copy
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .canonical_json import CanonicalJsonError, domain_fingerprint


RESULT_DOMAIN_V2 = "codex-smart/command-result/v2"
CHANGE_ORDER_V2 = (
    "migrated_manifest",
    "attested_codex",
    "staged_generation",
    "gate_closed",
    "installed_bootstrap_fence",
    "drained_controller",
    "migrated_database",
    "published_activation",
    "registered_marketplace",
    "enabled_plugin",
    "repaired_launchers",
    "accepted_controller",
    "committed_manifest",
    "gate_opened",
    "retired_generation",
    "removed_installation",
)
_CHANGE_RANK = {kind: rank for rank, kind in enumerate(CHANGE_ORDER_V2)}
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}
_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_SCHEMA_PATH = (
    _REPO_ROOT / "docs/contracts/schemas/lifecycle-command-result-v2.schema.json"
)
InstallerCommandNameV2 = Literal[
    "apply",
    "doctor",
    "smoke",
    "inspect",
    "rollback",
    "uninstall",
    "recover",
    "cleanup",
]
_OPERATION_MODES = (
    "doctor",
    "smoke",
    "inspect",
    "rollback",
    "uninstall",
    "recover",
    "cleanup",
)
_READ_ONLY_COMMANDS = frozenset({"doctor", "smoke", "inspect"})
_NEW_MUTATING_COMMANDS = frozenset({"rollback", "uninstall", "recover", "cleanup"})


class LifecycleCommandResultV2Error(ValueError):
    """Raised when a public lifecycle result is structurally invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class InvalidInstallerInvocationV2(ValueError):
    """Raised instead of terminating the process for invalid public argv."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "INVALID_INVOCATION"
        self.message = message


class ProvenTemporaryBusyV2(RuntimeError):
    """A temporary busy outcome backed by explicit machine-readable proof."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        proof: Mapping[str, Any],
    ) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("temporary busy code must be non-empty")
        if not isinstance(message, str) or not message:
            raise ValueError("temporary busy message must be non-empty")
        if not isinstance(proof, Mapping) or not proof:
            raise ValueError("temporary busy outcome requires proof")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.proof = copy.deepcopy(dict(proof))


@dataclass(frozen=True)
class InstallerInvocationV2:
    command: InstallerCommandNameV2
    execute: bool
    json: bool
    source_root: str
    codex_home: str | None
    bin_dir: str | None
    state_home: str | None
    codex_binary: str
    retain_data: bool


class _InstallerArgumentParserV2(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvalidInstallerInvocationV2(message)


def parse_installer_argv_v2(
    argv: Sequence[str],
    *,
    default_source_root: str | Path | None = None,
) -> InstallerInvocationV2:
    """Parse public installer arguments without exiting the hosting process."""

    parser = _InstallerArgumentParserV2(add_help=False, allow_abbrev=False)
    parser.add_argument("--source-root", default=str(default_source_root or _REPO_ROOT))
    parser.add_argument("--codex-home")
    parser.add_argument("--bin-dir")
    parser.add_argument("--state-home")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--retain-data", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    for name in _OPERATION_MODES:
        modes.add_argument(f"--{name}", action="store_true")
    arguments = parser.parse_args(list(argv))
    command: InstallerCommandNameV2 = "apply"
    for name in _OPERATION_MODES:
        if getattr(arguments, name):
            command = name
            break
    read_only = command in _READ_ONLY_COMMANDS
    new_mutating = command in _NEW_MUTATING_COMMANDS
    if arguments.preview and arguments.apply:
        raise InvalidInstallerInvocationV2(
            "укажите только один модификатор: --preview или --apply"
        )
    if read_only and (arguments.preview or arguments.apply):
        raise InvalidInstallerInvocationV2(
            f"--{command} не принимает --preview или --apply"
        )
    if new_mutating and arguments.preview == arguments.apply:
        raise InvalidInstallerInvocationV2(
            f"--{command} требует ровно один из --preview или --apply"
        )
    if command == "uninstall" and not arguments.retain_data:
        raise InvalidInstallerInvocationV2(
            "--uninstall требует явный флаг --retain-data"
        )
    if command != "uninstall" and arguments.retain_data:
        raise InvalidInstallerInvocationV2(
            "--retain-data разрешён только вместе с --uninstall"
        )
    return InstallerInvocationV2(
        command=command,
        execute=read_only or arguments.apply,
        json=arguments.json,
        source_root=arguments.source_root,
        codex_home=arguments.codex_home,
        bin_dir=arguments.bin_dir,
        state_home=arguments.state_home,
        codex_binary=arguments.codex_binary,
        retain_data=arguments.retain_data,
    )


def build_lifecycle_command_result_v2(
    *,
    command: str,
    status: str,
    readiness: str,
    operation_id: str | None = None,
    attempt_id: str | None = None,
    smoke_invocation_id: str | None = None,
    changes: Sequence[Mapping[str, Any]] = (),
    problems: Sequence[Mapping[str, Any]] = (),
    extensions: Mapping[str, Any] | None = None,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Build, fingerprint, and schema-validate one public lifecycle result."""

    try:
        normalized_changes = [copy.deepcopy(dict(change)) for change in changes]
        normalized_problems = [copy.deepcopy(dict(problem)) for problem in problems]
        normalized_extensions = copy.deepcopy(dict(extensions or {}))
        normalized_changes.sort(key=lambda change: _CHANGE_RANK[change["kind"]])
        normalized_problems.sort(
            key=lambda problem: (
                _SEVERITY_RANK[problem["severity"]],
                problem["component"].encode("utf-8"),
                problem["code"].encode("utf-8"),
                problem["message"].encode("utf-8"),
            )
        )
    except (AttributeError, KeyError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise LifecycleCommandResultV2Error(
            "RESULT_INPUT_INVALID", "result collections cannot be normalized"
        ) from exc

    result: dict[str, Any] = {
        "schemaVersion": 2,
        "command": command,
        "status": status,
        "readiness": readiness,
        "operationId": operation_id,
        "attemptId": attempt_id,
        "smokeInvocationId": smoke_invocation_id,
        "resultFingerprint": "",
        "changes": normalized_changes,
        "problems": normalized_problems,
        "extensions": normalized_extensions,
    }
    try:
        result["resultFingerprint"] = domain_fingerprint(
            RESULT_DOMAIN_V2, _result_projection_v2(result)
        )
    except (CanonicalJsonError, KeyError, TypeError) as exc:
        raise LifecycleCommandResultV2Error(
            "RESULT_FINGERPRINT_INPUT_INVALID",
            "result projection is outside canonical-json-v1",
        ) from exc

    _validate_result(
        result,
        schema_path=(schema_path or _DEFAULT_SCHEMA_PATH).resolve(),
    )
    return result


def exit_code_v2(
    outcome: Mapping[str, Any] | BaseException,
    *,
    schema_path: Path | None = None,
) -> int:
    """Map one public outcome to the closed installer exit-code set."""

    if isinstance(outcome, InvalidInstallerInvocationV2):
        return 64
    if isinstance(outcome, ProvenTemporaryBusyV2):
        return 75
    if isinstance(outcome, BaseException) or not isinstance(outcome, Mapping):
        return 70
    try:
        _validate_result(
            outcome,
            schema_path=(schema_path or _DEFAULT_SCHEMA_PATH).resolve(),
        )
    except Exception:  # boundary maps all structural/internal failures to EX_SOFTWARE
        return 70
    blocking_problem = any(
        problem["severity"] == "error" for problem in outcome["problems"]
    )
    successful_disabled_lifecycle = (
        outcome["readiness"] == "DISABLED"
        and (
            (
                outcome["command"] == "uninstall"
                and outcome["status"] in {"uninstalled", "unchanged"}
            )
            or (
                outcome["command"] == "recover"
                and outcome["status"] in {"recovered", "unchanged"}
            )
        )
    )
    if (
        (
            outcome["readiness"] == "READY"
            and outcome["status"] != "failed"
        )
        or successful_disabled_lifecycle
    ) and not blocking_problem:
        return 0
    return 2


def _validate_result(
    result: Mapping[str, Any],
    *,
    schema_path: Path,
) -> None:
    try:
        serialized = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        serialized.encode("utf-8")
        if json.loads(serialized) != result:
            raise TypeError("JSON round trip changed the result")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise LifecycleCommandResultV2Error(
            "RESULT_JSON_INVALID", "result is outside the strict JSON data model"
        ) from exc

    try:
        validator = _load_result_validator(schema_path)
    except ModuleNotFoundError:
        _validate_result_shape_without_dependency_v2(result, schema_path=schema_path)
    else:
        errors = sorted(
            validator.iter_errors(result),
            key=lambda error: tuple(str(part) for part in error.path),
        )
        if errors:
            raise LifecycleCommandResultV2Error(
                "RESULT_SCHEMA_INVALID", errors[0].message
            )

    changes = result["changes"]
    kinds = [change["kind"] for change in changes]
    if len(kinds) != len(set(kinds)):
        raise LifecycleCommandResultV2Error(
            "CHANGE_KIND_DUPLICATE", "each change kind may occur at most once"
        )
    if kinds != sorted(kinds, key=_CHANGE_RANK.__getitem__):
        raise LifecycleCommandResultV2Error(
            "CHANGE_ORDER_INVALID", "changes are outside normative order"
        )
    if any(
        change["beforeFingerprint"] == change["afterFingerprint"] for change in changes
    ):
        raise LifecycleCommandResultV2Error(
            "CHANGE_NO_EFFECT", "a reported change must alter its fingerprint"
        )
    if "retired_generation" in kinds and not (
        result["command"] == "cleanup" and result["status"] == "cleaned"
    ):
        raise LifecycleCommandResultV2Error(
            "RETIRED_GENERATION_OUTSIDE_CLEANUP",
            "retired_generation belongs only to successful cleanup",
        )
    if "removed_installation" in kinds and not (
        result["command"] == "uninstall" and result["status"] == "uninstalled"
    ):
        raise LifecycleCommandResultV2Error(
            "REMOVED_INSTALLATION_OUTSIDE_UNINSTALL",
            "removed_installation belongs only to successful uninstall",
        )

    problems = result["problems"]
    expected_problems = sorted(
        problems,
        key=lambda problem: (
            _SEVERITY_RANK[problem["severity"]],
            problem["component"].encode("utf-8"),
            problem["code"].encode("utf-8"),
            problem["message"].encode("utf-8"),
        ),
    )
    if list(problems) != expected_problems:
        raise LifecycleCommandResultV2Error(
            "PROBLEM_ORDER_INVALID", "problems are outside normative order"
        )

    expected_fingerprint = domain_fingerprint(
        RESULT_DOMAIN_V2, _result_projection_v2(result)
    )
    if result["resultFingerprint"] != expected_fingerprint:
        raise LifecycleCommandResultV2Error(
            "RESULT_FINGERPRINT_MISMATCH",
            "result fingerprint does not match its normative projection",
        )


def _result_projection_v2(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": result["schemaVersion"],
        "command": result["command"],
        "status": result["status"],
        "readiness": result["readiness"],
        "smokeInvocationId": result["smokeInvocationId"],
        "changes": copy.deepcopy(result["changes"]),
        "problems": [
            {
                "code": problem["code"],
                "severity": problem["severity"],
                "component": problem["component"],
            }
            for problem in result["problems"]
        ],
    }


@lru_cache(maxsize=8)
def _load_result_validator(schema_path: Path):
    from jsonschema import Draft202012Validator

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, TypeError, ValueError) as exc:
        raise LifecycleCommandResultV2Error(
            "RESULT_SCHEMA_UNAVAILABLE", "normative result schema cannot be loaded"
        ) from exc
    return Draft202012Validator(schema)


def _validate_result_shape_without_dependency_v2(
    result: Mapping[str, Any],
    *,
    schema_path: Path,
) -> None:
    """Проверить закрытый публичный результат средствами стандартной библиотеки.

    Установщик документирован как прямой ``python3``-скрипт и обязан уметь
    сообщить результат ещё до появления зависимостей расширения. Наличие и
    идентичность нормативной схемы всё равно проверяются; эта функция повторяет
    её закрытые структурные ограничения для загрузочного контура.
    """

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise LifecycleCommandResultV2Error(
            "RESULT_SCHEMA_UNAVAILABLE", "normative result schema cannot be loaded"
        ) from exc
    if (
        type(schema) is not dict
        or schema.get("$id")
        != "https://codex-settings.local/schemas/lifecycle-command-result-v2.schema.json"
    ):
        raise LifecycleCommandResultV2Error(
            "RESULT_SCHEMA_UNAVAILABLE", "normative result schema identity differs"
        )

    required = {
        "schemaVersion",
        "command",
        "status",
        "readiness",
        "operationId",
        "attemptId",
        "smokeInvocationId",
        "resultFingerprint",
        "changes",
        "problems",
        "extensions",
    }
    if type(result) is not dict or set(result) != required:
        _shape_error("result fields differ from the closed schema")
    commands = {
        "apply",
        "doctor",
        "smoke",
        "inspect",
        "rollback",
        "cleanup",
        "uninstall",
        "recover",
    }
    readiness_values = {
        "READY",
        "AWAITING_HOOK_TRUST",
        "DISABLED",
        "DEGRADED",
        "BROKEN",
    }
    if result["schemaVersion"] != 2 or result["command"] not in commands:
        _shape_error("result schemaVersion or command is invalid")
    if (
        type(result["status"]) is not str
        or not 1 <= len(result["status"]) <= 64
        or result["readiness"] not in readiness_values
        or not _matches_or_none(result["operationId"], r"^op2_[0-9a-f]{32}$")
        or not _matches_or_none(result["attemptId"], r"^opa2_[0-9a-f]{32}$")
        or not _matches_or_none(result["smokeInvocationId"], r"^sm2_[0-9a-f]{32}$")
        or type(result["resultFingerprint"]) is not str
        or re.fullmatch(r"^[0-9a-f]{64}$", result["resultFingerprint"]) is None
    ):
        _shape_error("result scalar field is invalid")
    if type(result["extensions"]) is not dict or len(result["extensions"]) > 128:
        _shape_error("result extensions are invalid")

    changes = result["changes"]
    if type(changes) is not list or len(changes) > 16:
        _shape_error("result changes are invalid")
    for change in changes:
        if type(change) is not dict or set(change) != {
            "kind",
            "beforeFingerprint",
            "afterFingerprint",
        }:
            _shape_error("change fields differ from the closed schema")
        if change["kind"] not in CHANGE_ORDER_V2 or not all(
            _matches_or_none(change[name], r"^[0-9a-f]{64}$")
            for name in ("beforeFingerprint", "afterFingerprint")
        ):
            _shape_error("change value is invalid")

    problems = result["problems"]
    if type(problems) is not list or len(problems) > 128:
        _shape_error("result problems are invalid")
    for problem in problems:
        if type(problem) is not dict or set(problem) != {
            "code",
            "severity",
            "component",
            "message",
            "remediation",
        }:
            _shape_error("problem fields differ from the closed schema")
        if (
            type(problem["code"]) is not str
            or re.fullmatch(r"^[A-Z][A-Z0-9_]{0,127}$", problem["code"]) is None
            or problem["severity"] not in _SEVERITY_RANK
            or not _bounded_string(problem["component"], 256)
            or not _bounded_string(problem["message"], 2048)
            or not _bounded_string(problem["remediation"], 4096)
        ):
            _shape_error("problem value is invalid")

    command = result["command"]
    statuses = {
        "apply": {
            "planned",
            "installed",
            "upgraded",
            "reconciled",
            "repaired",
            "unchanged",
            "failed",
        },
        "doctor": {"READY", "AWAITING_HOOK_TRUST", "DEGRADED", "BROKEN"},
        "smoke": {"READY", "NOT_READY", "failed"},
        "inspect": {"inspected", "failed"},
        "rollback": {"planned", "rolled_back", "unchanged", "failed"},
        "cleanup": {"planned", "cleaned", "unchanged", "failed"},
        "uninstall": {"planned", "uninstalled", "unchanged", "failed"},
        "recover": {"planned", "recovered", "unchanged", "failed"},
    }
    if result["status"] not in statuses[command]:
        _shape_error("status is invalid for command")

    if command == "doctor":
        if (
            result["status"] != result["readiness"]
            or any(
                result[name] is not None
                for name in ("operationId", "attemptId", "smokeInvocationId")
            )
            or changes
        ):
            _shape_error("doctor state is invalid")
        return
    if command == "smoke":
        if (
            result["operationId"] is not None
            or result["attemptId"] is not None
            or result["smokeInvocationId"] is None
            or changes
            or (
                result["status"] == "READY" and result["readiness"] != "READY"
            )
            or (
                result["status"] != "READY" and result["readiness"] == "READY"
            )
        ):
            _shape_error("smoke state is invalid")
        return
    if command == "inspect":
        if any(
            result[name] is not None
            for name in ("operationId", "attemptId", "smokeInvocationId")
        ) or changes:
            _shape_error("inspect state is invalid")
        return

    if result["smokeInvocationId"] is not None:
        _shape_error("mutating command cannot contain smokeInvocationId")
    if result["status"] in {"planned", "unchanged"}:
        if result["operationId"] is not None or result["attemptId"] is not None or changes:
            _shape_error("planned or unchanged mutating state is invalid")
    elif result["status"] == "failed":
        ids = (result["operationId"], result["attemptId"])
        if (ids[0] is None) != (ids[1] is None):
            _shape_error("failed mutating state has a partial operation identity")
    elif result["operationId"] is None or result["attemptId"] is None:
        _shape_error("successful mutating state requires operation identity")


def _matches_or_none(value: Any, pattern: str) -> bool:
    return value is None or (type(value) is str and re.fullmatch(pattern, value) is not None)


def _bounded_string(value: Any, maximum: int) -> bool:
    return type(value) is str and 1 <= len(value) <= maximum


def _shape_error(message: str) -> None:
    raise LifecycleCommandResultV2Error("RESULT_SCHEMA_INVALID", message)
