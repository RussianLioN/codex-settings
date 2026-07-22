"""Производственный исполнитель пяти стадий AccountEvidence."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from .evidence import ACCOUNT_ARGV, FIXED_PATH, EvidenceError
from .live_canary import AppServerError, StrictAppServerClient
from .managed_requirements_v1 import (
    ManagedRequirementsError,
    normalize_managed_requirements,
)
from .model_catalog import ModelCatalogError, read_account_model_pages


_STAGES = {
    "requirements-a",
    "catalog-a",
    "requirements-b",
    "catalog-b",
    "requirements-c",
}
_ENVIRONMENT_KEYS = {
    "CODEX_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "PATH",
    "TMPDIR",
}


class AppServerAccountEvidenceExecutorV2:
    """Открывает один новый app-server на каждую логическую стадию."""

    def __init__(
        self,
        *,
        client_factory: Callable[..., Any] = StrictAppServerClient,
        max_output_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if not callable(client_factory):
            raise TypeError("client_factory must be callable")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        self._client_factory = client_factory
        self._max_output_bytes = max_output_bytes

    def execute(
        self,
        stage: str,
        *,
        executable_path: str,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: float,
        cancel_check: Callable[[], bool] | None = None,
    ) -> Any:
        if stage not in _STAGES:
            self._fail("ACCOUNT_STAGE_INVALID", "неизвестная стадия AccountEvidence")
        if argv != ACCOUNT_ARGV:
            self._fail("ACCOUNT_ARGV_INVALID", "аргументы app-server изменены")
        executable = Path(executable_path)
        if not executable.is_absolute() or "\0" in executable_path:
            self._fail("ACCOUNT_EXECUTABLE_INVALID", "путь снимка неверен")
        if os.path.realpath(executable_path) != executable_path:
            self._fail(
                "ACCOUNT_EXECUTABLE_INVALID",
                "путь снимка должен быть каноническим",
            )
        environment = self._environment(environment)
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 180
        ):
            self._fail("ACCOUNT_DEADLINE_INVALID", "остаток срока неверен")
        client = self._client_factory(
            codex_executable=executable,
            codex_home=Path(environment["CODEX_HOME"]),
            home=Path(environment["HOME"]),
            tmpdir=Path(environment["TMPDIR"]),
            cwd=Path(environment["HOME"]),
            timeout_seconds=float(timeout_seconds),
            max_output_bytes=self._max_output_bytes,
            client_name="codex_smart_subagents",
            client_title="Codex Smart Subagents",
            client_version="0.2.0",
            use_temporary_sqlite_home=False,
            cancel_check=cancel_check,
        )
        try:
            if stage.startswith("requirements-"):
                return self._requirements(client)
            observed = client.run_session(read_account_model_pages)
            return [
                {"model": model, "reasoningEffort": effort}
                for model in sorted(observed, key=lambda value: value.encode("utf-8"))
                for effort in sorted(
                    observed[model], key=lambda value: value.encode("utf-8")
                )
            ]
        except EvidenceError:
            raise
        except ManagedRequirementsError as exc:
            raise EvidenceError(exc.code, str(exc)) from exc
        except ModelCatalogError as exc:
            raise EvidenceError(exc.code, exc.message) from exc
        except AppServerError as exc:
            if exc.code == "APP_SERVER_CANCELLED":
                raise EvidenceError(
                    "ACCOUNT_EVIDENCE_CANCELLED",
                    "сбор доказательств отменён",
                ) from exc
            raise EvidenceError("ACCOUNT_READ_FAILED", exc.message) from exc
        except (TypeError, ValueError, OSError) as exc:
            raise EvidenceError("ACCOUNT_READ_FAILED", str(exc)) from exc

    @staticmethod
    def _requirements(client: Any) -> Any:
        result = client.call("configRequirements/read", {})
        _validate_raw_requirements_envelope(result)
        if not isinstance(result, dict) or "requirements" not in result:
            raise EvidenceError(
                "MANAGED_REQUIREMENT_MALFORMED",
                "configRequirements/read не вернул requirements",
            )
        return normalize_managed_requirements(result["requirements"])

    @staticmethod
    def _environment(value: Mapping[str, str]) -> dict[str, str]:
        try:
            copied = copy.deepcopy(dict(value))
        except (TypeError, ValueError, RecursionError) as exc:
            raise EvidenceError(
                "ACCOUNT_ENVIRONMENT_INVALID", "окружение не является картой"
            ) from exc
        if set(copied) != _ENVIRONMENT_KEYS:
            raise EvidenceError(
                "ACCOUNT_ENVIRONMENT_INVALID", "набор переменных окружения изменён"
            )
        if (
            copied["LANG"] != "C"
            or copied["LC_ALL"] != "C"
            or copied["NO_COLOR"] != "1"
            or copied["PATH"] != FIXED_PATH
        ):
            raise EvidenceError(
                "ACCOUNT_ENVIRONMENT_INVALID", "постоянное окружение изменено"
            )
        for name, item in copied.items():
            if type(item) is not str or not item or "\0" in item:
                raise EvidenceError(
                    "ACCOUNT_ENVIRONMENT_INVALID", f"неверное значение {name}"
                )
        for name in ("CODEX_HOME", "HOME", "TMPDIR"):
            if not Path(copied[name]).is_absolute():
                raise EvidenceError(
                    "ACCOUNT_ENVIRONMENT_INVALID", f"{name} не является абсолютным путём"
                )
            if os.path.realpath(copied[name]) != copied[name]:
                raise EvidenceError(
                    "ACCOUNT_ENVIRONMENT_INVALID",
                    f"{name} не является каноническим путём",
                )
        return copied

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise EvidenceError(code, message)


def _validate_raw_requirements_envelope(value: Any) -> None:
    """Проверяет пределы разобранной внешней оболочки до копирования."""

    stack: list[tuple[Any, int, frozenset[int]]] = [(value, 0, frozenset())]
    nodes = 0
    while stack:
        current, depth, ancestors = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 16:
            raise EvidenceError(
                "MANAGED_REQUIREMENT_MALFORMED",
                "сырая оболочка требований превышает структурный предел",
            )
        if type(current) is dict:
            identity = id(current)
            if identity in ancestors:
                raise EvidenceError(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "сырая оболочка требований содержит цикл",
                )
            next_ancestors = ancestors | {identity}
            for key, child in current.items():
                if type(key) is not str:
                    raise EvidenceError(
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "сырая оболочка содержит нестроковый ключ",
                    )
                stack.append((child, depth + 1, next_ancestors))
        elif type(current) is list:
            identity = id(current)
            if identity in ancestors:
                raise EvidenceError(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "сырая оболочка требований содержит цикл",
                )
            next_ancestors = ancestors | {identity}
            for child in current:
                stack.append((child, depth + 1, next_ancestors))
        elif current is not None and type(current) not in {str, int, bool}:
            raise EvidenceError(
                "MANAGED_REQUIREMENT_MALFORMED",
                "сырая оболочка содержит неподдерживаемое значение",
            )
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceError(
            "MANAGED_REQUIREMENT_MALFORMED",
            "сырая оболочка требований не является каноническим JSON",
        ) from exc
    if len(encoded) > 1024 * 1024:
        raise EvidenceError(
            "MANAGED_REQUIREMENT_MALFORMED",
            "сырая оболочка требований превышает один МиБ",
        )
