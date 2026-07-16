"""Fail-closed verification of models bundled with the active Codex binary."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .catalog import Catalog
from .live_canary import AppServerError, StrictAppServerClient


MAX_CATALOG_BYTES = 16 * 1024 * 1024
PROBE_TIMEOUT_SECONDS = 15
FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
MAX_MODEL_LIST_PAGES = 8
MAX_MODEL_LIST_ROWS = 800


@dataclass
class ModelCatalogError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class AppServerModelCatalogInspector:
    """Read the account-visible model set from the strict app-server API."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        codex_home: Path,
        runtime_parent: Path,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 1024 * 1024,
        client_factory: Callable[..., Any] = StrictAppServerClient,
    ) -> None:
        self._codex = _owned_executable(codex_executable)
        self._codex_home = _private_directory(codex_home)
        self._runtime_parent = _owned_private_directory(runtime_parent)
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 60
        ):
            raise ValueError("timeout_seconds must be in (0, 60]")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._client_factory = client_factory

    def inspect(self) -> dict[str, frozenset[str]]:
        with tempfile.TemporaryDirectory(
            prefix="account-models-",
            dir=self._runtime_parent,
        ) as raw_root:
            root = Path(raw_root)
            home = _new_private_directory(root / "home")
            tmpdir = _new_private_directory(root / "tmp")
            cwd = _new_private_directory(root / "work")
            client = self._client_factory(
                codex_executable=self._codex,
                codex_home=self._codex_home,
                home=home,
                tmpdir=tmpdir,
                cwd=cwd,
                timeout_seconds=self._timeout_seconds,
                max_output_bytes=self._max_output_bytes,
            )
            return self._read_pages(client)

    def _read_pages(self, client: Any) -> dict[str, frozenset[str]]:
        observed: dict[str, frozenset[str]] = {}
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(MAX_MODEL_LIST_PAGES):
            parameters: dict[str, object] = {
                "includeHidden": True,
                "limit": 100,
            }
            if cursor is not None:
                parameters["cursor"] = cursor
            try:
                result = client.call("model/list", parameters)
            except AppServerError as exc:
                raise ModelCatalogError(
                    "MODEL_LIST_UNAVAILABLE",
                    "Codex account model list could not be read",
                ) from exc
            if (
                not isinstance(result, dict)
                or not set(result) <= {"data", "nextCursor"}
                or "data" not in result
                or not isinstance(result["data"], list)
                or len(result["data"]) > 100
            ):
                raise ModelCatalogError(
                    "MODEL_LIST_INVALID",
                    "Codex account model list is malformed",
                )
            for row in result["data"]:
                model, efforts = _account_model_record(row)
                if model in observed:
                    raise ModelCatalogError(
                        "MODEL_LIST_INVALID",
                        "Codex account model list contains a duplicate",
                    )
                observed[model] = efforts
                if len(observed) > MAX_MODEL_LIST_ROWS:
                    raise ModelCatalogError(
                        "MODEL_LIST_INVALID",
                        "Codex account model list exceeds the row limit",
                    )
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return observed
            if (
                not isinstance(next_cursor, str)
                or not next_cursor
                or len(next_cursor.encode("utf-8")) > 4096
                or next_cursor in seen_cursors
            ):
                raise ModelCatalogError(
                    "MODEL_LIST_INVALID",
                    "Codex account model cursor is invalid",
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise ModelCatalogError(
            "MODEL_LIST_INVALID",
            "Codex account model list exceeds the page limit",
        )


def parse_model_catalog(payload: bytes) -> dict[str, frozenset[str]]:
    if not payload or len(payload) > MAX_CATALOG_BYTES:
        raise ModelCatalogError(
            "MODEL_CATALOG_INVALID",
            "Codex model catalog size is outside the supported range",
        )
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelCatalogError(
            "MODEL_CATALOG_INVALID",
            "Codex model catalog is not valid JSON",
        ) from exc
    if isinstance(decoded, dict):
        records = decoded.get("models")
    else:
        records = decoded
    if not isinstance(records, list):
        raise ModelCatalogError(
            "MODEL_CATALOG_INVALID",
            "Codex model catalog must contain a model array",
        )

    observed: dict[str, frozenset[str]] = {}
    for raw in records:
        if not isinstance(raw, dict):
            raise ModelCatalogError(
                "MODEL_CATALOG_INVALID",
                "Codex model record must be an object",
            )
        slug = raw.get("slug")
        levels = raw.get("supported_reasoning_levels")
        if not isinstance(slug, str) or not slug or not isinstance(levels, list):
            raise ModelCatalogError(
                "MODEL_CATALOG_INVALID",
                "Codex model capability record is incomplete",
            )
        if slug in observed:
            raise ModelCatalogError(
                "MODEL_CATALOG_INVALID",
                f"Codex model catalog repeats {slug}",
            )
        efforts: set[str] = set()
        for level in levels:
            if not isinstance(level, dict):
                raise ModelCatalogError(
                    "MODEL_CATALOG_INVALID",
                    f"reasoning level for {slug} must be an object",
                )
            effort = level.get("effort")
            if not isinstance(effort, str) or not effort or effort in efforts:
                raise ModelCatalogError(
                    "MODEL_CATALOG_INVALID",
                    f"reasoning levels for {slug} are invalid",
                )
            efforts.add(effort)
        observed[slug] = frozenset(efforts)
    return observed


def probe_model_catalog(
    codex_executable: Path,
    codex_home: Path,
) -> dict[str, frozenset[str]]:
    executable = _owned_executable(codex_executable)
    home = _private_directory(codex_home)
    environment = {
        "CODEX_HOME": os.fspath(home),
        "HOME": os.fspath(home.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": FIXED_PATH,
    }
    try:
        result = subprocess.run(
            [os.fspath(executable), "debug", "models", "--bundled"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "Codex bundled model catalog probe failed",
        ) from exc
    if result.returncode != 0:
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "Codex bundled model catalog probe returned an error",
        )
    return parse_model_catalog(result.stdout)


def require_catalog_support(
    catalog: Catalog,
    observed: Mapping[str, frozenset[str]],
) -> None:
    for model, settings in catalog.models.items():
        supported = observed.get(model)
        if supported is None:
            raise ModelCatalogError(
                "MODEL_UNAVAILABLE",
                f"required model is absent from Codex catalog: {model}",
            )
        required = settings.get("reasoning_efforts")
        if (
            not isinstance(required, list)
            or not all(isinstance(item, str) for item in required)
        ):
            raise ModelCatalogError(
                "MODEL_POLICY_INVALID",
                f"active policy for {model} has invalid reasoning levels",
            )
        missing = set(required) - set(supported)
        if missing:
            raise ModelCatalogError(
                "MODEL_EFFORT_UNAVAILABLE",
                f"required reasoning levels are unavailable for {model}",
            )


def account_catalog_policy(
    catalog: Catalog,
    observed: Mapping[str, frozenset[str]],
) -> dict[str, frozenset[str]]:
    """Intersect account-visible capabilities with the trusted routing policy."""

    available: dict[str, frozenset[str]] = {}
    for model, settings in catalog.models.items():
        account_efforts = observed.get(model)
        if account_efforts is None:
            continue
        policy_efforts = settings.get("reasoning_efforts")
        if (
            not isinstance(policy_efforts, list)
            or not all(isinstance(item, str) for item in policy_efforts)
        ):
            raise ModelCatalogError(
                "MODEL_POLICY_INVALID",
                f"active policy for {model} has invalid reasoning levels",
            )
        allowed = frozenset(policy_efforts) & account_efforts
        if allowed:
            available[model] = allowed
    if not available:
        raise ModelCatalogError(
            "MODEL_UNAVAILABLE",
            "no trusted routing model is visible to the active account",
        )
    return available


def _account_model_record(value: object) -> tuple[str, frozenset[str]]:
    if not isinstance(value, dict):
        raise ModelCatalogError(
            "MODEL_LIST_INVALID",
            "Codex account model entry must be an object",
        )
    model = value.get("model")
    raw_efforts = value.get("supportedReasoningEfforts")
    if (
        not isinstance(model, str)
        or not model
        or len(model.encode("utf-8")) > 128
        or not isinstance(raw_efforts, list)
        or len(raw_efforts) > 32
    ):
        raise ModelCatalogError(
            "MODEL_LIST_INVALID",
            "Codex account model entry is incomplete",
        )
    efforts: set[str] = set()
    for item in raw_efforts:
        effort = (
            item.get("reasoningEffort")
            if isinstance(item, dict)
            else None
        )
        if (
            not isinstance(effort, str)
            or not effort
            or len(effort.encode("utf-8")) > 32
            or effort in efforts
        ):
            raise ModelCatalogError(
                "MODEL_LIST_INVALID",
                "Codex account reasoning efforts are invalid",
            )
        efforts.add(effort)
    return model, frozenset(efforts)


def _owned_private_directory(path: Path) -> Path:
    resolved = _private_directory(path)
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise ModelCatalogError(
            "MODEL_LIST_UNAVAILABLE",
            "model-list runtime parent must be private",
        )
    return resolved


def _new_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path.resolve(strict=True)


def _owned_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "Codex executable path must be absolute",
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "Codex executable cannot be inspected",
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o111 == 0
    ):
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "Codex executable is not a trusted executable file",
        )
    return resolved


def _private_directory(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "CODEX_HOME must be an absolute real directory",
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "CODEX_HOME cannot be inspected",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ModelCatalogError(
            "MODEL_CATALOG_UNAVAILABLE",
            "CODEX_HOME must be owned and not writable by other users",
        )
    return resolved
