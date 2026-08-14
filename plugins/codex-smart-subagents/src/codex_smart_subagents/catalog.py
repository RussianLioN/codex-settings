"""Strict TOML catalog for adaptive-subagent routing and resource limits."""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compatibility import codex_version_supported


ROOT_KEYS = {
    "schema_version",
    "algorithm_version",
    "minimum_codex_version",
    "supported_platforms",
    "coordinator",
    "models",
    "limits",
    "profiles",
    "retention",
    "validation",
}
MODEL_KEYS = {"reasoning_efforts", "rank"}
COORDINATOR_V1_KEYS = {"model", "reasoning_effort"}
COORDINATOR_V2_KEYS = {"selection", "candidates"}
COORDINATOR_CANDIDATE_KEYS = {"model", "reasoning_effort"}
COORDINATOR_SELECTION = "first-verified-available"
LIMIT_KEYS = {
    "global_processes",
    "root_processes",
    "sol_processes",
    "queue_nodes",
    "lease_seconds",
    "heartbeat_seconds",
    "recover_after_seconds",
    "max_nodes",
    "max_edges",
    "max_depth",
    "max_split_generation",
    "snapshot_max_files",
    "snapshot_max_file_bytes",
    "snapshot_max_total_bytes",
    "child_timeout_seconds",
    "child_max_output_bytes",
    "min_free_disk_bytes",
    "min_available_memory_bytes",
    "min_available_fds",
    "validation_timeout_seconds",
    "validation_max_output_bytes",
    "validation_max_address_space_bytes",
    "validation_max_processes",
    "validation_max_file_bytes",
    "validation_max_open_files",
    "validation_max_growth_bytes",
}
PROFILE_KEYS = {"permission_profile", "writer", "network"}
RETENTION_KEYS = {"success_days", "failure_days"}
VALIDATION_KEYS = {"commands"}
EXPECTED_MODELS_V1 = {
    "gpt-5.6-luna": (0, ("low", "medium")),
    "gpt-5.6-terra": (1, ("medium", "high", "xhigh")),
    "gpt-5.6-sol": (2, ("high", "xhigh", "max")),
}
EXPECTED_MODELS_V2 = {
    **EXPECTED_MODELS_V1,
    "gpt-5.6-sol": (2, ("medium", "high", "xhigh", "max")),
}


@dataclass
class CatalogError(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Catalog:
    source: Path
    generation: str
    canonical_sha256: str
    schema_version: int
    algorithm_version: str
    minimum_codex_version: str
    supported_platforms: tuple[str, ...]
    coordinator: dict[str, str]
    coordinator_selection: str
    coordinator_candidates: tuple[dict[str, str], ...]
    models: dict[str, dict[str, Any]]
    limits: dict[str, int]
    profiles: dict[str, dict[str, Any]]
    retention: dict[str, int]
    validation: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: Path) -> "Catalog":
        source = path.expanduser().resolve()
        try:
            data = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise CatalogError(f"cannot load catalog {source}: {exc}") from exc
        coordinator_selection, coordinator_candidates = _validate_catalog(data)
        normalized = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return cls(
            source=source,
            generation=f"cg1_{digest[:16]}",
            canonical_sha256=digest,
            schema_version=data["schema_version"],
            algorithm_version=data["algorithm_version"],
            minimum_codex_version=data["minimum_codex_version"],
            supported_platforms=tuple(data["supported_platforms"]),
            coordinator=dict(coordinator_candidates[0]),
            coordinator_selection=coordinator_selection,
            coordinator_candidates=tuple(
                dict(candidate) for candidate in coordinator_candidates
            ),
            models={
                name: dict(settings)
                for name, settings in data["models"].items()
            },
            limits=dict(data["limits"]),
            profiles={
                name: dict(settings)
                for name, settings in data["profiles"].items()
            },
            retention=dict(data["retention"]),
            validation={
                name: dict(settings)
                for name, settings in data["validation"].items()
            },
        )

    def opaque_id(self, kind: str, alias: str) -> str:
        if not kind.replace("_", "").isalnum() or not alias:
            raise CatalogError("opaque id kind and alias must be non-empty identifiers")
        material = (
            f"{self.canonical_sha256}\0{kind}\0{alias}".encode("utf-8")
        )
        return f"{kind}_{hashlib.sha256(material).hexdigest()[:16]}"

    def supports_codex_version(self, version: str) -> bool:
        return codex_version_supported(
            version,
            minimum=self.minimum_codex_version,
        )


def _validate_catalog(
    data: dict[str, Any],
) -> tuple[str, tuple[dict[str, str], ...]]:
    _exact_keys(data, ROOT_KEYS, "catalog")
    schema_version = data["schema_version"]
    if schema_version not in {1, 2}:
        raise CatalogError("schema_version must be 1 or 2")
    if data["algorithm_version"] != "route-v1":
        raise CatalogError("algorithm_version must be route-v1")
    minimum = data["minimum_codex_version"]
    if not isinstance(minimum, str) or not codex_version_supported(minimum):
        raise CatalogError(
            "minimum_codex_version must be a supported canonical stable version"
        )
    _string_list(data["supported_platforms"], "supported_platforms")

    models = _mapping(data["models"], "models")
    expected_models = (
        EXPECTED_MODELS_V1 if schema_version == 1 else EXPECTED_MODELS_V2
    )
    if set(models) != set(expected_models):
        raise CatalogError("models must define exactly Luna, Terra, and Sol")
    for name, (rank, efforts) in expected_models.items():
        settings = _mapping(models[name], f"models.{name}")
        _exact_keys(settings, MODEL_KEYS, f"models.{name}")
        if settings["rank"] != rank:
            raise CatalogError(f"models.{name}.rank must be {rank}")
        if tuple(settings["reasoning_efforts"]) != efforts:
            raise CatalogError(
                f"models.{name}.reasoning_efforts must be {efforts}"
            )

    coordinator_selection, coordinator_candidates = _validate_coordinator(
        data["coordinator"],
        schema_version=schema_version,
        models=models,
    )

    limits = _mapping(data["limits"], "limits")
    _exact_keys(limits, LIMIT_KEYS, "limits")
    for name, value in limits.items():
        if type(value) is not int or value <= 0:
            raise CatalogError(f"limits.{name} must be a positive integer")
    if limits["heartbeat_seconds"] >= limits["lease_seconds"]:
        raise CatalogError("heartbeat_seconds must be below lease_seconds")
    if limits["lease_seconds"] >= limits["recover_after_seconds"]:
        raise CatalogError("lease_seconds must be below recover_after_seconds")
    if limits["root_processes"] > limits["global_processes"]:
        raise CatalogError("root_processes must not exceed global_processes")
    if limits["sol_processes"] > limits["root_processes"]:
        raise CatalogError("sol_processes must not exceed root_processes")

    profiles = _mapping(data["profiles"], "profiles")
    if set(profiles) != {"reader", "writer"}:
        raise CatalogError("profiles must define exactly reader and writer")
    for name, raw in profiles.items():
        settings = _mapping(raw, f"profiles.{name}")
        _exact_keys(settings, PROFILE_KEYS, f"profiles.{name}")
        if not isinstance(settings["permission_profile"], str):
            raise CatalogError(
                f"profiles.{name}.permission_profile must be a string"
            )
        if type(settings["writer"]) is not bool:
            raise CatalogError(f"profiles.{name}.writer must be boolean")
        if type(settings["network"]) is not bool:
            raise CatalogError(f"profiles.{name}.network must be boolean")
    if profiles["reader"]["writer"] or not profiles["writer"]["writer"]:
        raise CatalogError("reader/writer profile flags are inconsistent")
    if profiles["reader"]["network"] or profiles["writer"]["network"]:
        raise CatalogError("v1 child profiles must disable network")

    retention = _mapping(data["retention"], "retention")
    _exact_keys(retention, RETENTION_KEYS, "retention")
    for name, value in retention.items():
        if type(value) is not int or value <= 0:
            raise CatalogError(f"retention.{name} must be a positive integer")

    validation = _mapping(data["validation"], "validation")
    if not validation:
        raise CatalogError("at least one validation profile is required")
    for name, raw in validation.items():
        settings = _mapping(raw, f"validation.{name}")
        _exact_keys(settings, VALIDATION_KEYS, f"validation.{name}")
        commands = settings["commands"]
        if not isinstance(commands, list):
            raise CatalogError(f"validation.{name}.commands must be an array")
        for index, command in enumerate(commands):
            if (
                not isinstance(command, list)
                or not command
                or not all(isinstance(part, str) and part for part in command)
                or not os.path.isabs(command[0])
                or any("\0" in part for part in command)
            ):
                raise CatalogError(
                    f"validation.{name}.commands[{index}] "
                    "must be a safe absolute argv array"
                )
    return coordinator_selection, coordinator_candidates


def _validate_coordinator(
    raw: Any,
    *,
    schema_version: int,
    models: dict[str, Any],
) -> tuple[str, tuple[dict[str, str], ...]]:
    coordinator = _mapping(raw, "coordinator")
    if schema_version == 1:
        _exact_keys(coordinator, COORDINATOR_V1_KEYS, "coordinator")
        candidates = (dict(coordinator),)
    else:
        _exact_keys(coordinator, COORDINATOR_V2_KEYS, "coordinator")
        if coordinator["selection"] != COORDINATOR_SELECTION:
            raise CatalogError(
                f"coordinator.selection must be {COORDINATOR_SELECTION}"
            )
        raw_candidates = coordinator["candidates"]
        if (
            type(raw_candidates) is not list
            or not 1 <= len(raw_candidates) <= 8
        ):
            raise CatalogError("coordinator.candidates must contain 1 to 8 pairs")
        candidates = tuple(
            dict(_mapping(candidate, f"coordinator.candidates[{index}]"))
            for index, candidate in enumerate(raw_candidates)
        )
        for index, candidate in enumerate(candidates):
            _exact_keys(
                candidate,
                COORDINATOR_CANDIDATE_KEYS,
                f"coordinator.candidates[{index}]",
            )
    for index, candidate in enumerate(candidates):
        model = candidate["model"]
        effort = candidate["reasoning_effort"]
        if not isinstance(model, str) or model not in models:
            raise CatalogError(
                f"coordinator.candidates[{index}].model must reference "
                "a configured model"
            )
        configured_efforts = models[model]["reasoning_efforts"]
        if not isinstance(effort, str) or effort not in configured_efforts:
            raise CatalogError(
                f"coordinator.candidates[{index}].reasoning_effort must be "
                "supported by its model"
            )
    if schema_version == 2:
        identities = tuple(
            (candidate["model"], candidate["reasoning_effort"])
            for candidate in candidates
        )
        if len(identities) != len(set(identities)):
            raise CatalogError("coordinator.candidates must be unique")
    return COORDINATOR_SELECTION, candidates


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{path} must be a table")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("unknown " + ", ".join(extra))
        raise CatalogError(f"{path} keys are invalid: {'; '.join(parts)}")


def _string_list(value: Any, path: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise CatalogError(f"{path} must be a non-empty string array")
