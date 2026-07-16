"""Strict TOML catalog for adaptive-subagent routing and resource limits."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT_KEYS = {
    "schema_version",
    "algorithm_version",
    "supported_codex_versions",
    "supported_platforms",
    "models",
    "limits",
    "profiles",
    "retention",
    "validation",
}
MODEL_KEYS = {"reasoning_efforts", "rank"}
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
}
PROFILE_KEYS = {"permission_profile", "writer", "network"}
RETENTION_KEYS = {"success_days", "failure_days"}
VALIDATION_KEYS = {"commands"}
EXPECTED_MODELS = {
    "gpt-5.6-luna": (0, ("low", "medium")),
    "gpt-5.6-terra": (1, ("medium", "high", "xhigh")),
    "gpt-5.6-sol": (2, ("high", "xhigh", "max")),
}


@dataclass(frozen=True)
class CatalogError(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Catalog:
    source: Path
    generation: str
    canonical_sha256: str
    algorithm_version: str
    supported_codex_versions: tuple[str, ...]
    supported_platforms: tuple[str, ...]
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
        _validate_catalog(data)
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
            algorithm_version=data["algorithm_version"],
            supported_codex_versions=tuple(data["supported_codex_versions"]),
            supported_platforms=tuple(data["supported_platforms"]),
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


def _validate_catalog(data: dict[str, Any]) -> None:
    _exact_keys(data, ROOT_KEYS, "catalog")
    if data["schema_version"] != 1:
        raise CatalogError("schema_version must be 1")
    if data["algorithm_version"] != "route-v1":
        raise CatalogError("algorithm_version must be route-v1")
    _string_list(data["supported_codex_versions"], "supported_codex_versions")
    _string_list(data["supported_platforms"], "supported_platforms")

    models = _mapping(data["models"], "models")
    if set(models) != set(EXPECTED_MODELS):
        raise CatalogError("models must define exactly Luna, Terra, and Sol")
    for name, (rank, efforts) in EXPECTED_MODELS.items():
        settings = _mapping(models[name], f"models.{name}")
        _exact_keys(settings, MODEL_KEYS, f"models.{name}")
        if settings["rank"] != rank:
            raise CatalogError(f"models.{name}.rank must be {rank}")
        if tuple(settings["reasoning_efforts"]) != efforts:
            raise CatalogError(
                f"models.{name}.reasoning_efforts must be {efforts}"
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
            ):
                raise CatalogError(
                    f"validation.{name}.commands[{index}] "
                    "must be a non-empty argv array"
                )


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

