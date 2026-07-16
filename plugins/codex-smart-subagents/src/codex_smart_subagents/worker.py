"""One-node reader worker that joins snapshot, canary, and child execution."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable

from .child_runner import (
    ChildRunRequest,
    ChildRunResult,
    ChildRunner,
    ChildRuntimeLayout,
    ChildTelemetryConfig,
    PermissionProfileDefinition,
)
from .snapshot import (
    SnapshotBuilder,
    SnapshotResult,
    SourceManifest,
    capture_source_manifest,
)


@dataclass
class ChildWorkerError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ChildWorkRequest:
    repository: Path
    base_sha: str
    runtime_root: Path
    codex_executable: Path
    codex_version: str
    model: str
    reasoning_effort: str
    permission_profile_name: str
    managed_config_sha256: str
    output_schema: Path
    prompt: str
    timeout_seconds: float
    max_output_bytes: int
    auth_file: Path | None = None
    telemetry: ChildTelemetryConfig | None = None

    def __post_init__(self) -> None:
        try:
            repository = self.repository.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("repository must exist") from exc
        if os.fspath(repository) in self.prompt:
            raise ValueError(
                "child model input must not contain the canonical source path"
            )
        object.__setattr__(self, "repository", repository)


@dataclass(frozen=True)
class ChildWorkResult:
    runtime: ChildRuntimeLayout
    snapshot: SnapshotResult
    child: ChildRunResult
    source_after_child: SourceManifest


ChildRunnerFactory = Callable[
    [
        PermissionProfileDefinition,
        SnapshotResult,
        ChildWorkRequest,
        ChildRuntimeLayout,
    ],
    ChildRunner,
]


class ChildWorker:
    """Execute the first, read-only worker slice with source integrity seals."""

    def __init__(
        self,
        *,
        snapshot_builder: SnapshotBuilder,
        child_runner: ChildRunner | None = None,
        child_runner_factory: ChildRunnerFactory | None = None,
    ) -> None:
        if (child_runner is None) == (child_runner_factory is None):
            raise ValueError(
                "exactly one child runner strategy must be configured"
            )
        self.snapshot_builder = snapshot_builder
        self.child_runner = child_runner
        self.child_runner_factory = child_runner_factory

    def run(
        self,
        request: ChildWorkRequest,
        *,
        cancellation: Event | None = None,
    ) -> ChildWorkResult:
        runtime = ChildRuntimeLayout.create(request.runtime_root)
        snapshot = self.snapshot_builder.build(
            repository=request.repository,
            base_sha=request.base_sha,
            destination=runtime.root / "snapshot",
        )
        profile = PermissionProfileDefinition.reader(
            name=request.permission_profile_name,
            snapshot_root=snapshot.root,
        )
        child_runner = self.child_runner
        if self.child_runner_factory is not None:
            child_runner = self.child_runner_factory(
                profile,
                snapshot,
                request,
                runtime,
            )
        if child_runner is None:
            raise ChildWorkerError(
                "CHILD_RUNNER_UNAVAILABLE",
                "child runner factory did not return a runner",
            )
        child_request = ChildRunRequest(
            codex_executable=request.codex_executable,
            codex_version=request.codex_version,
            model=request.model,
            reasoning_effort=request.reasoning_effort,
            permission_profile=profile,
            managed_config_sha256=request.managed_config_sha256,
            runtime=runtime,
            output_schema=request.output_schema,
            prompt=request.prompt,
            timeout_seconds=request.timeout_seconds,
            max_output_bytes=request.max_output_bytes,
            auth_file=request.auth_file,
            telemetry=request.telemetry,
        )

        child_error: Exception | None = None
        child: ChildRunResult | None = None
        try:
            child = child_runner.run(
                child_request,
                cancellation=cancellation,
            )
        except Exception as exc:
            child_error = exc

        source_after_child = capture_source_manifest(request.repository)
        if source_after_child != snapshot.source_after:
            raise ChildWorkerError(
                "SOURCE_CHANGED_DURING_CHILD",
                "source Git state changed after the read-only snapshot seal",
            ) from child_error
        if child_error is not None:
            raise child_error
        assert child is not None
        return ChildWorkResult(
            runtime=runtime,
            snapshot=snapshot,
            child=child,
            source_after_child=source_after_child,
        )
