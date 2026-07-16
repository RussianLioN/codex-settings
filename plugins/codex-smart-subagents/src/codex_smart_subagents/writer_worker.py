"""Single-writer worker over an isolated copy of an immutable Git snapshot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from .candidate import CandidateWorkspace, materialize_candidate_workspace
from .child_runner import (
    ChildRunRequest,
    ChildRunResult,
    ChildRunner,
    ChildResourceLimits,
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
from .worker import ChildRunnerFactory


@dataclass
class WriterWorkerError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class WriterWorkRequest:
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
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    resource_limits: ChildResourceLimits = ChildResourceLimits()
    auth_file: Path | None = None
    telemetry: ChildTelemetryConfig | None = None

    def __post_init__(self) -> None:
        try:
            repository = self.repository.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("repository must exist") from exc
        if os.fspath(repository) in self.prompt:
            raise ValueError(
                "writer model input must not contain the canonical source path"
            )
        object.__setattr__(self, "repository", repository)


@dataclass(frozen=True)
class WriterWorkResult:
    runtime: ChildRuntimeLayout
    snapshot: SnapshotResult
    workspace: CandidateWorkspace
    child: ChildRunResult
    source_after_child: SourceManifest


class WriterWorker:
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
        request: WriterWorkRequest,
        *,
        cancellation: Event | None = None,
    ) -> WriterWorkResult:
        runtime = ChildRuntimeLayout.create(request.runtime_root)
        snapshot = self.snapshot_builder.build(
            repository=request.repository,
            base_sha=request.base_sha,
            destination=runtime.root / "snapshot",
        )
        workspace = materialize_candidate_workspace(
            snapshot.root,
            runtime.root / "candidate",
            max_files=request.max_files,
            max_file_bytes=request.max_file_bytes,
            max_total_bytes=request.max_total_bytes,
        )
        profile = PermissionProfileDefinition.writer(
            name=request.permission_profile_name,
            snapshot_root=snapshot.root,
            writable_root=workspace.root,
        )
        child_runner = self.child_runner
        if self.child_runner_factory is not None:
            child_runner = self.child_runner_factory(
                profile,
                snapshot,
                request,  # type: ignore[arg-type]
                runtime,
            )
        if child_runner is None:
            raise WriterWorkerError(
                "CHILD_RUNNER_UNAVAILABLE",
                "writer child runner factory did not return a runner",
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
            resource_limits=request.resource_limits,
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
            raise WriterWorkerError(
                "SOURCE_CHANGED_DURING_WRITER",
                "source Git state changed after the writer snapshot seal",
            ) from child_error
        if child_error is not None:
            raise child_error
        assert child is not None
        return WriterWorkResult(
            runtime=runtime,
            snapshot=snapshot,
            workspace=workspace,
            child=child,
            source_after_child=source_after_child,
        )
