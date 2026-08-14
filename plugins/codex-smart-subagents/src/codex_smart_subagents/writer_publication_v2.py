"""Закрытая подготовка и публикация карантинного кандидата версии 2."""

from __future__ import annotations

import os
import re
import stat
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Literal, Protocol

from .candidate import CandidateWorkspace, materialize_candidate_workspace
from .identity import canonical_sha256
from .quarantine import (
    BaseImport,
    CandidateEvidence,
    CandidateResult,
    QuarantineRepository,
    RepositoryManifest,
    repository_manifest,
)
from .snapshot import (
    SnapshotBuilder,
    SnapshotResult,
    SourceManifest,
    capture_source_manifest,
)
from .validation import ValidationError, ValidationResult, ValidationRunner


_IDENTIFIERS = {
    "route_id": re.compile(r"^route2_[0-9a-f]{32}$"),
    "node_id": re.compile(r"^node2_[0-9a-f]{32}$"),
    "attempt_id": re.compile(r"^att2_[0-9a-f]{32}$"),
}
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


@dataclass
class WriterPublicationV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class WriterPublicationRequestV2:
    """Полный вход подготовки одной рабочей копии автора."""

    route_id: str
    node_id: str
    attempt_id: str
    repository: Path
    base_sha: str
    attempt_root: Path
    quarantine_state_root: Path
    validation_commands: tuple[tuple[str, ...], ...]
    source_date_epoch: int
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    max_diff_bytes: int
    deadline_at: datetime | None = None

    def __post_init__(self) -> None:
        for name, pattern in _IDENTIFIERS.items():
            if pattern.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"{name} имеет неверный формат")
        if _GIT_SHA.fullmatch(self.base_sha) is None:
            raise ValueError("base_sha должен быть полным 40-значным SHA Git")
        try:
            repository = self.repository.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("repository недоступен") from exc
        if not repository.is_dir():
            raise ValueError("repository должен быть каталогом")
        attempt_root = _absolute_fresh_path(self.attempt_root, "attempt_root")
        state_root = self.quarantine_state_root.expanduser()
        if not state_root.is_absolute():
            raise ValueError("quarantine_state_root должен быть абсолютным")
        if state_root.exists() and state_root.is_symlink():
            raise ValueError("quarantine_state_root не может быть ссылкой")
        commands = tuple(tuple(command) for command in self.validation_commands)
        if not commands or any(
            not command
            or any(
                type(argument) is not str or not argument or "\0" in argument
                for argument in command
            )
            for command in commands
        ):
            raise ValueError("validation_commands содержит неверную команду")
        if type(self.source_date_epoch) is not int or self.source_date_epoch < 0:
            raise ValueError("source_date_epoch должен быть неотрицательным целым")
        for name in (
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_diff_bytes",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} должен быть положительным целым")
        if self.deadline_at is not None and self.deadline_at.tzinfo is None:
            raise ValueError("deadline_at должен содержать часовой пояс")
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "attempt_root", attempt_root)
        object.__setattr__(self, "quarantine_state_root", state_root)
        object.__setattr__(self, "validation_commands", commands)


@dataclass(frozen=True)
class CandidateRefPublicationV2:
    """Вход владельца публикации ссылки Git.

    Реализация с базой состояния сможет записать намерение до ``update-ref``
    и завершить его после получения доказательства, не меняя координатор.
    """

    route_id: str
    node_id: str
    attempt_id: str
    quarantine: QuarantineRepository
    base: BaseImport
    candidate: CandidateResult
    source_manifest_sha256: str
    validation: ValidationResult
    validation_proof_sha256: str


class CandidateRefPublisherV2(Protocol):
    def publish(
        self,
        publication: CandidateRefPublicationV2,
    ) -> CandidateEvidence: ...


class DirectCandidateRefPublisherV2:
    """Минимальная публикация ссылки без хранилища состояния версии 2."""

    def publish(
        self,
        publication: CandidateRefPublicationV2,
    ) -> CandidateEvidence:
        publication.quarantine.publish_candidate(publication.candidate)
        return publication.quarantine.candidate_evidence(
            publication.candidate.ref
        )


@dataclass
class _CompletionGate:
    lock: threading.Lock = field(default_factory=threading.Lock)
    state: str = "PREPARED"

    def begin(self) -> None:
        with self.lock:
            if self.state != "PREPARED":
                raise WriterPublicationV2Error(
                    "PUBLICATION_ALREADY_COMPLETED",
                    "завершение публикации допускается ровно один раз",
                )
            self.state = "COMPLETING"

    def finish(self) -> None:
        with self.lock:
            self.state = "COMPLETED"


@dataclass(frozen=True)
class WriterPublicationSessionV2:
    """Подготовленная рабочая копия, которую автор может изменять."""

    request: WriterPublicationRequestV2
    snapshot: SnapshotResult
    workspace: CandidateWorkspace
    quarantine: QuarantineRepository
    source_manifest: SourceManifest
    repository_manifest: RepositoryManifest
    _completion: _CompletionGate = field(
        default_factory=_CompletionGate,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class WriterPublicationResultV2:
    """Закрытый результат: доверен только вариант ``VERIFIED``."""

    state: Literal["VERIFIED", "QUARANTINED"]
    validation_state: str
    error_code: str | None
    artifact_id: str | None
    ref: str | None
    commit_sha: str | None
    tree_sha: str | None
    base_commit_sha: str | None
    ref_published: bool
    proof_hash: str
    validation: ValidationResult | None


QuarantineFactoryV2 = Callable[[Path, Path], QuarantineRepository]


class WriterPublicationCoordinatorV2:
    """Создаёт рабочую копию и принимает только доказанный кандидат."""

    def __init__(
        self,
        *,
        snapshot_builder: SnapshotBuilder,
        validation_runner: ValidationRunner,
        ref_publisher: CandidateRefPublisherV2,
        quarantine_factory: QuarantineFactoryV2 = (
            QuarantineRepository.for_source
        ),
    ) -> None:
        if not callable(getattr(snapshot_builder, "build", None)):
            raise TypeError("snapshot_builder должен предоставлять build()")
        if not callable(getattr(validation_runner, "run", None)):
            raise TypeError("validation_runner должен предоставлять run()")
        if not callable(getattr(ref_publisher, "publish", None)):
            raise TypeError("ref_publisher должен предоставлять publish()")
        if not callable(quarantine_factory):
            raise TypeError("quarantine_factory должен быть вызываемым")
        self.snapshot_builder = snapshot_builder
        self.validation_runner = validation_runner
        self.ref_publisher = ref_publisher
        self.quarantine_factory = quarantine_factory

    def prepare(
        self,
        request: WriterPublicationRequestV2,
    ) -> WriterPublicationSessionV2:
        if not isinstance(request, WriterPublicationRequestV2):
            raise TypeError("request должен быть WriterPublicationRequestV2")
        attempt_root = _create_private_directory(request.attempt_root)
        source_before = capture_source_manifest(request.repository)
        repository_before = repository_manifest(request.repository)
        try:
            snapshot = self.snapshot_builder.build(
                repository=request.repository,
                base_sha=request.base_sha,
                destination=attempt_root / "snapshot",
                deadline_at=request.deadline_at,
            )
            source_after_snapshot = capture_source_manifest(request.repository)
            repository_after_snapshot = repository_manifest(request.repository)
            if (
                snapshot.source_before != source_before
                or snapshot.source_after != source_after_snapshot
                or source_before != source_after_snapshot
                or repository_before != repository_after_snapshot
            ):
                raise WriterPublicationV2Error(
                    "SOURCE_CHANGED_DURING_WRITER",
                    "источник изменился при подготовке снимка",
                )
            workspace = materialize_candidate_workspace(
                snapshot.root,
                attempt_root / "workspace",
                max_files=request.max_files,
                max_file_bytes=request.max_file_bytes,
                max_total_bytes=request.max_total_bytes,
            )
            source_after_workspace = capture_source_manifest(request.repository)
            repository_after_workspace = repository_manifest(request.repository)
            if (
                source_after_workspace != source_after_snapshot
                or repository_after_workspace != repository_after_snapshot
            ):
                raise WriterPublicationV2Error(
                    "SOURCE_CHANGED_DURING_WRITER",
                    "источник изменился при подготовке рабочей копии",
                )
            quarantine = self.quarantine_factory(
                request.quarantine_state_root,
                request.repository,
            )
            if not isinstance(quarantine, QuarantineRepository):
                raise TypeError(
                    "quarantine_factory должен вернуть QuarantineRepository"
                )
            _require_source_unchanged(
                request.repository,
                source_after_workspace,
                repository_after_workspace,
            )
            return WriterPublicationSessionV2(
                request=request,
                snapshot=snapshot,
                workspace=workspace,
                quarantine=quarantine,
                source_manifest=source_after_workspace,
                repository_manifest=repository_after_workspace,
            )
        except BaseException:
            _remove_private_tree(attempt_root)
            raise

    def complete(
        self,
        session: WriterPublicationSessionV2,
        *,
        cancellation: threading.Event,
    ) -> WriterPublicationResultV2:
        if not isinstance(session, WriterPublicationSessionV2):
            raise TypeError("session должен быть WriterPublicationSessionV2")
        if not isinstance(cancellation, threading.Event):
            raise TypeError("cancellation должен быть threading.Event")
        session._completion.begin()
        try:
            return self._complete_once(session, cancellation)
        finally:
            session._completion.finish()

    def _complete_once(
        self,
        session: WriterPublicationSessionV2,
        cancellation: threading.Event,
    ) -> WriterPublicationResultV2:
        request = session.request
        source_error = _source_error(session)
        base: BaseImport | None = None
        candidate: CandidateResult | None = None
        try:
            base = session.quarantine.import_base(request.base_sha)
            candidate = session.quarantine.prepare_candidate(
                session.workspace.root,
                base,
                source_date_epoch=request.source_date_epoch,
                max_files=request.max_files,
                max_file_bytes=request.max_file_bytes,
                max_total_bytes=request.max_total_bytes,
                max_diff_bytes=request.max_diff_bytes,
            )
        except Exception as exc:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=_exception_code(
                    exc,
                    "CANDIDATE_PREPARATION_FAILED",
                ),
                ref_published=False,
                validation=None,
            )
        if session.quarantine.fsck() != "ok":
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code="QUARANTINE_FSCK_FAILED",
                ref_published=False,
                validation=None,
            )
        if source_error is not None:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=source_error,
                ref_published=False,
                validation=None,
            )
        if cancellation.is_set():
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code="VALIDATION_CANCELLED",
                ref_published=False,
                validation=None,
            )

        validation_path = request.attempt_root / "validation"
        try:
            session.quarantine.materialize(candidate.commit_sha, validation_path)
            validation = self.validation_runner.run(
                workspace=validation_path,
                commands=request.validation_commands,
                cancellation=cancellation,
            )
            if not isinstance(validation, ValidationResult):
                raise WriterPublicationV2Error(
                    "VALIDATION_RESULT_INVALID",
                    "проверяющий вернул неизвестный результат",
                )
        except ValidationError as exc:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=_exception_code(exc, "VALIDATION_UNAVAILABLE"),
                ref_published=False,
                validation=None,
            )
        except Exception as exc:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=_exception_code(exc, "VALIDATION_UNAVAILABLE"),
                ref_published=False,
                validation=None,
            )

        validation_error = _validation_error(validation)
        if validation_error is not None:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state=(
                    "failed"
                    if validation.validation_state == "failed"
                    else "quarantined"
                ),
                error_code=validation_error,
                ref_published=False,
                validation=validation,
            )
        final_source_error = _source_error(session)
        if final_source_error is not None:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=final_source_error,
                ref_published=False,
                validation=validation,
            )
        if session.quarantine.fsck() != "ok":
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code="QUARANTINE_FSCK_FAILED",
                ref_published=False,
                validation=validation,
            )
        validation_proof = _validation_proof_sha256(
            session,
            base,
            candidate,
            validation,
        )
        publication = CandidateRefPublicationV2(
            route_id=request.route_id,
            node_id=request.node_id,
            attempt_id=request.attempt_id,
            quarantine=session.quarantine,
            base=base,
            candidate=candidate,
            source_manifest_sha256=_source_manifest_sha256(
                session.source_manifest,
                session.repository_manifest,
            ),
            validation=validation,
            validation_proof_sha256=validation_proof,
        )
        try:
            evidence = self.ref_publisher.publish(publication)
            _require_candidate_evidence(
                evidence,
                base,
                candidate,
            )
            try:
                observed_evidence = session.quarantine.candidate_evidence(
                    candidate.ref
                )
            except Exception as exc:
                raise WriterPublicationV2Error(
                    "CANDIDATE_PUBLICATION_MISMATCH",
                    "опубликованная ссылка недоступна для независимой проверки",
                ) from exc
            _require_candidate_evidence(
                observed_evidence,
                base,
                candidate,
            )
            if session.quarantine.fsck() != "ok":
                raise WriterPublicationV2Error(
                    "QUARANTINE_FSCK_FAILED",
                    "проверка хранилища кандидата не пройдена",
                )
        except Exception as exc:
            return _result(
                session,
                base=base,
                candidate=candidate,
                state="QUARANTINED",
                validation_state="quarantined",
                error_code=_exception_code(
                    exc,
                    "CANDIDATE_PUBLICATION_FAILED",
                ),
                ref_published=_candidate_ref_is_published(
                    session.quarantine,
                    base,
                    candidate,
                ),
                validation=validation,
            )
        return _result(
            session,
            base=base,
            candidate=candidate,
            state="VERIFIED",
            validation_state="passed",
            error_code=None,
            ref_published=True,
            validation=validation,
        )


def _absolute_fresh_path(path: Path, name: str) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError(f"{name} должен быть абсолютным")
    try:
        parent = expanded.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"родитель {name} недоступен") from exc
    target = parent / expanded.name
    if os.path.lexists(target):
        raise ValueError(f"{name} должен указывать на новый каталог")
    return target


def _create_private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
        metadata = path.stat()
    except OSError as exc:
        raise WriterPublicationV2Error(
            "ATTEMPT_ROOT_UNAVAILABLE",
            "не удалось создать каталог попытки",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WriterPublicationV2Error(
            "ATTEMPT_ROOT_UNSAFE",
            "каталог попытки не является частным каталогом владельца",
        )
    return path.resolve(strict=True)


def _remove_private_tree(root: Path) -> None:
    if not os.path.lexists(root):
        return
    for current, directories, files in os.walk(root, topdown=False):
        current_path = Path(current)
        current_path.chmod(0o700)
        for name in files:
            path = current_path / name
            path.chmod(0o600)
            path.unlink()
        for name in directories:
            path = current_path / name
            path.chmod(0o700)
            path.rmdir()
    root.rmdir()


def _require_source_unchanged(
    repository: Path,
    expected_source: SourceManifest,
    expected_repository: RepositoryManifest,
) -> None:
    if (
        capture_source_manifest(repository) != expected_source
        or repository_manifest(repository) != expected_repository
    ):
        raise WriterPublicationV2Error(
            "SOURCE_CHANGED_DURING_WRITER",
            "источник изменился при подготовке автора",
        )


def _source_error(session: WriterPublicationSessionV2) -> str | None:
    try:
        _require_source_unchanged(
            session.request.repository,
            session.source_manifest,
            session.repository_manifest,
        )
    except Exception:
        return "SOURCE_CHANGED_DURING_WRITER"
    return None


def _require_candidate_evidence(
    evidence: CandidateEvidence,
    base: BaseImport,
    candidate: CandidateResult,
) -> None:
    if not isinstance(evidence, CandidateEvidence) or (
        evidence.artifact_id != candidate.artifact_id
        or evidence.ref != candidate.ref
        or evidence.commit_sha != candidate.commit_sha
        or evidence.tree_sha != candidate.tree_sha
        or evidence.parent_sha != base.commit_sha
        or not evidence.message_bound
    ):
        raise WriterPublicationV2Error(
            "CANDIDATE_PUBLICATION_MISMATCH",
            "опубликованная ссылка не совпала с кандидатом",
        )


def _validation_error(validation: ValidationResult) -> str | None:
    if validation.validation_state == "passed":
        return None
    if validation.validation_state == "failed":
        return "VALIDATION_FAILED"
    if validation.validation_state == "not_applicable":
        return "VALIDATION_NOT_APPLICABLE"
    if validation.validation_state == "quarantined":
        return "VALIDATION_QUARANTINED"
    return "VALIDATION_RESULT_INVALID"


def _exception_code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and _ERROR_CODE.fullmatch(code) is not None:
        return code
    return fallback


def _source_manifest_sha256(
    source: SourceManifest,
    repository: RepositoryManifest,
) -> str:
    return canonical_sha256(
        {
            "sourceManifest": asdict(source),
            "repositoryManifestSha256": repository.digest,
        }
    )


def _validation_proof_sha256(
    session: WriterPublicationSessionV2,
    base: BaseImport,
    candidate: CandidateResult,
    validation: ValidationResult,
) -> str:
    return canonical_sha256(
        {
            "contractVersion": "writer-validation-proof-v2",
            "routeId": session.request.route_id,
            "nodeId": session.request.node_id,
            "attemptId": session.request.attempt_id,
            "artifactId": candidate.artifact_id,
            "ref": candidate.ref,
            "baseSourceSha": base.source_sha,
            "baseCommitSha": base.commit_sha,
            "baseTreeSha": base.tree_sha,
            "commitSha": candidate.commit_sha,
            "treeSha": candidate.tree_sha,
            "sourceManifestSha256": _source_manifest_sha256(
                session.source_manifest,
                session.repository_manifest,
            ),
            "validationState": validation.validation_state,
            "validation": [
                {
                    "argv": list(command.catalog_argv),
                    "exitCode": command.exit_code,
                    "stdoutSha256": command.stdout_sha256,
                    "stderrSha256": command.stderr_sha256,
                }
                for command in validation.commands
            ],
        }
    )


def _candidate_ref_is_published(
    quarantine: QuarantineRepository,
    base: BaseImport,
    candidate: CandidateResult,
) -> bool:
    try:
        evidence = quarantine.candidate_evidence(candidate.ref)
        _require_candidate_evidence(evidence, base, candidate)
    except Exception:
        return False
    return True


def _result(
    session: WriterPublicationSessionV2,
    *,
    base: BaseImport | None,
    candidate: CandidateResult | None,
    state: Literal["VERIFIED", "QUARANTINED"],
    validation_state: str,
    error_code: str | None,
    ref_published: bool,
    validation: ValidationResult | None,
) -> WriterPublicationResultV2:
    payload = {
        "contractVersion": "writer-publication-v2",
        "routeId": session.request.route_id,
        "nodeId": session.request.node_id,
        "attemptId": session.request.attempt_id,
        "state": state,
        "validationState": validation_state,
        "errorCode": error_code or "",
        "artifactId": candidate.artifact_id if candidate is not None else "",
        "ref": candidate.ref if candidate is not None else "",
        "commitSha": candidate.commit_sha if candidate is not None else "",
        "treeSha": candidate.tree_sha if candidate is not None else "",
        "baseCommitSha": base.commit_sha if base is not None else "",
        "refPublished": ref_published,
        "sourceManifestSha256": _source_manifest_sha256(
            session.source_manifest,
            session.repository_manifest,
        ),
        "validation": [
            {
                "argv": list(command.catalog_argv),
                "exitCode": command.exit_code,
                "stdoutSha256": command.stdout_sha256,
                "stderrSha256": command.stderr_sha256,
            }
            for command in (validation.commands if validation is not None else ())
        ],
    }
    return WriterPublicationResultV2(
        state=state,
        validation_state=validation_state,
        error_code=error_code,
        artifact_id=(candidate.artifact_id if candidate is not None else None),
        ref=(candidate.ref if candidate is not None else None),
        commit_sha=(candidate.commit_sha if candidate is not None else None),
        tree_sha=(candidate.tree_sha if candidate is not None else None),
        base_commit_sha=(base.commit_sha if base is not None else None),
        ref_published=ref_published,
        proof_hash=canonical_sha256(payload),
        validation=validation,
    )
