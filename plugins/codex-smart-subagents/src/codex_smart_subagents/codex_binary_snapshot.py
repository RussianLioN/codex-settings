"""Private, content-addressed snapshots of the selected Codex executable."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol

from .compatibility import (
    MINIMUM_STABLE_CODEX_VERSION,
    codex_version_supported,
)
from . import finite_file_lock_v2
from .live_canary import (
    CanaryCommand,
    LiveCanaryError,
    SubprocessExecutor,
)
from .operation_deadline_v2 import (
    OperationDeadlineExceededV2,
    checkpoint_current_operation_deadline_if_scoped_v2,
)


MAX_CODEX_BINARY_BYTES = 1024 * 1024 * 1024
FIXED_PROCESS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
CODE_SIGNATURE_REQUIREMENT = (
    '=identifier "codex" and anchor apple generic and certificate '
    "1[field.1.2.840.113635.100.6.2.6] exists and certificate "
    "leaf[field.1.2.840.113635.100.6.1.13] exists and certificate "
    'leaf[subject.OU] = "2DC432GLL2"'
)

_MACHO_64_MAGIC = 0xFEEDFACF
_CPU_TYPE_ARM64 = 0x0100000C
_MACHO_HEADER_SIZE = 32
_VERSION = re.compile(r"codex-cli (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_CD_HASH = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_ENVIRONMENT = MappingProxyType(
    {
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": FIXED_PROCESS_PATH,
    }
)


@dataclass
class SnapshotBinaryError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class SnapshotCommand:
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    timeout_seconds: float
    max_output_bytes: int

    def __post_init__(self) -> None:
        if (
            not self.argv
            or not all(
                isinstance(item, str) and item and "\0" not in item
                for item in self.argv
            )
            or not Path(self.argv[0]).is_absolute()
        ):
            raise ValueError(
                "argv must contain an absolute executable and safe arguments"
            )
        if not self.cwd.is_absolute():
            raise ValueError("command cwd must be absolute")
        environment = dict(self.environment)
        if not all(
            isinstance(name, str)
            and name
            and "=" not in name
            and "\0" not in name
            and isinstance(value, str)
            and "\0" not in value
            for name, value in environment.items()
        ):
            raise ValueError("command environment must be a safe string mapping")
        object.__setattr__(self, "environment", MappingProxyType(environment))
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 30
        ):
            raise ValueError("command timeout must be in (0, 30]")
        if (
            type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 1024 * 1024
        ):
            raise ValueError("command output limit is outside the supported range")


@dataclass(frozen=True)
class SnapshotCommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int:
            raise ValueError("exit_code must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("command output must be bytes")


@dataclass(frozen=True)
class SnapshotMaterializationIdentity:
    """Результат снимка с атомарным признаком создания либо переиспользования."""

    subject: Mapping[str, object]
    snapshot_disposition: str
    digest_directory_disposition: str

    def __post_init__(self) -> None:
        if self.snapshot_disposition not in {"created", "reused"}:
            raise ValueError("snapshot disposition must be created or reused")
        if self.digest_directory_disposition not in {"created", "reused"}:
            raise ValueError("digest directory disposition must be created or reused")


class SnapshotCommandExecutor(Protocol):
    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        """Execute one bounded command without a shell."""


class SnapshotSubprocessExecutor:
    """Production adapter over the existing bounded process-group executor."""

    def __init__(self) -> None:
        self._delegate = SubprocessExecutor()

    def run(self, command: SnapshotCommand) -> SnapshotCommandResult:
        try:
            result = self._delegate.run(
                CanaryCommand(
                    argv=command.argv,
                    cwd=command.cwd,
                    environment=command.environment,
                    stdin=b"",
                    timeout_seconds=command.timeout_seconds,
                    max_output_bytes=command.max_output_bytes,
                )
            )
        except LiveCanaryError as exc:
            raise SnapshotBinaryError("PROCESS_FAILED", str(exc)) from exc
        return SnapshotCommandResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )


@dataclass(frozen=True)
class _SignatureMetadata:
    identifier: str
    team_identifier: str
    cd_hash: str


class CodexBinarySnapshotter:
    """Copy, verify and publish one immutable Codex executable snapshot."""

    def __init__(
        self,
        *,
        snapshot_root: str | os.PathLike[str],
        executor: SnapshotCommandExecutor | None = None,
        minimum_version: str = MINIMUM_STABLE_CODEX_VERSION,
        command_timeout_seconds: float = 10.0,
        max_output_bytes: int = 256 * 1024,
    ) -> None:
        raw_root = os.fspath(snapshot_root)
        if not isinstance(raw_root, str) or not raw_root or "\0" in raw_root:
            raise ValueError("snapshot_root must be a non-empty path")
        self._snapshot_root = Path(os.path.abspath(raw_root))
        self._executor = executor or SnapshotSubprocessExecutor()
        if not codex_version_supported(minimum_version, minimum=minimum_version):
            raise ValueError("minimum_version must be a canonical stable version")
        self._minimum_version = minimum_version
        if (
            not isinstance(command_timeout_seconds, (int, float))
            or isinstance(command_timeout_seconds, bool)
            or not 0 < float(command_timeout_seconds) <= 30
        ):
            raise ValueError("command_timeout_seconds must be in (0, 30]")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        self._command_timeout_seconds = float(command_timeout_seconds)
        self._max_output_bytes = max_output_bytes

    def materialize(self, source_locator: str | os.PathLike[str]) -> dict[str, object]:
        """Return a strict SubjectV1 dictionary for a verified private snapshot."""

        return dict(self.materialize_with_identity(source_locator).subject)

    def materialize_with_identity(
        self, source_locator: str | os.PathLike[str]
    ) -> SnapshotMaterializationIdentity:
        """Материализовать снимок и сообщить владение опубликованными именами."""

        lexical_source = _lexical_absolute(source_locator)
        try:
            resolved_source = Path(lexical_source).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SnapshotBinaryError("SOURCE_UNAVAILABLE", str(exc)) from exc

        source_parent_fd = _open_absolute_directory(
            resolved_source.parent,
            "SOURCE_UNSAFE",
            require_trusted_permissions=False,
        )
        source_fd = -1
        root_fd = -1
        temporary_name: str | None = None
        try:
            source_fd = _open_regular_at(
                source_parent_fd,
                resolved_source.name,
                code="SOURCE_UNAVAILABLE",
            )
            source_before = os.fstat(source_fd)
            _validate_source_file(source_before)

            root_fd, canonical_root = self._open_or_create_snapshot_root()
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    root_fd,
                    exclusive=True,
                    timeout_seconds=(
                        finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                    ),
                    timeout_code="SNAPSHOT_ROOT_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise SnapshotBinaryError(
                    error.code,
                    "Codex snapshot root remained locked until its deadline",
                ) from error
            temporary_name = f".codex-copy-{uuid.uuid4().hex}"
            temporary_fd = _create_private_file_at(root_fd, temporary_name)
            try:
                observed_sha = _copy_and_hash(
                    source_fd,
                    temporary_fd,
                    maximum=MAX_CODEX_BINARY_BYTES,
                )
                os.fchmod(temporary_fd, 0o500)
                os.fsync(temporary_fd)
            finally:
                os.close(temporary_fd)

            source_after = os.fstat(source_fd)
            if not _same_source_observation(source_before, source_after):
                raise SnapshotBinaryError(
                    "SOURCE_CHANGED",
                    "Codex source changed while it was copied",
                )

            temporary_path = canonical_root / temporary_name
            temporary_read_fd = _open_regular_at(
                root_fd,
                temporary_name,
                code="SNAPSHOT_TEMPORARY_INVALID",
            )
            try:
                temporary_stat = os.fstat(temporary_read_fd)
                _validate_private_snapshot_file(
                    temporary_stat, "SNAPSHOT_TEMPORARY_INVALID"
                )
                if _hash_fd(temporary_read_fd) != observed_sha:
                    raise SnapshotBinaryError(
                        "SNAPSHOT_TEMPORARY_INVALID",
                        "temporary snapshot hash changed after copy",
                    )
                self._verify_architecture_and_signature(
                    temporary_path, temporary_read_fd
                )
                signature = self._read_signature_metadata(temporary_path)
                version = self._read_version(temporary_path)

                if not _same_file_observation(
                    temporary_stat, os.fstat(temporary_read_fd)
                ):
                    raise SnapshotBinaryError(
                        "SNAPSHOT_TEMPORARY_INVALID",
                        "temporary snapshot changed during verification",
                    )
                if _hash_fd(temporary_read_fd) != observed_sha:
                    raise SnapshotBinaryError(
                        "SNAPSHOT_TEMPORARY_INVALID",
                        "temporary snapshot hash changed before publication",
                    )
                self._verify_architecture_and_signature(
                    temporary_path, temporary_read_fd
                )
                _verify_name_binding(
                    root_fd,
                    temporary_name,
                    temporary_read_fd,
                    observed_sha,
                    "SNAPSHOT_TEMPORARY_INVALID",
                )

                (
                    sha_directory_fd,
                    sha_directory_path,
                    sha_directory_created,
                ) = _open_or_create_sha_directory(root_fd, canonical_root, observed_sha)
                try:
                    published_path = sha_directory_path / "codex"
                    existing_fd = _try_open_regular_at(sha_directory_fd, "codex")
                    snapshot_created = existing_fd is None
                    if existing_fd is not None:
                        try:
                            signature, version = self._verify_existing_snapshot(
                                published_path=published_path,
                                published_fd=existing_fd,
                                temporary_fd=temporary_read_fd,
                                expected_sha=observed_sha,
                                expected_signature=signature,
                                expected_version=version,
                            )
                        finally:
                            os.close(existing_fd)
                        os.unlink(temporary_name, dir_fd=root_fd)
                        temporary_name = None
                        os.fsync(root_fd)
                    else:
                        os.rename(
                            temporary_name,
                            "codex",
                            src_dir_fd=root_fd,
                            dst_dir_fd=sha_directory_fd,
                        )
                        temporary_name = None
                        os.fsync(sha_directory_fd)
                        os.fsync(root_fd)

                    published_fd = _open_regular_at(
                        sha_directory_fd,
                        "codex",
                        code="SNAPSHOT_PUBLICATION_INVALID",
                    )
                    try:
                        published_stat = os.fstat(published_fd)
                        _validate_private_snapshot_file(
                            published_stat,
                            "SNAPSHOT_PUBLICATION_INVALID",
                        )
                        if _hash_fd(published_fd) != observed_sha:
                            raise SnapshotBinaryError(
                                "SNAPSHOT_PUBLICATION_INVALID",
                                "published snapshot hash does not match its directory",
                            )
                        _validate_macho_arm64(published_fd)
                    finally:
                        os.close(published_fd)
                finally:
                    os.close(sha_directory_fd)
            finally:
                os.close(temporary_read_fd)

            return SnapshotMaterializationIdentity(
                subject={
                    "snapshotSha256": observed_sha,
                    "snapshotPath": os.fspath(published_path),
                    "size": published_stat.st_size,
                    "mode": stat.S_IMODE(published_stat.st_mode),
                    "uid": published_stat.st_uid,
                    "device": published_stat.st_dev,
                    "inode": published_stat.st_ino,
                    "mtimeNs": str(published_stat.st_mtime_ns),
                    "version": version,
                    "platform": "darwin",
                    "architecture": "arm64",
                    "signatureIdentifier": signature.identifier,
                    "teamIdentifier": signature.team_identifier,
                    "cdHash": signature.cd_hash,
                    "sourceLocator": lexical_source,
                    "sourceObservedSha256": observed_sha,
                },
                snapshot_disposition="created" if snapshot_created else "reused",
                digest_directory_disposition=(
                    "created" if sha_directory_created else "reused"
                ),
            )
        except SnapshotBinaryError:
            raise
        except OSError as exc:
            raise SnapshotBinaryError("SNAPSHOT_IO_FAILED", str(exc)) from exc
        finally:
            if temporary_name is not None and root_fd >= 0:
                try:
                    os.unlink(temporary_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
            if root_fd >= 0:
                try:
                    fcntl.flock(root_fd, fcntl.LOCK_UN)
                finally:
                    os.close(root_fd)
            if source_fd >= 0:
                os.close(source_fd)
            os.close(source_parent_fd)

    def _open_or_create_snapshot_root(self) -> tuple[int, Path]:
        parent = self._snapshot_root.parent.resolve(strict=True)
        name = self._snapshot_root.name
        if name in {"", ".", ".."}:
            raise SnapshotBinaryError(
                "SNAPSHOT_ROOT_UNSAFE", "invalid snapshot root name"
            )
        parent_fd = _open_absolute_directory(parent, "SNAPSHOT_ROOT_UNSAFE")
        created = False
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                root_fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise SnapshotBinaryError("SNAPSHOT_ROOT_UNSAFE", str(exc)) from exc
        finally:
            os.close(parent_fd)
        try:
            if created:
                os.fchmod(root_fd, 0o700)
                os.fsync(root_fd)
            root_stat = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or root_stat.st_uid != os.getuid()
                or stat.S_IMODE(root_stat.st_mode) != 0o700
            ):
                raise SnapshotBinaryError(
                    "SNAPSHOT_ROOT_UNSAFE",
                    "snapshot root must be owned by the current user with mode 0700",
                )
        except BaseException:
            os.close(root_fd)
            raise
        return root_fd, parent / name

    def _verify_architecture_and_signature(self, path: Path, descriptor: int) -> None:
        _validate_macho_arm64(descriptor)
        lipo = self._run(("/usr/bin/lipo", "-archs", os.fspath(path)), path.parent)
        try:
            architectures = lipo.stdout.decode("utf-8", "strict").split()
        except UnicodeDecodeError as exc:
            raise SnapshotBinaryError(
                "ARCHITECTURE_INVALID",
                "lipo architecture output is not UTF-8",
            ) from exc
        if lipo.exit_code != 0 or lipo.stderr or architectures != ["arm64"]:
            raise SnapshotBinaryError(
                "ARCHITECTURE_INVALID",
                "lipo did not report exactly one arm64 architecture",
            )
        self._require_success(
            (
                "/usr/bin/codesign",
                "-v",
                "--strict",
                "--all-architectures",
                os.fspath(path),
            ),
            path.parent,
            "SIGNATURE_INVALID",
        )
        self._require_success(
            (
                "/usr/bin/codesign",
                "-v",
                "--strict",
                "--all-architectures",
                "-R",
                CODE_SIGNATURE_REQUIREMENT,
                os.fspath(path),
            ),
            path.parent,
            "SIGNATURE_INVALID",
        )

    def _read_signature_metadata(self, path: Path) -> _SignatureMetadata:
        result = self._run(
            ("/usr/bin/codesign", "-d", "--verbose=4", os.fspath(path)),
            path.parent,
        )
        if result.exit_code != 0 or result.stdout:
            raise SnapshotBinaryError(
                "SIGNATURE_METADATA_INVALID",
                "codesign metadata inspection failed",
            )
        try:
            lines = result.stderr.decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError as exc:
            raise SnapshotBinaryError(
                "SIGNATURE_METADATA_INVALID",
                "codesign metadata is not UTF-8",
            ) from exc
        values: dict[str, list[str]] = {
            "Identifier": [],
            "TeamIdentifier": [],
            "CDHash": [],
        }
        for line in lines:
            for key in values:
                prefix = f"{key}="
                if line.startswith(prefix):
                    values[key].append(line[len(prefix) :])
        if any(len(value) != 1 for value in values.values()):
            raise SnapshotBinaryError(
                "SIGNATURE_METADATA_INVALID",
                "codesign metadata is missing or ambiguous",
            )
        identifier = values["Identifier"][0]
        team_identifier = values["TeamIdentifier"][0]
        cd_hash = values["CDHash"][0]
        if identifier != "codex" or team_identifier != "2DC432GLL2":
            raise SnapshotBinaryError(
                "SIGNATURE_IDENTITY_INVALID",
                "Codex signature identity does not match the pinned policy",
            )
        if _CD_HASH.fullmatch(cd_hash) is None:
            raise SnapshotBinaryError(
                "SIGNATURE_METADATA_INVALID",
                "Codex CDHash is not a 40-character lowercase hexadecimal value",
            )
        return _SignatureMetadata(identifier, team_identifier, cd_hash)

    def _read_version(self, path: Path) -> str:
        result = self._run((os.fspath(path), "--version"), path.parent)
        try:
            version = result.stdout.decode("utf-8", "strict").rstrip("\n")
        except UnicodeDecodeError as exc:
            raise SnapshotBinaryError(
                "VERSION_UNSUPPORTED", "Codex version is not UTF-8"
            ) from exc
        match = _VERSION.fullmatch(version)
        if (
            result.exit_code != 0
            or result.stderr
            or len(version.encode("utf-8")) > 64
            or match is None
        ):
            raise SnapshotBinaryError(
                "VERSION_UNSUPPORTED",
                "Codex did not return one canonical stable version line",
            )
        semantic_version = ".".join(match.groups())
        if not codex_version_supported(semantic_version, minimum=self._minimum_version):
            raise SnapshotBinaryError(
                "VERSION_UNSUPPORTED",
                "Codex version is outside the source-verified compatibility set",
            )
        return version

    def _verify_existing_snapshot(
        self,
        *,
        published_path: Path,
        published_fd: int,
        temporary_fd: int,
        expected_sha: str,
        expected_signature: _SignatureMetadata,
        expected_version: str,
    ) -> tuple[_SignatureMetadata, str]:
        try:
            published_stat = os.fstat(published_fd)
            _validate_private_snapshot_file(published_stat, "SNAPSHOT_CORRUPT")
            if _hash_fd(published_fd) != expected_sha or not _files_equal(
                published_fd,
                temporary_fd,
            ):
                raise SnapshotBinaryError(
                    "SNAPSHOT_CORRUPT",
                    "existing content-addressed snapshot has different bytes",
                )
            self._verify_architecture_and_signature(published_path, published_fd)
            signature = self._read_signature_metadata(published_path)
            version = self._read_version(published_path)
            if signature != expected_signature or version != expected_version:
                raise SnapshotBinaryError(
                    "SNAPSHOT_CORRUPT",
                    "existing snapshot metadata differs from the verified copy",
                )
            if not _same_file_observation(published_stat, os.fstat(published_fd)):
                raise SnapshotBinaryError(
                    "SNAPSHOT_CORRUPT",
                    "existing snapshot changed during re-verification",
                )
            return signature, version
        except SnapshotBinaryError as exc:
            if exc.code == "SNAPSHOT_CORRUPT":
                raise
            raise SnapshotBinaryError("SNAPSHOT_CORRUPT", str(exc)) from exc

    def _require_success(self, argv: tuple[str, ...], cwd: Path, code: str) -> None:
        result = self._run(argv, cwd)
        if result.exit_code != 0 or result.stdout:
            raise SnapshotBinaryError(code, f"command failed: {argv[0]}")

    def _run(self, argv: tuple[str, ...], cwd: Path) -> SnapshotCommandResult:
        command = SnapshotCommand(
            argv=argv,
            cwd=cwd,
            environment=_SAFE_ENVIRONMENT,
            timeout_seconds=self._command_timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        try:
            result = self._executor.run(command)
        except OperationDeadlineExceededV2:
            raise
        except SnapshotBinaryError:
            raise
        except Exception as exc:
            raise SnapshotBinaryError("PROCESS_FAILED", str(exc)) from exc
        if not isinstance(result, SnapshotCommandResult):
            raise SnapshotBinaryError(
                "PROCESS_FAILED",
                "snapshot command executor returned an invalid result",
            )
        if len(result.stdout) + len(result.stderr) > command.max_output_bytes:
            raise SnapshotBinaryError(
                "PROCESS_FAILED",
                "snapshot command executor exceeded its output limit",
            )
        return result


def _lexical_absolute(path: str | os.PathLike[str]) -> str:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise SnapshotBinaryError(
            "SOURCE_UNAVAILABLE", "source path is empty or invalid"
        )
    return os.path.abspath(raw)


def _open_absolute_directory(
    path: Path,
    code: str,
    *,
    require_trusted_permissions: bool = True,
) -> int:
    if not path.is_absolute():
        raise SnapshotBinaryError(code, "directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        _validate_traversed_directory(
            os.fstat(descriptor),
            code,
            require_trusted_permissions=require_trusted_permissions,
        )
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise SnapshotBinaryError(
                    code, "directory path contains an invalid component"
                )
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            _validate_traversed_directory(
                os.fstat(descriptor),
                code,
                require_trusted_permissions=require_trusted_permissions,
            )
        return descriptor
    except SnapshotBinaryError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise SnapshotBinaryError(code, str(exc)) from exc


def _validate_traversed_directory(
    value: os.stat_result,
    code: str,
    *,
    require_trusted_permissions: bool,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise SnapshotBinaryError(code, "path component is not a directory")
    if require_trusted_permissions and (
        value.st_uid not in {0, os.getuid()} or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise SnapshotBinaryError(
            code,
            "directory traversal crossed an untrusted directory",
        )


def _open_regular_at(parent_fd: int, name: str, *, code: str) -> int:
    if name in {"", ".", ".."} or "/" in name:
        raise SnapshotBinaryError(code, "invalid file name")
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise SnapshotBinaryError(code, str(exc)) from exc


def _try_open_regular_at(parent_fd: int, name: str) -> int | None:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SnapshotBinaryError("SNAPSHOT_CORRUPT", str(exc)) from exc


def _create_private_file_at(parent_fd: int, name: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, 0o500, dir_fd=parent_fd)
    except OSError as exc:
        raise SnapshotBinaryError("SNAPSHOT_TEMPORARY_INVALID", str(exc)) from exc
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise SnapshotBinaryError(
                "SNAPSHOT_TEMPORARY_INVALID",
                "temporary snapshot is not a private regular file",
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_source_file(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_size <= 0
        or value.st_size > MAX_CODEX_BINARY_BYTES
    ):
        raise SnapshotBinaryError(
            "SOURCE_UNSAFE",
            "Codex source must be a non-empty regular file of at most 1 GiB",
        )


def _validate_private_snapshot_file(value: os.stat_result, code: str) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o500
        or value.st_nlink != 1
        or value.st_size <= 0
        or value.st_size > MAX_CODEX_BINARY_BYTES
    ):
        raise SnapshotBinaryError(
            code,
            "snapshot must be an owned regular file with mode 0500 and one link",
        )


def _copy_and_hash(source_fd: int, destination_fd: int, *, maximum: int) -> str:
    digest = hashlib.sha256()
    copied = 0
    os.lseek(source_fd, 0, os.SEEK_SET)
    while True:
        checkpoint_current_operation_deadline_if_scoped_v2()
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        copied += len(chunk)
        if copied > maximum:
            raise SnapshotBinaryError("SOURCE_UNSAFE", "Codex source exceeds 1 GiB")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            checkpoint_current_operation_deadline_if_scoped_v2()
            written = os.write(destination_fd, view)
            if written <= 0:
                raise SnapshotBinaryError(
                    "SNAPSHOT_IO_FAILED", "short write while copying Codex"
                )
            view = view[written:]
    return digest.hexdigest()


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        checkpoint_current_operation_deadline_if_scoped_v2()
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _files_equal(first_fd: int, second_fd: int) -> bool:
    if os.fstat(first_fd).st_size != os.fstat(second_fd).st_size:
        return False
    os.lseek(first_fd, 0, os.SEEK_SET)
    os.lseek(second_fd, 0, os.SEEK_SET)
    while True:
        checkpoint_current_operation_deadline_if_scoped_v2()
        first = os.read(first_fd, 1024 * 1024)
        second = os.read(second_fd, 1024 * 1024)
        if first != second:
            return False
        if not first:
            return True


def _same_source_observation(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_size,
        first.st_mtime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_size,
        second.st_mtime_ns,
    )


def _same_file_observation(first: os.stat_result, second: os.stat_result) -> bool:
    return _same_source_observation(first, second) and (
        first.st_mode,
        first.st_uid,
        first.st_nlink,
    ) == (
        second.st_mode,
        second.st_uid,
        second.st_nlink,
    )


def _validate_macho_arm64(descriptor: int) -> None:
    try:
        header = os.pread(descriptor, _MACHO_HEADER_SIZE, 0)
    except AttributeError:
        position = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        header = os.read(descriptor, _MACHO_HEADER_SIZE)
        os.lseek(descriptor, position, os.SEEK_SET)
    if len(header) != _MACHO_HEADER_SIZE:
        raise SnapshotBinaryError("MACHO_INVALID", "Codex Mach-O header is truncated")
    try:
        magic, cpu_type, _cpu_subtype, file_type = struct.unpack_from("<IiiI", header)
    except struct.error as exc:
        raise SnapshotBinaryError(
            "MACHO_INVALID", "Codex Mach-O header is invalid"
        ) from exc
    if magic != _MACHO_64_MAGIC or cpu_type != _CPU_TYPE_ARM64 or file_type != 2:
        raise SnapshotBinaryError(
            "MACHO_INVALID",
            "Codex must be a little-endian 64-bit arm64 Mach-O executable",
        )


def _open_or_create_sha_directory(
    root_fd: int,
    root_path: Path,
    sha256: str,
) -> tuple[int, Path, bool]:
    if _SHA256.fullmatch(sha256) is None:
        raise SnapshotBinaryError(
            "SNAPSHOT_PUBLICATION_INVALID", "invalid snapshot SHA-256"
        )
    created = False
    try:
        os.mkdir(sha256, 0o700, dir_fd=root_fd)
        created = True
        os.fsync(root_fd)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(sha256, flags, dir_fd=root_fd)
    except OSError as exc:
        raise SnapshotBinaryError("SNAPSHOT_CORRUPT", str(exc)) from exc
    try:
        if created:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        value = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o700
        ):
            raise SnapshotBinaryError(
                "SNAPSHOT_CORRUPT",
                "content-addressed snapshot directory is not private",
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, root_path / sha256, created


def _verify_name_binding(
    parent_fd: int,
    name: str,
    expected_fd: int,
    expected_sha: str,
    code: str,
) -> None:
    rebound_fd = _open_regular_at(parent_fd, name, code=code)
    try:
        if (
            not _same_file_observation(os.fstat(expected_fd), os.fstat(rebound_fd))
            or _hash_fd(rebound_fd) != expected_sha
            or not _files_equal(expected_fd, rebound_fd)
        ):
            raise SnapshotBinaryError(
                code,
                "snapshot path no longer names the verified file",
            )
    finally:
        os.close(rebound_fd)
