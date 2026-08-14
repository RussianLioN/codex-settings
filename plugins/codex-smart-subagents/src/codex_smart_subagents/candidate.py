"""Safe writable copies derived only from immutable committed snapshots."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CandidateWorkspaceError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class CandidateWorkspace:
    root: Path
    file_count: int
    total_bytes: int


def materialize_candidate_workspace(
    snapshot_root: Path,
    destination: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> CandidateWorkspace:
    """Copy one frozen snapshot without links, filters, hooks, or Git commands."""

    for name, value in (
        ("max_files", max_files),
        ("max_file_bytes", max_file_bytes),
        ("max_total_bytes", max_total_bytes),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    source = _safe_source(snapshot_root)
    target = _fresh_destination(destination)
    target.mkdir(mode=0o700)
    file_count = 0
    total_bytes = 0
    try:
        for current, directory_names, file_names in os.walk(
            source,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current)
            relative_parent = current_path.relative_to(source)
            output_parent = target / relative_parent
            output_parent.chmod(0o700)
            for name in directory_names:
                input_path = current_path / name
                metadata = input_path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise CandidateWorkspaceError(
                        "CANDIDATE_SOURCE_LINK",
                        "snapshot contains a symbolic link",
                    )
                if not stat.S_ISDIR(metadata.st_mode):
                    raise CandidateWorkspaceError(
                        "CANDIDATE_SOURCE_SPECIAL",
                        "snapshot contains a special directory entry",
                    )
                output_path = output_parent / name
                output_path.mkdir(mode=0o700)
            for name in file_names:
                input_path = current_path / name
                metadata = input_path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise CandidateWorkspaceError(
                        "CANDIDATE_SOURCE_LINK",
                        "snapshot contains a symbolic link",
                    )
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise CandidateWorkspaceError(
                        "CANDIDATE_SOURCE_SPECIAL",
                        "snapshot contains a special or linked file",
                    )
                if metadata.st_size > max_file_bytes:
                    raise CandidateWorkspaceError(
                        "CANDIDATE_FILE_TOO_LARGE",
                        f"snapshot file exceeds {max_file_bytes} bytes",
                    )
                file_count += 1
                if file_count > max_files:
                    raise CandidateWorkspaceError(
                        "CANDIDATE_TOO_MANY_FILES",
                        f"snapshot contains more than {max_files} files",
                    )
                data = _read_stable(input_path, metadata)
                total_bytes += len(data)
                if total_bytes > max_total_bytes:
                    raise CandidateWorkspaceError(
                        "CANDIDATE_TOO_LARGE",
                        f"snapshot exceeds {max_total_bytes} bytes",
                    )
                output_path = output_parent / name
                _write_new_file(
                    output_path,
                    data,
                    executable=bool(metadata.st_mode & 0o111),
                )
    except BaseException:
        _remove_tree(target)
        raise
    return CandidateWorkspace(
        root=target.resolve(strict=True),
        file_count=file_count,
        total_bytes=total_bytes,
    )


def _safe_source(path: Path) -> Path:
    if path.is_symlink():
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_UNSAFE",
            "snapshot root must not be a symbolic link",
        )
    try:
        source = path.expanduser().resolve(strict=True)
        metadata = source.stat()
    except OSError as exc:
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_UNSAFE",
            "snapshot root is unavailable",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_UNSAFE",
            "snapshot root must be a directory",
        )
    return source


def _fresh_destination(path: Path) -> Path:
    expanded = path.expanduser()
    try:
        parent = expanded.parent.resolve(strict=True)
    except OSError as exc:
        raise CandidateWorkspaceError(
            "CANDIDATE_DESTINATION_UNSAFE",
            "candidate destination parent is unavailable",
        ) from exc
    target = parent / expanded.name
    if os.path.lexists(target):
        raise CandidateWorkspaceError(
            "CANDIDATE_DESTINATION_EXISTS",
            "candidate destination must be fresh",
        )
    return target


def _read_stable(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_CHANGED",
            "snapshot file could not be opened safely",
        ) from exc
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(expected) or identity(after) != identity(before):
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_CHANGED",
            "snapshot file changed while it was copied",
        )
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise CandidateWorkspaceError(
            "CANDIDATE_SOURCE_CHANGED",
            "snapshot file size changed while it was copied",
        )
    return data


def _write_new_file(path: Path, data: bytes, *, executable: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o700 if executable else 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o700 if executable else 0o600)


def _remove_tree(root: Path) -> None:
    if not os.path.lexists(root):
        return
    for current, directories, files in os.walk(root, topdown=False):
        current_path = Path(current)
        for name in files:
            (current_path / name).unlink()
        for name in directories:
            (current_path / name).rmdir()
    root.rmdir()
