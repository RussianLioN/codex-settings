"""Read-only Git snapshots built from committed blob objects only."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


_GIT = Path("/usr/bin/git")
_HEX_OBJECT = re.compile(r"[0-9a-fA-F]{40,64}")
_LFS_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"
_READ_CHUNK = 1024 * 1024


@dataclass
class SnapshotError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int

    def __post_init__(self) -> None:
        for name in ("max_files", "max_file_bytes", "max_total_bytes"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class SourceManifest:
    head_sha: str
    status_sha256: str
    refs_sha256: str
    worktrees_sha256: str
    git_control_sha256: str


@dataclass(frozen=True)
class SnapshotResult:
    root: Path
    base_sha: str
    file_count: int
    total_bytes: int
    manifest_sha256: str
    source_before: SourceManifest
    source_after: SourceManifest


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    object_type: str
    object_id: str
    size: int | None
    path: str


class SnapshotBuilder:
    """Materialize a clean HEAD without checkout, filters, or hooks."""

    def __init__(self, limits: SnapshotLimits) -> None:
        self.limits = limits

    def build(
        self,
        *,
        repository: Path,
        base_sha: str,
        destination: Path,
    ) -> SnapshotResult:
        source = _canonical_repository(repository)
        target = _fresh_destination(destination)
        resolved_base = _verify_clean_head(source, base_sha)
        source_before = _source_manifest(source)
        entries = _read_tree(source, resolved_base)
        validate_snapshot_paths(entry.path for entry in entries)
        _validate_entries(entries, self.limits)

        target.mkdir(mode=0o700)
        try:
            total_bytes = self._materialize(source, target, entries)
            source_after = _source_manifest(source)
            if source_after != source_before:
                raise SnapshotError(
                    "SOURCE_CHANGED",
                    "Git source state changed while the snapshot was read",
                )
            _freeze_tree(target)
        except BaseException:
            _remove_tree(target)
            raise

        manifest_sha256 = _snapshot_manifest_sha(entries)
        return SnapshotResult(
            root=target,
            base_sha=resolved_base,
            file_count=len(entries),
            total_bytes=total_bytes,
            manifest_sha256=manifest_sha256,
            source_before=source_before,
            source_after=source_after,
        )

    def _materialize(
        self,
        repository: Path,
        target: Path,
        entries: list[_TreeEntry],
    ) -> int:
        total_bytes = 0
        for entry in entries:
            blob = _git(repository, "cat-file", "blob", entry.object_id)
            if entry.size is None or len(blob) != entry.size:
                raise SnapshotError(
                    "OBJECT_SIZE_MISMATCH",
                    f"blob size changed for {entry.path}",
                )
            if blob.startswith(_LFS_PREFIX):
                raise SnapshotError(
                    "GIT_LFS_UNSUPPORTED",
                    f"Git LFS pointer is not allowed: {entry.path}",
                )
            if _declares_git_lfs(entry.path, blob):
                raise SnapshotError(
                    "GIT_LFS_UNSUPPORTED",
                    f"Git LFS configuration is not allowed: {entry.path}",
                )
            total_bytes += len(blob)
            if total_bytes > self.limits.max_total_bytes:
                raise SnapshotError(
                    "SNAPSHOT_TOO_LARGE",
                    "snapshot exceeds the configured total byte limit",
                )
            output = _safe_output_path(target, entry.path)
            _write_blob(output, blob, executable=entry.mode == "100755")
        return total_bytes


def capture_source_manifest(repository: Path) -> SourceManifest:
    """Capture the source-side integrity fields without modifying Git state."""

    return _source_manifest(_canonical_repository(repository))


def validate_snapshot_paths(paths: Iterable[str]) -> None:
    """Reject paths that are ambiguous on supported local filesystems."""

    normalized: dict[str, str] = {}
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path:
            raise SnapshotError("INVALID_PATH", "snapshot path must be non-empty")
        if "\\" in raw_path or "\x00" in raw_path:
            raise SnapshotError(
                "INVALID_PATH",
                f"snapshot path contains a forbidden separator: {raw_path!r}",
            )
        path = PurePosixPath(raw_path)
        parts = path.parts
        if path.is_absolute() or not parts:
            raise SnapshotError("INVALID_PATH", f"path must be relative: {raw_path}")
        if any(part in {"", ".", ".."} for part in parts):
            raise SnapshotError(
                "PATH_TRAVERSAL",
                f"path leaves the snapshot root: {raw_path}",
            )
        if any(
            unicodedata.normalize("NFC", part).casefold() == ".git"
            for part in parts
        ):
            raise SnapshotError(
                "GIT_METADATA_PATH",
                f"Git metadata path is forbidden: {raw_path}",
            )
        folded = unicodedata.normalize("NFC", raw_path).casefold()
        previous = normalized.get(folded)
        if previous is not None and previous != raw_path:
            raise SnapshotError(
                "PATH_COLLISION",
                f"paths collide by case or Unicode normalization: "
                f"{previous!r}, {raw_path!r}",
            )
        normalized[folded] = raw_path


def _canonical_repository(repository: Path) -> Path:
    try:
        source = repository.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SnapshotError("SOURCE_UNAVAILABLE", str(exc)) from exc
    if not source.is_dir():
        raise SnapshotError("SOURCE_UNAVAILABLE", "repository is not a directory")
    try:
        top_level = Path(
            os.fsdecode(_git(source, "rev-parse", "--show-toplevel")).strip()
        ).resolve(strict=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SnapshotError("NOT_A_REPOSITORY", str(source)) from exc
    if top_level != source:
        raise SnapshotError(
            "REPOSITORY_BOUNDARY",
            "snapshot source must be the canonical repository root",
        )
    return source


def _fresh_destination(destination: Path) -> Path:
    expanded = destination.expanduser()
    try:
        parent = expanded.parent.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError("DESTINATION_PARENT_UNSAFE", str(exc)) from exc
    if not parent.is_dir():
        raise SnapshotError(
            "DESTINATION_PARENT_UNSAFE",
            "destination parent is not a directory",
        )
    target = parent / expanded.name
    if os.path.lexists(target):
        raise SnapshotError(
            "DESTINATION_EXISTS",
            "snapshot destination must not already exist",
        )
    return target


def _verify_clean_head(repository: Path, base_sha: str) -> str:
    if not isinstance(base_sha, str) or _HEX_OBJECT.fullmatch(base_sha) is None:
        raise SnapshotError("INVALID_BASE_SHA", "base SHA must be a full object id")
    try:
        head = os.fsdecode(
            _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
        ).strip()
        resolved_base = os.fsdecode(
            _git(repository, "rev-parse", "--verify", f"{base_sha}^{{commit}}")
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise SnapshotError(
            "BASE_SHA_MISMATCH",
            "base SHA must resolve to the current committed HEAD",
        ) from exc
    if resolved_base != head:
        raise SnapshotError(
            "BASE_SHA_MISMATCH",
            "base SHA must be the current committed HEAD",
        )
    status_output = _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status_output:
        raise SnapshotError(
            "SOURCE_DIRTY",
            "the first snapshot requires a completely clean worktree",
        )
    worktree_output = _git(repository, "worktree", "list", "--porcelain", "-z")
    worktree_paths = _parse_worktree_paths(worktree_output)
    if len(worktree_paths) != 1 or worktree_paths[0] != repository:
        raise SnapshotError(
            "EXTERNAL_WORKTREE",
            "linked or external Git worktrees are not supported",
        )
    return resolved_base


def _parse_worktree_paths(output: bytes) -> list[Path]:
    paths: list[Path] = []
    for field in output.split(b"\0"):
        if field.startswith(b"worktree "):
            raw = os.fsdecode(field[len(b"worktree ") :])
            try:
                paths.append(Path(raw).resolve(strict=True))
            except OSError as exc:
                raise SnapshotError("EXTERNAL_WORKTREE", str(exc)) from exc
    return paths


def _read_tree(repository: Path, base_sha: str) -> list[_TreeEntry]:
    output = _git(
        repository,
        "ls-tree",
        "-r",
        "-z",
        "-l",
        "--full-tree",
        base_sha,
    )
    entries: list[_TreeEntry] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.split(b" ", 3)
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise SnapshotError(
                "INVALID_TREE",
                "Git tree contains an unsupported record",
            ) from exc
        stripped_size = raw_size.strip()
        size = None if stripped_size == b"-" else int(stripped_size)
        entries.append(
            _TreeEntry(
                mode=mode.decode("ascii"),
                object_type=object_type.decode("ascii"),
                object_id=object_id.decode("ascii"),
                size=size,
                path=path,
            )
        )
    return entries


def _validate_entries(
    entries: list[_TreeEntry],
    limits: SnapshotLimits,
) -> None:
    if len(entries) > limits.max_files:
        raise SnapshotError(
            "TOO_MANY_FILES",
            "snapshot exceeds the configured file-count limit",
        )
    total = 0
    for entry in entries:
        if entry.mode == "120000":
            raise SnapshotError(
                "SYMLINK_UNSUPPORTED",
                f"symbolic links are not allowed: {entry.path}",
            )
        if entry.mode == "160000" or entry.object_type == "commit":
            raise SnapshotError(
                "SUBMODULE_UNSUPPORTED",
                f"submodules are not allowed: {entry.path}",
            )
        if entry.mode not in {"100644", "100755"} or entry.object_type != "blob":
            raise SnapshotError(
                "SPECIAL_FILE_UNSUPPORTED",
                f"unsupported Git entry {entry.mode} {entry.object_type}",
            )
        if entry.size is None or entry.size < 0:
            raise SnapshotError("INVALID_TREE", f"missing blob size: {entry.path}")
        if entry.size > limits.max_file_bytes:
            raise SnapshotError(
                "FILE_TOO_LARGE",
                f"tracked file exceeds the configured limit: {entry.path}",
            )
        total += entry.size
        if total > limits.max_total_bytes:
            raise SnapshotError(
                "SNAPSHOT_TOO_LARGE",
                "snapshot exceeds the configured total byte limit",
            )


def _source_manifest(repository: Path) -> SourceManifest:
    head = os.fsdecode(
        _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    ).strip()
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    refs = _git(repository, "show-ref", "--head", "--dereference")
    worktrees = _git(repository, "worktree", "list", "--porcelain", "-z")
    git_dir = _git_path(repository, "--git-dir")
    common_dir = _git_path(repository, "--git-common-dir")
    return SourceManifest(
        head_sha=head,
        status_sha256=_sha256(status),
        refs_sha256=_sha256(refs),
        worktrees_sha256=_sha256(worktrees),
        git_control_sha256=_hash_git_control(git_dir, common_dir),
    )


def _git_path(repository: Path, flag: str) -> Path:
    raw = os.fsdecode(_git(repository, "rev-parse", flag)).strip()
    path = Path(raw)
    if not path.is_absolute():
        path = repository / path
    return path.resolve(strict=True)


def _hash_git_control(git_dir: Path, common_dir: Path) -> str:
    digest = hashlib.sha256()
    roots = sorted({git_dir, common_dir}, key=os.fspath)
    for root in roots:
        digest.update(os.fsencode(root))
        for entry in _control_entries(root):
            relative = entry.relative_to(root)
            metadata = entry.lstat()
            digest.update(os.fsencode(relative))
            digest.update(str(stat.S_IFMT(metadata.st_mode)).encode("ascii"))
            digest.update(str(metadata.st_mode & 0o7777).encode("ascii"))
            digest.update(str(metadata.st_size).encode("ascii"))
            digest.update(str(metadata.st_mtime_ns).encode("ascii"))
            if stat.S_ISLNK(metadata.st_mode):
                digest.update(os.fsencode(os.readlink(entry)))
            elif stat.S_ISREG(metadata.st_mode):
                with entry.open("rb") as handle:
                    while chunk := handle.read(_READ_CHUNK):
                        digest.update(chunk)
    return digest.hexdigest()


def _control_entries(root: Path) -> list[Path]:
    entries: list[Path] = []
    excluded = {"objects", "logs", "lfs", "rr-cache"}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        if current_path == root:
            directories[:] = [
                name for name in directories if name not in excluded
            ]
        for name in sorted(directories):
            entries.append(current_path / name)
        for name in sorted(filenames):
            entries.append(current_path / name)
    return sorted(entries, key=lambda path: os.fsencode(path.relative_to(root)))


def _safe_output_path(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    parent = root
    for part in parts[:-1]:
        parent = parent / part
        if os.path.lexists(parent):
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise SnapshotError(
                    "UNSAFE_DESTINATION",
                    f"snapshot parent is not a plain directory: {relative}",
                )
        else:
            parent.mkdir(mode=0o700)
    return parent / parts[-1]


def _write_blob(path: Path, blob: bytes, *, executable: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SnapshotError("UNSAFE_DESTINATION", str(exc)) from exc
    try:
        view = memoryview(blob)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SnapshotError(
            "UNSAFE_DESTINATION",
            f"snapshot file is not a private regular file: {path.name}",
        )
    path.chmod(0o555 if executable else 0o444)


def _freeze_tree(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in sorted(
        directories,
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o555)
    root.chmod(0o555)


def _remove_tree(root: Path) -> None:
    if not os.path.lexists(root):
        return
    for current, directories, filenames in os.walk(root, topdown=False):
        current_path = Path(current)
        for name in filenames:
            path = current_path / name
            if not path.is_symlink():
                path.chmod(0o600)
            path.unlink()
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o700)
                path.rmdir()
    root.chmod(0o700)
    root.rmdir()


def _snapshot_manifest_sha(entries: list[_TreeEntry]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry.mode.encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.object_id.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _declares_git_lfs(path: str, blob: bytes) -> bool:
    if path == ".lfsconfig":
        return True
    if PurePosixPath(path).name != ".gitattributes":
        return False
    for raw_line in blob.splitlines():
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line or line.startswith("#"):
            continue
        if any(
            token.replace(" ", "") == "filter=lfs"
            for token in line.split()
        ):
            return True
    return False


def _git(repository: Path, *arguments: str) -> bytes:
    executable = _GIT if _GIT.exists() else Path(shutil.which("git") or "")
    if not executable:
        raise SnapshotError("GIT_UNAVAILABLE", "Git executable was not found")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.fspath(repository),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    try:
        completed = subprocess.run(
            [
                os.fspath(executable),
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(repository),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        raise
    except OSError as exc:
        raise SnapshotError("GIT_UNAVAILABLE", str(exc)) from exc
    return completed.stdout


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
