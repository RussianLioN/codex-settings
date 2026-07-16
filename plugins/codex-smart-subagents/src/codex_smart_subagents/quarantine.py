"""Independent Git object quarantine for untrusted writer candidates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .identity import new_opaque_id, sha256_text


DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_DIFF_BYTES = 128 * 1024 * 1024
_ALLOWED_MODES = frozenset({"100644", "100755"})
_ARTIFACT_ID = re.compile(r"art1_[A-Za-z0-9_-]{43}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass
class QuarantineError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RepositoryManifest:
    canonical_bytes: bytes
    digest: str


@dataclass(frozen=True)
class BaseImport:
    source_sha: str
    commit_sha: str
    tree_sha: str
    ref: str
    entries: dict[str, tuple[str, str, int]]


@dataclass(frozen=True)
class CandidateResult:
    artifact_id: str
    commit_sha: str
    tree_sha: str
    ref: str
    file_count: int
    total_bytes: int
    diff_bytes: int


@dataclass(frozen=True)
class CandidateEvidence:
    artifact_id: str
    ref: str
    commit_sha: str
    tree_sha: str
    parent_sha: str
    message_bound: bool


@dataclass(frozen=True)
class _File:
    path: str
    mode: str
    data: bytes


class QuarantineRepository:
    def __init__(
        self,
        *,
        source_root: Path,
        git_dir: Path,
        git_binary: Path,
    ) -> None:
        self.source_root = source_root
        self.git_dir = git_dir
        self.git_binary = git_binary

    @classmethod
    def for_source(
        cls,
        state_root: Path,
        source_root: Path,
        *,
        git_binary: Path | None = None,
    ) -> "QuarantineRepository":
        source = source_root.expanduser().resolve()
        if not source.is_dir():
            raise QuarantineError(
                "SOURCE_INVALID",
                "source repository root is not a directory",
            )
        binary = git_binary or _default_git()
        binary = binary.expanduser().resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise QuarantineError("GIT_UNAVAILABLE", f"git is unavailable: {binary}")
        root = state_root.expanduser()
        _secure_directory(root)
        repositories = root / "quarantine"
        _secure_directory(repositories)
        git_dir = repositories / f"{sha256_text(str(source))[:24]}.git"
        instance = cls(
            source_root=source,
            git_dir=git_dir,
            git_binary=binary,
        )
        instance._initialize()
        return instance

    @classmethod
    def open_registered(
        cls,
        *,
        state_root: Path,
        source_root: Path,
        git_dir: Path,
        git_binary: Path | None = None,
    ) -> "QuarantineRepository":
        source = source_root.expanduser().resolve(strict=True)
        root = state_root.expanduser().resolve(strict=True)
        registered_git = git_dir.expanduser().resolve(strict=True)
        expected_parent = (root / "quarantine").resolve(strict=True)
        expected_name = f"{sha256_text(str(source))[:24]}.git"
        if (
            not source.is_dir()
            or root.is_symlink()
            or not root.is_dir()
            or registered_git.is_symlink()
            or not registered_git.is_dir()
            or registered_git.parent != expected_parent
            or registered_git.name != expected_name
        ):
            raise QuarantineError(
                "REGISTERED_REPOSITORY_UNSAFE",
                "registered quarantine repository identity is unsafe",
            )
        for path in (root, expected_parent, registered_git):
            metadata = path.stat()
            if (
                metadata.st_uid != os.getuid()
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise QuarantineError(
                    "REGISTERED_REPOSITORY_UNSAFE",
                    "registered quarantine repository permissions are unsafe",
                )
        binary = (git_binary or _default_git()).expanduser().resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise QuarantineError("GIT_UNAVAILABLE", f"git is unavailable: {binary}")
        instance = cls(
            source_root=source,
            git_dir=registered_git,
            git_binary=binary,
        )
        alternates = instance.git_dir / "objects" / "info" / "alternates"
        if alternates.exists():
            raise QuarantineError(
                "ALTERNATES_FORBIDDEN",
                "quarantine Git must not use object alternates",
            )
        instance._secure_git_dir()
        return instance

    def import_base(self, base_sha: str) -> BaseImport:
        source_commit = self._source_git(
            "rev-parse",
            "--verify",
            f"{base_sha}^{{commit}}",
        ).decode("ascii").strip()
        if source_commit != base_sha:
            raise QuarantineError(
                "BASE_SHA_NOT_EXACT",
                "base SHA must be the full resolved commit identifier",
            )
        files = self._source_tree(source_commit)
        entries = self._store_files(files)
        tree_sha = self._write_tree(entries)
        epoch_text = self._source_git(
            "show",
            "-s",
            "--format=%ct",
            source_commit,
        ).decode("ascii").strip()
        try:
            epoch = int(epoch_text)
        except ValueError as exc:
            raise QuarantineError(
                "BASE_TIMESTAMP_INVALID",
                "source commit timestamp is invalid",
            ) from exc
        commit_sha = self._commit_tree(
            tree_sha,
            parent=None,
            message=f"quarantine base {source_commit}\n",
            source_date_epoch=epoch,
        )
        ref = f"refs/bases/{source_commit}"
        self._git("update-ref", ref, commit_sha)
        self._secure_git_dir()
        if self.fsck() != "ok":
            raise QuarantineError("FSCK_FAILED", "base quarantine fsck failed")
        return BaseImport(
            source_sha=source_commit,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            ref=ref,
            entries=entries,
        )

    def build_candidate(
        self,
        candidate_root: Path,
        base: BaseImport,
        *,
        source_date_epoch: int,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES,
    ) -> CandidateResult:
        candidate = self.prepare_candidate(
            candidate_root,
            base,
            source_date_epoch=source_date_epoch,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_diff_bytes=max_diff_bytes,
        )
        self.publish_candidate(candidate)
        return candidate

    def prepare_candidate(
        self,
        candidate_root: Path,
        base: BaseImport,
        *,
        source_date_epoch: int,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES,
    ) -> CandidateResult:
        if source_date_epoch < 0:
            raise ValueError("source_date_epoch must be non-negative")
        files = _collect_files(
            candidate_root,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        stored = self._store_files(files)
        diff_bytes = _diff_bytes(base.entries, stored)
        if diff_bytes > max_diff_bytes:
            raise QuarantineError(
                "DIFF_TOO_LARGE",
                f"candidate diff exceeds {max_diff_bytes} bytes",
            )
        tree_sha = self._write_tree(stored)
        artifact_id = new_opaque_id("art1")
        commit_sha = self._commit_tree(
            tree_sha,
            parent=base.commit_sha,
            message=f"quarantine candidate {artifact_id}\n",
            source_date_epoch=source_date_epoch,
        )
        ref = f"refs/candidates/{artifact_id}"
        return CandidateResult(
            artifact_id=artifact_id,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            ref=ref,
            file_count=len(files),
            total_bytes=sum(len(file.data) for file in files),
            diff_bytes=diff_bytes,
        )

    def publish_candidate(self, candidate: CandidateResult) -> None:
        expected_ref = f"refs/candidates/{candidate.artifact_id}"
        if (
            _ARTIFACT_ID.fullmatch(candidate.artifact_id) is None
            or candidate.ref != expected_ref
            or _GIT_SHA.fullmatch(candidate.commit_sha) is None
            or _GIT_SHA.fullmatch(candidate.tree_sha) is None
        ):
            raise QuarantineError(
                "CANDIDATE_IDENTITY_INVALID",
                "candidate publication identity is invalid",
            )
        zero = "0" * 40
        self._git("update-ref", candidate.ref, candidate.commit_sha, zero)
        self._secure_git_dir()
        if self.fsck() != "ok":
            raise QuarantineError(
                "FSCK_FAILED",
                "candidate quarantine fsck failed",
            )
        evidence = self.candidate_evidence(candidate.ref)
        if (
            evidence.commit_sha != candidate.commit_sha
            or evidence.tree_sha != candidate.tree_sha
            or not evidence.message_bound
        ):
            raise QuarantineError(
                "CANDIDATE_PUBLICATION_MISMATCH",
                "published candidate does not match its prepared identity",
            )

    def ref_exists(self, ref: str) -> bool:
        _artifact_from_ref(ref)
        result = self._git(
            "show-ref",
            "--verify",
            "--quiet",
            ref,
            check=False,
        )
        return result.returncode == 0

    def candidate_refs(self) -> dict[str, str]:
        payload = self._git(
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/candidates",
        )
        refs: dict[str, str] = {}
        for line in payload.splitlines():
            try:
                raw_ref, raw_commit = line.split(b"\0", 1)
                ref = raw_ref.decode("ascii")
                commit = raw_commit.decode("ascii")
            except (ValueError, UnicodeDecodeError) as exc:
                raise QuarantineError(
                    "CANDIDATE_REF_INVALID",
                    "candidate reference listing is invalid",
                ) from exc
            if (
                not ref.startswith("refs/candidates/")
                or len(ref) > 512
                or _GIT_SHA.fullmatch(commit) is None
            ):
                raise QuarantineError(
                    "CANDIDATE_REF_INVALID",
                    "candidate reference identity is invalid",
                )
            refs[ref] = commit
        return refs

    def candidate_evidence(self, ref: str) -> CandidateEvidence:
        artifact_id = _artifact_from_ref(ref)
        commit_sha = self._git(
            "rev-parse",
            "--verify",
            f"{ref}^{{commit}}",
        ).decode("ascii").strip()
        if _GIT_SHA.fullmatch(commit_sha) is None:
            raise QuarantineError(
                "CANDIDATE_COMMIT_INVALID",
                "candidate commit identifier is invalid",
            )
        payload = self._git(
            "show",
            "-s",
            "--format=%T%x00%P%x00%B",
            commit_sha,
        )
        try:
            raw_tree, raw_parents, raw_message = payload.split(b"\0", 2)
            tree_sha = raw_tree.decode("ascii").strip()
            parent_text = raw_parents.decode("ascii").strip()
            message = raw_message.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise QuarantineError(
                "CANDIDATE_COMMIT_INVALID",
                "candidate commit evidence is invalid",
            ) from exc
        parents = parent_text.split()
        if (
            _GIT_SHA.fullmatch(tree_sha) is None
            or len(parents) != 1
            or _GIT_SHA.fullmatch(parents[0]) is None
        ):
            raise QuarantineError(
                "CANDIDATE_COMMIT_INVALID",
                "candidate commit topology is invalid",
            )
        return CandidateEvidence(
            artifact_id=artifact_id,
            ref=ref,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            parent_sha=parents[0],
            message_bound=message.rstrip("\n") == (
                f"quarantine candidate {artifact_id}"
            ),
        )

    def base_evidence_matches(
        self,
        *,
        source_sha: str,
        commit_sha: str,
        tree_sha: str,
    ) -> bool:
        if not all(
            _GIT_SHA.fullmatch(value) is not None
            for value in (source_sha, commit_sha, tree_sha)
        ):
            return False
        ref = f"refs/bases/{source_sha}"
        result = self._git(
            "rev-parse",
            "--verify",
            f"{ref}^{{commit}}",
            check=False,
        )
        if result.returncode != 0:
            return False
        observed_commit = result.stdout.decode("ascii", "replace").strip()
        if observed_commit != commit_sha:
            return False
        payload = self._git(
            "show",
            "-s",
            "--format=%T%x00%P%x00%B",
            commit_sha,
        )
        try:
            raw_tree, raw_parents, raw_message = payload.split(b"\0", 2)
            observed_tree = raw_tree.decode("ascii").strip()
            parents = raw_parents.decode("ascii").strip()
            message = raw_message.decode("utf-8").rstrip("\n")
        except (ValueError, UnicodeDecodeError):
            return False
        return (
            observed_tree == tree_sha
            and not parents
            and message == f"quarantine base {source_sha}"
        )

    def materialize(self, revision: str, destination: Path) -> None:
        root = destination.expanduser()
        if root.exists():
            if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
                raise QuarantineError(
                    "DESTINATION_NOT_EMPTY",
                    "materialization destination must be a new or empty directory",
                )
        else:
            _secure_directory(root)
        records = self._list_tree(revision)
        _validate_path_set(path for path, _mode, _oid in records)
        for path_text, mode, object_id in records:
            relative = PurePosixPath(path_text)
            parent = root.joinpath(*relative.parts[:-1])
            _secure_directory(parent)
            target = root.joinpath(*relative.parts)
            data = self._git("cat-file", "blob", object_id)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o700 if mode == "100755" else 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            os.chmod(target, 0o700 if mode == "100755" else 0o600)

    def fsck(self) -> str:
        result = self._git(
            "fsck",
            "--strict",
            "--no-reflogs",
            check=False,
            stderr=subprocess.PIPE,
        )
        return "ok" if result.returncode == 0 else "failed"

    def _initialize(self) -> None:
        if self.git_dir.exists():
            if self.git_dir.is_symlink() or not self.git_dir.is_dir():
                raise QuarantineError(
                    "QUARANTINE_PATH_UNSAFE",
                    "quarantine Git path has an unexpected type",
                )
        else:
            result = subprocess.run(
                [str(self.git_binary), "init", "--bare", "-q", str(self.git_dir)],
                env=_git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode != 0:
                raise QuarantineError(
                    "GIT_INIT_FAILED",
                    result.stderr.decode("utf-8", "replace")[:1000],
                )
        self._git("config", "core.hooksPath", "/dev/null")
        self._git("config", "gc.auto", "0")
        alternates = self.git_dir / "objects" / "info" / "alternates"
        if alternates.exists():
            raise QuarantineError(
                "ALTERNATES_FORBIDDEN",
                "quarantine Git must not use object alternates",
            )
        self._secure_git_dir()

    def _source_tree(self, revision: str) -> list[_File]:
        records = _parse_ls_tree(
            self._source_git(
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                revision,
            )
        )
        _validate_path_set(path for path, _mode, _oid in records)
        files: list[_File] = []
        for path, mode, object_id in records:
            if mode not in _ALLOWED_MODES:
                code = "SYMLINK_FORBIDDEN" if mode == "120000" else "GIT_ENTRY_FORBIDDEN"
                raise QuarantineError(
                    code,
                    f"unsupported Git entry mode {mode} at {path}",
                )
            data = self._source_git("cat-file", "blob", object_id)
            files.append(_File(path=path, mode=mode, data=data))
        return files

    def _store_files(
        self,
        files: Iterable[_File],
    ) -> dict[str, tuple[str, str, int]]:
        entries: dict[str, tuple[str, str, int]] = {}
        for file in files:
            object_id = self._git(
                "hash-object",
                "-w",
                "--stdin",
                input_data=file.data,
            ).decode("ascii").strip()
            entries[file.path] = (file.mode, object_id, len(file.data))
        return entries

    def _write_tree(
        self,
        entries: dict[str, tuple[str, str, int]],
    ) -> str:
        node: dict[str, Any] = {}
        for path, (mode, object_id, _size) in entries.items():
            parts = PurePosixPath(path).parts
            cursor = node
            for part in parts[:-1]:
                existing = cursor.setdefault(part, {})
                if not isinstance(existing, dict):
                    raise QuarantineError(
                        "PATH_COLLISION",
                        f"file and directory collide at {path}",
                    )
                cursor = existing
            if parts[-1] in cursor:
                raise QuarantineError("PATH_COLLISION", f"duplicate path: {path}")
            cursor[parts[-1]] = (mode, object_id)
        return self._write_tree_node(node)

    def _write_tree_node(self, node: dict[str, Any]) -> str:
        records: list[bytes] = []
        for name in sorted(node, key=lambda value: value.encode("utf-8")):
            value = node[name]
            encoded_name = name.encode("utf-8")
            if isinstance(value, dict):
                object_id = self._write_tree_node(value)
                records.append(b"040000 tree " + object_id.encode() + b"\t" + encoded_name + b"\0")
            else:
                mode, object_id = value
                records.append(
                    mode.encode()
                    + b" blob "
                    + object_id.encode()
                    + b"\t"
                    + encoded_name
                    + b"\0"
                )
        return self._git(
            "mktree",
            "-z",
            input_data=b"".join(records),
        ).decode("ascii").strip()

    def _commit_tree(
        self,
        tree_sha: str,
        *,
        parent: str | None,
        message: str,
        source_date_epoch: int,
    ) -> str:
        arguments = ["commit-tree", tree_sha]
        if parent is not None:
            arguments.extend(["-p", parent])
        environment = _git_environment()
        date = f"{source_date_epoch} +0000"
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Codex Smart Subagents",
                "GIT_AUTHOR_EMAIL": "codex-smart-subagents@localhost",
                "GIT_AUTHOR_DATE": date,
                "GIT_COMMITTER_NAME": "Codex Smart Subagents",
                "GIT_COMMITTER_EMAIL": "codex-smart-subagents@localhost",
                "GIT_COMMITTER_DATE": date,
            }
        )
        return self._git(
            *arguments,
            input_data=message.encode("utf-8"),
            env=environment,
        ).decode("ascii").strip()

    def _list_tree(self, revision: str) -> list[tuple[str, str, str]]:
        return _parse_ls_tree(
            self._git("ls-tree", "-r", "-z", "--full-tree", revision)
        )

    def _source_git(self, *arguments: str) -> bytes:
        result = subprocess.run(
            [
                str(self.git_binary),
                "-C",
                str(self.source_root),
                *arguments,
            ],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise QuarantineError(
                "SOURCE_GIT_FAILED",
                result.stderr.decode("utf-8", "replace")[:1000],
            )
        return result.stdout

    def _git(
        self,
        *arguments: str,
        input_data: bytes | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        stderr: int = subprocess.PIPE,
    ) -> bytes | subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [
                str(self.git_binary),
                f"--git-dir={self.git_dir}",
                *arguments,
            ],
            env=env or _git_environment(),
            input=input_data,
            stdin=subprocess.DEVNULL if input_data is None else None,
            stdout=subprocess.PIPE,
            stderr=stderr,
            check=False,
        )
        if check and result.returncode != 0:
            error = (
                b""
                if result.stderr is None
                else result.stderr
            ).decode("utf-8", "replace")[:1000]
            raise QuarantineError("QUARANTINE_GIT_FAILED", error)
        return result.stdout if check else result

    def _secure_git_dir(self) -> None:
        for root, directories, files in os.walk(self.git_dir, followlinks=False):
            root_path = Path(root)
            if root_path.is_symlink():
                raise QuarantineError(
                    "QUARANTINE_SYMLINK",
                    "quarantine Git contains a symbolic link",
                )
            os.chmod(root_path, 0o700)
            for name in directories:
                path = root_path / name
                if path.is_symlink():
                    raise QuarantineError(
                        "QUARANTINE_SYMLINK",
                        "quarantine Git contains a symbolic link",
                    )
                os.chmod(path, 0o700)
            for name in files:
                path = root_path / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise QuarantineError(
                        "QUARANTINE_FILE_UNSAFE",
                        "quarantine Git contains an unsafe file",
                    )
                os.chmod(path, 0o600)


def repository_manifest(source_root: Path) -> RepositoryManifest:
    source = source_root.expanduser().resolve()
    git_binary = _default_git()

    def run(*arguments: str) -> bytes:
        result = subprocess.run(
            [str(git_binary), "-C", str(source), *arguments],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise QuarantineError(
                "SOURCE_MANIFEST_FAILED",
                result.stderr.decode("utf-8", "replace")[:1000],
            )
        return result.stdout

    git_dir_text = run("rev-parse", "--git-dir").decode("utf-8").strip()
    git_dir = Path(git_dir_text)
    if not git_dir.is_absolute():
        git_dir = source / git_dir
    index = git_dir / "index"
    index_digest = _file_digest(index) if index.is_file() else ""
    material = {
        "head": run("rev-parse", "HEAD").decode("ascii").strip(),
        "status": run(
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        ).hex(),
        "worktreeDiff": run(
            "diff",
            "--no-ext-diff",
            "--binary",
            "--no-renames",
        ).hex(),
        "indexDiff": run(
            "diff",
            "--cached",
            "--no-ext-diff",
            "--binary",
            "--no-renames",
        ).hex(),
        "refs": run(
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
        ).hex(),
        "worktrees": run("worktree", "list", "--porcelain").hex(),
        "objects": run("count-objects", "-v").decode("utf-8", "replace"),
        "index": index_digest,
    }
    canonical = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return RepositoryManifest(
        canonical_bytes=canonical,
        digest=hashlib.sha256(canonical).hexdigest(),
    )


def validate_paths(paths: Iterable[str]) -> None:
    """Validate portable Git paths without materializing them first."""

    _validate_path_set(paths)


def _artifact_from_ref(ref: str) -> str:
    prefix = "refs/candidates/"
    if not ref.startswith(prefix):
        raise QuarantineError(
            "CANDIDATE_REF_INVALID",
            "candidate reference is outside the allowed namespace",
        )
    artifact_id = ref[len(prefix) :]
    if _ARTIFACT_ID.fullmatch(artifact_id) is None:
        raise QuarantineError(
            "CANDIDATE_REF_INVALID",
            "candidate reference artifact identifier is invalid",
        )
    return artifact_id


def _collect_files(
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> list[_File]:
    candidate = root.expanduser()
    info = candidate.lstat()
    if not stat.S_ISDIR(info.st_mode) or candidate.is_symlink():
        raise QuarantineError(
            "CANDIDATE_ROOT_UNSAFE",
            "candidate root must be a real directory",
        )
    files: list[_File] = []
    total = 0
    for current, directory_names, file_names in os.walk(
        candidate,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in list(directory_names):
            path = current_path / name
            entry = path.lstat()
            if stat.S_ISLNK(entry.st_mode):
                raise QuarantineError(
                    "SYMLINK_FORBIDDEN",
                    f"symbolic link is forbidden: {path.relative_to(candidate)}",
                )
            if not stat.S_ISDIR(entry.st_mode):
                raise QuarantineError(
                    "SPECIAL_FILE_FORBIDDEN",
                    f"special directory entry is forbidden: {path.relative_to(candidate)}",
                )
        for name in file_names:
            path = current_path / name
            entry = path.lstat()
            relative = path.relative_to(candidate).as_posix()
            if not stat.S_ISREG(entry.st_mode):
                code = "SYMLINK_FORBIDDEN" if stat.S_ISLNK(entry.st_mode) else "SPECIAL_FILE_FORBIDDEN"
                raise QuarantineError(code, f"unsupported candidate entry: {relative}")
            if entry.st_nlink != 1:
                raise QuarantineError(
                    "HARDLINK_FORBIDDEN",
                    f"hard-linked candidate file is forbidden: {relative}",
                )
            if entry.st_size > max_file_bytes:
                raise QuarantineError(
                    "FILE_TOO_LARGE",
                    f"candidate file exceeds {max_file_bytes} bytes: {relative}",
                )
            data = path.read_bytes()
            if len(data) != entry.st_size:
                raise QuarantineError(
                    "CANDIDATE_CHANGED",
                    f"candidate file changed while reading: {relative}",
                )
            total += len(data)
            if total > max_total_bytes:
                raise QuarantineError(
                    "CANDIDATE_TOO_LARGE",
                    f"candidate tree exceeds {max_total_bytes} bytes",
                )
            mode = "100755" if entry.st_mode & 0o111 else "100644"
            files.append(_File(path=relative, mode=mode, data=data))
            if len(files) > max_files:
                raise QuarantineError(
                    "TOO_MANY_FILES",
                    f"candidate contains more than {max_files} files",
                )
    _validate_path_set(file.path for file in files)
    return sorted(files, key=lambda item: item.path.encode("utf-8"))


def _parse_ls_tree(payload: bytes) -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        try:
            header, raw_path = raw.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise QuarantineError(
                "GIT_TREE_INVALID",
                "Git tree contains an unsupported path or record",
            ) from exc
        if object_type != "blob":
            raise QuarantineError(
                "GIT_ENTRY_FORBIDDEN",
                f"unsupported Git object type {object_type} at {path}",
            )
        records.append((path, mode, object_id))
    return records


def _validate_path_set(paths: Iterable[str]) -> None:
    seen: dict[str, str] = {}
    for path in paths:
        pure = PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(part.casefold() == ".git" for part in pure.parts)
        ):
            raise QuarantineError("PATH_FORBIDDEN", f"unsafe path: {path}")
        normalized = unicodedata.normalize("NFC", path)
        if normalized != path:
            raise QuarantineError(
                "UNICODE_NORMALIZATION_FORBIDDEN",
                f"path is not NFC-normalized: {path}",
            )
        collision_key = normalized.casefold()
        previous = seen.get(collision_key)
        if previous is not None and previous != path:
            raise QuarantineError(
                "CASE_COLLISION",
                f"paths collide by case or normalization: {previous}, {path}",
            )
        seen[collision_key] = path


def _diff_bytes(
    base: dict[str, tuple[str, str, int]],
    candidate: dict[str, tuple[str, str, int]],
) -> int:
    changed = 0
    for path in set(base) | set(candidate):
        before = base.get(path)
        after = candidate.get(path)
        if before == after:
            continue
        if before is not None:
            changed += before[2]
        if after is not None:
            changed += after[2]
    return changed


def _secure_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise QuarantineError("DIRECTORY_UNSAFE", f"directory is a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise QuarantineError(
            "DIRECTORY_UNSAFE",
            f"directory has unexpected owner or type: {path}",
        )
    os.chmod(path, 0o700)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_git() -> Path:
    system = Path("/usr/bin/git")
    if system.is_file() and os.access(system, os.X_OK):
        return system
    found = shutil.which("git")
    if found is None:
        raise QuarantineError("GIT_UNAVAILABLE", "git executable is unavailable")
    return Path(found).resolve()


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    }
