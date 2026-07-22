from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.snapshot import (  # noqa: E402
    SnapshotBuilder,
    SnapshotError,
    SnapshotLimits,
    validate_snapshot_paths,
)


def git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def initialize_repository(root: Path) -> str:
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Snapshot Test")
    git(root, "config", "user.email", "snapshot@example.invalid")
    (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    executable = root / "tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    git(root, "add", "tracked.txt", "tool.sh")
    git(root, "commit", "-qm", "base")
    return git(root, "rev-parse", "HEAD").decode().strip()


class SnapshotPathValidationTests(unittest.TestCase):
    def test_rejects_traversal_git_metadata_and_normalization_collisions(self) -> None:
        invalid_sets = (
            ("../escape",),
            (".git/config",),
            ("safe/../../escape",),
            ("A.txt", "a.txt"),
            ("\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "e\u0301.txt"),
        )
        for paths in invalid_sets:
            with self.subTest(paths=paths):
                with self.assertRaises(SnapshotError):
                    validate_snapshot_paths(paths)


class SnapshotBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.repository = self.base / "repository"
        self.base_sha = initialize_repository(self.repository)
        self.builder = SnapshotBuilder(
            SnapshotLimits(
                max_files=20,
                max_file_bytes=4096,
                max_total_bytes=16384,
            )
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def build(self, name: str = "snapshot"):
        return self.builder.build(
            repository=self.repository,
            base_sha=self.base_sha,
            destination=self.base / name,
        )

    def test_materializes_only_tracked_blobs_from_clean_head(self) -> None:
        (self.repository / "untracked.txt").write_text(
            "must not leak\n",
            encoding="utf-8",
        )
        (self.repository / "untracked.txt").unlink()

        result = self.build()

        self.assertEqual(self.base_sha, result.base_sha)
        self.assertEqual(2, result.file_count)
        self.assertEqual(
            "tracked\n",
            (result.root / "tracked.txt").read_text(encoding="utf-8"),
        )
        self.assertFalse((result.root / ".git").exists())
        self.assertFalse((result.root / "untracked.txt").exists())
        self.assertEqual(
            0o444,
            stat.S_IMODE((result.root / "tracked.txt").stat().st_mode),
        )
        self.assertEqual(
            0o555,
            stat.S_IMODE((result.root / "tool.sh").stat().st_mode),
        )
        self.assertEqual(result.source_before, result.source_after)
        self.assertEqual(64, len(result.manifest_sha256))

    def test_rejects_dirty_or_wrong_head(self) -> None:
        (self.repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotError, "SOURCE_DIRTY"):
            self.build("dirty-tracked")

        git(self.repository, "restore", "tracked.txt")
        (self.repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotError, "SOURCE_DIRTY"):
            self.build("dirty-untracked")

        (self.repository / "untracked.txt").unlink()
        with self.assertRaisesRegex(SnapshotError, "BASE_SHA_MISMATCH"):
            self.builder.build(
                repository=self.repository,
                base_sha="0" * 40,
                destination=self.base / "wrong-head",
            )

    def test_rejects_symlinks_submodules_lfs_and_linked_worktrees(self) -> None:
        symlink = self.repository / "link"
        symlink.symlink_to("tracked.txt")
        git(self.repository, "add", "link")
        git(self.repository, "commit", "-qm", "symlink")
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(SnapshotError, "SYMLINK"):
            self.build("symlink")

        git(self.repository, "reset", "--hard", "HEAD~1")
        lfs = self.repository / "large.bin"
        lfs.write_text(
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "a" * 64 + "\n"
            "size 12\n",
            encoding="utf-8",
        )
        git(self.repository, "add", "large.bin")
        git(self.repository, "commit", "-qm", "lfs pointer")
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(SnapshotError, "GIT_LFS"):
            self.build("lfs")

        git(self.repository, "reset", "--hard", "HEAD~1")
        linked = self.base / "linked-worktree"
        git(self.repository, "worktree", "add", "-q", "-b", "linked-test", str(linked))
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(SnapshotError, "EXTERNAL_WORKTREE"):
            self.build("linked")
        git(self.repository, "worktree", "remove", "--force", str(linked))

        nested = self.base / "nested"
        nested_sha = initialize_repository(nested)
        del nested_sha
        git(
            self.repository,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(nested),
            "vendor/nested",
        )
        git(self.repository, "commit", "-qm", "submodule")
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(SnapshotError, "SUBMODULE"):
            self.build("submodule")

    def test_enforces_file_and_total_size_limits(self) -> None:
        (self.repository / "large.txt").write_bytes(b"x" * 128)
        git(self.repository, "add", "large.txt")
        git(self.repository, "commit", "-qm", "large")
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()
        builder = SnapshotBuilder(
            SnapshotLimits(
                max_files=20,
                max_file_bytes=64,
                max_total_bytes=16384,
            )
        )
        with self.assertRaisesRegex(SnapshotError, "FILE_TOO_LARGE"):
            builder.build(
                repository=self.repository,
                base_sha=self.base_sha,
                destination=self.base / "too-large",
            )

    def test_rejects_repository_level_git_lfs_configuration(self) -> None:
        (self.repository / ".gitattributes").write_text(
            "*.bin filter=lfs diff=lfs merge=lfs -text\n",
            encoding="utf-8",
        )
        (self.repository / "ordinary.bin").write_bytes(b"ordinary content\n")
        git(self.repository, "add", ".gitattributes", "ordinary.bin")
        git(self.repository, "commit", "-qm", "lfs attributes")
        self.base_sha = git(self.repository, "rev-parse", "HEAD").decode().strip()

        with self.assertRaisesRegex(SnapshotError, "GIT_LFS"):
            self.build("lfs-attributes")

    def test_destination_must_be_fresh_and_cannot_be_a_symlink(self) -> None:
        occupied = self.base / "occupied"
        occupied.mkdir()
        with self.assertRaisesRegex(SnapshotError, "DESTINATION_EXISTS"):
            self.builder.build(
                repository=self.repository,
                base_sha=self.base_sha,
                destination=occupied,
            )

        target = self.base / "target"
        target.mkdir()
        symlink = self.base / "destination-link"
        symlink.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(SnapshotError, "DESTINATION_EXISTS"):
            self.builder.build(
                repository=self.repository,
                base_sha=self.base_sha,
                destination=symlink,
            )

    def test_deadline_closes_snapshot_before_any_destination_is_created(self) -> None:
        destination = self.base / "expired"

        with self.assertRaisesRegex(SnapshotError, "SNAPSHOT_DEADLINE_EXCEEDED"):
            self.builder.build(
                repository=self.repository,
                base_sha=self.base_sha,
                destination=destination,
                deadline_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )

        self.assertFalse(destination.exists())

    def test_deadline_bounds_git_process_and_normalizes_timeout(self) -> None:
        with mock.patch(
            "codex_smart_subagents.snapshot.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=1),
        ) as run:
            with self.assertRaisesRegex(
                SnapshotError,
                "SNAPSHOT_DEADLINE_EXCEEDED",
            ):
                self.builder.build(
                    repository=self.repository,
                    base_sha=self.base_sha,
                    destination=self.base / "timed-out",
                    deadline_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                )

        self.assertIn("timeout", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
