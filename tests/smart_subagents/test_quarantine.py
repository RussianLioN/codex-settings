from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.quarantine import (  # noqa: E402
    QuarantineError,
    QuarantineRepository,
    repository_manifest,
    validate_paths,
)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


class QuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.source, "init", "-q")
        git(self.source, "config", "user.name", "Test")
        git(self.source, "config", "user.email", "test@example.invalid")
        (self.source / "src").mkdir()
        (self.source / "src" / "app.py").write_text(
            "print('base')\n",
            encoding="utf-8",
        )
        executable = self.source / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        git(self.source, "add", ".")
        git(self.source, "commit", "-qm", "base")
        self.base_sha = git(self.source, "rev-parse", "HEAD")
        self.state = self.root / "state"
        self.quarantine = QuarantineRepository.for_source(
            self.state,
            self.source,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_candidate_is_independent_verified_and_source_is_unchanged(
        self,
    ) -> None:
        before = repository_manifest(self.source)
        base = self.quarantine.import_base(self.base_sha)

        candidate = self.root / "candidate"
        shutil.copytree(self.source, candidate, ignore=shutil.ignore_patterns(".git"))
        (candidate / "src" / "app.py").write_text(
            "print('candidate')\n",
            encoding="utf-8",
        )
        (candidate / "README.md").write_text("candidate\n", encoding="utf-8")

        result = self.quarantine.build_candidate(
            candidate,
            base,
            source_date_epoch=1_700_000_000,
        )
        after = repository_manifest(self.source)
        self.assertEqual(before, after)
        self.assertEqual("ok", self.quarantine.fsck())
        self.assertFalse(
            (self.quarantine.git_dir / "objects" / "info" / "alternates").exists()
        )

        materialized = self.root / "materialized"
        self.quarantine.materialize(result.commit_sha, materialized)
        self.assertEqual(
            "print('candidate')\n",
            (materialized / "src" / "app.py").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            0o700,
            stat.S_IMODE((materialized / "run.sh").stat().st_mode),
        )
        self.assertEqual(result.commit_sha, git(self.quarantine.git_dir, "rev-parse", result.ref))

        source_blob = git(self.source, "rev-parse", f"{self.base_sha}:src/app.py")
        source_object = (
            self.source
            / ".git"
            / "objects"
            / source_blob[:2]
            / source_blob[2:]
        )
        quarantine_object = (
            self.quarantine.git_dir
            / "objects"
            / source_blob[:2]
            / source_blob[2:]
        )
        self.assertTrue(quarantine_object.exists())
        if source_object.exists():
            self.assertNotEqual(
                source_object.stat().st_ino,
                quarantine_object.stat().st_ino,
            )

    def test_tree_hash_is_reproducible_for_same_candidate(self) -> None:
        base = self.quarantine.import_base(self.base_sha)
        candidate = self.root / "candidate"
        shutil.copytree(self.source, candidate, ignore=shutil.ignore_patterns(".git"))
        first = self.quarantine.build_candidate(
            candidate,
            base,
            source_date_epoch=1_700_000_000,
        )
        second = self.quarantine.build_candidate(
            candidate,
            base,
            source_date_epoch=1_700_000_000,
        )
        self.assertEqual(first.tree_sha, second.tree_sha)

    def test_symlink_special_case_collision_and_size_limits_fail_closed(
        self,
    ) -> None:
        base = self.quarantine.import_base(self.base_sha)
        cases: list[tuple[str, callable]] = []

        def symlink_case(root: Path) -> None:
            os.symlink("/etc/passwd", root / "escape")

        def oversized_case(root: Path) -> None:
            (root / "large.bin").write_bytes(b"x" * 33)

        cases.extend(
            [
                ("symlink", symlink_case),
                ("oversized", oversized_case),
            ]
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                candidate = self.root / f"candidate-{name}"
                shutil.copytree(
                    self.source,
                    candidate,
                    ignore=shutil.ignore_patterns(".git"),
                )
                mutate(candidate)
                with self.assertRaises(QuarantineError):
                    self.quarantine.build_candidate(
                        candidate,
                        base,
                        source_date_epoch=1_700_000_000,
                        max_file_bytes=32,
                        max_total_bytes=1_000,
                    )
        with self.assertRaises(QuarantineError):
            validate_paths(["Readme", "README"])
        with self.assertRaises(QuarantineError):
            validate_paths(["Cafe\u0301", "Caf\u00e9"])

    def test_manifest_detects_index_ref_and_worktree_changes(self) -> None:
        baseline = repository_manifest(self.source)
        (self.source / "src" / "app.py").write_text(
            "print('dirty')\n",
            encoding="utf-8",
        )
        dirty = repository_manifest(self.source)
        self.assertNotEqual(baseline.digest, dirty.digest)
        self.assertEqual(
            hashlib.sha256(baseline.canonical_bytes).hexdigest(),
            baseline.digest,
        )


if __name__ == "__main__":
    unittest.main()
