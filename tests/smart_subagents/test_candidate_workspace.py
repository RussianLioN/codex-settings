from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.candidate import (  # noqa: E402
    CandidateWorkspaceError,
    materialize_candidate_workspace,
)


class CandidateWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir(mode=0o700)
        (self.snapshot / "src").mkdir(mode=0o700)
        (self.snapshot / "src" / "app.py").write_text(
            "print('base')\n",
            encoding="utf-8",
        )
        (self.snapshot / "src" / "app.py").chmod(0o400)
        executable = self.snapshot / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o500)
        (self.snapshot / "src").chmod(0o500)
        self.snapshot.chmod(0o500)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_materializes_fresh_writable_copy_without_links(self) -> None:
        destination = self.root / "candidate"

        result = materialize_candidate_workspace(
            self.snapshot,
            destination,
            max_files=10,
            max_file_bytes=1024,
            max_total_bytes=4096,
        )

        self.assertEqual(destination.resolve(), result.root)
        self.assertEqual(2, result.file_count)
        self.assertEqual(0o700, stat.S_IMODE(destination.stat().st_mode))
        copied = destination / "src" / "app.py"
        copied.write_text("print('candidate')\n", encoding="utf-8")
        self.assertEqual(
            "print('base')\n",
            (self.snapshot / "src" / "app.py").read_text(encoding="utf-8"),
        )
        self.assertNotEqual(copied.stat().st_ino, (self.snapshot / "src" / "app.py").stat().st_ino)
        self.assertEqual(0o700, stat.S_IMODE((destination / "run.sh").stat().st_mode))

    def test_rejects_links_existing_destination_and_limits(self) -> None:
        link = self.snapshot / "escape"
        self.snapshot.chmod(0o700)
        os.symlink("/etc/passwd", link)
        self.snapshot.chmod(0o500)
        with self.assertRaisesRegex(
            CandidateWorkspaceError,
            "CANDIDATE_SOURCE_LINK",
        ):
            materialize_candidate_workspace(
                self.snapshot,
                self.root / "linked",
                max_files=10,
                max_file_bytes=1024,
                max_total_bytes=4096,
            )
        self.snapshot.chmod(0o700)
        link.unlink()
        self.snapshot.chmod(0o500)

        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(
            CandidateWorkspaceError,
            "CANDIDATE_DESTINATION_EXISTS",
        ):
            materialize_candidate_workspace(
                self.snapshot,
                existing,
                max_files=10,
                max_file_bytes=1024,
                max_total_bytes=4096,
            )

        with self.assertRaisesRegex(
            CandidateWorkspaceError,
            "CANDIDATE_FILE_TOO_LARGE",
        ):
            materialize_candidate_workspace(
                self.snapshot,
                self.root / "limited",
                max_files=10,
                max_file_bytes=4,
                max_total_bytes=4096,
            )


if __name__ == "__main__":
    unittest.main()
