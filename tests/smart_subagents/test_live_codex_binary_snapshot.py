from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.codex_binary_snapshot import (  # noqa: E402
    CodexBinarySnapshotter,
)


@unittest.skipUnless(
    os.environ.get("CODEX_SMART_RUN_LIVE_SNAPSHOT") == "1",
    "set CODEX_SMART_RUN_LIVE_SNAPSHOT=1 to copy and verify the live Codex binary",
)
class LiveCodexBinarySnapshotTests(unittest.TestCase):
    def test_current_codex_binary_passes_private_snapshot_verification(self) -> None:
        source = Path(
            os.environ.get("CODEX_SMART_LIVE_CODEX_BINARY", "/opt/homebrew/bin/codex")
        )
        self.assertTrue(source.exists(), f"Codex binary is unavailable: {source}")
        with tempfile.TemporaryDirectory() as temporary:
            subject = CodexBinarySnapshotter(
                snapshot_root=Path(temporary).resolve() / "codex-snapshots",
                command_timeout_seconds=30,
            ).materialize(source)
            published = Path(subject["snapshotPath"])
            self.assertTrue(published.is_file())
            self.assertEqual(0o500, stat.S_IMODE(published.stat().st_mode))

        self.assertEqual("darwin", subject["platform"])
        self.assertEqual("arm64", subject["architecture"])
        self.assertEqual("codex", subject["signatureIdentifier"])
        self.assertEqual("2DC432GLL2", subject["teamIdentifier"])
        self.assertRegex(subject["cdHash"], r"^[0-9a-f]{40}$")
        self.assertRegex(subject["snapshotSha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
