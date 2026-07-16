from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.resource_gate import (  # noqa: E402
    ResourceGate,
    ResourceLimitError,
    ResourceSnapshot,
    parse_vm_stat,
)


class ResourceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.snapshot = ResourceSnapshot(
            free_disk_bytes=4_000,
            available_memory_bytes=3_000,
            available_fds=200,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_accepts_snapshot_at_or_above_every_threshold(self) -> None:
        gate = ResourceGate(
            root=self.root,
            min_free_disk_bytes=4_000,
            min_available_memory_bytes=3_000,
            min_available_fds=200,
            probe=lambda _root: self.snapshot,
        )

        self.assertEqual(self.snapshot, gate.require_capacity())

    def test_fails_closed_for_each_exhausted_resource(self) -> None:
        cases = (
            (
                ResourceSnapshot(3_999, 3_000, 200),
                "DISK_CAPACITY_EXHAUSTED",
            ),
            (
                ResourceSnapshot(4_000, 2_999, 200),
                "MEMORY_CAPACITY_EXHAUSTED",
            ),
            (
                ResourceSnapshot(4_000, 3_000, 199),
                "FD_CAPACITY_EXHAUSTED",
            ),
        )
        for snapshot, code in cases:
            with self.subTest(code=code):
                gate = ResourceGate(
                    root=self.root,
                    min_free_disk_bytes=4_000,
                    min_available_memory_bytes=3_000,
                    min_available_fds=200,
                    probe=lambda _root, value=snapshot: value,
                )
                with self.assertRaisesRegex(ResourceLimitError, code):
                    gate.require_capacity()

    def test_probe_failure_is_not_treated_as_capacity(self) -> None:
        def fail(_root: Path) -> ResourceSnapshot:
            raise OSError("probe unavailable")

        gate = ResourceGate(
            root=self.root,
            min_free_disk_bytes=1,
            min_available_memory_bytes=1,
            min_available_fds=1,
            probe=fail,
        )
        with self.assertRaisesRegex(ResourceLimitError, "RESOURCE_PROBE_FAILED"):
            gate.require_capacity()

    def test_parses_darwin_vm_stat_without_locale_assumptions(self) -> None:
        output = (
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            "Pages free: 10.\n"
            "Pages inactive: 20.\n"
            "Pages speculative: 3.\n"
            "Pages purgeable: 2.\n"
            "Pages wired down: 999.\n"
        )
        self.assertEqual(35 * 16384, parse_vm_stat(output))


if __name__ == "__main__":
    unittest.main()
