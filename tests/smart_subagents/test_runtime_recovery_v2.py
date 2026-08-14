from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.runtime_recovery_v2 import (  # noqa: E402
    RuntimeRecoveryV2,
    prepare_attempts_root_v2,
    write_attempt_marker_v2,
)


class _Store:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.sealed: list[tuple[str, bool]] = []

    def runtime_artifacts(self):
        return [dict(record) for record in self.records]

    def seal_runtime_artifact(self, artifact_id: str, *, terminal: bool):
        self.sealed.append((artifact_id, terminal))
        record = next(
            item for item in self.records if item["artifactId"] == artifact_id
        )
        path = Path(str(record["path"]))
        if path.exists() and not terminal:
            info = path.lstat()
            record["state"] = "ACTIVE"
            record["device"] = info.st_dev
            record["inode"] = info.st_ino
        elif path.exists():
            record["state"] = "TERMINAL"
        else:
            record["state"] = "MISSING"
            record["device"] = None
            record["inode"] = None
        return dict(record)


class RuntimeRecoveryV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="rrv2-")
        self.root = Path(self.temporary.name).resolve()
        self.attempts = self.root / "attempt-runtimes-v2"
        self.attempts.mkdir(mode=0o700)
        self.removed: list[Path] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(
        self,
        *,
        artifact_id: str = "ra2_" + "a" * 32,
        attempt_id: str = "att2_" + "b" * 32,
        state: str = "RESERVED",
        exists: bool = False,
        marker: bool = False,
    ) -> tuple[dict[str, object], Path]:
        path = self.attempts / f"attempt-{attempt_id}"
        device = None
        inode = None
        if exists:
            path.mkdir(mode=0o700)
            if marker:
                write_attempt_marker_v2(
                    path,
                    artifact_id=artifact_id,
                    attempt_id=attempt_id,
                )
            info = path.lstat()
            if state == "ACTIVE":
                device = info.st_dev
                inode = info.st_ino
        return (
            {
                "artifactId": artifact_id,
                "routeId": "route2_" + "c" * 32,
                "nodeId": "node2_" + "d" * 32,
                "kind": "attempt_runtime_v2",
                "path": str(path),
                "allowedRoot": str(self.attempts),
                "state": state,
                "device": device,
                "inode": inode,
            },
            path,
        )

    def _remover(self, path: Path, expected_root: Path) -> None:
        self.assertEqual(self.attempts, expected_root)
        for item in sorted(path.rglob("*"), reverse=True):
            if item.is_dir():
                item.rmdir()
            else:
                item.unlink()
        path.rmdir()
        self.removed.append(path)

    def test_dry_run_plans_owned_reserved_directory_without_mutation(self) -> None:
        record, path = self._record(exists=True, marker=True)
        store = _Store([record])

        report = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
            remover=self._remover,
        ).run(apply=False)

        self.assertTrue(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual(["ADOPT_AND_REMOVE"], [item.kind for item in report.actions])
        self.assertTrue(path.exists())
        self.assertEqual([], store.sealed)

    def test_attempts_root_creation_is_idempotent(self) -> None:
        state_home = self.root / "state"
        state_home.mkdir(mode=0o700)

        first = prepare_attempts_root_v2(state_home)
        second = prepare_attempts_root_v2(state_home)

        self.assertEqual(first, second)
        self.assertEqual(self.root / "state" / "attempt-runtimes-v2", first)
        self.assertEqual(0o700, stat.S_IMODE(first.stat().st_mode))

    def test_apply_adopts_removes_and_seals_owned_reserved_directory(self) -> None:
        record, path = self._record(exists=True, marker=True)
        store = _Store([record])

        report = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
        ).run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertFalse(path.exists())
        self.assertEqual(
            [(record["artifactId"], False), (record["artifactId"], True)],
            store.sealed,
        )

    def test_active_directory_requires_exact_recorded_inode(self) -> None:
        record, path = self._record(state="ACTIVE", exists=True, marker=True)
        record["inode"] = int(record["inode"]) + 1
        store = _Store([record])

        report = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
            remover=self._remover,
        ).run(apply=True)

        self.assertFalse(report.ok)
        self.assertEqual(["ARTIFACT_IDENTITY_MISMATCH"], list(report.blockers))
        self.assertTrue(path.exists())
        self.assertEqual([], store.sealed)

    def test_unknown_or_unmarked_leftover_blocks_all_cleanup(self) -> None:
        record, owned = self._record(exists=True, marker=False)
        unknown = self.attempts / ("attempt-att2_" + "e" * 32)
        unknown.mkdir(mode=0o700)
        store = _Store([record])

        report = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
            remover=self._remover,
        ).run(apply=True)

        self.assertFalse(report.ok)
        self.assertEqual(
            ["ATTEMPT_MARKER_INVALID", "UNREGISTERED_ATTEMPT_RUNTIME"],
            list(report.blockers),
        )
        self.assertTrue(owned.exists())
        self.assertTrue(unknown.exists())
        self.assertEqual([], store.sealed)

    def test_missing_reserved_record_is_closed_idempotently(self) -> None:
        record, path = self._record(exists=False)
        store = _Store([record])
        recovery = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
            remover=self._remover,
        )

        first = recovery.run(apply=True)
        second = recovery.run(apply=True)

        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertFalse(path.exists())
        self.assertEqual([(record["artifactId"], True)], store.sealed)

    def test_marker_is_private_exact_and_rejects_tampering(self) -> None:
        artifact_id = "ra2_" + "a" * 32
        attempt_id = "att2_" + "b" * 32
        attempt = self.attempts / f"attempt-{attempt_id}"
        attempt.mkdir(mode=0o700)

        marker = write_attempt_marker_v2(
            attempt,
            artifact_id=artifact_id,
            attempt_id=attempt_id,
        )

        self.assertEqual(0o600, stat.S_IMODE(marker.stat().st_mode))
        self.assertEqual(
            {
                "artifactId": artifact_id,
                "attemptId": attempt_id,
                "kind": "codex-smart-attempt-runtime/v2",
                "schemaVersion": 2,
            },
            json.loads(marker.read_text(encoding="utf-8")),
        )
        marker.chmod(0o644)
        record, _ = self._record(
            artifact_id=artifact_id,
            attempt_id=attempt_id,
            exists=False,
        )
        # Existing directory is the one prepared above.
        store = _Store([record])
        report = RuntimeRecoveryV2(
            store=store,
            attempts_root=self.attempts,
            remover=self._remover,
        ).run(apply=False)
        self.assertFalse(report.ok)
        self.assertIn("ATTEMPT_MARKER_INVALID", report.blockers)


if __name__ == "__main__":
    unittest.main()
