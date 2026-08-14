from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
FAKE_CODEX = Path(__file__).with_name("test_child_fake_codex.py")
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.child_runner import ChildRunner  # noqa: E402
from codex_smart_subagents.permissions import (  # noqa: E402
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    PermissionDenied,
    PermissionGate,
)
from codex_smart_subagents.snapshot import (  # noqa: E402
    SnapshotBuilder,
    SnapshotError,
    SnapshotLimits,
)
from codex_smart_subagents.worker import (  # noqa: E402
    ChildWorkRequest,
    ChildWorker,
    ChildWorkerError,
)


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    ).stdout.strip()


def initialize_repository(root: Path) -> str:
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Worker Test")
    git(root, "config", "user.email", "worker@example.invalid")
    (root / "tracked.txt").write_text("source\n", encoding="utf-8")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-qm", "base")
    return git(root, "rev-parse", "HEAD")


class ConfigurableCanary:
    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.calls = []

    def verify(self, request):
        self.calls.append(request)
        if not self.allow:
            raise RuntimeError("negative probes unavailable")
        return CanaryEvidence(
            probe_id="pc1_" + "A" * 43,
            codex_version=request.codex_version,
            permission_profile=request.permission_profile,
            profile_sha256=request.profile_sha256,
            managed_config_sha256=request.managed_config_sha256,
            verified_at=datetime.now(timezone.utc),
            legacy_sandbox_mode=False,
            checks={name: True for name in REQUIRED_CANARY_CHECKS},
        )


class ChildWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.repository = self.base / "repository"
        self.base_sha = initialize_repository(self.repository)
        self.schema = self.base / "output.schema.json"
        self.schema.write_text(
            '{"type":"object","additionalProperties":false}',
            encoding="utf-8",
        )
        self.canary = ConfigurableCanary()
        self.worker = ChildWorker(
            snapshot_builder=SnapshotBuilder(
                SnapshotLimits(
                    max_files=100,
                    max_file_bytes=1024 * 1024,
                    max_total_bytes=8 * 1024 * 1024,
                )
            ),
            child_runner=ChildRunner(PermissionGate(self.canary)),
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, **overrides: object) -> ChildWorkRequest:
        values: dict[str, object] = {
            "repository": self.repository,
            "base_sha": self.base_sha,
            "runtime_root": self.base / "runtime",
            "codex_executable": FAKE_CODEX,
            "codex_version": "0.144.4",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "medium",
            "permission_profile_name": "adaptive_reader",
            "managed_config_sha256": "b" * 64,
            "output_schema": self.schema,
            "prompt": "Проверь содержимое снимка и верни отчёт.",
            "timeout_seconds": 5.0,
            "max_output_bytes": 1024 * 1024,
        }
        values.update(overrides)
        return ChildWorkRequest(**values)

    def test_runs_one_reader_against_snapshot_without_mutating_source(self) -> None:
        before_status = git(self.repository, "status", "--porcelain=v1")
        before_head = git(self.repository, "rev-parse", "HEAD")

        result = self.worker.run(self.request())

        self.assertTrue(result.child.succeeded)
        self.assertEqual(
            "source\n",
            (result.snapshot.root / "tracked.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(result.snapshot.source_after, result.source_after_child)
        self.assertEqual(before_status, git(self.repository, "status", "--porcelain=v1"))
        self.assertEqual(before_head, git(self.repository, "rev-parse", "HEAD"))
        invocation = (
            result.runtime.work_dir / "fake-codex-invocation.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn(str(self.repository.resolve()), invocation)
        self.assertEqual(1, len(self.canary.calls))

    def test_dirty_source_stops_before_canary_or_child(self) -> None:
        (self.repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(SnapshotError, "SOURCE_DIRTY"):
            self.worker.run(self.request())

        self.assertEqual([], self.canary.calls)
        self.assertFalse(
            (
                self.base
                / "runtime"
                / "work"
                / "fake-codex-invocation.json"
            ).exists()
        )

    def test_canary_failure_stops_before_child_execution(self) -> None:
        canary = ConfigurableCanary(allow=False)
        worker = ChildWorker(
            snapshot_builder=self.worker.snapshot_builder,
            child_runner=ChildRunner(PermissionGate(canary)),
        )

        with self.assertRaisesRegex(
            PermissionDenied,
            "PERMISSION_CANARY_UNAVAILABLE",
        ):
            worker.run(self.request())

        self.assertEqual(1, len(canary.calls))
        self.assertFalse(
            (
                self.base
                / "runtime"
                / "work"
                / "fake-codex-invocation.json"
            ).exists()
        )

    def test_detects_source_mutation_even_if_child_exits_successfully(self) -> None:
        with self.assertRaisesRegex(
            ChildWorkerError,
            "SOURCE_CHANGED_DURING_CHILD",
        ):
            self.worker.run(
                self.request(
                    prompt=(
                        "FAKE_MUTATE_RELATIVE:"
                        "../../repository/tracked.txt"
                    )
                )
            )

        self.assertEqual(
            "mutated by fake child\n",
            (self.repository / "tracked.txt").read_text(encoding="utf-8"),
        )

    def test_model_input_cannot_embed_the_canonical_source_path(self) -> None:
        with self.assertRaises(ValueError):
            self.request(
                prompt=f"Прочитай {self.repository.resolve()} напрямую.",
            )

    def test_runner_factory_is_bound_to_the_materialized_snapshot(self) -> None:
        calls = []

        def factory(profile, snapshot, work_request, runtime):
            calls.append((profile, snapshot, work_request, runtime))
            return self.worker.child_runner

        worker = ChildWorker(
            snapshot_builder=self.worker.snapshot_builder,
            child_runner_factory=factory,
        )

        result = worker.run(self.request())

        self.assertTrue(result.child.succeeded)
        self.assertEqual(1, len(calls))
        profile, snapshot, work_request, runtime = calls[0]
        self.assertEqual(result.snapshot, snapshot)
        self.assertEqual(result.runtime, runtime)
        self.assertEqual(result.snapshot.root, profile.snapshot_root)
        self.assertEqual(self.repository.resolve(), work_request.repository)

    def test_worker_requires_exactly_one_runner_strategy(self) -> None:
        with self.assertRaises(ValueError):
            ChildWorker(snapshot_builder=self.worker.snapshot_builder)
        with self.assertRaises(ValueError):
            ChildWorker(
                snapshot_builder=self.worker.snapshot_builder,
                child_runner=self.worker.child_runner,
                child_runner_factory=lambda *_args: self.worker.child_runner,
            )


if __name__ == "__main__":
    unittest.main()
