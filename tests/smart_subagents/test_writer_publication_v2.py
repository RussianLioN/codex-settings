from __future__ import annotations

import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.snapshot import (  # noqa: E402
    SnapshotBuilder,
    SnapshotLimits,
)
from codex_smart_subagents.quarantine import CandidateEvidence  # noqa: E402
from codex_smart_subagents.validation import (  # noqa: E402
    ValidationError,
    ValidationResult,
)
from codex_smart_subagents.writer_publication_v2 import (  # noqa: E402
    CandidateRefPublicationV2,
    DirectCandidateRefPublisherV2,
    WriterPublicationCoordinatorV2,
    WriterPublicationRequestV2,
)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class _ValidationRunner:
    def __init__(
        self,
        result: ValidationResult | None = None,
        *,
        failure: BaseException | None = None,
        before_run: Callable[[], None] | None = None,
        trace: list[str] | None = None,
    ) -> None:
        self.result = result or ValidationResult("passed", ())
        self.failure = failure
        self.before_run = before_run
        self.trace = trace
        self.calls: list[tuple[Path, tuple[tuple[str, ...], ...]]] = []

    def run(self, *, workspace, commands, cancellation):
        if self.trace is not None:
            self.trace.append("validate")
        command_tuple = tuple(tuple(command) for command in commands)
        self.calls.append((workspace, command_tuple))
        if self.before_run is not None:
            self.before_run()
        if self.failure is not None:
            raise self.failure
        return self.result


class _FailingRefPublisher:
    def __init__(self, trace: list[str] | None = None) -> None:
        self.calls: list[CandidateRefPublicationV2] = []
        self.trace = trace

    def publish(self, publication: CandidateRefPublicationV2):
        if self.trace is not None:
            self.trace.append("publish")
        self.calls.append(publication)
        raise RuntimeError("ref storage is unavailable")


class _RecordingRefPublisher:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.delegate = DirectCandidateRefPublisherV2()
        self.calls: list[CandidateRefPublicationV2] = []

    def publish(self, publication: CandidateRefPublicationV2):
        self.trace.append("publish")
        self.calls.append(publication)
        return self.delegate.publish(publication)


class _FabricatingRefPublisher:
    def publish(self, publication: CandidateRefPublicationV2):
        return CandidateEvidence(
            artifact_id=publication.candidate.artifact_id,
            ref=publication.candidate.ref,
            commit_sha=publication.candidate.commit_sha,
            tree_sha=publication.candidate.tree_sha,
            parent_sha=publication.base.commit_sha,
            message_bound=True,
        )


class _PartialFailingRefPublisher:
    def publish(self, publication: CandidateRefPublicationV2):
        publication.quarantine.publish_candidate(publication.candidate)
        raise RuntimeError("state finalization failed after update-ref")


class WriterPublicationCoordinatorV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-q")
        git(self.repository, "config", "user.name", "Writer V2 Test")
        git(
            self.repository,
            "config",
            "user.email",
            "writer-v2@example.invalid",
        )
        (self.repository / "tracked.txt").write_text(
            "base\n",
            encoding="utf-8",
        )
        git(self.repository, "add", "tracked.txt")
        git(self.repository, "commit", "-qm", "base")
        self.base_sha = git(self.repository, "rev-parse", "HEAD")
        self.snapshot_builder = SnapshotBuilder(
            SnapshotLimits(
                max_files=100,
                max_file_bytes=1024 * 1024,
                max_total_bytes=8 * 1024 * 1024,
            )
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, name: str) -> WriterPublicationRequestV2:
        return WriterPublicationRequestV2(
            route_id="route2_" + "1" * 32,
            node_id="node2_" + "2" * 32,
            attempt_id="att2_" + "3" * 32,
            repository=self.repository,
            base_sha=self.base_sha,
            attempt_root=self.root / name,
            quarantine_state_root=self.root / "state",
            validation_commands=(("/usr/bin/true",),),
            source_date_epoch=1_700_000_000,
            max_files=100,
            max_file_bytes=1024 * 1024,
            max_total_bytes=8 * 1024 * 1024,
            max_diff_bytes=4 * 1024 * 1024,
        )

    def coordinator(
        self,
        validation_runner: _ValidationRunner,
        *,
        ref_publisher=None,
    ) -> WriterPublicationCoordinatorV2:
        return WriterPublicationCoordinatorV2(
            snapshot_builder=self.snapshot_builder,
            validation_runner=validation_runner,
            ref_publisher=(
                ref_publisher or DirectCandidateRefPublisherV2()
            ),
        )

    def test_success_publishes_only_verified_quarantine_candidate(self) -> None:
        trace: list[str] = []
        validation = _ValidationRunner(trace=trace)
        publisher = _RecordingRefPublisher(trace)
        coordinator = self.coordinator(validation, ref_publisher=publisher)
        session = coordinator.prepare(self.request("success"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("VERIFIED", result.state)
        self.assertIsNone(result.error_code)
        self.assertEqual("passed", result.validation_state)
        self.assertTrue(result.ref_published)
        self.assertRegex(result.artifact_id or "", r"^art1_[A-Za-z0-9_-]{43}$")
        self.assertRegex(result.proof_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(
            "base\n",
            (self.repository / "tracked.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "base\n",
            (session.snapshot.root / "tracked.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "candidate\n",
            (validation.calls[0][0] / "tracked.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            result.commit_sha,
            git(session.quarantine.git_dir, "rev-parse", result.ref or ""),
        )
        self.assertEqual(["validate", "publish"], trace)
        self.assertEqual("passed", publisher.calls[0].validation.validation_state)

    def test_source_change_during_validation_leaves_candidate_without_ref(
        self,
    ) -> None:
        def mutate_source() -> None:
            (self.repository / "tracked.txt").write_text(
                "source changed\n",
                encoding="utf-8",
            )

        validation = _ValidationRunner(before_run=mutate_source)
        coordinator = self.coordinator(validation)
        session = coordinator.prepare(self.request("source-change"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("SOURCE_CHANGED_DURING_WRITER", result.error_code)
        self.assertEqual("quarantined", result.validation_state)
        self.assertFalse(result.ref_published)
        self.assertFalse(session.quarantine.ref_exists(result.ref or ""))

    def test_fabricated_publication_evidence_without_ref_is_rejected(self) -> None:
        validation = _ValidationRunner()
        coordinator = self.coordinator(
            validation,
            ref_publisher=_FabricatingRefPublisher(),
        )
        session = coordinator.prepare(self.request("fabricated-publication"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("CANDIDATE_PUBLICATION_MISMATCH", result.error_code)
        self.assertFalse(result.ref_published)
        self.assertFalse(session.quarantine.ref_exists(result.ref or ""))

    def test_failure_after_update_ref_reports_recovery_required_ref(self) -> None:
        validation = _ValidationRunner()
        coordinator = self.coordinator(
            validation,
            ref_publisher=_PartialFailingRefPublisher(),
        )
        session = coordinator.prepare(self.request("partial-publication"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("CANDIDATE_PUBLICATION_FAILED", result.error_code)
        self.assertTrue(result.ref_published)
        self.assertTrue(session.quarantine.ref_exists(result.ref or ""))

    def test_failed_validation_keeps_candidate_quarantined(self) -> None:
        validation = _ValidationRunner(ValidationResult("failed", ()))
        coordinator = self.coordinator(validation)
        session = coordinator.prepare(self.request("validation-failed"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("VALIDATION_FAILED", result.error_code)
        self.assertEqual("failed", result.validation_state)
        self.assertFalse(result.ref_published)
        self.assertFalse(session.quarantine.ref_exists(result.ref or ""))

    def test_unavailable_validation_keeps_candidate_quarantined(self) -> None:
        validation = _ValidationRunner(
            failure=ValidationError(
                "MANAGED_CONFIG_UNAVAILABLE",
                "managed configuration cannot be rechecked",
            )
        )
        coordinator = self.coordinator(validation)
        session = coordinator.prepare(self.request("validation-unavailable"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("MANAGED_CONFIG_UNAVAILABLE", result.error_code)
        self.assertEqual("quarantined", result.validation_state)
        self.assertFalse(result.ref_published)
        self.assertFalse(session.quarantine.ref_exists(result.ref or ""))

    def test_ref_publication_failure_is_closed_after_validation(self) -> None:
        trace: list[str] = []
        validation = _ValidationRunner(trace=trace)
        publisher = _FailingRefPublisher(trace)
        coordinator = self.coordinator(
            validation,
            ref_publisher=publisher,
        )
        session = coordinator.prepare(self.request("publication-failed"))
        (session.workspace.root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )

        result = coordinator.complete(
            session,
            cancellation=threading.Event(),
        )

        self.assertEqual("QUARANTINED", result.state)
        self.assertEqual("CANDIDATE_PUBLICATION_FAILED", result.error_code)
        self.assertEqual("quarantined", result.validation_state)
        self.assertFalse(result.ref_published)
        self.assertRegex(result.commit_sha or "", r"^[0-9a-f]{40}$")
        self.assertEqual(1, len(validation.calls))
        self.assertEqual(1, len(publisher.calls))
        self.assertFalse(session.quarantine.ref_exists(result.ref or ""))
        self.assertEqual(["validate", "publish"], trace)


if __name__ == "__main__":
    unittest.main()
