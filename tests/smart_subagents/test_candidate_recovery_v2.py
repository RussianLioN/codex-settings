from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.candidate_recovery_v2 import (  # noqa: E402
    CandidateRecoveryV2,
)
from codex_smart_subagents.quarantine import QuarantineRepository  # noqa: E402
from codex_smart_subagents.state_candidate_publisher_v2 import (  # noqa: E402
    StateCandidateRefPublisherV2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    PlannedNodeV2,
    RequestContextV2,
    SmartStoreV2,
)
from codex_smart_subagents.validation import ValidationResult  # noqa: E402
from codex_smart_subagents.writer_publication_v2 import (  # noqa: E402
    CandidateRefPublicationV2,
)


NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)
VALIDATION_PROOF = "7" * 64


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _database_identity() -> DatabaseIdentityV2:
    return DatabaseIdentityV2(
        database_id="db2_" + "a" * 32,
        activation_binding_nonce="0" * 64,
        activation_id="act2_" + "b" * 64,
        activation_fingerprint="a" * 64,
        created_operation_id="op2_" + "c" * 32,
        created_at=NOW,
    )


def _controller() -> AcceptingControllerV2:
    return AcceptingControllerV2(
        controller_identity="d" * 64,
        instance_id="ci2_" + "e" * 32,
        controller_start_id="cs2_" + "f" * 32,
        controller_pid=1001,
        controller_process_start_marker="pid-1001-start-7",
        controller_process_group_id=1001,
        control_epoch=7,
        activation_id=_database_identity().activation_id,
        activation_fingerprint="a" * 64,
        compatibility_fingerprint="b" * 64,
        routing_policy_fingerprint="c" * 64,
        bundled_catalog_fingerprint="d" * 64,
        socket_path="/tmp/codex-smart-v2-candidate-recovery.sock",
        socket_device=1,
        socket_inode=2,
        socket_owner_uid=os.getuid(),
        socket_owner_gid=os.getgid(),
        socket_mode="0600",
        updated_at=NOW,
    )


def _request_context(repository: Path, base_sha: str) -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-candidate-recovery-v2",
        session_id="session-candidate-recovery-v2",
        turn_id="turn-candidate-recovery-v2",
        codex_home="/Users/test/.codex",
        repo_root=str(repository.resolve(strict=True)),
        base_sha=base_sha,
        worktree_fingerprint="e" * 64,
        activation_fingerprint="a" * 64,
        compatibility_fingerprint="b" * 64,
        issued_control_epoch=7,
    )


def _node() -> PlannedNodeV2:
    return PlannedNodeV2(
        node_id="node2_" + "2" * 32,
        ordinal=0,
        role="implementer",
        mission="Восстановить публикацию кандидата.",
        dependencies=(),
        context_refs=("request",),
        scope_id="candidate-recovery-v2",
        artifact_profile_id="candidate-v2",
        validation_profile_id="strict-v2",
        assessment={"q": 2, "p": 2, "v": 2, "o": 2},
        risk_flags=(),
        selected_model="gpt-5.6-terra",
        reasoning_effort="high",
        permission_profile_id="writer-v2",
        disposition="delegate",
    )


class CandidateRecoveryV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="candidate-recovery-v2-",
        )
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "source"
        self.repository.mkdir()
        _git(self.repository, "init", "-q")
        _git(self.repository, "config", "user.name", "Candidate Recovery V2")
        _git(
            self.repository,
            "config",
            "user.email",
            "candidate-recovery-v2@example.invalid",
        )
        (self.repository / "tracked.txt").write_text("base\n", encoding="utf-8")
        _git(self.repository, "add", "tracked.txt")
        _git(self.repository, "commit", "-qm", "base")
        self.base_sha = _git(self.repository, "rev-parse", "HEAD")
        self.store = SmartStoreV2(
            self.root / "database" / "state-v2.sqlite3",
            database_identity=_database_identity(),
            controller=_controller(),
        )
        context = _request_context(self.repository, self.base_sha)
        binding = self.store.issue_turn_binding(
            context,
            ttl_seconds=120,
            now=NOW,
        )
        self.route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "1" * 32,
            request_hash="f" * 64,
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(_node(),),
            now=NOW + timedelta(seconds=1),
        )
        self.state_root = self.root / "candidate-state"
        self.quarantine = QuarantineRepository.for_source(
            self.state_root,
            self.repository,
        )
        self.repository_id = self.store.register_quarantine_repository(
            source_root=self.repository,
            state_root=self.state_root,
            git_dir=self.quarantine.git_dir,
        )
        self.base = self.quarantine.import_base(self.base_sha)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_dry_run_plans_exact_recovery_without_writing(self) -> None:
        intent_id, candidate = self._pending("dry-run", publish=True)
        before = self._metadata_tree()
        before_changes = self.store._connection.total_changes  # noqa: SLF001

        report = CandidateRecoveryV2(store=self.store).run(apply=False)
        after = self._metadata_tree()

        self.assertTrue(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual(["RECOVER_VERIFIED"], [item.kind for item in report.actions])
        self.assertEqual(intent_id, report.actions[0].intent_id)
        self.assertEqual(VALIDATION_PROOF, report.actions[0].proof_hash)
        self.assertEqual("PENDING", self.store.candidate_intent(intent_id)["state"])
        self.assertEqual([], self.store.candidate_records())
        self.assertTrue(self.quarantine.ref_exists(candidate.ref))
        self.assertEqual(before, after)
        self.assertEqual(
            before_changes,
            self.store._connection.total_changes,  # noqa: SLF001
        )

    def test_dry_run_reports_permission_drift_without_repairing_it(self) -> None:
        intent_id, _ = self._pending("mode-drift", publish=True)
        head = self.quarantine.git_dir / "HEAD"
        head.chmod(0o666)

        report = CandidateRecoveryV2(store=self.store).run(apply=False)

        self.assertFalse(report.ok)
        self.assertFalse(report.applied)
        self.assertTrue(
            any(
                item.startswith("QUARANTINE_REPOSITORY_UNAVAILABLE:")
                for item in report.blockers
            )
        )
        self.assertEqual(0o666, stat.S_IMODE(head.stat().st_mode))
        self.assertEqual("PENDING", self.store.candidate_intent(intent_id)["state"])

    def test_apply_recovers_exact_candidate_with_saved_validation_proof(self) -> None:
        intent_id, candidate = self._pending("exact", publish=True)
        recovery = CandidateRecoveryV2(store=self.store)

        first = recovery.run(apply=True)
        second = recovery.run(apply=True)

        self.assertTrue(first.ok)
        self.assertTrue(first.applied)
        self.assertEqual("RECOVERED", self.store.candidate_intent(intent_id)["state"])
        records = self.store.candidate_records(self.repository_id)
        self.assertEqual(1, len(records))
        self.assertEqual("VERIFIED", records[0]["state"])
        self.assertEqual("passed", records[0]["validationState"])
        self.assertEqual(VALIDATION_PROOF, records[0]["proofHash"])
        self.assertEqual(candidate.commit_sha, records[0]["observedCommitSha"])
        self.assertEqual(candidate.tree_sha, records[0]["observedTreeSha"])
        self.assertTrue(records[0]["trusted"])
        replayed = self.store.recover_candidate_publication(
            intent_id,
            observed_commit_sha=candidate.commit_sha,
            observed_tree_sha=candidate.tree_sha,
        )
        self.assertEqual(records[0], replayed)
        self.assertTrue(second.ok)
        self.assertFalse(second.applied)
        self.assertEqual((), second.actions)

    def test_missing_ref_is_aborted_and_recorded_as_untrusted(self) -> None:
        intent_id, candidate = self._pending("missing", publish=False)

        report = CandidateRecoveryV2(store=self.store).run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertEqual(["ABORT_MISSING"], [item.kind for item in report.actions])
        self.assertFalse(self.quarantine.ref_exists(candidate.ref))
        self.assertEqual("ABORTED", self.store.candidate_intent(intent_id)["state"])
        record = self.store.candidate_records(self.repository_id)[0]
        self.assertEqual("REF_MISSING_QUARANTINED", record["state"])
        self.assertEqual("quarantined", record["validationState"])
        self.assertEqual("", record["observedCommitSha"])
        self.assertEqual("", record["observedTreeSha"])
        self.assertEqual(report.actions[0].proof_hash, record["proofHash"])
        self.assertFalse(record["trusted"])
        self.assertEqual(
            record,
            self.store.abort_candidate_publication(
                intent_id,
                proof_hash=report.actions[0].proof_hash,
            ),
        )

    def test_normal_publisher_replays_a_recovered_verified_candidate(self) -> None:
        intent_id, candidate = self._pending("publisher-replay", publish=True)
        CandidateRecoveryV2(store=self.store).run(apply=True)
        publication = CandidateRefPublicationV2(
            route_id=self.route_id,
            node_id=_node().node_id,
            attempt_id="att2_" + "3" * 32,
            quarantine=self.quarantine,
            base=self.base,
            candidate=candidate,
            source_manifest_sha256="6" * 64,
            validation=ValidationResult("passed", ()),
            validation_proof_sha256=VALIDATION_PROOF,
        )

        evidence = StateCandidateRefPublisherV2(store=self.store).publish(
            publication
        )

        self.assertEqual(candidate.commit_sha, evidence.commit_sha)
        self.assertEqual("RECOVERED", self.store.candidate_intent(intent_id)["state"])
        self.assertEqual(1, len(self.store.candidate_records(self.repository_id)))

    def test_mismatched_ref_is_quarantined_with_observed_identity(self) -> None:
        intent_id, candidate = self._pending("expected", publish=False)
        conflicting_root = self.root / "candidate-conflicting"
        conflicting_root.mkdir()
        (conflicting_root / "tracked.txt").write_text(
            "conflicting\n",
            encoding="utf-8",
        )
        conflicting = self.quarantine.prepare_candidate(
            conflicting_root,
            self.base,
            source_date_epoch=1_700_000_001,
        )
        _git(
            self.quarantine.git_dir,
            "update-ref",
            candidate.ref,
            conflicting.commit_sha,
        )

        report = CandidateRecoveryV2(store=self.store).run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertEqual(["QUARANTINE_MISMATCH"], [item.kind for item in report.actions])
        self.assertEqual("QUARANTINED", self.store.candidate_intent(intent_id)["state"])
        record = self.store.candidate_records(self.repository_id)[0]
        self.assertEqual("REF_MISMATCH_QUARANTINED", record["state"])
        self.assertEqual(conflicting.commit_sha, record["observedCommitSha"])
        self.assertEqual(conflicting.tree_sha, record["observedTreeSha"])
        self.assertFalse(record["trusted"])
        self.assertEqual(
            record,
            self.store.quarantine_mismatched_publication(
                intent_id,
                observed_commit_sha=conflicting.commit_sha,
                observed_tree_sha=conflicting.tree_sha,
                proof_hash=report.actions[0].proof_hash,
            ),
        )

    def test_missing_saved_validation_proof_blocks_every_write(self) -> None:
        missing_intent, _ = self._pending("would-abort", publish=False)
        exact_intent, _ = self._pending("proof-lost", publish=True)
        self.store._connection.execute(  # noqa: SLF001 - legacy-shape fixture
            "update candidate_publication_intents "
            "set validation_proof_sha256=null where intent_id=?",
            (exact_intent,),
        )

        report = CandidateRecoveryV2(store=self.store).run(apply=True)

        self.assertFalse(report.ok)
        self.assertFalse(report.applied)
        self.assertIn(
            f"VALIDATION_PROOF_UNAVAILABLE:{exact_intent}",
            report.blockers,
        )
        self.assertEqual("PENDING", self.store.candidate_intent(missing_intent)["state"])
        self.assertEqual("PENDING", self.store.candidate_intent(exact_intent)["state"])
        self.assertEqual([], self.store.candidate_records())

    def _pending(self, name: str, *, publish: bool):
        workspace = self.root / f"candidate-{name}"
        workspace.mkdir()
        (workspace / "tracked.txt").write_text(
            f"candidate {name}\n",
            encoding="utf-8",
        )
        candidate = self.quarantine.prepare_candidate(
            workspace,
            self.base,
            source_date_epoch=1_700_000_000,
        )
        intent_id = self.store.begin_candidate_publication(
            route_id=self.route_id,
            node_id=_node().node_id,
            repository_id=self.repository_id,
            artifact_id=candidate.artifact_id,
            ref=candidate.ref,
            base_source_sha=self.base.source_sha,
            base_commit_sha=self.base.commit_sha,
            base_tree_sha=self.base.tree_sha,
            commit_sha=candidate.commit_sha,
            tree_sha=candidate.tree_sha,
            validation_proof_sha256=VALIDATION_PROOF,
        )
        if publish:
            self.quarantine.publish_candidate(candidate)
        return intent_id, candidate

    def _metadata_tree(self) -> list[tuple[str, int, int, int, int, int, int]]:
        records: list[tuple[str, int, int, int, int, int, int]] = []
        for path in sorted(
            (self.state_root, *self.state_root.rglob("*")),
            key=lambda item: str(item.relative_to(self.state_root.parent)),
        ):
            metadata = path.lstat()
            records.append(
                (
                    str(path.relative_to(self.state_root.parent)),
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
            )
        return records


if __name__ == "__main__":
    unittest.main()
