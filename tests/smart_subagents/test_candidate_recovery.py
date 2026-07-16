from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.candidate_recovery import (  # noqa: E402
    CandidateRecovery,
    CandidateRecoveryError,
)
from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.quarantine import (  # noqa: E402
    QuarantineRepository,
    repository_manifest,
)
from codex_smart_subagents.service import SmartService  # noqa: E402
from codex_smart_subagents.store import SmartStore  # noqa: E402

from tests.smart_subagents.fixtures import valid_plan


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class CandidateRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.source, "init", "-q")
        git(self.source, "config", "user.name", "Recovery Test")
        git(self.source, "config", "user.email", "recovery@example.invalid")
        (self.source / "tracked.txt").write_text("base\n", encoding="utf-8")
        git(self.source, "add", "tracked.txt")
        git(self.source, "commit", "-qm", "base")
        self.base_sha = git(self.source, "rev-parse", "HEAD")

        self.store = SmartStore(self.root / "controller-state")
        self.catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.service = SmartService(self.store, self.catalog)
        self.context = RequestContext(
            shell_session_id="shell-recovery",
            session_id="session-recovery",
            turn_id="turn-recovery",
            codex_home="/Users/test/.codex",
            repo_root=str(self.source),
            base_sha=self.base_sha,
            worktree_fingerprint="b" * 64,
        )
        payload = valid_plan(self.catalog)
        payload["turnBinding"] = self.store.issue_turn_binding(self.context)
        payload["catalogGeneration"] = self.catalog.generation
        plan = self.service.smart_plan(payload, self.context)
        self.route_id = plan["routeId"]
        self.node_id = "node-1"

        self.quarantine_root = self.root / "quarantine-state"
        self.quarantine_root.mkdir(mode=0o700)
        self.quarantine = QuarantineRepository.for_source(
            self.quarantine_root,
            self.source,
        )
        self.repository_id = self.store.register_quarantine_repository(
            source_root=self.source,
            state_root=self.quarantine_root,
            git_dir=self.quarantine.git_dir,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def _prepare_publication(self):
        candidate_root = self.root / f"candidate-{len(self.store.candidate_records())}"
        shutil.copytree(
            self.source,
            candidate_root,
            ignore=shutil.ignore_patterns(".git"),
        )
        (candidate_root / "tracked.txt").write_text(
            "candidate\n",
            encoding="utf-8",
        )
        base = self.quarantine.import_base(self.base_sha)
        candidate = self.quarantine.prepare_candidate(
            candidate_root,
            base,
            source_date_epoch=1_700_000_000,
        )
        intent_id = self.store.begin_candidate_publication(
            route_id=self.route_id,
            node_id=self.node_id,
            repository_id=self.repository_id,
            artifact_id=candidate.artifact_id,
            ref=candidate.ref,
            base_source_sha=base.source_sha,
            base_commit_sha=base.commit_sha,
            base_tree_sha=base.tree_sha,
            commit_sha=candidate.commit_sha,
            tree_sha=candidate.tree_sha,
        )
        return base, candidate, intent_id

    def test_crash_before_update_ref_aborts_intent_and_closes_running_work(
        self,
    ) -> None:
        _base, candidate, intent_id = self._prepare_publication()
        generic_intent = self.store.record_intent(
            route_id=self.route_id,
            node_id=self.node_id,
            kind="execute_node",
            payload={"fingerprint": "c" * 64},
        )
        attempt_id = self.store.begin_attempt(
            route_id=self.route_id,
            node_id=self.node_id,
            model="gpt-5.6-luna",
            reasoning_effort="medium",
            permission_profile_id="permission_reader",
            pid=123,
            argv_fingerprint="d" * 64,
            permission_probe_id="pc1_" + "A" * 43,
        )
        backup = self.root / "backup" / "before-recover.sqlite3"

        report = CandidateRecovery(self.store).apply(
            backup_path=backup,
            controller_stopped=True,
        )

        self.assertTrue(backup.is_file())
        self.assertEqual("ABORTED", self.store.candidate_intent(intent_id)["state"])
        self.assertEqual([], self.store.candidate_records())
        self.assertEqual([], self.store.pending_intents(self.route_id))
        attempts = self.store.attempts_for_route(self.route_id)
        self.assertEqual(attempt_id, attempts[0]["attemptId"])
        self.assertEqual("FAILED", attempts[0]["state"])
        self.assertEqual("RECOVERED_AFTER_CRASH", attempts[0]["errorCode"])
        self.assertEqual(1, report.aborted_publications)
        self.assertEqual(1, report.closed_attempts)
        self.assertEqual(1, report.closed_intents)
        self.assertNotEqual(generic_intent, intent_id)
        self.assertFalse(
            self.quarantine.ref_exists(candidate.ref),
            "recovery must not create a missing candidate ref",
        )

    def test_crash_after_update_ref_recovers_only_exact_candidate_as_quarantined(
        self,
    ) -> None:
        before = repository_manifest(self.source)
        _base, candidate, intent_id = self._prepare_publication()
        self.quarantine.publish_candidate(candidate)

        report = CandidateRecovery(self.store).apply()

        self.assertEqual(before, repository_manifest(self.source))
        intent = self.store.candidate_intent(intent_id)
        self.assertEqual("RECOVERED", intent["state"])
        records = self.store.candidate_records()
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual(candidate.artifact_id, record["artifactId"])
        self.assertEqual(candidate.commit_sha, record["commitSha"])
        self.assertEqual(candidate.tree_sha, record["treeSha"])
        self.assertEqual("RECOVERED_QUARANTINED", record["state"])
        self.assertEqual("quarantined", record["validationState"])
        self.assertFalse(record["trusted"])
        self.assertRegex(record["proofHash"], r"^[0-9a-f]{64}$")
        self.assertEqual(1, report.recovered_publications)
        self.assertIsNotNone(report.backup_path)
        self.assertTrue(Path(report.backup_path).is_file())

    def test_extra_ref_is_registered_as_untrusted_orphan_and_never_deleted(
        self,
    ) -> None:
        candidate_root = self.root / "orphan"
        shutil.copytree(
            self.source,
            candidate_root,
            ignore=shutil.ignore_patterns(".git"),
        )
        (candidate_root / "tracked.txt").write_text("orphan\n", encoding="utf-8")
        base = self.quarantine.import_base(self.base_sha)
        candidate = self.quarantine.prepare_candidate(
            candidate_root,
            base,
            source_date_epoch=1_700_000_001,
        )
        self.quarantine.publish_candidate(candidate)

        report = CandidateRecovery(self.store).apply()

        self.assertTrue(self.quarantine.ref_exists(candidate.ref))
        records = self.store.candidate_records()
        self.assertEqual(1, len(records))
        self.assertEqual(candidate.artifact_id, records[0]["artifactId"])
        self.assertEqual("ORPHANED_QUARANTINED", records[0]["state"])
        self.assertEqual("quarantined", records[0]["validationState"])
        self.assertFalse(records[0]["trusted"])
        self.assertEqual(1, report.orphaned_refs)

    def test_non_commit_and_malformed_extra_refs_are_durable_orphans(
        self,
    ) -> None:
        blob = subprocess.run(
            [
                "/usr/bin/git",
                f"--git-dir={self.quarantine.git_dir}",
                "hash-object",
                "-w",
                "--stdin",
            ],
            input=b"untrusted blob\n",
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode("ascii").strip()
        blob_ref = "refs/candidates/art1_" + "Z" * 43
        malformed_ref = "refs/candidates/manual"
        git(self.quarantine.git_dir, "update-ref", blob_ref, blob)
        base = self.quarantine.import_base(self.base_sha)
        git(
            self.quarantine.git_dir,
            "update-ref",
            malformed_ref,
            base.commit_sha,
        )

        report = CandidateRecovery(self.store).apply()

        self.assertEqual(2, report.orphaned_refs)
        self.assertEqual((), report.errors)
        records = self.store.candidate_records()
        self.assertEqual(
            {blob_ref, malformed_ref},
            {record["ref"] for record in records},
        )
        self.assertTrue(self.quarantine.ref_exists(blob_ref))
        self.assertEqual(
            "ORPHANED_QUARANTINED",
            next(record for record in records if record["ref"] == blob_ref)[
                "state"
            ],
        )

    def test_mismatched_intent_ref_is_quarantined_without_ref_deletion(
        self,
    ) -> None:
        _base, expected, intent_id = self._prepare_publication()
        self.quarantine.publish_candidate(expected)
        other_root = self.root / "other-candidate"
        shutil.copytree(
            self.source,
            other_root,
            ignore=shutil.ignore_patterns(".git"),
        )
        (other_root / "tracked.txt").write_text("other\n", encoding="utf-8")
        other_base = self.quarantine.import_base(self.base_sha)
        other = self.quarantine.prepare_candidate(
            other_root,
            other_base,
            source_date_epoch=1_700_000_002,
        )
        self.quarantine.publish_candidate(other)
        git(
            self.quarantine.git_dir,
            "update-ref",
            expected.ref,
            other.commit_sha,
            expected.commit_sha,
        )

        report = CandidateRecovery(self.store).apply()

        self.assertEqual(1, report.quarantined_publications)
        self.assertEqual("QUARANTINED", self.store.candidate_intent(intent_id)["state"])
        record = next(
            item
            for item in self.store.candidate_records()
            if item["ref"] == expected.ref
        )
        self.assertEqual("ORPHANED_QUARANTINED", record["state"])
        self.assertEqual(other.commit_sha, record["observedCommitSha"])
        self.assertEqual(
            other.commit_sha,
            git(self.quarantine.git_dir, "rev-parse", expected.ref),
        )

    def test_repeated_recovery_is_idempotent(self) -> None:
        _base, candidate, _intent_id = self._prepare_publication()
        self.quarantine.publish_candidate(candidate)

        first = CandidateRecovery(self.store).apply()
        first_records = self.store.candidate_records()
        backup_root = self.store.state_dir / "recovery-backups"
        first_backups = list(backup_root.glob("*.sqlite3"))
        second = CandidateRecovery(self.store).apply()

        self.assertEqual(1, first.recovered_publications)
        self.assertEqual(0, second.recovered_publications)
        self.assertEqual(0, second.orphaned_refs)
        self.assertIsNone(second.backup_path)
        self.assertEqual(first_backups, list(backup_root.glob("*.sqlite3")))
        self.assertEqual(first_records, self.store.candidate_records())

    def test_plan_is_read_only_serializable_and_apply_checks_integrity(
        self,
    ) -> None:
        _base, candidate, intent_id = self._prepare_publication()
        self.quarantine.publish_candidate(candidate)
        recovery = CandidateRecovery(self.store)

        planned = recovery.plan()

        self.assertEqual(1, planned.recovered_publications)
        self.assertIsNone(planned.backup_path)
        self.assertEqual("PENDING", self.store.candidate_intent(intent_id)["state"])
        self.assertEqual([], self.store.candidate_records())
        self.assertEqual(
            1,
            planned.to_wire()["recoveredPublications"],
        )

        original = self.store.integrity_check
        self.store.integrity_check = lambda: "corrupt"  # type: ignore[method-assign]
        try:
            with self.assertRaises(CandidateRecoveryError):
                recovery.apply()
        finally:
            self.store.integrity_check = original  # type: ignore[method-assign]
        self.assertEqual("PENDING", self.store.candidate_intent(intent_id)["state"])

    def test_unexpired_lease_is_requeued_only_with_controller_stop_proof(
        self,
    ) -> None:
        self.service.smart_start(
            {"schemaVersion": "1", "routeId": self.route_id},
            self.context,
        )
        claim = self.store.claim_next_route(
            owner_id="controller-old",
            pid=123,
            start_marker="old-process",
            now=datetime.now(timezone.utc),
            lease_seconds=300,
        )
        self.assertIsNotNone(claim)
        _base, candidate, candidate_intent = self._prepare_publication()
        self.quarantine.publish_candidate(candidate)
        self.store.record_intent(
            route_id=self.route_id,
            node_id=self.node_id,
            kind="execute_node",
            payload={"fingerprint": "e" * 64},
        )
        self.store.begin_attempt(
            route_id=self.route_id,
            node_id=self.node_id,
            model="gpt-5.6-luna",
            reasoning_effort="medium",
            permission_profile_id="permission_reader",
            pid=456,
            argv_fingerprint="f" * 64,
            permission_probe_id="pc1_" + "C" * 43,
        )
        recovery = CandidateRecovery(self.store)

        without_proof = recovery.plan(controller_stopped=False)
        with_proof = recovery.plan(controller_stopped=True)

        self.assertEqual(0, without_proof.requeued_routes)
        self.assertEqual(0, without_proof.closed_attempts)
        self.assertEqual(0, without_proof.closed_intents)
        self.assertEqual(0, without_proof.recovered_publications)
        self.assertEqual(1, with_proof.requeued_routes)
        self.assertEqual(1, with_proof.closed_attempts)
        self.assertEqual(1, with_proof.closed_intents)
        self.assertEqual(1, with_proof.recovered_publications)
        self.assertEqual(
            "LEASED",
            self.store.execution_bundle(self.route_id).route.state.value,
        )
        self.assertEqual(
            "PENDING",
            self.store.candidate_intent(candidate_intent)["state"],
        )

        applied = recovery.apply(controller_stopped=True)

        self.assertEqual(1, applied.requeued_routes)
        self.assertEqual(
            "QUEUED",
            self.store.execution_bundle(self.route_id).route.state.value,
        )
        self.assertEqual(
            "RECOVERED",
            self.store.candidate_intent(candidate_intent)["state"],
        )


if __name__ == "__main__":
    unittest.main()
