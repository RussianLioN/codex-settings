from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    PlannedNodeV2,
    RequestContextV2,
    SmartStoreV2,
    StateStoreV2Error,
)
from codex_smart_subagents.quarantine import QuarantineRepository  # noqa: E402
from codex_smart_subagents.state_candidate_publisher_v2 import (  # noqa: E402
    StateCandidatePublisherV2Error,
    StateCandidateRefPublisherV2,
)
from codex_smart_subagents.validation import ValidationResult  # noqa: E402
from codex_smart_subagents.writer_publication_v2 import (  # noqa: E402
    CandidateRefPublicationV2,
)


NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


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
        socket_path="/tmp/codex-smart-v2-candidate.sock",
        socket_device=1,
        socket_inode=2,
        socket_owner_uid=os.getuid(),
        socket_owner_gid=os.getgid(),
        socket_mode="0600",
        updated_at=NOW,
    )


def _request_context(repository: Path, base_sha: str) -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-candidate-v2",
        session_id="session-candidate-v2",
        turn_id="turn-candidate-v2",
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
        mission="Подготовить проверенный кандидат.",
        dependencies=(),
        context_refs=("request",),
        scope_id="candidate-publication-v2",
        artifact_profile_id="candidate-v2",
        validation_profile_id="strict-v2",
        assessment={"q": 2, "p": 2, "v": 2, "o": 2},
        risk_flags=(),
        selected_model="gpt-5.6-terra",
        reasoning_effort="high",
        permission_profile_id="writer-v2",
        disposition="delegate",
    )


class StateCandidatePublisherV2ContractTests(unittest.TestCase):
    def test_state_candidate_publisher_module_exposes_contract(self) -> None:
        specification = importlib.util.find_spec(
            "codex_smart_subagents.state_candidate_publisher_v2"
        )
        self.assertIsNotNone(specification)

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = SmartStoreV2(
            self.root / "database" / "state-v2.sqlite3",
            database_identity=_database_identity(),
            controller=_controller(),
        )
        self.repository = self.root / "source"
        self.repository.mkdir()
        _git(self.repository, "init", "-q")
        _git(self.repository, "config", "user.name", "Candidate V2 Test")
        _git(
            self.repository,
            "config",
            "user.email",
            "candidate-v2@example.invalid",
        )
        (self.repository / "tracked.txt").write_text("base\n", encoding="utf-8")
        _git(self.repository, "add", "tracked.txt")
        _git(self.repository, "commit", "-qm", "base")
        self.base_sha = _git(self.repository, "rev-parse", "HEAD")
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

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def test_state_store_exposes_candidate_publication_contract(self) -> None:
        for method_name in (
            "register_quarantine_repository",
            "quarantine_repositories",
            "begin_candidate_publication",
            "candidate_intent",
            "pending_candidate_publications",
            "complete_candidate_publication",
            "recover_candidate_publication",
            "abort_candidate_publication",
            "quarantine_mismatched_publication",
            "candidate_records",
        ):
            with self.subTest(method_name=method_name):
                self.assertTrue(
                    callable(getattr(self.store, method_name, None)),
                    method_name,
                )

    def test_quarantine_registration_is_exact_idempotent_and_conflict_closed(
        self,
    ) -> None:
        arguments = {
            "source_root": self.repository,
            "state_root": self.state_root,
            "git_dir": self.quarantine.git_dir,
        }

        repository_id = self.store.register_quarantine_repository(**arguments)
        replayed_id = self.store.register_quarantine_repository(**arguments)

        self.assertRegex(repository_id, r"^qr2_[A-Za-z0-9_-]{43}$")
        self.assertEqual(repository_id, replayed_id)
        self.assertEqual(
            [
                {
                    "repositoryId": repository_id,
                    "sourceRoot": str(self.repository.resolve(strict=True)),
                    "stateRoot": str(self.state_root.resolve(strict=True)),
                    "gitDir": str(self.quarantine.git_dir.resolve(strict=True)),
                    "state": "ACTIVE",
                }
            ],
            [
                {
                    key: record[key]
                    for key in (
                        "repositoryId",
                        "sourceRoot",
                        "stateRoot",
                        "gitDir",
                        "state",
                    )
                }
                for record in self.store.quarantine_repositories()
            ],
        )

        other_state_root = self.root / "other-candidate-state"
        other_quarantine = QuarantineRepository.for_source(
            other_state_root,
            self.repository,
        )
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.register_quarantine_repository(
                source_root=self.repository,
                state_root=other_state_root,
                git_dir=other_quarantine.git_dir,
            )
        self.assertEqual("QUARANTINE_REPOSITORY_CONFLICT", caught.exception.code)
        self.assertEqual(1, len(self.store.quarantine_repositories()))

    def test_candidate_intent_is_pending_before_ref_and_replays_exactly(self) -> None:
        repository_id, base, candidate = self._prepared_candidate("intent")
        arguments = {
            "route_id": self.route_id,
            "node_id": _node().node_id,
            "repository_id": repository_id,
            "artifact_id": candidate.artifact_id,
            "ref": candidate.ref,
            "base_source_sha": base.source_sha,
            "base_commit_sha": base.commit_sha,
            "base_tree_sha": base.tree_sha,
            "commit_sha": candidate.commit_sha,
            "tree_sha": candidate.tree_sha,
            "validation_proof_sha256": "7" * 64,
        }

        intent_id = self.store.begin_candidate_publication(**arguments)
        replayed_id = self.store.begin_candidate_publication(**arguments)

        self.assertRegex(intent_id, r"^cpi2_[A-Za-z0-9_-]{43}$")
        self.assertEqual(intent_id, replayed_id)
        self.assertFalse(self.quarantine.ref_exists(candidate.ref))
        intent = self.store.candidate_intent(intent_id)
        self.assertEqual("PENDING", intent["state"])
        self.assertEqual(self.route_id, intent["routeId"])
        self.assertEqual(repository_id, intent["repositoryId"])
        self.assertEqual(candidate.artifact_id, intent["artifactId"])
        self.assertEqual(candidate.commit_sha, intent["commitSha"])
        self.assertEqual("7" * 64, intent["validationProofSha256"])
        self.assertEqual([intent], self.store.pending_candidate_publications())

        conflicting = dict(arguments)
        conflicting["tree_sha"] = "9" * 40
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.begin_candidate_publication(**conflicting)
        self.assertEqual("CANDIDATE_PUBLICATION_CONFLICT", caught.exception.code)
        self.assertEqual([intent], self.store.pending_candidate_publications())

    def test_verified_completion_is_atomic_exact_and_idempotent(self) -> None:
        repository_id, base, candidate = self._prepared_candidate("complete")
        intent_id = self.store.begin_candidate_publication(
            route_id=self.route_id,
            node_id=_node().node_id,
            repository_id=repository_id,
            artifact_id=candidate.artifact_id,
            ref=candidate.ref,
            base_source_sha=base.source_sha,
            base_commit_sha=base.commit_sha,
            base_tree_sha=base.tree_sha,
            commit_sha=candidate.commit_sha,
            tree_sha=candidate.tree_sha,
            validation_proof_sha256="8" * 64,
        )
        self.quarantine.publish_candidate(candidate)
        evidence = self.quarantine.candidate_evidence(candidate.ref)
        proof_hash = "8" * 64

        record = self.store.complete_candidate_publication(
            intent_id,
            observed_commit_sha=evidence.commit_sha,
            observed_tree_sha=evidence.tree_sha,
            proof_hash=proof_hash,
        )
        replayed = self.store.complete_candidate_publication(
            intent_id,
            observed_commit_sha=evidence.commit_sha,
            observed_tree_sha=evidence.tree_sha,
            proof_hash=proof_hash,
        )

        self.assertRegex(record["candidateId"], r"^cand2_[A-Za-z0-9_-]{43}$")
        self.assertEqual(record, replayed)
        self.assertEqual("VERIFIED", record["state"])
        self.assertEqual("passed", record["validationState"])
        self.assertTrue(record["trusted"])
        self.assertEqual(candidate.commit_sha, record["observedCommitSha"])
        self.assertEqual(candidate.tree_sha, record["observedTreeSha"])
        self.assertEqual(proof_hash, record["proofHash"])
        self.assertEqual("COMPLETED", self.store.candidate_intent(intent_id)["state"])
        self.assertEqual([], self.store.pending_candidate_publications(repository_id))
        self.assertEqual([record], self.store.candidate_records(repository_id))

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.complete_candidate_publication(
                intent_id,
                observed_commit_sha="7" * 40,
                observed_tree_sha=evidence.tree_sha,
                proof_hash=proof_hash,
            )
        self.assertEqual(
            "CANDIDATE_PUBLICATION_EVIDENCE_MISMATCH",
            caught.exception.code,
        )
        self.assertEqual([record], self.store.candidate_records(repository_id))

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.complete_candidate_publication(
                intent_id,
                observed_commit_sha=evidence.commit_sha,
                observed_tree_sha=evidence.tree_sha,
                proof_hash="9" * 64,
            )
        self.assertEqual(
            "CANDIDATE_VALIDATION_PROOF_MISMATCH",
            caught.exception.code,
        )
        self.assertEqual([record], self.store.candidate_records(repository_id))

    def test_state_publisher_records_pending_before_ref_and_replays(self) -> None:
        publication = self._publication("publisher-success")
        pending_during_update: list[list[str | None]] = []
        direct_publish = publication.quarantine.publish_candidate

        def observed_publish(candidate) -> None:
            pending_during_update.append(
                [
                    item["validationProofSha256"]
                    for item in self.store.pending_candidate_publications()
                ]
            )
            direct_publish(candidate)

        publication.quarantine.publish_candidate = observed_publish
        publisher = StateCandidateRefPublisherV2(store=self.store)

        evidence = publisher.publish(publication)
        replayed = publisher.publish(publication)

        self.assertEqual([[publication.validation_proof_sha256]], pending_during_update)
        self.assertEqual(evidence, replayed)
        self.assertEqual(publication.candidate.commit_sha, evidence.commit_sha)
        self.assertEqual(publication.candidate.tree_sha, evidence.tree_sha)
        self.assertEqual(publication.base.commit_sha, evidence.parent_sha)
        self.assertTrue(evidence.message_bound)
        self.assertEqual([], self.store.pending_candidate_publications())
        records = self.store.candidate_records()
        self.assertEqual(1, len(records))
        self.assertEqual("VERIFIED", records[0]["state"])
        self.assertEqual(publication.validation_proof_sha256, records[0]["proofHash"])

    def test_finalization_failure_preserves_pending_recovery_window(self) -> None:
        publication = self._publication("recovery-window")
        publisher = StateCandidateRefPublisherV2(store=self.store)
        direct_complete = self.store.complete_candidate_publication

        def fail_completion(*args, **kwargs):
            raise StateStoreV2Error(
                "CANDIDATE_STATE_FINALIZATION_UNAVAILABLE",
                "injected completion failure",
            )

        self.store.complete_candidate_publication = fail_completion
        with self.assertRaises(StateStoreV2Error) as caught:
            publisher.publish(publication)
        self.assertEqual(
            "CANDIDATE_STATE_FINALIZATION_UNAVAILABLE",
            caught.exception.code,
        )
        self.assertTrue(publication.quarantine.ref_exists(publication.candidate.ref))
        self.assertEqual(
            ["PENDING"],
            [item["state"] for item in self.store.pending_candidate_publications()],
        )
        self.assertEqual([], self.store.candidate_records())

        self.store.complete_candidate_publication = direct_complete
        recovered = publisher.publish(publication)

        self.assertEqual(publication.candidate.commit_sha, recovered.commit_sha)
        self.assertEqual([], self.store.pending_candidate_publications())
        self.assertEqual("VERIFIED", self.store.candidate_records()[0]["state"])

    def test_existing_mismatched_ref_fails_closed_and_leaves_pending(self) -> None:
        publication = self._publication("ref-conflict")
        conflicting_root = self.root / "conflicting-workspace"
        conflicting_root.mkdir()
        (conflicting_root / "tracked.txt").write_text(
            "other candidate\n",
            encoding="utf-8",
        )
        conflicting = publication.quarantine.prepare_candidate(
            conflicting_root,
            publication.base,
            source_date_epoch=1_700_000_001,
        )
        _git(
            publication.quarantine.git_dir,
            "update-ref",
            publication.candidate.ref,
            conflicting.commit_sha,
        )
        publisher = StateCandidateRefPublisherV2(store=self.store)

        with self.assertRaises(StateCandidatePublisherV2Error) as caught:
            publisher.publish(publication)

        self.assertEqual("CANDIDATE_PUBLICATION_CONFLICT", caught.exception.code)
        self.assertEqual(
            ["PENDING"],
            [item["state"] for item in self.store.pending_candidate_publications()],
        )
        self.assertEqual([], self.store.candidate_records())

    def test_unpassed_validation_cannot_create_intent_or_ref(self) -> None:
        publication = self._publication("validation-failed")
        rejected = replace(
            publication,
            validation=ValidationResult("failed", ()),
        )

        with self.assertRaises(StateCandidatePublisherV2Error) as caught:
            StateCandidateRefPublisherV2(store=self.store).publish(rejected)

        self.assertEqual("CANDIDATE_VALIDATION_NOT_PASSED", caught.exception.code)
        self.assertEqual([], self.store.pending_candidate_publications())
        self.assertEqual([], self.store.quarantine_repositories())
        self.assertFalse(publication.quarantine.ref_exists(publication.candidate.ref))

    def test_completed_record_never_recreates_a_missing_ref(self) -> None:
        publication = self._publication("completed-ref-missing")
        publisher = StateCandidateRefPublisherV2(store=self.store)
        publisher.publish(publication)
        _git(
            publication.quarantine.git_dir,
            "update-ref",
            "-d",
            publication.candidate.ref,
        )

        with self.assertRaises(StateCandidatePublisherV2Error) as caught:
            publisher.publish(publication)

        self.assertEqual("CANDIDATE_PUBLICATION_CONFLICT", caught.exception.code)
        self.assertFalse(publication.quarantine.ref_exists(publication.candidate.ref))
        self.assertEqual("VERIFIED", self.store.candidate_records()[0]["state"])

    def _prepared_candidate(self, name: str, *, register: bool = True):
        repository_id = None
        if register:
            repository_id = self.store.register_quarantine_repository(
                source_root=self.repository,
                state_root=self.state_root,
                git_dir=self.quarantine.git_dir,
            )
        base = self.quarantine.import_base(self.base_sha)
        candidate_root = self.root / f"candidate-workspace-{name}"
        candidate_root.mkdir()
        (candidate_root / "tracked.txt").write_text(
            f"candidate {name}\n",
            encoding="utf-8",
        )
        candidate = self.quarantine.prepare_candidate(
            candidate_root,
            base,
            source_date_epoch=1_700_000_000,
        )
        return repository_id, base, candidate

    def _publication(self, name: str) -> CandidateRefPublicationV2:
        _, base, candidate = self._prepared_candidate(name, register=False)
        return CandidateRefPublicationV2(
            route_id=self.route_id,
            node_id=_node().node_id,
            attempt_id="att2_" + "3" * 32,
            quarantine=self.quarantine,
            base=base,
            candidate=candidate,
            source_manifest_sha256="6" * 64,
            validation=ValidationResult("passed", ()),
            validation_proof_sha256="7" * 64,
        )


if __name__ == "__main__":
    unittest.main()
