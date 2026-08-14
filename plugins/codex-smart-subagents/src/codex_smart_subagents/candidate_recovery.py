"""Idempotent evidence-based recovery of registered quarantine candidates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .identity import canonical_sha256
from .quarantine import QuarantineError, QuarantineRepository
from .store import SmartStore


@dataclass(frozen=True)
class CandidateRecoveryReport:
    closed_attempts: int
    closed_intents: int
    aborted_publications: int
    recovered_publications: int
    quarantined_publications: int
    orphaned_refs: int
    quarantined_records: int
    requeued_routes: int
    errors: tuple[str, ...]
    backup_path: str | None

    def to_wire(self) -> dict[str, Any]:
        return {
            "closedAttempts": self.closed_attempts,
            "closedIntents": self.closed_intents,
            "abortedPublications": self.aborted_publications,
            "recoveredPublications": self.recovered_publications,
            "quarantinedPublications": self.quarantined_publications,
            "orphanedRefs": self.orphaned_refs,
            "quarantinedRecords": self.quarantined_records,
            "requeuedRoutes": self.requeued_routes,
            "errors": list(self.errors),
            "backupPath": self.backup_path,
        }


@dataclass
class CandidateRecoveryError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class CandidateRecovery:
    """Recover only repositories explicitly registered in the controller DB."""

    def __init__(self, store: SmartStore) -> None:
        self.store = store

    def apply(
        self,
        *,
        backup_path: Path | None = None,
        controller_stopped: bool = False,
    ) -> CandidateRecoveryReport:
        self._require_integrity()
        planned = self._run(
            apply=False,
            backup_path=None,
            controller_stopped=controller_stopped,
        )
        if planned.errors:
            raise CandidateRecoveryError(
                "RECOVERY_PREFLIGHT_FAILED",
                "registered quarantine evidence is unavailable or unsafe",
            )
        if not _requires_mutation(planned):
            return planned
        selected_backup = backup_path or self.store.recovery_backup_path()
        self.store.backup(selected_backup)
        recovered = self._run(
            apply=True,
            backup_path=selected_backup,
            controller_stopped=controller_stopped,
        )
        if recovered.errors:
            raise CandidateRecoveryError(
                "RECOVERY_RACE_DETECTED",
                "registered quarantine evidence changed during recovery",
            )
        return recovered

    def plan(
        self,
        *,
        controller_stopped: bool = False,
    ) -> CandidateRecoveryReport:
        self._require_integrity()
        return self._run(
            apply=False,
            backup_path=None,
            controller_stopped=controller_stopped,
        )

    inspect = plan

    def _require_integrity(self) -> None:
        integrity = self.store.integrity_check()
        if integrity != "ok":
            raise CandidateRecoveryError(
                "DATABASE_INTEGRITY_FAILED",
                "controller database failed integrity verification",
            )

    def _run(
        self,
        *,
        apply: bool,
        backup_path: Path | None,
        controller_stopped: bool,
    ) -> CandidateRecoveryReport:
        now = datetime.now(timezone.utc)
        recoverable_routes = self.store.recoverable_lease_routes(
            now=now,
            include_unexpired=controller_stopped,
        )
        work_scope = None if controller_stopped else recoverable_routes
        if apply:
            closed_attempts, closed_intents = self.store.close_interrupted_work(
                work_scope
            )
        else:
            closed_attempts, closed_intents = self.store.interrupted_work_counts(
                work_scope
            )
        protected_routes = (
            set()
            if controller_stopped
            else set(self.store.active_lease_routes(now=now))
        )
        if apply:
            recovered_routes = self.store.recover_route_leases(
                now=now,
                include_unexpired=controller_stopped,
            )
            for route_id in recovered_routes:
                self.store.requeue_recovering(route_id)
            requeued_routes = len(recovered_routes)
        else:
            requeued_routes = len(recoverable_routes)
        aborted = 0
        recovered = 0
        quarantined_publications = 0
        orphaned = 0
        quarantined_records = 0
        errors: list[str] = []
        for registered in self.store.quarantine_repositories():
            repository_id = registered["repositoryId"]
            try:
                quarantine = QuarantineRepository.open_registered(
                    state_root=Path(registered["stateRoot"]),
                    source_root=Path(registered["sourceRoot"]),
                    git_dir=Path(registered["gitDir"]),
                )
                refs = quarantine.candidate_refs()
                fsck_ok = quarantine.fsck() == "ok"
            except (OSError, QuarantineError) as exc:
                errors.append(f"{repository_id}:{getattr(exc, 'code', 'UNAVAILABLE')}")
                continue

            intents = self.store.pending_candidate_publications(repository_id)
            existing_records = self.store.candidate_records(repository_id)
            existing_record_refs = {item["ref"] for item in existing_records}
            known_refs = set(existing_record_refs)
            known_refs.update(item["ref"] for item in intents)
            for intent in intents:
                if intent["routeId"] in protected_routes:
                    continue
                if intent["ref"] in existing_record_refs:
                    errors.append(
                        f"{repository_id}:{intent['ref']}:REGISTRY_INTENT_CONFLICT"
                    )
                    continue
                observed_commit = refs.get(intent["ref"])
                if observed_commit is None:
                    changed = (
                        self.store.abort_candidate_publication(intent["intentId"])
                        if apply
                        else True
                    )
                    if changed:
                        aborted += 1
                    continue
                observed_tree = ""
                exact = False
                evidence_payload: dict[str, object]
                try:
                    evidence = quarantine.candidate_evidence(intent["ref"])
                    observed_tree = evidence.tree_sha
                    base_matches = quarantine.base_evidence_matches(
                        source_sha=intent["baseSourceSha"],
                        commit_sha=intent["baseCommitSha"],
                        tree_sha=intent["baseTreeSha"],
                    )
                    exact = (
                        fsck_ok
                        and base_matches
                        and evidence.message_bound
                        and evidence.artifact_id == intent["artifactId"]
                        and evidence.commit_sha == intent["commitSha"]
                        and evidence.tree_sha == intent["treeSha"]
                        and evidence.parent_sha == intent["baseCommitSha"]
                    )
                    evidence_payload = {
                        "artifactId": evidence.artifact_id,
                        "commitSha": evidence.commit_sha,
                        "treeSha": evidence.tree_sha,
                        "parentSha": evidence.parent_sha,
                        "messageBound": evidence.message_bound,
                        "baseMatches": base_matches,
                    }
                except QuarantineError as exc:
                    evidence_payload = {"errorCode": exc.code}
                proof_hash = _proof_hash(
                    repository_id=repository_id,
                    ref=intent["ref"],
                    expected={
                        "artifactId": intent["artifactId"],
                        "baseSourceSha": intent["baseSourceSha"],
                        "baseCommitSha": intent["baseCommitSha"],
                        "baseTreeSha": intent["baseTreeSha"],
                        "commitSha": intent["commitSha"],
                        "treeSha": intent["treeSha"],
                    },
                    observed={
                        "refCommitSha": observed_commit,
                        "evidence": evidence_payload,
                        "fsck": "ok" if fsck_ok else "failed",
                    },
                )
                if exact:
                    changed = True
                    if apply:
                        changed = self.store.recover_candidate_publication(
                            intent["intentId"],
                            observed_commit_sha=observed_commit,
                            observed_tree_sha=observed_tree,
                            proof_hash=proof_hash,
                        )
                    recovered += int(changed)
                else:
                    changed = True
                    if apply:
                        changed = self.store.quarantine_mismatched_publication(
                            intent["intentId"],
                            observed_commit_sha=observed_commit,
                            observed_tree_sha=observed_tree,
                            proof_hash=proof_hash,
                        )
                    quarantined_publications += int(changed)

            records = self.store.candidate_records(repository_id)
            for record in records:
                if record["state"] == "ORPHANED_QUARANTINED":
                    continue
                observed_commit = refs.get(record["ref"])
                if observed_commit is None:
                    proof_hash = _proof_hash(
                        repository_id=repository_id,
                        ref=record["ref"],
                        expected={
                            "commitSha": record["commitSha"],
                            "treeSha": record["treeSha"],
                        },
                        observed={"missing": True},
                    )
                    changed = True
                    if apply:
                        changed = self.store.quarantine_registered_candidate(
                            record["candidateId"],
                            state="REF_MISSING_QUARANTINED",
                            observed_commit_sha="",
                            observed_tree_sha="",
                            proof_hash=proof_hash,
                        )
                    quarantined_records += int(changed)
                    continue
                observed_tree = ""
                matches = False
                evidence_payload = {}
                try:
                    evidence = quarantine.candidate_evidence(record["ref"])
                    observed_tree = evidence.tree_sha
                    base_matches = quarantine.base_evidence_matches(
                        source_sha=record["baseSourceSha"],
                        commit_sha=record["baseCommitSha"],
                        tree_sha=record["baseTreeSha"],
                    )
                    matches = (
                        fsck_ok
                        and base_matches
                        and evidence.message_bound
                        and evidence.artifact_id == record["artifactId"]
                        and evidence.commit_sha == record["commitSha"]
                        and evidence.tree_sha == record["treeSha"]
                        and evidence.parent_sha == record["baseCommitSha"]
                    )
                    evidence_payload = {
                        "artifactId": evidence.artifact_id,
                        "commitSha": evidence.commit_sha,
                        "treeSha": evidence.tree_sha,
                        "parentSha": evidence.parent_sha,
                        "messageBound": evidence.message_bound,
                        "baseMatches": base_matches,
                    }
                except QuarantineError as exc:
                    evidence_payload = {"errorCode": exc.code}
                if matches:
                    continue
                proof_hash = _proof_hash(
                    repository_id=repository_id,
                    ref=record["ref"],
                    expected={
                        "commitSha": record["commitSha"],
                        "treeSha": record["treeSha"],
                    },
                    observed={
                        "refCommitSha": observed_commit,
                        "evidence": evidence_payload,
                        "fsck": "ok" if fsck_ok else "failed",
                    },
                )
                changed = True
                if apply:
                    changed = self.store.quarantine_registered_candidate(
                        record["candidateId"],
                        state="REF_MISMATCH_QUARANTINED",
                        observed_commit_sha=observed_commit,
                        observed_tree_sha=observed_tree,
                        proof_hash=proof_hash,
                    )
                quarantined_records += int(changed)

            for ref, observed_commit in sorted(refs.items()):
                if ref in known_refs:
                    continue
                artifact_id = _orphan_artifact_id(ref)
                observed_tree = ""
                base_commit = ""
                evidence_payload: dict[str, object]
                try:
                    evidence = quarantine.candidate_evidence(ref)
                    artifact_id = evidence.artifact_id
                    observed_tree = evidence.tree_sha
                    base_commit = evidence.parent_sha
                    evidence_payload = {
                        "artifactId": evidence.artifact_id,
                        "commitSha": evidence.commit_sha,
                        "treeSha": evidence.tree_sha,
                        "parentSha": evidence.parent_sha,
                        "messageBound": evidence.message_bound,
                        "fsck": "ok" if fsck_ok else "failed",
                    }
                except QuarantineError as exc:
                    evidence_payload = {
                        "errorCode": exc.code,
                        "refTargetSha": observed_commit,
                        "fsck": "ok" if fsck_ok else "failed",
                    }
                proof_hash = _proof_hash(
                    repository_id=repository_id,
                    ref=ref,
                    expected={"registered": False},
                    observed=evidence_payload,
                )
                changed = True
                if apply:
                    changed = self.store.register_orphan_candidate(
                        repository_id=repository_id,
                        artifact_id=artifact_id,
                        ref=ref,
                        observed_commit_sha=observed_commit,
                        observed_tree_sha=observed_tree,
                        base_commit_sha=base_commit,
                        proof_hash=proof_hash,
                    )
                orphaned += int(changed)

        return CandidateRecoveryReport(
            closed_attempts=closed_attempts,
            closed_intents=closed_intents,
            aborted_publications=aborted,
            recovered_publications=recovered,
            quarantined_publications=quarantined_publications,
            orphaned_refs=orphaned,
            quarantined_records=quarantined_records,
            requeued_routes=requeued_routes,
            errors=tuple(errors),
            backup_path=(
                None if backup_path is None else str(backup_path.resolve())
            ),
        )


def _proof_hash(
    *,
    repository_id: str,
    ref: str,
    expected: dict[str, object],
    observed: dict[str, object],
) -> str:
    return canonical_sha256(
        {
            "contractVersion": "candidate-recovery-proof-v1",
            "repositoryId": repository_id,
            "ref": ref,
            "expected": expected,
            "observed": observed,
        }
    )


def _orphan_artifact_id(ref: str) -> str:
    prefix = "refs/candidates/"
    suffix = ref[len(prefix) :] if ref.startswith(prefix) else ""
    if (
        suffix.startswith("art1_")
        and len(suffix) == 48
        and all(
            character.isascii()
            and (character.isalnum() or character in "_-")
            for character in suffix[5:]
        )
    ):
        return suffix
    return f"orphan1_{canonical_sha256({'ref': ref})[:43]}"


def _requires_mutation(report: CandidateRecoveryReport) -> bool:
    return any(
        (
            report.closed_attempts,
            report.closed_intents,
            report.aborted_publications,
            report.recovered_publications,
            report.quarantined_publications,
            report.orphaned_refs,
            report.quarantined_records,
            report.requeued_routes,
        )
    )
