"""Публикация кандидата через хранилище состояния версии 2."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .quarantine import (
    BaseImport,
    CandidateEvidence,
    CandidateResult,
    QuarantineRepository,
)
from .state_store_v2 import SmartStoreV2
from .validation import ValidationResult
from .writer_publication_v2 import CandidateRefPublicationV2


@dataclass
class StateCandidatePublisherV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class StateCandidateRefPublisherV2:
    """Владелец перехода ``PENDING -> VERIFIED``."""

    def __init__(self, *, store: SmartStoreV2) -> None:
        if not isinstance(store, SmartStoreV2):
            raise TypeError("store должен быть SmartStoreV2")
        self.store = store

    def publish(
        self,
        publication: CandidateRefPublicationV2,
    ) -> CandidateEvidence:
        _require_publication(publication)
        quarantine = publication.quarantine
        repository_id = self.store.register_quarantine_repository(
            source_root=quarantine.source_root,
            state_root=quarantine.git_dir.parent.parent,
            git_dir=quarantine.git_dir,
        )
        intent_id = self.store.begin_candidate_publication(
            route_id=publication.route_id,
            node_id=publication.node_id,
            repository_id=repository_id,
            artifact_id=publication.candidate.artifact_id,
            ref=publication.candidate.ref,
            base_source_sha=publication.base.source_sha,
            base_commit_sha=publication.base.commit_sha,
            base_tree_sha=publication.base.tree_sha,
            commit_sha=publication.candidate.commit_sha,
            tree_sha=publication.candidate.tree_sha,
            validation_proof_sha256=publication.validation_proof_sha256,
        )
        intent_state = self.store.candidate_intent(intent_id)["state"]
        ref_exists = quarantine.ref_exists(publication.candidate.ref)
        if intent_state in {"COMPLETED", "RECOVERED"} and not ref_exists:
            raise StateCandidatePublisherV2Error(
                "CANDIDATE_PUBLICATION_CONFLICT",
                "a completed candidate reference is missing",
            )

        if not ref_exists:
            try:
                quarantine.publish_candidate(publication.candidate)
            except Exception as publish_error:
                try:
                    evidence = _read_candidate_evidence(publication)
                except Exception:
                    raise publish_error
            else:
                evidence = _read_candidate_evidence(publication)
        else:
            evidence = _read_candidate_evidence(publication)

        _require_exact_evidence(publication, evidence)
        if intent_state == "RECOVERED":
            self.store.recover_candidate_publication(
                intent_id,
                observed_commit_sha=evidence.commit_sha,
                observed_tree_sha=evidence.tree_sha,
            )
        else:
            self.store.complete_candidate_publication(
                intent_id,
                observed_commit_sha=evidence.commit_sha,
                observed_tree_sha=evidence.tree_sha,
                proof_hash=publication.validation_proof_sha256,
            )
        return evidence


_ROUTE_ID = re.compile(r"^route2_[0-9a-f]{32}$")
_NODE_ID = re.compile(r"^node2_[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^att2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _require_publication(publication: CandidateRefPublicationV2) -> None:
    if not isinstance(publication, CandidateRefPublicationV2):
        raise TypeError("publication должен быть CandidateRefPublicationV2")
    if (
        _ROUTE_ID.fullmatch(publication.route_id) is None
        or _NODE_ID.fullmatch(publication.node_id) is None
        or _ATTEMPT_ID.fullmatch(publication.attempt_id) is None
        or not isinstance(publication.quarantine, QuarantineRepository)
        or not isinstance(publication.base, BaseImport)
        or not isinstance(publication.candidate, CandidateResult)
        or not isinstance(publication.validation, ValidationResult)
        or _SHA256.fullmatch(publication.source_manifest_sha256) is None
        or _SHA256.fullmatch(publication.validation_proof_sha256) is None
    ):
        raise StateCandidatePublisherV2Error(
            "CANDIDATE_PUBLICATION_INVALID",
            "candidate publication identity is invalid",
        )
    if publication.validation.validation_state != "passed":
        raise StateCandidatePublisherV2Error(
            "CANDIDATE_VALIDATION_NOT_PASSED",
            "only a passed validation may publish a trusted candidate",
        )


def _read_candidate_evidence(
    publication: CandidateRefPublicationV2,
) -> CandidateEvidence:
    try:
        return publication.quarantine.candidate_evidence(
            publication.candidate.ref
        )
    except Exception as exc:
        raise StateCandidatePublisherV2Error(
            "CANDIDATE_PUBLICATION_CONFLICT",
            "candidate reference evidence is unavailable",
        ) from exc


def _require_exact_evidence(
    publication: CandidateRefPublicationV2,
    evidence: CandidateEvidence,
) -> None:
    try:
        base_matches = publication.quarantine.base_evidence_matches(
            source_sha=publication.base.source_sha,
            commit_sha=publication.base.commit_sha,
            tree_sha=publication.base.tree_sha,
        )
        fsck_ok = publication.quarantine.fsck() == "ok"
    except Exception as exc:
        raise StateCandidatePublisherV2Error(
            "CANDIDATE_PUBLICATION_CONFLICT",
            "candidate repository evidence is unavailable",
        ) from exc
    if (
        not isinstance(evidence, CandidateEvidence)
        or not base_matches
        or not fsck_ok
        or not evidence.message_bound
        or evidence.artifact_id != publication.candidate.artifact_id
        or evidence.ref != publication.candidate.ref
        or evidence.commit_sha != publication.candidate.commit_sha
        or evidence.tree_sha != publication.candidate.tree_sha
        or evidence.parent_sha != publication.base.commit_sha
    ):
        raise StateCandidatePublisherV2Error(
            "CANDIDATE_PUBLICATION_CONFLICT",
            "published candidate differs from its persisted intent",
        )
