"""Доказательное восстановление незавершённых публикаций кандидатов.

Модуль обслуживает только долговечное состояние версии 2.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .canonical_json import domain_fingerprint
from .identity import sha256_text
from .quarantine import CandidateEvidence, QuarantineError, QuarantineRepository


_INTENT_ID = re.compile(r"^cpi2_[A-Za-z0-9_-]{43}$")
_REPOSITORY_ID = re.compile(r"^qr2_[A-Za-z0-9_-]{43}$")
_ARTIFACT_ID = re.compile(r"^art1_[A-Za-z0-9_-]{43}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class CandidateRecoveryV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class CandidateRecoveryActionV2:
    kind: str
    intent_id: str
    repository_id: str
    ref: str
    observed_commit_sha: str
    observed_tree_sha: str
    proof_hash: str


@dataclass(frozen=True)
class CandidateRecoveryReportV2:
    ok: bool
    applied: bool
    actions: tuple[CandidateRecoveryActionV2, ...]
    blockers: tuple[str, ...]


class CandidateRecoveryStoreV2(Protocol):
    def quarantine_repositories(self) -> list[dict[str, Any]]: ...

    def pending_candidate_publications(
        self,
        repository_id: str | None = None,
    ) -> list[dict[str, Any]]: ...

    def candidate_intent(self, intent_id: str) -> dict[str, Any]: ...

    def recover_candidate_publication(
        self,
        intent_id: str,
        *,
        observed_commit_sha: str,
        observed_tree_sha: str,
    ) -> Mapping[str, Any]: ...

    def abort_candidate_publication(
        self,
        intent_id: str,
        *,
        proof_hash: str,
    ) -> Mapping[str, Any]: ...

    def quarantine_mismatched_publication(
        self,
        intent_id: str,
        *,
        observed_commit_sha: str,
        observed_tree_sha: str,
        proof_hash: str,
    ) -> Mapping[str, Any]: ...


RepositoryOpenerV2 = Callable[..., QuarantineRepository]


class CandidateRecoveryV2:
    """Планирует исходы без записи и применяет непротиворечивый план."""

    def __init__(
        self,
        *,
        store: CandidateRecoveryStoreV2,
        repository_opener: RepositoryOpenerV2 | None = None,
    ) -> None:
        required = (
            "quarantine_repositories",
            "pending_candidate_publications",
            "candidate_intent",
            "recover_candidate_publication",
            "abort_candidate_publication",
            "quarantine_mismatched_publication",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError(
                "store не предоставляет операции восстановления кандидата"
            )
        opener = repository_opener or _open_registered_read_only_v2
        if not callable(opener):
            raise TypeError("repository_opener должен быть вызываемым")
        self.store = store
        self.repository_opener = opener

    def run(self, *, apply: bool) -> CandidateRecoveryReportV2:
        if type(apply) is not bool:
            raise TypeError("apply должен быть bool")
        actions, blockers = self._plan()
        if blockers or not apply:
            return CandidateRecoveryReportV2(
                ok=not blockers,
                applied=False,
                actions=tuple(actions),
                blockers=tuple(blockers),
            )

        confirmed_actions, confirmed_blockers = self._plan()
        if confirmed_blockers or confirmed_actions != actions:
            blockers = list(confirmed_blockers)
            blockers.append("CANDIDATE_RECOVERY_PLAN_CHANGED")
            return CandidateRecoveryReportV2(
                ok=False,
                applied=False,
                actions=tuple(confirmed_actions),
                blockers=tuple(dict.fromkeys(blockers)),
            )
        for action in actions:
            self._apply(action)
        return CandidateRecoveryReportV2(
            ok=True,
            applied=bool(actions),
            actions=tuple(actions),
            blockers=(),
        )

    def _plan(
        self,
    ) -> tuple[list[CandidateRecoveryActionV2], list[str]]:
        try:
            registrations = self.store.quarantine_repositories()
            intents = self.store.pending_candidate_publications()
        except Exception as exc:
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_STORE_UNAVAILABLE",
                str(exc),
            ) from exc
        if type(registrations) is not list or type(intents) is not list:
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_STORE_INVALID",
                "списки регистраций и намерений должны быть точными "
                "списками",
            )

        by_repository: dict[str, Mapping[str, Any]] = {}
        blockers: list[str] = []
        for raw in registrations:
            parsed = _parse_registration(raw)
            if parsed is None:
                blockers.append("QUARANTINE_REGISTRATION_INVALID")
                continue
            repository_id = str(parsed["repositoryId"])
            if repository_id in by_repository:
                blockers.append(f"QUARANTINE_REGISTRATION_CONFLICT:{repository_id}")
                continue
            by_repository[repository_id] = parsed

        parsed_intents: list[Mapping[str, Any]] = []
        seen_intents: set[str] = set()
        seen_refs: set[tuple[str, str]] = set()
        for raw in intents:
            parsed = _parse_intent(raw)
            if parsed is None:
                blockers.append("CANDIDATE_INTENT_INVALID")
                continue
            intent_id = str(parsed["intentId"])
            ref_identity = (
                str(parsed["repositoryId"]),
                str(parsed["ref"]),
            )
            if intent_id in seen_intents or ref_identity in seen_refs:
                blockers.append(f"CANDIDATE_INTENT_CONFLICT:{intent_id}")
                continue
            seen_intents.add(intent_id)
            seen_refs.add(ref_identity)
            parsed_intents.append(parsed)

        actions: list[CandidateRecoveryActionV2] = []
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for intent in parsed_intents:
            grouped.setdefault(str(intent["repositoryId"]), []).append(intent)
        for repository_id in sorted(grouped):
            registration = by_repository.get(repository_id)
            if registration is None:
                blockers.append(
                    f"QUARANTINE_REGISTRATION_UNAVAILABLE:{repository_id}"
                )
                continue
            try:
                quarantine = self.repository_opener(
                    state_root=Path(str(registration["stateRoot"])),
                    source_root=Path(str(registration["sourceRoot"])),
                    git_dir=Path(str(registration["gitDir"])),
                )
                refs = quarantine.candidate_refs()
                fsck_state = quarantine.fsck()
            except (OSError, QuarantineError) as exc:
                blockers.append(
                    f"QUARANTINE_REPOSITORY_UNAVAILABLE:{repository_id}:"
                    f"{getattr(exc, 'code', type(exc).__name__)}"
                )
                continue
            except Exception as exc:
                blockers.append(
                    f"QUARANTINE_REPOSITORY_UNAVAILABLE:{repository_id}:"
                    f"{type(exc).__name__}"
                )
                continue
            if type(refs) is not dict or fsck_state not in {"ok", "failed"}:
                blockers.append(
                    f"QUARANTINE_REPOSITORY_EVIDENCE_INVALID:{repository_id}"
                )
                continue
            for intent in grouped[repository_id]:
                action, blocker = self._classify(
                    quarantine=quarantine,
                    intent=intent,
                    refs=refs,
                    fsck_state=fsck_state,
                )
                if blocker is not None:
                    blockers.append(blocker)
                elif action is not None:
                    actions.append(action)
        actions.sort(key=lambda item: (item.repository_id, item.intent_id))
        return actions, list(dict.fromkeys(blockers))

    def _classify(
        self,
        *,
        quarantine: QuarantineRepository,
        intent: Mapping[str, Any],
        refs: Mapping[str, str],
        fsck_state: str,
    ) -> tuple[CandidateRecoveryActionV2 | None, str | None]:
        intent_id = str(intent["intentId"])
        repository_id = str(intent["repositoryId"])
        ref = str(intent["ref"])
        observed_commit = refs.get(ref)
        expected = _expected_evidence(intent)
        if observed_commit is None:
            proof_hash = _recovery_proof_hash(
                intent=intent,
                observed={"missing": True, "fsck": fsck_state},
            )
            return (
                CandidateRecoveryActionV2(
                    kind="ABORT_MISSING",
                    intent_id=intent_id,
                    repository_id=repository_id,
                    ref=ref,
                    observed_commit_sha="",
                    observed_tree_sha="",
                    proof_hash=proof_hash,
                ),
                None,
            )
        if type(observed_commit) is not str or _GIT_SHA.fullmatch(observed_commit) is None:
            return None, f"CANDIDATE_REF_EVIDENCE_INVALID:{intent_id}"

        observed_tree = ""
        base_matches = False
        evidence_value: dict[str, Any]
        evidence: CandidateEvidence | None = None
        try:
            evidence = quarantine.candidate_evidence(ref)
            observed_tree = evidence.tree_sha
            base_matches = quarantine.base_evidence_matches(
                source_sha=str(intent["baseSourceSha"]),
                commit_sha=str(intent["baseCommitSha"]),
                tree_sha=str(intent["baseTreeSha"]),
            )
            evidence_value = {
                "artifactId": evidence.artifact_id,
                "ref": evidence.ref,
                "commitSha": evidence.commit_sha,
                "treeSha": evidence.tree_sha,
                "parentSha": evidence.parent_sha,
                "messageBound": evidence.message_bound,
                "baseMatches": base_matches,
            }
        except (OSError, QuarantineError) as exc:
            evidence_value = {
                "errorCode": getattr(exc, "code", type(exc).__name__),
                "baseMatches": False,
            }
        except Exception as exc:
            evidence_value = {
                "errorCode": type(exc).__name__,
                "baseMatches": False,
            }

        exact = bool(
            fsck_state == "ok"
            and base_matches
            and evidence is not None
            and evidence.message_bound
            and evidence.artifact_id == expected["artifactId"]
            and evidence.ref == ref
            and observed_commit == expected["commitSha"]
            and evidence.commit_sha == expected["commitSha"]
            and evidence.tree_sha == expected["treeSha"]
            and evidence.parent_sha == expected["baseCommitSha"]
        )
        if exact:
            validation_proof = intent.get("validationProofSha256")
            if (
                type(validation_proof) is not str
                or _SHA256.fullmatch(validation_proof) is None
            ):
                return None, f"VALIDATION_PROOF_UNAVAILABLE:{intent_id}"
            return (
                CandidateRecoveryActionV2(
                    kind="RECOVER_VERIFIED",
                    intent_id=intent_id,
                    repository_id=repository_id,
                    ref=ref,
                    observed_commit_sha=observed_commit,
                    observed_tree_sha=observed_tree,
                    proof_hash=validation_proof,
                ),
                None,
            )

        proof_hash = _recovery_proof_hash(
            intent=intent,
            observed={
                "refCommitSha": observed_commit,
                "evidence": evidence_value,
                "fsck": fsck_state,
            },
        )
        return (
            CandidateRecoveryActionV2(
                kind="QUARANTINE_MISMATCH",
                intent_id=intent_id,
                repository_id=repository_id,
                ref=ref,
                observed_commit_sha=observed_commit,
                observed_tree_sha=observed_tree,
                proof_hash=proof_hash,
            ),
            None,
        )

    def _apply(self, action: CandidateRecoveryActionV2) -> None:
        try:
            if action.kind == "RECOVER_VERIFIED":
                record = self.store.recover_candidate_publication(
                    action.intent_id,
                    observed_commit_sha=action.observed_commit_sha,
                    observed_tree_sha=action.observed_tree_sha,
                )
                expected_state = "VERIFIED"
                expected_trusted = True
                expected_intent_state = "RECOVERED"
            elif action.kind == "ABORT_MISSING":
                record = self.store.abort_candidate_publication(
                    action.intent_id,
                    proof_hash=action.proof_hash,
                )
                expected_state = "REF_MISSING_QUARANTINED"
                expected_trusted = False
                expected_intent_state = "ABORTED"
            elif action.kind == "QUARANTINE_MISMATCH":
                record = self.store.quarantine_mismatched_publication(
                    action.intent_id,
                    observed_commit_sha=action.observed_commit_sha,
                    observed_tree_sha=action.observed_tree_sha,
                    proof_hash=action.proof_hash,
                )
                expected_state = "REF_MISMATCH_QUARANTINED"
                expected_trusted = False
                expected_intent_state = "QUARANTINED"
            else:
                raise CandidateRecoveryV2Error(
                    "CANDIDATE_RECOVERY_ACTION_INVALID",
                    action.kind,
                )
        except CandidateRecoveryV2Error:
            raise
        except Exception as exc:
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_APPLY_FAILED",
                f"{action.intent_id}:{exc}",
            ) from exc
        if (
            record.get("state") != expected_state
            or record.get("trusted") is not expected_trusted
            or record.get("proofHash") != action.proof_hash
        ):
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_RESULT_MISMATCH",
                action.intent_id,
            )
        try:
            intent = self.store.candidate_intent(action.intent_id)
        except Exception as exc:
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_RESULT_MISMATCH",
                f"{action.intent_id}:{exc}",
            ) from exc
        if intent.get("state") != expected_intent_state:
            raise CandidateRecoveryV2Error(
                "CANDIDATE_RECOVERY_RESULT_MISMATCH",
                action.intent_id,
            )


def _parse_registration(raw: object) -> Mapping[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    required = ("repositoryId", "sourceRoot", "stateRoot", "gitDir", "state")
    if any(name not in raw for name in required):
        return None
    repository_id = raw["repositoryId"]
    paths = (raw["sourceRoot"], raw["stateRoot"], raw["gitDir"])
    if (
        type(repository_id) is not str
        or _REPOSITORY_ID.fullmatch(repository_id) is None
        or raw["state"] != "ACTIVE"
        or any(type(value) is not str or not Path(value).is_absolute() for value in paths)
    ):
        return None
    return raw


def _parse_intent(raw: object) -> Mapping[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    required = (
        "intentId",
        "repositoryId",
        "artifactId",
        "ref",
        "baseSourceSha",
        "baseCommitSha",
        "baseTreeSha",
        "commitSha",
        "treeSha",
        "state",
    )
    if any(name not in raw for name in required):
        return None
    if (
        type(raw["intentId"]) is not str
        or _INTENT_ID.fullmatch(raw["intentId"]) is None
        or type(raw["repositoryId"]) is not str
        or _REPOSITORY_ID.fullmatch(raw["repositoryId"]) is None
        or raw["state"] != "PENDING"
        or type(raw["artifactId"]) is not str
        or _ARTIFACT_ID.fullmatch(raw["artifactId"]) is None
        or type(raw["ref"]) is not str
        or raw["ref"] != f"refs/candidates/{raw['artifactId']}"
        or any(
            type(raw[name]) is not str or _GIT_SHA.fullmatch(raw[name]) is None
            for name in (
                "baseSourceSha",
                "baseCommitSha",
                "baseTreeSha",
                "commitSha",
                "treeSha",
            )
        )
    ):
        return None
    return raw


def _expected_evidence(intent: Mapping[str, Any]) -> dict[str, str]:
    return {
        "artifactId": str(intent["artifactId"]),
        "baseSourceSha": str(intent["baseSourceSha"]),
        "baseCommitSha": str(intent["baseCommitSha"]),
        "baseTreeSha": str(intent["baseTreeSha"]),
        "commitSha": str(intent["commitSha"]),
        "treeSha": str(intent["treeSha"]),
    }


def _recovery_proof_hash(
    *,
    intent: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> str:
    return domain_fingerprint(
        "codex-smart/candidate-recovery-observation/v2",
        {
            "contractVersion": "candidate-recovery-observation-v2",
            "intentId": str(intent["intentId"]),
            "repositoryId": str(intent["repositoryId"]),
            "ref": str(intent["ref"]),
            "expected": _expected_evidence(intent),
            "observed": dict(observed),
        },
    )


def _open_registered_read_only_v2(
    *,
    state_root: Path,
    source_root: Path,
    git_dir: Path,
) -> QuarantineRepository:
    """Открывает зарегистрированный карантин без исправления его метаданных."""

    try:
        if source_root.is_symlink() or state_root.is_symlink() or git_dir.is_symlink():
            raise QuarantineError(
                "REGISTERED_REPOSITORY_UNSAFE",
                "registered quarantine repository identity is unsafe",
            )
        source = source_root.expanduser().resolve(strict=True)
        root = state_root.expanduser().resolve(strict=True)
        registered_git = git_dir.expanduser().resolve(strict=True)
        quarantine_root = root / "quarantine"
        if quarantine_root.is_symlink():
            raise QuarantineError(
                "REGISTERED_REPOSITORY_UNSAFE",
                "registered quarantine repository identity is unsafe",
            )
        expected_parent = quarantine_root.resolve(strict=True)
    except OSError as exc:
        raise QuarantineError(
            "REGISTERED_REPOSITORY_UNSAFE",
            "registered quarantine repository identity is unavailable",
        ) from exc
    if (
        not source.is_dir()
        or registered_git.parent != expected_parent
        or registered_git.name != f"{sha256_text(str(source))[:24]}.git"
    ):
        raise QuarantineError(
            "REGISTERED_REPOSITORY_UNSAFE",
            "registered quarantine repository identity is unsafe",
        )
    _require_private_repository_tree_v2(root, expected_parent, registered_git)
    alternates = registered_git / "objects" / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink():
        raise QuarantineError(
            "ALTERNATES_FORBIDDEN",
            "quarantine Git must not use object alternates",
        )
    git_binary = Path("/usr/bin/git")
    if not git_binary.is_file() or not os.access(git_binary, os.X_OK):
        selected = shutil.which("git")
        if selected is None:
            raise QuarantineError(
                "GIT_UNAVAILABLE",
                "git executable is unavailable",
            )
        git_binary = Path(selected).resolve(strict=True)
    return QuarantineRepository(
        source_root=source,
        git_dir=registered_git,
        git_binary=git_binary,
    )


def _require_private_repository_tree_v2(
    state_root: Path,
    quarantine_root: Path,
    git_dir: Path,
) -> None:
    for path in (state_root, quarantine_root, git_dir):
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise QuarantineError(
                "REGISTERED_REPOSITORY_UNSAFE",
                "registered quarantine repository permissions are unsafe",
            )
    for current, directories, filenames in os.walk(git_dir, followlinks=False):
        current_path = Path(current)
        current_info = current_path.lstat()
        if (
            current_path.is_symlink()
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_uid != os.getuid()
            or not _owned_readable_directory_mode_v2(current_info.st_mode)
        ):
            raise QuarantineError(
                "REGISTERED_REPOSITORY_UNSAFE",
                "registered quarantine repository permissions are unsafe",
            )
        for name in directories:
            path = current_path / name
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or not _owned_readable_directory_mode_v2(info.st_mode)
            ):
                raise QuarantineError(
                    "REGISTERED_REPOSITORY_UNSAFE",
                    "registered quarantine repository permissions are unsafe",
                )
        for name in filenames:
            path = current_path / name
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or not _owned_readable_file_mode_v2(info.st_mode)
            ):
                raise QuarantineError(
                    "REGISTERED_REPOSITORY_UNSAFE",
                    "registered quarantine repository file is unsafe",
                )


def _owned_readable_directory_mode_v2(value: int) -> bool:
    mode = stat.S_IMODE(value)
    return mode & 0o500 == 0o500 and mode & 0o022 == 0


def _owned_readable_file_mode_v2(value: int) -> bool:
    mode = stat.S_IMODE(value)
    return mode & 0o400 == 0o400 and mode & 0o022 == 0
