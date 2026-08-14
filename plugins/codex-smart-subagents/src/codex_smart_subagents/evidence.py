"""Strict builders and verifiers for Codex compatibility evidence."""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from .canonical_json import (
    MAX_SAFE_INTEGER,
    CanonicalJsonError,
    canonical_json_bytes,
    domain_fingerprint,
)
from .compatibility import codex_version_supported


INTERFACE_CONTRACT = "codex-interface-v1"
ACCOUNT_CONTRACT = "codex-account-v1"

SUBJECT_DOMAIN = "codex-smart/subject/v1"
SEMANTIC_DOMAIN = "codex-smart/semantic/v1"
COMPATIBILITY_DOMAIN = "codex-smart/compatibility/v1"
REQUIREMENTS_DOMAIN = "codex-smart/requirements/v1"
ACCOUNT_CATALOG_DOMAIN = "codex-smart/account-catalog/v1"
ACCOUNT_CONTEXT_DOMAIN = "codex-smart/account-context/v1"
ACCOUNT_RECORD_DOMAIN = "codex-smart/account-record/v1"
ACCOUNT_ENVIRONMENT_DOMAIN = "codex-smart/account-environment/v1"
ACCOUNT_PROCESS_DOMAIN = "codex-smart/account-process/v1"
ACCOUNT_COLLECTION_DOMAIN = "codex-smart/account-collection/v1"

ACCOUNT_DEADLINE_SECONDS = 180.0
ACCOUNT_ARGV = ("app-server", "--strict-config", "--listen", "stdio://")
FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

_ACCOUNT_STAGES = (
    (1, "requirements-a", "#/requirementsFingerprint"),
    (2, "catalog-a", "#/accountCatalogFingerprint"),
    (3, "requirements-b", "#/requirementsFingerprint"),
    (4, "catalog-b", "#/accountCatalogFingerprint"),
    (5, "requirements-c", "#/requirementsFingerprint"),
)
_ACCOUNT_ROOT_REFERENCES = {
    "executablePath": "#/subject/snapshotPath",
    "subjectFingerprint": "#/subject/subjectFingerprint",
    "compatibilityFingerprint": "#/compatibilityFingerprint",
    "requirementsResult": "#/requirementsFingerprint",
    "catalogResult": "#/accountCatalogFingerprint",
}

_SHA256 = re.compile(r"[0-9a-f]{64}")
_CDHASH = re.compile(r"[0-9a-f]{40}")
_CODEX_VERSION = re.compile(r"codex-cli ([0-9]+)\.([0-9]+)\.([0-9]+)")
_RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_DECIMAL_NANOSECONDS = re.compile(r"(?:0|[1-9][0-9]{0,31})")

_SUBJECT_FIELDS = {
    "snapshotSha256",
    "snapshotPath",
    "size",
    "mode",
    "uid",
    "device",
    "inode",
    "mtimeNs",
    "version",
    "platform",
    "architecture",
    "signatureIdentifier",
    "teamIdentifier",
    "cdHash",
    "sourceLocator",
    "sourceObservedSha256",
}
_SEMANTIC_FIELDS = {
    "extensionRelease",
    "contractVersion",
    "platformAdapter",
    "commands",
    "options",
    "appServerMethods",
    "machineSchemas",
    "probeBudgets",
    "negativeProbeIds",
    "arg0AdapterVersion",
    "routingPolicyFingerprint",
    "bundledCatalogFingerprint",
    "childProfiles",
}
_REQUIRED_MACHINE_SCHEMAS = {
    "interface-evidence-v1",
    "account-evidence-v1",
    "config-requirements-normalized-v1",
    "config-requirements-vector-recipe-v1",
    "child-profile-v1",
    "routing-policy-v2",
    "child-jsonl-v1",
    "otel-logs-v1",
    "boundary-result-v1",
    "reader-result-v1",
    "writer-result-v1",
}


@dataclass
class EvidenceError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class AccountEvidenceExecutor(Protocol):
    """Execute one fresh app-server process for one collection stage."""

    def execute(
        self,
        stage: str,
        *,
        executable_path: str,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: float,
        cancel_check: Callable[[], bool] | None = None,
    ) -> Any: ...


def build_interface_evidence(
    *,
    subject: Mapping[str, Any],
    semantic: Mapping[str, Any],
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build InterfaceEvidence from an already verified snapshot and semantics."""

    candidate_subject = _copy_object(subject, "subject")
    candidate_semantic = _copy_object(semantic, "semantic")
    _validate_interface_subject(candidate_subject)
    _validate_interface_semantic(candidate_semantic)
    subject_fingerprint = domain_fingerprint(SUBJECT_DOMAIN, candidate_subject)
    semantic_fingerprint = domain_fingerprint(SEMANTIC_DOMAIN, candidate_semantic)
    compatibility_fingerprint = domain_fingerprint(
        COMPATIBILITY_DOMAIN,
        {
            "contractVersion": INTERFACE_CONTRACT,
            "semanticFingerprint": semantic_fingerprint,
            "subjectFingerprint": subject_fingerprint,
        },
    )
    evidence: dict[str, Any] = {
        "schemaVersion": 1,
        "contractVersion": INTERFACE_CONTRACT,
        "subject": candidate_subject,
        "semantic": candidate_semantic,
        "subjectFingerprint": subject_fingerprint,
        "semanticFingerprint": semantic_fingerprint,
        "compatibilityFingerprint": compatibility_fingerprint,
    }
    if extensions is not None:
        evidence["extensions"] = _copy_object(extensions, "extensions")
        _validate_extensions(evidence["extensions"])
    return evidence


def verify_interface_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate form and every protected InterfaceEvidence fingerprint."""

    evidence = _copy_object(value, "InterfaceEvidence")
    _expect_exact_fields(
        evidence,
        required={
            "schemaVersion",
            "contractVersion",
            "subject",
            "semantic",
            "subjectFingerprint",
            "semanticFingerprint",
            "compatibilityFingerprint",
        },
        optional={"extensions"},
        code="INTERFACE_SCHEMA_INVALID",
    )
    if evidence["schemaVersion"] != 1 or evidence["contractVersion"] != INTERFACE_CONTRACT:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "interface contract identity is invalid")
    _validate_interface_subject(evidence["subject"])
    _validate_interface_semantic(evidence["semantic"])
    for name in (
        "subjectFingerprint",
        "semanticFingerprint",
        "compatibilityFingerprint",
    ):
        _expect_sha256(evidence[name], name, "INTERFACE_SCHEMA_INVALID")
    if "extensions" in evidence:
        _validate_extensions(evidence["extensions"])
    expected = build_interface_evidence(
        subject=evidence["subject"],
        semantic=evidence["semantic"],
        extensions=evidence.get("extensions"),
    )
    for name in (
        "subjectFingerprint",
        "semanticFingerprint",
        "compatibilityFingerprint",
    ):
        if evidence[name] != expected[name]:
            raise EvidenceError(
                "INTERFACE_FINGERPRINT_INVALID",
                f"{name} does not match the protected projection",
            )
    return evidence


def build_account_evidence(
    *,
    interface_evidence: Mapping[str, Any],
    codex_home: str,
    home: str,
    tmpdir: str,
    requirements: Any,
    available_pairs: Mapping[str, Sequence[str]] | Sequence[Mapping[str, str]],
    started_at: str | None = None,
    finished_at: str | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build AccountEvidence from mutually consistent, already verified reads."""

    interface = verify_interface_evidence(interface_evidence)
    for name, path in (("codexHome", codex_home), ("HOME", home), ("TMPDIR", tmpdir)):
        _expect_path(path, name, "ACCOUNT_SCHEMA_INVALID")
    normalized_requirements = _copy_requirements(requirements)
    pairs = _normalize_available_pairs(available_pairs)
    subject = {
        "snapshotPath": interface["subject"]["snapshotPath"],
        "snapshotSha256": interface["subject"]["snapshotSha256"],
        "subjectFingerprint": interface["subjectFingerprint"],
    }
    compatibility_fingerprint = interface["compatibilityFingerprint"]
    requirements_fingerprint = domain_fingerprint(
        REQUIREMENTS_DOMAIN, normalized_requirements
    )
    catalog_fingerprint = domain_fingerprint(ACCOUNT_CATALOG_DOMAIN, pairs)
    environment = {
        "CODEX_HOME": codex_home,
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": FIXED_PATH,
        "TMPDIR": tmpdir,
    }
    environment_fingerprint = domain_fingerprint(
        ACCOUNT_ENVIRONMENT_DOMAIN, environment
    )
    process_fingerprints: list[str] = []
    processes: list[dict[str, Any]] = []
    for ordinal, stage, result_reference in _ACCOUNT_STAGES:
        result_fingerprint = (
            requirements_fingerprint
            if result_reference == "#/requirementsFingerprint"
            else catalog_fingerprint
        )
        record = {
            "ordinal": ordinal,
            "stage": stage,
            "resultFingerprintRef": result_reference,
        }
        projection = {
            "record": record,
            "resolved": {
                "executablePath": subject["snapshotPath"],
                "subjectFingerprint": subject["subjectFingerprint"],
                "compatibilityFingerprint": compatibility_fingerprint,
                "resultFingerprint": result_fingerprint,
            },
            "argv": list(ACCOUNT_ARGV),
            "environment": environment,
            "environmentFingerprint": environment_fingerprint,
        }
        process_fingerprint = domain_fingerprint(
            ACCOUNT_PROCESS_DOMAIN, projection
        )
        process_fingerprints.append(process_fingerprint)
        processes.append({**record, "processFingerprint": process_fingerprint})
    collection_fingerprint = domain_fingerprint(
        ACCOUNT_COLLECTION_DOMAIN,
        {"processFingerprints": process_fingerprints},
    )
    context_fingerprint = domain_fingerprint(
        ACCOUNT_CONTEXT_DOMAIN,
        {
            "codexHome": codex_home,
            "subjectFingerprint": subject["subjectFingerprint"],
            "compatibilityFingerprint": compatibility_fingerprint,
            "requirementsFingerprint": requirements_fingerprint,
            "accountCatalogFingerprint": catalog_fingerprint,
            "collectionFingerprint": collection_fingerprint,
        },
    )
    record_fingerprint = domain_fingerprint(
        ACCOUNT_RECORD_DOMAIN,
        {
            "schemaVersion": 1,
            "contractVersion": ACCOUNT_CONTRACT,
            "subjectFingerprint": subject["subjectFingerprint"],
            "compatibilityFingerprint": compatibility_fingerprint,
            "requirementsFingerprint": requirements_fingerprint,
            "accountCatalogFingerprint": catalog_fingerprint,
            "accountContextFingerprint": context_fingerprint,
            "collectionFingerprint": collection_fingerprint,
        },
    )
    evidence: dict[str, Any] = {
        "schemaVersion": 1,
        "contractVersion": ACCOUNT_CONTRACT,
        "subject": subject,
        "codexHome": codex_home,
        "requirements": normalized_requirements,
        "availablePairs": pairs,
        "compatibilityFingerprint": compatibility_fingerprint,
        "requirementsFingerprint": requirements_fingerprint,
        "accountCatalogFingerprint": catalog_fingerprint,
        "accountContextFingerprint": context_fingerprint,
        "collection": {
            "rootReferences": copy.deepcopy(_ACCOUNT_ROOT_REFERENCES),
            "argv": list(ACCOUNT_ARGV),
            "environment": environment,
            "environmentFingerprint": environment_fingerprint,
            "processes": processes,
            "collectionFingerprint": collection_fingerprint,
        },
        "recordFingerprint": record_fingerprint,
    }
    for name, timestamp in (("startedAt", started_at), ("finishedAt", finished_at)):
        if timestamp is not None:
            _expect_rfc3339(timestamp, name)
            evidence[name] = timestamp
    if extensions is not None:
        evidence["extensions"] = _copy_object(extensions, "extensions")
        _validate_extensions(evidence["extensions"])
    return evidence


def verify_account_evidence(
    value: Mapping[str, Any],
    interface_evidence: Mapping[str, Any],
    *,
    expected_codex_home: str | None = None,
) -> dict[str, Any]:
    """Validate AccountEvidence and bind it to current InterfaceEvidence."""

    evidence = _copy_object(value, "AccountEvidence")
    interface = verify_interface_evidence(interface_evidence)
    required = {
        "schemaVersion",
        "contractVersion",
        "subject",
        "codexHome",
        "requirements",
        "availablePairs",
        "compatibilityFingerprint",
        "requirementsFingerprint",
        "accountCatalogFingerprint",
        "accountContextFingerprint",
        "collection",
        "recordFingerprint",
    }
    _expect_exact_fields(
        evidence,
        required=required,
        optional={"startedAt", "finishedAt", "extensions"},
        code="ACCOUNT_SCHEMA_INVALID",
    )
    if evidence["schemaVersion"] != 1 or evidence["contractVersion"] != ACCOUNT_CONTRACT:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "account contract identity is invalid")
    subject = evidence["subject"]
    if type(subject) is not dict:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "account subject must be an object")
    _expect_exact_fields(
        subject,
        required={"snapshotPath", "snapshotSha256", "subjectFingerprint"},
        code="ACCOUNT_SCHEMA_INVALID",
    )
    _expect_path(subject["snapshotPath"], "snapshotPath", "ACCOUNT_SCHEMA_INVALID")
    _expect_sha256(subject["snapshotSha256"], "snapshotSha256", "ACCOUNT_SCHEMA_INVALID")
    _expect_sha256(subject["subjectFingerprint"], "subjectFingerprint", "ACCOUNT_SCHEMA_INVALID")
    expected_subject = {
        "snapshotPath": interface["subject"]["snapshotPath"],
        "snapshotSha256": interface["subject"]["snapshotSha256"],
        "subjectFingerprint": interface["subjectFingerprint"],
    }
    if subject != expected_subject:
        raise EvidenceError("ACCOUNT_INTERFACE_MISMATCH", "account subject does not match InterfaceEvidence")
    _expect_path(evidence["codexHome"], "codexHome", "ACCOUNT_SCHEMA_INVALID")
    if expected_codex_home is not None and evidence["codexHome"] != expected_codex_home:
        raise EvidenceError("ACCOUNT_CONTEXT_MISMATCH", "CODEX_HOME does not match the current context")
    _copy_requirements(evidence["requirements"])
    pairs = _validate_available_pairs(evidence["availablePairs"], require_sorted=True)
    if evidence["compatibilityFingerprint"] != interface["compatibilityFingerprint"]:
        raise EvidenceError("ACCOUNT_INTERFACE_MISMATCH", "compatibility fingerprint does not match")
    for name in (
        "compatibilityFingerprint",
        "requirementsFingerprint",
        "accountCatalogFingerprint",
        "accountContextFingerprint",
        "recordFingerprint",
    ):
        _expect_sha256(evidence[name], name, "ACCOUNT_SCHEMA_INVALID")
    collection = evidence["collection"]
    if type(collection) is not dict:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "collection must be an object")
    _expect_exact_fields(
        collection,
        required={
            "rootReferences",
            "argv",
            "environment",
            "environmentFingerprint",
            "processes",
            "collectionFingerprint",
        },
        code="ACCOUNT_SCHEMA_INVALID",
    )
    if collection["rootReferences"] != _ACCOUNT_ROOT_REFERENCES:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "root references are not the fixed local references")
    if collection["argv"] != list(ACCOUNT_ARGV):
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "app-server argv is invalid")
    environment = collection["environment"]
    _validate_account_environment(environment, evidence["codexHome"])
    _expect_sha256(collection["environmentFingerprint"], "environmentFingerprint", "ACCOUNT_SCHEMA_INVALID")
    _expect_sha256(collection["collectionFingerprint"], "collectionFingerprint", "ACCOUNT_SCHEMA_INVALID")
    _validate_process_records(collection["processes"])
    for name in ("startedAt", "finishedAt"):
        if name in evidence:
            _expect_rfc3339(evidence[name], name)
    if "extensions" in evidence:
        _validate_extensions(evidence["extensions"])

    expected = build_account_evidence(
        interface_evidence=interface,
        codex_home=evidence["codexHome"],
        home=environment["HOME"],
        tmpdir=environment["TMPDIR"],
        requirements=evidence["requirements"],
        available_pairs=pairs,
        started_at=evidence.get("startedAt"),
        finished_at=evidence.get("finishedAt"),
        extensions=evidence.get("extensions"),
    )
    protected_fields = (
        "requirementsFingerprint",
        "accountCatalogFingerprint",
        "accountContextFingerprint",
        "recordFingerprint",
    )
    for name in protected_fields:
        if evidence[name] != expected[name]:
            raise EvidenceError("ACCOUNT_FINGERPRINT_INVALID", f"{name} does not match")
    for name in ("environmentFingerprint", "collectionFingerprint"):
        if collection[name] != expected["collection"][name]:
            raise EvidenceError("ACCOUNT_FINGERPRINT_INVALID", f"{name} does not match")
    if collection["processes"] != expected["collection"]["processes"]:
        raise EvidenceError("ACCOUNT_FINGERPRINT_INVALID", "process fingerprints do not match")
    return evidence


class AccountEvidenceCollector:
    """Collect exactly five fresh account reads under one monotonic deadline."""

    def __init__(
        self,
        *,
        interface_evidence: Mapping[str, Any],
        codex_home: str,
        home: str,
        tmpdir: str,
        executor: AccountEvidenceExecutor,
        verify_subject: Callable[[dict[str, Any]], None],
        monotonic: Callable[[], float] = time.monotonic,
        timeout_seconds: float = ACCOUNT_DEADLINE_SECONDS,
        stage_callback: Callable[[str], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        self._interface_evidence = verify_interface_evidence(interface_evidence)
        for name, path in (("codexHome", codex_home), ("HOME", home), ("TMPDIR", tmpdir)):
            _expect_path(path, name, "ACCOUNT_SCHEMA_INVALID")
        if not callable(getattr(executor, "execute", None)):
            raise TypeError("executor must provide execute()")
        if not callable(verify_subject) or not callable(monotonic):
            raise TypeError("verify_subject and monotonic must be callable")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= ACCOUNT_DEADLINE_SECONDS
        ):
            raise ValueError("timeout_seconds must be within the account deadline")
        if stage_callback is not None and not callable(stage_callback):
            raise TypeError("stage_callback must be callable")
        if cancel_check is not None and not callable(cancel_check):
            raise TypeError("cancel_check must be callable")
        self._codex_home = codex_home
        self._home = home
        self._tmpdir = tmpdir
        self._executor = executor
        self._verify_subject = verify_subject
        self._monotonic = monotonic
        self._timeout_seconds = float(timeout_seconds)
        self._stage_callback = stage_callback
        self._cancel_check = cancel_check

    def collect(self) -> dict[str, Any]:
        interface = verify_interface_evidence(self._interface_evidence)
        environment = {
            "CODEX_HOME": self._codex_home,
            "HOME": self._home,
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PATH,
            "TMPDIR": self._tmpdir,
        }
        started = self._monotonic()
        results: dict[str, Any] = {}
        for _ordinal, stage, _reference in _ACCOUNT_STAGES:
            if self._cancel_check is not None and self._cancel_check():
                raise EvidenceError(
                    "ACCOUNT_EVIDENCE_CANCELLED",
                    "account evidence collection was cancelled",
                )
            remaining = self._timeout_seconds - (self._monotonic() - started)
            if remaining <= 0:
                raise EvidenceError("ACCOUNT_DEADLINE_EXCEEDED", "account evidence deadline expired")
            if self._stage_callback is not None:
                self._stage_callback(stage)
            try:
                self._verify_subject(copy.deepcopy(interface["subject"]))
            except Exception as exc:
                if isinstance(exc, EvidenceError):
                    raise
                raise EvidenceError("ACCOUNT_SUBJECT_INVALID", "snapshot verification failed") from exc
            try:
                raw = self._executor.execute(
                    stage,
                    executable_path=interface["subject"]["snapshotPath"],
                    argv=ACCOUNT_ARGV,
                    environment=copy.deepcopy(environment),
                    timeout_seconds=remaining,
                    cancel_check=self._cancel_check,
                )
            except Exception as exc:
                if isinstance(exc, EvidenceError):
                    raise
                raise EvidenceError("ACCOUNT_READ_FAILED", f"{stage} failed") from exc
            if stage.startswith("requirements-"):
                results[stage] = _copy_requirements(raw)
            else:
                results[stage] = _normalize_available_pairs(raw)

        requirements_values = [
            results["requirements-a"],
            results["requirements-b"],
            results["requirements-c"],
        ]
        if len({canonical_json_bytes(value) for value in requirements_values}) != 1:
            raise EvidenceError("ACCOUNT_REQUIREMENTS_DRIFT", "three requirements reads differ")
        catalog_values = [results["catalog-a"], results["catalog-b"]]
        if len({canonical_json_bytes(value) for value in catalog_values}) != 1:
            raise EvidenceError("ACCOUNT_CATALOG_DRIFT", "two account catalogs differ")
        return build_account_evidence(
            interface_evidence=interface,
            codex_home=self._codex_home,
            home=self._home,
            tmpdir=self._tmpdir,
            requirements=requirements_values[0],
            available_pairs=catalog_values[0],
        )


def _copy_requirements(value: Any) -> Any:
    if value is not None and type(value) is not dict:
        raise EvidenceError(
            "ACCOUNT_SCHEMA_INVALID",
            "normalized requirements must be an object or null",
        )
    try:
        copied = copy.deepcopy(value)
        canonical_json_bytes(copied)
    except (CanonicalJsonError, RecursionError) as exc:
        raise EvidenceError(
            "ACCOUNT_SCHEMA_INVALID",
            "normalized requirements are outside canonical-json-v1",
        ) from exc
    return copied


def _normalize_available_pairs(
    value: Mapping[str, Sequence[str]] | Sequence[Mapping[str, str]] | Any,
) -> list[dict[str, str]]:
    pairs: list[dict[str, str]] = []
    if isinstance(value, Mapping):
        for model, raw_efforts in value.items():
            _expect_bounded_string(
                model, "model", 128, "ACCOUNT_SCHEMA_INVALID"
            )
            if isinstance(raw_efforts, (str, bytes, Mapping)):
                raise EvidenceError(
                    "ACCOUNT_SCHEMA_INVALID",
                    "reasoning efforts must be an iterable of strings",
                )
            try:
                efforts = list(raw_efforts)
            except TypeError as exc:
                raise EvidenceError(
                    "ACCOUNT_SCHEMA_INVALID",
                    "reasoning efforts must be iterable",
                ) from exc
            for effort in efforts:
                pairs.append({"model": model, "reasoningEffort": effort})
    elif type(value) is list or type(value) is tuple:
        for raw_pair in value:
            if type(raw_pair) is not dict:
                raise EvidenceError(
                    "ACCOUNT_SCHEMA_INVALID", "model pair must be an object"
                )
            _expect_exact_fields(
                raw_pair,
                required={"model", "reasoningEffort"},
                code="ACCOUNT_SCHEMA_INVALID",
            )
            pairs.append(copy.deepcopy(raw_pair))
    else:
        raise EvidenceError(
            "ACCOUNT_SCHEMA_INVALID", "account catalog must be a mapping or array"
        )
    return _validate_available_pairs(pairs, require_sorted=False)


def _validate_available_pairs(
    value: Any, *, require_sorted: bool
) -> list[dict[str, str]]:
    if type(value) is not list or len(value) > 800:
        raise EvidenceError(
            "ACCOUNT_SCHEMA_INVALID", "availablePairs must be a bounded array"
        )
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_pair in value:
        if type(raw_pair) is not dict:
            raise EvidenceError(
                "ACCOUNT_SCHEMA_INVALID", "model pair must be an object"
            )
        _expect_exact_fields(
            raw_pair,
            required={"model", "reasoningEffort"},
            code="ACCOUNT_SCHEMA_INVALID",
        )
        model = raw_pair["model"]
        effort = raw_pair["reasoningEffort"]
        _expect_bounded_string(model, "model", 128, "ACCOUNT_SCHEMA_INVALID")
        _expect_bounded_string(
            effort, "reasoningEffort", 32, "ACCOUNT_SCHEMA_INVALID"
        )
        pair = (model, effort)
        if pair in seen:
            raise EvidenceError(
                "ACCOUNT_SCHEMA_INVALID", "account catalog contains a duplicate pair"
            )
        seen.add(pair)
        normalized.append({"model": model, "reasoningEffort": effort})
    expected = sorted(
        normalized,
        key=lambda pair: (
            pair["model"].encode("utf-8"),
            pair["reasoningEffort"].encode("utf-8"),
        ),
    )
    if require_sorted and normalized != expected:
        raise EvidenceError(
            "ACCOUNT_CATALOG_ORDER_INVALID",
            "availablePairs must be in canonical UTF-8 order",
        )
    return expected


def _validate_account_environment(value: Any, codex_home: str) -> None:
    if type(value) is not dict:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "environment must be an object")
    _expect_exact_fields(
        value,
        required={"CODEX_HOME", "HOME", "LANG", "LC_ALL", "NO_COLOR", "PATH", "TMPDIR"},
        code="ACCOUNT_SCHEMA_INVALID",
    )
    if value["CODEX_HOME"] != codex_home:
        raise EvidenceError("ACCOUNT_CONTEXT_MISMATCH", "environment CODEX_HOME differs")
    for name in ("CODEX_HOME", "HOME", "TMPDIR"):
        _expect_path(value[name], name, "ACCOUNT_SCHEMA_INVALID")
    expected = {"LANG": "C", "LC_ALL": "C", "NO_COLOR": "1", "PATH": FIXED_PATH}
    for name, required in expected.items():
        if value[name] != required:
            raise EvidenceError("ACCOUNT_SCHEMA_INVALID", f"environment {name} is invalid")


def _validate_process_records(value: Any) -> None:
    if type(value) is not list or len(value) != len(_ACCOUNT_STAGES):
        raise EvidenceError(
            "ACCOUNT_SCHEMA_INVALID", "collection must contain exactly five processes"
        )
    for raw, (ordinal, stage, reference) in zip(value, _ACCOUNT_STAGES, strict=True):
        if type(raw) is not dict:
            raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "process record must be an object")
        _expect_exact_fields(
            raw,
            required={"ordinal", "stage", "resultFingerprintRef", "processFingerprint"},
            code="ACCOUNT_SCHEMA_INVALID",
        )
        if (
            raw["ordinal"] != ordinal
            or raw["stage"] != stage
            or raw["resultFingerprintRef"] != reference
        ):
            raise EvidenceError("ACCOUNT_SCHEMA_INVALID", "process stage order is invalid")
        _expect_sha256(raw["processFingerprint"], "processFingerprint", "ACCOUNT_SCHEMA_INVALID")


def _expect_rfc3339(value: Any, name: str) -> None:
    if type(value) is not str or _RFC3339.fullmatch(value) is None:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", f"{name} is not RFC 3339 date-time")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    except ValueError as exc:
        raise EvidenceError("ACCOUNT_SCHEMA_INVALID", f"{name} is not RFC 3339 date-time") from exc


def _validate_interface_subject(subject: Any) -> None:
    if type(subject) is not dict:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "subject must be an object")
    _expect_exact_fields(
        subject,
        required=_SUBJECT_FIELDS,
        code="INTERFACE_SCHEMA_INVALID",
    )
    for name in ("snapshotSha256", "sourceObservedSha256"):
        _expect_sha256(subject[name], name, "INTERFACE_SCHEMA_INVALID")
    for name in ("snapshotPath", "sourceLocator"):
        _expect_path(subject[name], name, "INTERFACE_SCHEMA_INVALID")
    for name in ("size", "uid", "device", "inode"):
        _expect_nonnegative_safe_integer(
            subject[name], name, "INTERFACE_SCHEMA_INVALID"
        )
    if (
        type(subject["mtimeNs"]) is not str
        or _DECIMAL_NANOSECONDS.fullmatch(subject["mtimeNs"]) is None
    ):
        raise EvidenceError(
            "INTERFACE_SCHEMA_INVALID",
            "mtimeNs must be an exact decimal nanosecond string",
        )
    if type(subject["mode"]) is not int or not 0 <= subject["mode"] <= 0o7777:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "mode is outside 0o7777")
    match = _CODEX_VERSION.fullmatch(subject["version"]) if type(subject["version"]) is str else None
    observed_version = None if match is None else ".".join(match.groups())
    if (
        observed_version is None
        or len(subject["version"].encode("utf-8")) > 64
        or not codex_version_supported(observed_version)
    ):
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "Codex version is unsupported")
    constants = {
        "platform": "darwin",
        "architecture": "arm64",
        "signatureIdentifier": "codex",
        "teamIdentifier": "2DC432GLL2",
    }
    for name, expected in constants.items():
        if subject[name] != expected:
            raise EvidenceError("INTERFACE_SCHEMA_INVALID", f"{name} is invalid")
    if type(subject["cdHash"]) is not str or _CDHASH.fullmatch(subject["cdHash"]) is None:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "cdHash is invalid")


def _validate_interface_semantic(semantic: Any) -> None:
    if type(semantic) is not dict:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "semantic must be an object")
    _expect_exact_fields(
        semantic,
        required=_SEMANTIC_FIELDS,
        code="INTERFACE_SCHEMA_INVALID",
    )
    constants = {
        "contractVersion": INTERFACE_CONTRACT,
        "platformAdapter": "darwin-arm64-v1",
        "arg0AdapterVersion": "arg0-v1",
    }
    for name, expected in constants.items():
        if semantic[name] != expected:
            raise EvidenceError("INTERFACE_SCHEMA_INVALID", f"semantic {name} is invalid")
    _expect_bounded_string(
        semantic["extensionRelease"], "extensionRelease", 256, "INTERFACE_SCHEMA_INVALID"
    )
    for name in ("commands", "options", "appServerMethods", "negativeProbeIds"):
        _expect_string_set(semantic[name], name)
    schemas = semantic["machineSchemas"]
    if type(schemas) is not dict or not 11 <= len(schemas) <= 32:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "machineSchemas has invalid size")
    if not _REQUIRED_MACHINE_SCHEMAS <= set(schemas):
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "required machine schema is absent")
    for name, record in schemas.items():
        _expect_bounded_string(name, "machine schema name", 256, "INTERFACE_SCHEMA_INVALID")
        if type(record) is not dict:
            raise EvidenceError("INTERFACE_SCHEMA_INVALID", "machine schema record must be an object")
        _expect_exact_fields(
            record,
            required={"schemaId", "schemaSha256"},
            code="INTERFACE_SCHEMA_INVALID",
        )
        _expect_bounded_string(record["schemaId"], "schemaId", 256, "INTERFACE_SCHEMA_INVALID")
        _expect_sha256(record["schemaSha256"], "schemaSha256", "INTERFACE_SCHEMA_INVALID")
    budgets = semantic["probeBudgets"]
    if type(budgets) is not dict or not 1 <= len(budgets) <= 32:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "probeBudgets has invalid size")
    for name, amount in budgets.items():
        _expect_bounded_string(name, "probe budget name", 256, "INTERFACE_SCHEMA_INVALID")
        _expect_nonnegative_safe_integer(amount, name, "INTERFACE_SCHEMA_INVALID")
    for name in ("routingPolicyFingerprint", "bundledCatalogFingerprint"):
        _expect_sha256(semantic[name], name, "INTERFACE_SCHEMA_INVALID")
    profiles = semantic["childProfiles"]
    if type(profiles) is not dict:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", "childProfiles must be an object")
    _expect_exact_fields(
        profiles,
        required={"classifier", "reader", "writer"},
        code="INTERFACE_SCHEMA_INVALID",
    )
    for role, fingerprint in profiles.items():
        _expect_sha256(fingerprint, role, "INTERFACE_SCHEMA_INVALID")


def _expect_string_set(value: Any, name: str) -> None:
    if type(value) is not list or len(value) > 256:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", f"{name} must be a bounded array")
    for item in value:
        _expect_bounded_string(item, name, 256, "INTERFACE_SCHEMA_INVALID")
    expected = sorted(set(value), key=lambda item: item.encode("utf-8"))
    if value != expected:
        raise EvidenceError("INTERFACE_SCHEMA_INVALID", f"{name} must be sorted and unique")


def _validate_extensions(value: Any) -> None:
    if type(value) is not dict or len(value) > 128:
        raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", "extensions must be a bounded object")
    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 128 or depth > 4:
            raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", "extensions exceed structural limits")
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str or key == "extensions":
                    raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", "nested extensions are forbidden")
                visit(child, depth + 1)
        elif type(current) is list:
            for child in current:
                visit(child, depth + 1)
        else:
            try:
                canonical_json_bytes(current)
            except CanonicalJsonError as exc:
                raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", str(exc)) from exc

    visit(value, 0)
    try:
        size = len(canonical_json_bytes(value))
    except CanonicalJsonError as exc:
        raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", str(exc)) from exc
    if size > 16 * 1024:
        raise EvidenceError("EVIDENCE_EXTENSIONS_INVALID", "extensions exceed the byte limit")


def _copy_object(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError("EVIDENCE_SCHEMA_INVALID", f"{name} must be a plain object")
    try:
        copied = copy.deepcopy(value)
        canonical_json_bytes(copied)
    except (CanonicalJsonError, RecursionError) as exc:
        raise EvidenceError("EVIDENCE_SCHEMA_INVALID", f"{name} is not canonical JSON") from exc
    return copied


def _expect_exact_fields(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    code: str,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if not required <= set(value) or not set(value) <= allowed:
        raise EvidenceError(code, "object fields do not match the closed contract")


def _expect_sha256(value: Any, name: str, code: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise EvidenceError(code, f"{name} must be a lowercase SHA-256")


def _expect_path(value: Any, name: str, code: str) -> None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or "\0" in value
        or not 1 <= len(value.encode("utf-8")) <= 4096
    ):
        raise EvidenceError(code, f"{name} must be a bounded absolute path")


def _expect_nonnegative_safe_integer(value: Any, name: str, code: str) -> None:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise EvidenceError(code, f"{name} must be a non-negative safe integer")


def _expect_bounded_string(
    value: Any, name: str, maximum: int, code: str
) -> None:
    if (
        type(value) is not str
        or not value
        or "\0" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise EvidenceError(code, f"{name} must be a bounded non-empty string")
