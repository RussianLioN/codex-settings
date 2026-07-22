"""Самодостаточная проверка договора тишины для миграции SQLite версии 2."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn

from .canonical_json import canonical_json_v1, domain_fingerprint


# Отпечаток нормативного lifecycle-projection-v2.schema.json. Узкий тест
# установленного дерева одновременно обнаруживает его дрейф в репозитории.
_LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_ZERO_WORK_COUNTS = {
    "nonterminalRoutes": 0,
    "nonterminalNodes": 0,
    "activeAttempts": 0,
    "activeLeases": 0,
    "openIntents": 0,
    "inflightLaunchPermits": 0,
    "activeRuntimeArtifacts": 0,
    "pendingCandidatePublications": 0,
    "activeEvidenceJobs": 0,
    "queuedEvidenceJobs": 0,
}
_LEGACY_PROOF_FIELDS = {
    "proofKind",
    "legacyStateHome",
    "legacyProcessSetFingerprint",
    "targetProcess",
    "armedWatchdog",
    "gatewayFenceProofFingerprint",
    "bridgeFenceProofFingerprint",
    "databaseFile",
    "databaseIdentityFingerprint",
    "databaseSnapshotFingerprint",
    "exclusiveDatabaseLeaseProofFingerprint",
    "externalBarrierProofFingerprint",
    "workCounts",
    "quiescent",
}
_FILE_FIELDS = {
    "path",
    "device",
    "inode",
    "ownerUid",
    "ownerGid",
    "mode",
    "linkCount",
    "size",
    "sha256",
}

Fail = Callable[[str, str], NoReturn]
FileProjection = Callable[..., dict[str, Any]]


def validate_quiescence_projection(
    value: Mapping[str, Any],
    *,
    state_home: Path,
    source: Path,
    fail: Fail,
    file_projection: FileProjection,
) -> dict[str, Any]:
    """Проверить закрытый вариант legacy-migration без внешних зависимостей."""

    _exact_object(
        value,
        {"schemaId", "schemaSha256", "value", "valueFingerprint"},
        "quiescence proof fields differ",
        fail,
    )
    proof = dict(value)
    if proof["schemaId"] != "quiescence-proof-v2":
        fail("INVALID_QUIESCENCE_PROOF", "projection schema id differs")
    _sha256(proof["schemaSha256"], "schemaSha256", fail)
    _sha256(proof["valueFingerprint"], "valueFingerprint", fail)
    if proof["schemaSha256"] != _LIFECYCLE_SCHEMA_SHA256:
        fail("INVALID_QUIESCENCE_PROOF", "projection schema SHA-256 differs")

    payload = proof["value"]
    _exact_object(
        payload,
        _LEGACY_PROOF_FIELDS,
        "legacy quiescence fields differ",
        fail,
    )
    if payload["proofKind"] != "legacy-migration":
        fail("INVALID_QUIESCENCE_PROOF", "proof kind differs")
    _absolute_path(payload["legacyStateHome"], "legacyStateHome", fail)
    if payload["legacyStateHome"] != os.fspath(state_home):
        fail("INVALID_QUIESCENCE_PROOF", "legacy STATE_HOME differs")

    for name in (
        "legacyProcessSetFingerprint",
        "gatewayFenceProofFingerprint",
        "bridgeFenceProofFingerprint",
        "databaseIdentityFingerprint",
        "databaseSnapshotFingerprint",
        "exclusiveDatabaseLeaseProofFingerprint",
        "externalBarrierProofFingerprint",
    ):
        _sha256(payload[name], name, fail)
    _process_identity(payload["targetProcess"], fail)
    _armed_watchdog(payload["armedWatchdog"], fail)
    _file_object(payload["databaseFile"], fail)
    _zero_work_counts(payload["workCounts"], fail)
    if payload["quiescent"] is not True:
        fail("INVALID_QUIESCENCE_PROOF", "quiescent must be true")

    expected_value_fingerprint = domain_fingerprint(
        "codex-smart/journal-state/v2",
        {name: proof[name] for name in ("schemaId", "schemaSha256", "value")},
    )
    if proof["valueFingerprint"] != expected_value_fingerprint:
        fail("INVALID_QUIESCENCE_PROOF", "projection value fingerprint differs")
    expected_file = file_projection(source, include_sha=True)
    if payload["databaseFile"] != expected_file:
        fail("INVALID_QUIESCENCE_PROOF", "legacy database file identity differs")
    canonical_json_v1(proof)
    return proof


def _process_identity(value: Any, fail: Fail) -> None:
    _exact_object(
        value,
        {"pid", "processStartMarker", "processGroupId", "ownerUid"},
        "target process fields differ",
        fail,
    )
    _bounded_integer(value["pid"], 1, 2_147_483_647, "targetProcess.pid", fail)
    _bounded_integer(
        value["processGroupId"],
        1,
        2_147_483_647,
        "targetProcess.processGroupId",
        fail,
    )
    _bounded_integer(
        value["ownerUid"], 0, _MAX_SAFE_INTEGER, "targetProcess.ownerUid", fail
    )
    marker = value["processStartMarker"]
    if type(marker) is not str or not 1 <= len(marker) <= 256:
        fail("INVALID_QUIESCENCE_PROOF", "target process marker is invalid")


def _armed_watchdog(value: Any, fail: Fail) -> None:
    _exact_object(
        value,
        {
            "watchdogId",
            "pid",
            "processStartMarker",
            "processGroupId",
            "state",
            "proofFingerprint",
        },
        "armed watchdog fields differ",
        fail,
    )
    _identifier(value["watchdogId"], "wd2_", 32, "watchdogId", fail)
    _bounded_integer(value["pid"], 1, 2_147_483_647, "watchdog.pid", fail)
    _bounded_integer(
        value["processGroupId"], 1, 2_147_483_647, "watchdog.processGroupId", fail
    )
    marker = value["processStartMarker"]
    if type(marker) is not str or not 1 <= len(marker) <= 256:
        fail("INVALID_QUIESCENCE_PROOF", "watchdog process marker is invalid")
    if value["state"] != "ARMED":
        fail("INVALID_QUIESCENCE_PROOF", "watchdog is not armed")
    _sha256(value["proofFingerprint"], "watchdog.proofFingerprint", fail)


def _file_object(value: Any, fail: Fail) -> None:
    _exact_object(value, _FILE_FIELDS, "database file fields differ", fail)
    _absolute_path(value["path"], "databaseFile.path", fail)
    for name in ("device", "inode", "ownerUid", "ownerGid", "size"):
        _bounded_integer(
            value[name], 0, _MAX_SAFE_INTEGER, f"databaseFile.{name}", fail
        )
    _bounded_integer(
        value["linkCount"],
        1,
        _MAX_SAFE_INTEGER,
        "databaseFile.linkCount",
        fail,
    )
    mode = value["mode"]
    if (
        type(mode) is not str
        or len(mode) != 4
        or mode[0] != "0"
        or any(character not in "01234567" for character in mode[1:])
    ):
        fail("INVALID_QUIESCENCE_PROOF", "databaseFile.mode is invalid")
    _sha256(value["sha256"], "databaseFile.sha256", fail)


def _zero_work_counts(value: Any, fail: Fail) -> None:
    _exact_object(value, set(_ZERO_WORK_COUNTS), "work count fields differ", fail)
    if any(type(value[name]) is not int or value[name] != 0 for name in value):
        fail("INVALID_QUIESCENCE_PROOF", "work counts are not zero")


def _exact_object(
    value: Any, fields: set[str], message: str, fail: Fail
) -> None:
    if type(value) is not dict or set(value) != fields:
        fail("INVALID_QUIESCENCE_PROOF", message)


def _absolute_path(value: Any, name: str, fail: Fail) -> None:
    if type(value) is not str or not 1 <= len(value) <= 4096 or not value.startswith("/"):
        fail("INVALID_QUIESCENCE_PROOF", f"{name} is not an absolute path")


def _bounded_integer(
    value: Any, minimum: int, maximum: int, name: str, fail: Fail
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        fail("INVALID_QUIESCENCE_PROOF", f"{name} is outside its range")


def _sha256(value: Any, name: str, fail: Fail) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail("INVALID_QUIESCENCE_PROOF", f"{name} is not lowercase SHA-256")


def _identifier(
    value: Any, prefix: str, suffix_length: int, name: str, fail: Fail
) -> None:
    if (
        type(value) is not str
        or not value.startswith(prefix)
        or len(value) != len(prefix) + suffix_length
        or any(character not in "0123456789abcdef" for character in value[len(prefix) :])
    ):
        fail("INVALID_QUIESCENCE_PROOF", f"{name} has an invalid identifier")
