"""Строгие связи заранее известных ограничений с фактическими проекциями."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .lifecycle_operation_v2 import ProjectionV2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def matches_controller_candidate_registration_v2(
    observed: ProjectionV2,
    constraint: ProjectionV2,
) -> bool:
    """Связать ``EXPECTED_REGISTRATION`` с точной готовой регистрацией."""

    if not _same_envelope(observed, constraint, "controller-candidate-v2"):
        return False
    expected = constraint.value
    actual = observed.value
    if (
        expected.get("status") != "EXPECTED_REGISTRATION"
        or actual.get("status") != "REGISTERED_READY"
    ):
        return False
    stable = (
        "candidateId",
        "controllerIdentity",
        "controllerStartId",
        "operationId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "argvFingerprint",
        "snapshotFingerprint",
        "privateReadyChannelPath",
        "readinessTokenHash",
        "readinessWindowMs",
        "processGroupPolicy",
        "workingSocketPublished",
        "acceptingNewRoutes",
        "exitProofFingerprint",
    )
    ready = actual.get("privateReadyChannel")
    return bool(
        _same_fields(expected, actual, stable)
        and _all_none(
            expected,
            (
                "privateReadyChannel",
                "pid",
                "processStartMarker",
                "processGroupId",
                "registrationFingerprint",
                "databaseLeaseProofFingerprint",
            ),
        )
        and expected.get("databaseOpened") is False
        and isinstance(ready, Mapping)
        and ready.get("path") == expected.get("privateReadyChannelPath")
        and ready.get("mode") == "0600"
        and _positive_integer(actual.get("pid"))
        and _nonempty_string(actual.get("processStartMarker"))
        and _positive_integer(actual.get("processGroupId"))
        and _sha256(actual.get("registrationFingerprint"))
        and _sha256(actual.get("databaseLeaseProofFingerprint"))
        and actual.get("databaseOpened") is True
    )


def matches_shutdown_constraint_v2(
    observed: ProjectionV2,
    constraint: ProjectionV2,
    *,
    require_orphan_proof: bool = False,
) -> bool:
    """Связать ожидаемый shutdown с commit-фактом либо полным orphan-proof."""

    if not _same_envelope(observed, constraint, "shutdown-intent-v2"):
        return False
    expected = constraint.value
    actual = observed.value
    if expected.get("status") != "EXPECTED_SHUTDOWN_PROOF":
        return False
    status = actual.get("status")
    allowed = (
        {"SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN"}
        if require_orphan_proof
        else {
            "SHUTDOWN_COMMITTED",
            "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
        }
    )
    stable = (
        "controllerAfter",
        "operationId",
        "commandId",
        "requestFingerprint",
        "commandReceiptFingerprint",
        "previousControlEpoch",
        "newControlEpoch",
        "targetPid",
        "targetStartMarker",
        "targetProcessGroupId",
        "socket",
        "lockPath",
    )
    if (
        status not in allowed
        or not _same_fields(expected, actual, stable)
        or not _all_none(
            expected,
            (
                "processExitProofFingerprint",
                "exclusiveLockProofFingerprint",
            ),
        )
    ):
        return False
    exit_proof = actual.get("processExitProofFingerprint")
    lock_proof = actual.get("exclusiveLockProofFingerprint")
    if status == "SHUTDOWN_COMMITTED":
        return exit_proof is None and lock_proof is None
    return _sha256(exit_proof) and _sha256(lock_proof)


def matches_controller_runtime_constraint_v2(
    observed: ProjectionV2,
    constraint: ProjectionV2,
) -> bool:
    """Связать ожидаемое состояние контроллера с назначенной средой процесса."""

    if not _same_envelope(observed, constraint, "controller-state-v2"):
        return False
    expected = constraint.value
    actual = observed.value
    state_pair = (expected.get("state"), actual.get("state"))
    if expected.get("state") == "EXPECTED_DRAIN_OR_MAINTENANCE":
        stable = tuple(name for name in expected if name not in {"state", "quiescent"})
        return bool(
            expected.get("quiescent") is False
            and actual.get("state") in {"DRAINING", "MAINTENANCE"}
            and actual.get("quiescent") is (actual.get("state") == "MAINTENANCE")
            and _same_fields(expected, actual, stable)
        )
    if state_pair not in {
        ("EXPECTED_MAINTENANCE", "MAINTENANCE"),
        ("EXPECTED_ACCEPTING", "ACCEPTING"),
    }:
        return False
    stable = (
        "controllerIdentity",
        "controllerStartId",
        "controlEpoch",
        "maintenanceMode",
        "operationId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "lockHeld",
        "acceptingNewRoutes",
        "quiescent",
    )
    socket = actual.get("socket")
    return bool(
        _same_fields(expected, actual, stable)
        and _all_none(
            expected,
            (
                "instanceId",
                "pid",
                "processStartMarker",
                "processGroupId",
                "socket",
            ),
        )
        and _nonempty_string(actual.get("instanceId"))
        and _positive_integer(actual.get("pid"))
        and _nonempty_string(actual.get("processStartMarker"))
        and _positive_integer(actual.get("processGroupId"))
        and isinstance(socket, Mapping)
        and socket.get("mode") == "0600"
    )


def matches_registry_constraint_v2(
    observed: ProjectionV2,
    constraint: ProjectionV2,
) -> bool:
    """Связать семантический registry intent с фактическим inode конфигурации."""

    if not _same_envelope(observed, constraint, "registry-state-v2"):
        return False
    expected = constraint.value
    actual = observed.value
    status_pairs = {
        "EXPECTED_MARKETPLACE_REGISTERED": "MARKETPLACE_REGISTERED",
        "EXPECTED_PLUGIN_ENABLED": "PLUGIN_ENABLED",
    }
    if status_pairs.get(expected.get("status")) != actual.get("status"):
        return False
    stable = (
        "marketplaceName",
        "marketplacePath",
        "marketplaceFingerprint",
        "pluginId",
        "pluginEnabled",
        "pluginFingerprint",
        "configSemanticFingerprint",
    )
    config = actual.get("configFile")
    return bool(
        _same_fields(expected, actual, stable)
        and _all_none(
            expected,
            (
                "configFile",
                "marketplaceListFingerprint",
                "pluginListFingerprint",
            ),
        )
        and isinstance(config, Mapping)
        and _nonempty_string(config.get("path"))
        and _positive_integer(config.get("device"), allow_zero=True)
        and _positive_integer(config.get("inode"))
        and config.get("mode") == "0600"
        and _sha256(config.get("sha256"))
        and _sha256(actual.get("marketplaceListFingerprint"))
        and _sha256(actual.get("pluginListFingerprint"))
    )


def _same_envelope(
    observed: Any,
    constraint: Any,
    schema_id: str,
) -> bool:
    return bool(
        isinstance(observed, ProjectionV2)
        and isinstance(constraint, ProjectionV2)
        and observed.schema_id == schema_id
        and constraint.schema_id == schema_id
        and observed.schema_sha256 == constraint.schema_sha256
    )


def _same_fields(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    names: Sequence[str],
) -> bool:
    return all(expected.get(name) == actual.get(name) for name in names)


def _all_none(value: Mapping[str, Any], names: Sequence[str]) -> bool:
    return all(value.get(name) is None for name in names)


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _positive_integer(value: Any, *, allow_zero: bool = False) -> bool:
    return type(value) is int and value >= (0 if allow_zero else 1)


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


__all__ = [
    "matches_controller_candidate_registration_v2",
    "matches_controller_runtime_constraint_v2",
    "matches_registry_constraint_v2",
    "matches_shutdown_constraint_v2",
]
