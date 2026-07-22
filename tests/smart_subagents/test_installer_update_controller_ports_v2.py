from __future__ import annotations

import copy
import os
import socket
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    CandidateSpawnActionV2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.controller_transition_rehydration_v2 import (  # noqa: E402
    ControllerTransitionRehydrationV2Error,
    RehydratedControllerCommandV2,
)
from codex_smart_subagents.installer_update_controller_ports_v2 import (  # noqa: E402
    InstallerUpdateControllerPortsV2Error,
    build_update_controller_step_ports_v2,
    observe_controller_database_v2,
    observe_runtime_quiescence_database_v2,
)
from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipStoreV2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    TransientProcessLeaseV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerCommandProofV2,
    LifecycleControllerQuiescenceV2,
    LifecycleControllerProtocolV2,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ProjectionV2,
    StepDefinitionV2,
)
from codex_smart_subagents.shutdown_socket_cleanup_v2 import (  # noqa: E402
    ShutdownSocketOrphanProofV2,
)
from codex_smart_subagents.state_store_v2 import SmartStoreV2  # noqa: E402
from tests.smart_subagents.test_state_store_v2 import (  # noqa: E402
    controller as store_controller,
    database_identity as store_database_identity,
)


OPERATION_ID = "op2_" + "1" * 32
PREVIOUS_OPERATION_ID = "op2_" + "0" * 32
ACTIVATION_ID = "act2_" + "2" * 64
ACTIVATION_FINGERPRINT = "2" * 64
DATABASE_ID = "db2_" + "3" * 32
CONTROLLER_IDENTITY = "4" * 64
INSTANCE_ID = "ci2_" + "5" * 32
CONTROLLER_START_ID = "cs2_" + "6" * 32
SCHEMA_SHA256 = "7" * 64
SOCKET_VALUE = {
    "path": "/tmp/codex-smart-controller.sock",
    "device": 11,
    "inode": 12,
    "ownerUid": os.getuid(),
    "ownerGid": os.getgid(),
    "mode": "0600",
}
CANDIDATE_WORKING_SOCKET = {
    **SOCKET_VALUE,
    "path": "/tmp/candidate-controller.sock",
}
CANDIDATE_ARGV = [
    "/private/runtime/python3",
    "/private/activation/controller/server.py",
    "--serve-candidate-v2",
]
CANDIDATE_ARGV_FINGERPRINT = domain_fingerprint(
    "codex-smart/controller-candidate-argv/v2",
    {"argv": CANDIDATE_ARGV},
)
_SOCKET_UNSET = object()
SHUTDOWN_CLEANUP_PLAN_FINGERPRINT = "f" * 64


def _orphan_proof(
    *,
    plan_fingerprint: str = SHUTDOWN_CLEANUP_PLAN_FINGERPRINT,
    shutdown_proof_fingerprint: str = "1" * 64,
) -> ShutdownSocketOrphanProofV2:
    unsigned = {
        "planFingerprint": plan_fingerprint,
        "shutdownProofFingerprint": shutdown_proof_fingerprint,
        "processExitProofFingerprint": "d" * 64,
        "exclusiveLockProofFingerprint": "e" * 64,
    }
    return ShutdownSocketOrphanProofV2(
        plan_fingerprint=plan_fingerprint,
        shutdown_proof_fingerprint=shutdown_proof_fingerprint,
        process_exit_proof_fingerprint="d" * 64,
        exclusive_lock_proof_fingerprint="e" * 64,
        proof_fingerprint=domain_fingerprint(
            "codex-smart/shutdown-socket-orphan-proof/v2",
            unsigned,
        ),
    )


def _projection(schema_id: str, value: dict[str, object]) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": SCHEMA_SHA256,
        "value": copy.deepcopy(value),
    }
    domains = {
        "controller-state-v2": "codex-smart/controller-state/v2",
        "controller-candidate-v2": "codex-smart/controller-candidate/v2",
        "quiescence-proof-v2": "codex-smart/quiescence-proof/v2",
        "shutdown-intent-v2": "codex-smart/shutdown-intent/v2",
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=SCHEMA_SHA256,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(domains[schema_id], envelope),
    )


def _controller(
    *,
    epoch: int,
    state: str,
    mode: str | None,
    operation_id: str | None,
    accepting: bool,
    quiescent: bool,
    instance_id: str | None = INSTANCE_ID,
    pid: int | None = 4100,
    marker: str | None = "darwin:100:1",
    process_group_id: int | None = 4100,
    socket_value: dict[str, object] | None | object = _SOCKET_UNSET,
) -> ProjectionV2:
    if socket_value is _SOCKET_UNSET and instance_id is not None:
        socket_value = SOCKET_VALUE
    return _projection(
        "controller-state-v2",
        {
            "controllerIdentity": CONTROLLER_IDENTITY,
            "instanceId": instance_id,
            "controllerStartId": CONTROLLER_START_ID,
            "pid": pid,
            "processStartMarker": marker,
            "processGroupId": process_group_id,
            "controlEpoch": epoch,
            "state": state,
            "maintenanceMode": mode,
            "operationId": operation_id,
            "activationId": ACTIVATION_ID,
            "activationFingerprint": ACTIVATION_FINGERPRINT,
            "databaseId": DATABASE_ID,
            "socket": copy.deepcopy(socket_value),
            "lockHeld": state != "STOPPED",
            "acceptingNewRoutes": accepting,
            "quiescent": quiescent,
        },
    )


def _candidate(*, expected: bool) -> ProjectionV2:
    value = {
        "candidateId": "cand2_" + "8" * 32,
        "controllerIdentity": CONTROLLER_IDENTITY,
        "controllerStartId": CONTROLLER_START_ID,
        "operationId": OPERATION_ID,
        "activationId": ACTIVATION_ID,
        "activationFingerprint": ACTIVATION_FINGERPRINT,
        "databaseId": DATABASE_ID,
        "argvFingerprint": CANDIDATE_ARGV_FINGERPRINT,
        "snapshotFingerprint": "a" * 64,
        "privateReadyChannelPath": "/tmp/codex-smart-candidate.ready.sock",
        "privateReadyChannel": (
            None
            if expected
            else {
                "path": "/tmp/codex-smart-candidate.ready.sock",
                "device": 21,
                "inode": 22,
                "ownerUid": os.getuid(),
                "ownerGid": os.getgid(),
                "mode": "0600",
            }
        ),
        "readinessTokenHash": "b" * 64,
        "readinessWindowMs": 30_000,
        "processGroupPolicy": "NEW_PRIVATE_GROUP",
        "pid": None if expected else 4200,
        "processStartMarker": None if expected else "darwin:101:1",
        "processGroupId": None if expected else 4200,
        "registrationFingerprint": None if expected else "c" * 64,
        "databaseLeaseProofFingerprint": None if expected else "d" * 64,
        "databaseOpened": not expected,
        "workingSocketPublished": False,
        "acceptingNewRoutes": False,
        "status": "EXPECTED_REGISTRATION" if expected else "REGISTERED_READY",
        "exitProofFingerprint": None,
    }
    return _projection("controller-candidate-v2", value)


def _quiescence(epoch: int) -> ProjectionV2:
    counts = {
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
    return _projection(
        "quiescence-proof-v2",
        {
            "proofKind": "runtime-v2",
            "controllerIdentity": CONTROLLER_IDENTITY,
            "instanceId": INSTANCE_ID,
            "controlEpoch": epoch,
            "workCounts": counts,
            "databasePredicatesFingerprint": "e" * 64,
            "barrierHeld": True,
            "quiescent": True,
        },
    )


def _step(
    kind: str,
    *,
    before: ProjectionV2,
    expected_after: ProjectionV2,
    epoch: int | None = None,
    command_token: str | None = None,
) -> StepDefinitionV2:
    if kind == "wait_runtime_quiescent":
        action = {
            "actionKind": "verify",
            "predicate": "runtime-quiescent",
            "timeoutMs": 2500,
        }
        command_id = None
    else:
        methods = {
            "maintenance_begin": "maintenance_begin",
            "maintenance_strengthen": "maintenance_strengthen",
            "controller_shutdown": "shutdown",
            "controller_accept": "controller_accept",
            "maintenance_resume": "maintenance_resume",
        }
        action = {
            "actionKind": "controller-command",
            "method": methods[kind],
            "operationId": OPERATION_ID,
            "expectedControlEpoch": epoch,
        }
        command_id = "cc2_" + str(command_token) * 32
    return StepDefinitionV2(
        kind=kind,
        command_id=command_id,
        action=action,
        before=before,
        expected_after=expected_after,
    )


def _proof(
    *, method: str, status: str, command_id: str, epoch: int
) -> LifecycleControllerCommandProofV2:
    request_fingerprint = domain_fingerprint(
        "test/request", {"method": method, "commandId": command_id}
    )
    result_fingerprint = domain_fingerprint(
        "test/result", {"method": method, "commandId": command_id}
    )
    payload: dict[str, object] = {
        "status": status,
        "previousControlEpoch": epoch,
        "newControlEpoch": epoch + 1,
        "commandReceipt": {
            "commandId": command_id,
            "requestFingerprint": request_fingerprint,
            "resultFingerprint": result_fingerprint,
            "controlEpoch": epoch + 1,
        },
    }
    if method == "controller_accept":
        payload.update(
            {
                "controllerIdentity": CONTROLLER_IDENTITY,
                "instanceId": INSTANCE_ID,
                "controllerStartId": CONTROLLER_START_ID,
            }
        )
    if method == "shutdown":
        payload["socketIntent"] = {
            "path": SOCKET_VALUE["path"],
            "device": SOCKET_VALUE["device"],
            "inode": SOCKET_VALUE["inode"],
            "ownerUid": SOCKET_VALUE["ownerUid"],
            "ownerGid": SOCKET_VALUE["ownerGid"],
            "mode": SOCKET_VALUE["mode"],
            "controllerPid": 4100,
            "controllerStartMarker": "darwin:100:1",
            "controllerProcessGroupId": 4100,
            "lockPath": "/tmp/controller.lock",
            "processExitRequired": True,
            "exclusiveLockRequired": True,
        }
    return LifecycleControllerCommandProofV2(
        method=method,
        status=status,
        command_id=command_id,
        request_fingerprint=request_fingerprint,
        response_fingerprint=domain_fingerprint(
            "test/response", {"method": method, "commandId": command_id}
        ),
        previous_control_epoch=epoch,
        new_control_epoch=epoch + 1,
        payload=payload,
    )


class _FakeClient:
    def __init__(self, owner: "InstallerUpdateControllerPortsV2Tests", arguments):
        self.owner = owner
        self.arguments = arguments

    def _commit(self, method: str, status: str):
        command_id = self.arguments["command_ids"][(OPERATION_ID, method)]
        proof = _proof(
            method=method,
            status=status,
            command_id=command_id,
            epoch=self.arguments["control_epoch"],
        )
        self.owner.receipts[(self.arguments["database_path"], method)] = proof
        return proof

    def maintenance_begin(self, *, operation_id: str, reason_code: str):
        self.owner.calls.append(("maintenance_begin", operation_id, reason_code))
        self.owner.states[self.arguments["database_path"]] = self.owner.begin_after
        return self._commit("maintenance_begin", "MAINTENANCE_BEGUN")

    def wait_quiescent(self, *, operation_id: str, timeout_seconds: float):
        self.owner.calls.append(("wait_quiescent", operation_id, timeout_seconds))
        self.owner.quiescence_ready = True
        self.owner.states[self.arguments["database_path"]] = (
            self.owner.drain_quiescent_controller
        )
        return LifecycleControllerQuiescenceV2(
            operation_id=operation_id,
            state="MAINTENANCE",
            maintenance_mode="drain",
            control_epoch=self.arguments["control_epoch"],
            quiescent=True,
        )

    def maintenance_strengthen(self, *, operation_id: str):
        self.owner.calls.append(("maintenance_strengthen", operation_id))
        self.owner.states[self.arguments["database_path"]] = self.owner.strengthen_after
        return self._commit("maintenance_strengthen", "MAINTENANCE_STRENGTHENED")

    def shutdown(self, *, operation_id: str):
        self.owner.calls.append(("shutdown", operation_id))
        self.owner.shutdown_done = True
        return self._commit("shutdown", "SHUTDOWN_COMMITTED")

    def candidate_accept(self, **arguments):
        self.owner.calls.append(("controller_accept", arguments))
        self.owner.states[self.arguments["database_path"]] = self.owner.accept_after
        return self._commit("controller_accept", "CONTROLLER_ACCEPTED")

    def maintenance_resume(self, *, operation_id: str):
        self.owner.calls.append(("maintenance_resume", operation_id))
        self.owner.states[self.arguments["database_path"]] = self.owner.resume_after
        return self._commit("maintenance_resume", "MAINTENANCE_RESUMED")


class InstallerUpdateControllerPortsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csucp2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.current_database = self.root / "current.sqlite3"
        self.candidate_database = self.root / "candidate.sqlite3"
        self.current_database.write_bytes(b"current")
        self.candidate_database.write_bytes(b"candidate")
        self.current_database.chmod(0o600)
        self.candidate_database.chmod(0o600)

        self.accepting = _controller(
            epoch=7,
            state="ACCEPTING",
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
        )
        self.begin_after = _controller(
            epoch=8,
            state="DRAINING",
            mode="drain",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=False,
        )
        self.begin_constraint = _controller(
            epoch=8,
            state="EXPECTED_DRAIN_OR_MAINTENANCE",
            mode="drain",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=False,
        )
        self.quiescent = _quiescence(8)
        self.drain_quiescent_controller = _controller(
            epoch=8,
            state="MAINTENANCE",
            mode="drain",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=True,
        )
        self.strengthen_after = _controller(
            epoch=9,
            state="MAINTENANCE",
            mode="freeze",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=True,
        )
        self.candidate_expected = _candidate(expected=True)
        self.candidate_actual = _candidate(expected=False)
        self.accept_expected = _controller(
            epoch=2,
            state="EXPECTED_MAINTENANCE",
            mode="freeze",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=True,
            instance_id=None,
            pid=None,
            marker=None,
            process_group_id=None,
            socket_value=None,
        )
        self.accept_after = _controller(
            epoch=2,
            state="MAINTENANCE",
            mode="freeze",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=True,
            pid=4200,
            marker="darwin:101:1",
            process_group_id=4200,
            socket_value=CANDIDATE_WORKING_SOCKET,
        )
        self.resume_expected = _controller(
            epoch=3,
            state="EXPECTED_ACCEPTING",
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
            instance_id=None,
            pid=None,
            marker=None,
            process_group_id=None,
            socket_value=None,
        )
        self.resume_after = _controller(
            epoch=3,
            state="ACCEPTING",
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
            pid=4200,
            marker="darwin:101:1",
            process_group_id=4200,
            socket_value=CANDIDATE_WORKING_SOCKET,
        )
        self.shutdown_expected = self._shutdown_projection(actual=False)
        self.shutdown_after = self._shutdown_projection(actual=True)

        self.definitions = {
            "maintenance_begin": _step(
                "maintenance_begin",
                before=self.accepting,
                expected_after=self.begin_constraint,
                epoch=7,
                command_token="1",
            ),
            "wait_runtime_quiescent": _step(
                "wait_runtime_quiescent",
                before=self.begin_constraint,
                expected_after=self.quiescent,
            ),
            "maintenance_strengthen": _step(
                "maintenance_strengthen",
                before=self.drain_quiescent_controller,
                expected_after=self.strengthen_after,
                epoch=8,
                command_token="2",
            ),
            "controller_shutdown": _step(
                "controller_shutdown",
                before=self.strengthen_after,
                expected_after=self.shutdown_expected,
                epoch=9,
                command_token="3",
            ),
            "controller_accept": _step(
                "controller_accept",
                before=self.candidate_expected,
                expected_after=self.accept_expected,
                epoch=1,
                command_token="4",
            ),
            "maintenance_resume": _step(
                "maintenance_resume",
                before=self.accept_expected,
                expected_after=self.resume_expected,
                epoch=2,
                command_token="5",
            ),
        }
        self.candidate_spawn_action = {
            "actionKind": "controller-candidate-spawn",
            "argv": list(CANDIDATE_ARGV),
            **{
                name: self.candidate_expected.value[name]
                for name in (
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
                )
            },
        }
        self.states = {
            self.current_database: self.accepting,
            self.candidate_database: self.accept_after,
        }
        self.receipts: dict[tuple[Path, str], LifecycleControllerCommandProofV2] = {}
        self.calls: list[tuple[object, ...]] = []
        self.client_arguments: list[dict[str, object]] = []
        self.quiescence_ready = False
        self.shutdown_done = False

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _shutdown_projection(self, *, actual: bool) -> ProjectionV2:
        command_id = "cc2_" + "3" * 32
        proof = _proof(
            method="shutdown",
            status="SHUTDOWN_COMMITTED",
            command_id=command_id,
            epoch=9,
        )
        value = {
            "controllerAfter": _controller(
                epoch=10,
                state="STOPPED",
                mode=None,
                operation_id=None,
                accepting=False,
                quiescent=True,
                socket_value=None,
            ).value,
            "operationId": OPERATION_ID,
            "commandId": command_id,
            "requestFingerprint": proof.request_fingerprint,
            "commandReceiptFingerprint": proof.payload["commandReceipt"][
                "resultFingerprint"
            ],
            "previousControlEpoch": 9,
            "newControlEpoch": 10,
            "targetPid": 4100,
            "targetStartMarker": "darwin:100:1",
            "targetProcessGroupId": 4100,
            "socket": SOCKET_VALUE,
            "lockPath": "/tmp/controller.lock",
            "processExitProofFingerprint": "d" * 64 if actual else None,
            "exclusiveLockProofFingerprint": "e" * 64 if actual else None,
            "status": (
                "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN"
                if actual
                else "EXPECTED_SHUTDOWN_PROOF"
            ),
        }
        return _projection("shutdown-intent-v2", value)

    def _command_loader(self, *, database_path, operation_id, command_id, method):
        del operation_id
        proof = self.receipts.get((database_path, method))
        if proof is None:
            raise ControllerTransitionRehydrationV2Error(
                "REHYDRATION_RECEIPT_MISSING", "квитанции ещё нет"
            )
        request = {
            "operationId": OPERATION_ID,
            "commandId": command_id,
            "method": method,
            "controllerIdentity": CONTROLLER_IDENTITY,
            "instanceId": None if method == "controller_accept" else INSTANCE_ID,
            "controllerStartId": CONTROLLER_START_ID,
            "expectedControlEpoch": proof.previous_control_epoch,
            "params": (
                {"reasonCode": "UPGRADE"}
                if method == "maintenance_begin"
                else {"mode": "freeze"}
                if method == "maintenance_strengthen"
                else {
                    "activationId": ACTIVATION_ID,
                    "databaseId": DATABASE_ID,
                    "pid": 4200,
                    "processStartMarker": "darwin:101:1",
                    "processGroupId": 4200,
                    "expectedOrphanOperationId": None,
                }
                if method == "controller_accept"
                else {}
            ),
        }
        return RehydratedControllerCommandV2(
            row={}, request=request, response={}, proof=proof
        )

    def _client_factory(self, **arguments):
        self.client_arguments.append(arguments)
        methods = {method for _operation_id, method in arguments["command_ids"]}
        arguments["database_path"] = (
            self.candidate_database
            if methods.intersection({"controller_accept", "maintenance_resume"})
            else self.current_database
        )
        return _FakeClient(self, arguments)

    def _candidate_reconnect(self, **_arguments):
        return SimpleNamespace(
            registration=copy.deepcopy(dict(self.candidate_actual.value)),
            working_controller_socket=copy.deepcopy(CANDIDATE_WORKING_SOCKET),
        )

    def _ports(
        self,
        *,
        maintenance_reason_code="UPGRADE",
        expected_orphan_operation_id=None,
        shutdown_cleanup_plan_fingerprint=SHUTDOWN_CLEANUP_PLAN_FINGERPRINT,
        shutdown_orphan_prover=None,
    ):
        orphan_prover = shutdown_orphan_prover or (
            lambda _shutdown: _orphan_proof(
                plan_fingerprint=shutdown_cleanup_plan_fingerprint,
            )
        )
        return build_update_controller_step_ports_v2(
            operation_id=OPERATION_ID,
            activation_proof_fingerprint="a" * 64,
            shutdown_cleanup_plan_fingerprint=(
                shutdown_cleanup_plan_fingerprint
            ),
            codex_home=self.codex_home,
            current_database_path=self.current_database,
            candidate_database_path=self.candidate_database,
            definitions=self.definitions,
            candidate_spawn_action=self.candidate_spawn_action,
            maintenance_reason_code=maintenance_reason_code,
            expected_orphan_operation_id=expected_orphan_operation_id,
            client_factory=self._client_factory,
            command_rehydrator=self._command_loader,
            controller_observer=lambda path: self.states[path],
            quiescence_observer=lambda _path, _operation_id: (
                self.quiescent if self.quiescence_ready else None
            ),
            candidate_reconnect=self._candidate_reconnect,
            dispatch_intent_loader=lambda **_arguments: SimpleNamespace(),
            shutdown_orphan_prover=orphan_prover,
            shutdown_rehydrator=lambda **_arguments: (
                SimpleNamespace(
                    complete=True,
                    operation_id=OPERATION_ID,
                    activation_proof_fingerprint="a" * 64,
                    shutdown=_proof(
                        method="shutdown",
                        status="SHUTDOWN_COMMITTED",
                        command_id="cc2_" + "3" * 32,
                        epoch=9,
                    ),
                    proof_fingerprint="1" * 64,
                )
                if self.shutdown_done
                or (self.candidate_database, "controller_accept") in self.receipts
                else (_ for _ in ()).throw(
                    ControllerTransitionRehydrationV2Error(
                        "REHYDRATION_RECEIPT_MISSING", "ещё нет"
                    )
                )
            ),
            acceptance_rehydrator=lambda **_arguments: (
                SimpleNamespace(
                    complete=True,
                    candidate_accept=self.receipts[
                        (self.candidate_database, "controller_accept")
                    ],
                )
                if (self.candidate_database, "controller_accept") in self.receipts
                else (_ for _ in ()).throw(
                    ControllerTransitionRehydrationV2Error(
                        "REHYDRATION_RECEIPT_MISSING", "ещё нет"
                    )
                )
            ),
        )

    def _publish_candidate_ownership(
        self,
        *,
        marker: str = "darwin:101:1",
    ) -> DurableProcessOwnershipStoreV2:
        action = CandidateSpawnActionV2.from_mapping(self.candidate_spawn_action)
        lease = TransientProcessLeaseV2(
            lease_id="transient-" + "a" * 32,
            label="candidate-controller",
            pid=4200,
            process_group_id=4200,
            session_id=4200,
            process_start_marker=marker,
            process=object(),
        )
        store = DurableProcessOwnershipStoreV2(self.codex_home)
        store.publish(
            lease,
            {
                "schemaVersion": 2,
                "contextKind": "candidate-dispatch-v2",
                "operationId": action.operation_id,
                "candidateId": action.candidate_id,
                "controllerStartId": action.controller_start_id,
                "actionFingerprint": action.action_fingerprint,
                "dispatchReceiptFingerprint": "d" * 64,
            },
        )
        return store

    def test_command_port_uses_durable_id_and_rehydrates_factual_after(self) -> None:
        port = self._ports()["maintenance_begin"]
        definition = self.definitions["maintenance_begin"]

        self.assertTrue(port.matches_before(port.observe(definition), definition))
        port.apply(definition)
        observed = port.observe(definition)

        self.assertTrue(port.matches_after(observed, definition))
        self.assertEqual(self.begin_after.value, observed.value)
        self.assertEqual(
            "EXPECTED_DRAIN_OR_MAINTENANCE",
            definition.expected_after.value["state"],
        )
        self.assertEqual(
            {
                (OPERATION_ID, "maintenance_begin"): definition.command_id,
            },
            self.client_arguments[0]["command_ids"],
        )
        self.assertEqual([("maintenance_begin", OPERATION_ID, "UPGRADE")], self.calls)

    def test_maintenance_begin_accepts_quiescent_race_result_bound_to_receipt(
        self,
    ) -> None:
        self.begin_after = self.drain_quiescent_controller
        port = self._ports()["maintenance_begin"]
        definition = self.definitions["maintenance_begin"]

        port.apply(definition)
        observed = port.observe(definition)

        self.assertEqual("MAINTENANCE", observed.value["state"])
        self.assertTrue(observed.value["quiescent"])
        self.assertTrue(port.matches_after(observed, definition))
        self.assertEqual(
            definition.command_id,
            self.receipts[(self.current_database, "maintenance_begin")].command_id,
        )

    def test_rollback_reason_is_sent_to_maintenance_begin(self) -> None:
        port = self._ports(
            maintenance_reason_code="ROLLBACK",
            expected_orphan_operation_id=PREVIOUS_OPERATION_ID,
        )["maintenance_begin"]

        port.apply(self.definitions["maintenance_begin"])

        self.assertEqual(
            [("maintenance_begin", OPERATION_ID, "ROLLBACK")],
            self.calls,
        )

    def test_upgrade_rejects_orphan_operation_rebinding(self) -> None:
        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            self._ports(
                maintenance_reason_code="UPGRADE",
                expected_orphan_operation_id=PREVIOUS_OPERATION_ID,
            )

        self.assertEqual(
            "CONTROLLER_ORPHAN_REBIND_POLICY_INVALID",
            caught.exception.code,
        )
        self.assertEqual([], self.calls)

    def test_rollback_requires_expected_orphan_operation(self) -> None:
        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            self._ports(maintenance_reason_code="ROLLBACK")

        self.assertEqual(
            "CONTROLLER_ORPHAN_REBIND_POLICY_INVALID",
            caught.exception.code,
        )
        self.assertEqual([], self.calls)

    def test_unknown_maintenance_reason_is_rejected_before_effects(self) -> None:
        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            self._ports(maintenance_reason_code="UNKNOWN")

        self.assertEqual("MAINTENANCE_REASON_CODE_INVALID", caught.exception.code)
        self.assertEqual([], self.calls)

    def test_wait_quiescent_returns_fact_not_constraint_and_uses_timeout(self) -> None:
        self.states[self.current_database] = self.begin_after
        port = self._ports()["wait_runtime_quiescent"]
        definition = self.definitions["wait_runtime_quiescent"]

        self.assertTrue(port.matches_before(port.observe(definition), definition))
        port.apply(definition)
        observed = port.observe(definition)

        self.assertEqual("quiescence-proof-v2", observed.schema_id)
        self.assertTrue(port.matches_after(observed, definition))
        self.assertIn(("wait_quiescent", OPERATION_ID, 2.5), self.calls)

    def test_wait_quiescent_accepts_a_proof_racing_maintenance_begin(self) -> None:
        self.states[self.current_database] = self.drain_quiescent_controller
        self.quiescence_ready = True
        port = self._ports()["wait_runtime_quiescent"]
        definition = self.definitions["wait_runtime_quiescent"]

        observed = port.observe(definition)

        self.assertEqual("quiescence-proof-v2", observed.schema_id)
        self.assertTrue(port.matches_before(observed, definition))
        self.assertTrue(port.matches_after(observed, definition))
        self.assertTrue(
            port.replay_safe_when_indistinguishable(observed, definition)
        )
        port.apply(definition)
        self.assertIn(("wait_quiescent", OPERATION_ID, 2.5), self.calls)

    def test_accept_and_resume_match_constraints_to_factual_controller(self) -> None:
        ports = self._ports()
        accept = self.definitions["controller_accept"]

        self.assertTrue(
            ports["controller_accept"].matches_before(
                ports["controller_accept"].observe(accept), accept
            )
        )
        ports["controller_accept"].apply(accept)
        accepted = ports["controller_accept"].observe(accept)

        self.assertEqual("MAINTENANCE", accepted.value["state"])
        self.assertTrue(ports["controller_accept"].matches_after(accepted, accept))
        self.assertNotEqual(accept.expected_after, accepted)
        accept_call = next(
            call for call in self.calls if call[0] == "controller_accept"
        )
        self.assertEqual(4200, accept_call[1]["pid"])
        self.assertEqual("darwin:101:1", accept_call[1]["process_start_marker"])

        resume = self.definitions["maintenance_resume"]
        ports["maintenance_resume"].apply(resume)
        resumed = ports["maintenance_resume"].observe(resume)

        self.assertEqual("ACCEPTING", resumed.value["state"])
        self.assertTrue(ports["maintenance_resume"].matches_after(resumed, resume))
        changed = ProjectionV2(
            schema_id=resumed.schema_id,
            schema_sha256=resumed.schema_sha256,
            value={**resumed.value, "databaseId": "db2_" + "f" * 32},
            value_fingerprint=resumed.value_fingerprint,
        )
        self.assertFalse(ports["maintenance_resume"].matches_after(changed, resume))

    def test_accept_proof_clears_exact_durable_candidate_ownership(self) -> None:
        store = self._publish_candidate_ownership()
        port = self._ports()["controller_accept"]
        definition = self.definitions["controller_accept"]

        port.apply(definition)

        self.assertEqual((), store.load_all())

    def test_rehydrated_accept_after_parent_crash_clears_without_signal(self) -> None:
        port = self._ports()["controller_accept"]
        definition = self.definitions["controller_accept"]
        port.apply(definition)
        store = self._publish_candidate_ownership()

        observed = port.observe(definition)

        self.assertEqual(self.accept_after, observed)
        self.assertEqual((), store.load_all())

    def test_rehydrated_accept_preserves_mismatched_durable_identity(self) -> None:
        port = self._ports()["controller_accept"]
        definition = self.definitions["controller_accept"]
        port.apply(definition)
        store = self._publish_candidate_ownership(marker="other-start-marker")

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as raised:
            port.observe(definition)

        self.assertEqual("DURABLE_OWNERSHIP_BINDING_MISMATCH", raised.exception.code)
        self.assertEqual(1, len(store.load_all()))

    def test_resume_rehydrates_actual_candidate_before_building_client(self) -> None:
        ports = self._ports()
        ports["controller_accept"].apply(self.definitions["controller_accept"])
        self.calls.clear()
        self.client_arguments.clear()
        resume = self.definitions["maintenance_resume"]
        port = ports["maintenance_resume"]

        observed = port.observe(resume)

        self.assertEqual("EXPECTED_MAINTENANCE", resume.before.value["state"])
        self.assertIsNone(resume.before.value["instanceId"])
        self.assertEqual(self.accept_after, observed)
        self.assertTrue(port.matches_before(observed, resume))

        port.apply(resume)

        self.assertEqual([("maintenance_resume", OPERATION_ID)], self.calls)
        self.assertEqual(1, len(self.client_arguments))
        arguments = self.client_arguments[0]
        self.assertEqual(
            Path(CANDIDATE_WORKING_SOCKET["path"]), arguments["socket_path"]
        )
        self.assertEqual(INSTANCE_ID, arguments["instance_id"])
        self.assertEqual(CONTROLLER_START_ID, arguments["controller_start_id"])
        self.assertEqual(2, arguments["control_epoch"])

    def test_only_resume_relaxes_before_to_a_controller_constraint(self) -> None:
        ports = self._ports()
        begin = self.definitions["maintenance_begin"]
        changed_begin = _controller(
            epoch=7,
            state="ACCEPTING",
            mode=None,
            operation_id=None,
            accepting=True,
            quiescent=False,
            pid=4999,
            marker="darwin:199:1",
            process_group_id=4999,
        )

        self.assertFalse(
            ports["maintenance_begin"].matches_before(changed_begin, begin)
        )
        resume = self.definitions["maintenance_resume"]
        self.assertTrue(
            ports["maintenance_resume"].matches_before(self.accept_after, resume)
        )

    def test_resume_rejects_actual_that_violates_durable_constraint_before_client(
        self,
    ) -> None:
        ports = self._ports()
        ports["controller_accept"].apply(self.definitions["controller_accept"])
        self.calls.clear()
        self.client_arguments.clear()
        self.states[self.candidate_database] = _projection(
            "controller-state-v2",
            {
                **self.accept_after.value,
                "databaseId": "db2_" + "f" * 32,
            },
        )

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            ports["maintenance_resume"].apply(self.definitions["maintenance_resume"])

        self.assertEqual("CONTROLLER_COMMAND_STATE_MISMATCH", caught.exception.code)
        self.assertEqual([], self.client_arguments)
        self.assertEqual([], self.calls)

    def test_resume_rejects_actual_not_bound_to_durable_accept_receipt(self) -> None:
        ports = self._ports()
        ports["controller_accept"].apply(self.definitions["controller_accept"])
        self.calls.clear()
        self.client_arguments.clear()
        self.states[self.candidate_database] = _controller(
            epoch=2,
            state="MAINTENANCE",
            mode="freeze",
            operation_id=OPERATION_ID,
            accepting=False,
            quiescent=True,
            instance_id="ci2_" + "f" * 32,
            pid=4200,
            marker="darwin:101:1",
            process_group_id=4200,
            socket_value=CANDIDATE_WORKING_SOCKET,
        )

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            ports["maintenance_resume"].apply(self.definitions["maintenance_resume"])

        self.assertEqual("CONTROLLER_COMMAND_STATE_MISMATCH", caught.exception.code)
        self.assertEqual([], self.client_arguments)
        self.assertEqual([], self.calls)

    def test_accept_rejects_ready_socket_bound_to_another_path(self) -> None:
        changed = copy.deepcopy(dict(self.candidate_actual.value))
        changed["privateReadyChannel"] = {
            **changed["privateReadyChannel"],
            "path": "/tmp/foreign-candidate.ready.sock",
        }
        self.candidate_actual = _projection("controller-candidate-v2", changed)
        port = self._ports()["controller_accept"]

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.observe(self.definitions["controller_accept"])

        self.assertEqual("CANDIDATE_RECONNECT_INVALID", caught.exception.code)

    def test_shutdown_rehydrates_chain_with_exit_and_lock_proofs(
        self,
    ) -> None:
        self.states[self.current_database] = self.strengthen_after
        port = self._ports()["controller_shutdown"]
        definition = self.definitions["controller_shutdown"]

        self.assertTrue(port.matches_before(port.observe(definition), definition))
        port.apply(definition)
        observed = port.observe(definition)

        self.assertEqual(
            "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
            observed.value["status"],
        )
        self.assertEqual(
            "d" * 64,
            observed.value["processExitProofFingerprint"],
        )
        self.assertEqual(
            "e" * 64,
            observed.value["exclusiveLockProofFingerprint"],
        )
        self.assertTrue(port.matches_after(observed, definition))
        self.assertNotEqual(definition.expected_after.value, observed.value)

    def test_shutdown_rejects_orphan_proof_from_another_cleanup_plan(self) -> None:
        self.states[self.current_database] = self.strengthen_after
        port = self._ports(
            shutdown_orphan_prover=lambda _shutdown: _orphan_proof(
                plan_fingerprint="0" * 64,
            )
        )["controller_shutdown"]
        definition = self.definitions["controller_shutdown"]
        port.apply(definition)

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.observe(definition)

        self.assertEqual(
            "CONTROLLER_SHUTDOWN_ORPHAN_PROOF_INVALID",
            caught.exception.code,
        )

    def test_shutdown_rejects_orphan_proof_from_another_shutdown_chain(
        self,
    ) -> None:
        self.states[self.current_database] = self.strengthen_after
        port = self._ports(
            shutdown_orphan_prover=lambda _shutdown: _orphan_proof(
                shutdown_proof_fingerprint="0" * 64,
            )
        )["controller_shutdown"]
        definition = self.definitions["controller_shutdown"]
        port.apply(definition)

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.observe(definition)

        self.assertEqual(
            "CONTROLLER_SHUTDOWN_ORPHAN_PROOF_INVALID",
            caught.exception.code,
        )

    def test_shutdown_rejects_an_untyped_orphan_proof(self) -> None:
        self.states[self.current_database] = self.strengthen_after
        port = self._ports(
            shutdown_orphan_prover=lambda _shutdown: SimpleNamespace(
                complete=True,
                plan_fingerprint=SHUTDOWN_CLEANUP_PLAN_FINGERPRINT,
                shutdown_proof_fingerprint="1" * 64,
                process_exit_proof_fingerprint="d" * 64,
                exclusive_lock_proof_fingerprint="e" * 64,
            )
        )["controller_shutdown"]
        definition = self.definitions["controller_shutdown"]
        port.apply(definition)

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.observe(definition)

        self.assertEqual(
            "CONTROLLER_SHUTDOWN_ORPHAN_PROOF_INVALID",
            caught.exception.code,
        )

    def test_builder_rejects_invalid_shutdown_cleanup_plan_fingerprint(
        self,
    ) -> None:
        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            self._ports(shutdown_cleanup_plan_fingerprint="not-a-sha256")

        self.assertEqual(
            "SHUTDOWN_CLEANUP_PLAN_FINGERPRINT_INVALID",
            caught.exception.code,
        )

    def test_all_completed_ports_rehydrate_immediate_after_resume(self) -> None:
        ports = self._ports()
        immediate: dict[str, ProjectionV2] = {}

        for kind in (
            "maintenance_begin",
            "wait_runtime_quiescent",
            "maintenance_strengthen",
            "controller_shutdown",
            "controller_accept",
            "maintenance_resume",
        ):
            definition = self.definitions[kind]
            port = ports[kind]
            self.assertTrue(
                port.matches_before(port.observe(definition), definition),
                kind,
            )
            port.apply(definition)
            immediate[kind] = port.observe(definition)
            self.assertTrue(
                port.matches_after(immediate[kind], definition),
                kind,
            )

        for kind, expected in immediate.items():
            current = ports[kind].observe(self.definitions[kind])
            self.assertTrue(
                ports[kind].completed_current_matches(
                    expected,
                    current,
                    self.definitions[kind],
                ),
                kind,
            )

    def test_non_missing_rehydration_failure_is_not_downgraded_to_before(self) -> None:
        def corrupted(**_arguments):
            raise ControllerTransitionRehydrationV2Error(
                "REHYDRATION_RESPONSE_FINGERPRINT_MISMATCH", "повреждено"
            )

        ports = build_update_controller_step_ports_v2(
            operation_id=OPERATION_ID,
            activation_proof_fingerprint="a" * 64,
            shutdown_cleanup_plan_fingerprint=(
                SHUTDOWN_CLEANUP_PLAN_FINGERPRINT
            ),
            codex_home=self.codex_home,
            current_database_path=self.current_database,
            candidate_database_path=self.candidate_database,
            definitions=self.definitions,
            candidate_spawn_action=self.candidate_spawn_action,
            client_factory=self._client_factory,
            command_rehydrator=corrupted,
            controller_observer=lambda path: self.states[path],
            quiescence_observer=lambda _path, _operation_id: None,
            candidate_reconnect=self._candidate_reconnect,
            shutdown_orphan_prover=lambda _shutdown: None,
            shutdown_rehydrator=lambda **_arguments: None,
            acceptance_rehydrator=lambda **_arguments: None,
        )

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as caught:
            ports["maintenance_begin"].observe(self.definitions["maintenance_begin"])

        self.assertEqual(
            "REHYDRATION_RESPONSE_FINGERPRINT_MISMATCH", caught.exception.code
        )

    def test_foreign_definition_is_rejected_before_any_effect(self) -> None:
        port = self._ports()["maintenance_begin"]
        foreign = _step(
            "maintenance_begin",
            before=self.accepting,
            expected_after=self.begin_after,
            epoch=6,
            command_token="f",
        )

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.apply(foreign)

        self.assertEqual("CONTROLLER_STEP_DEFINITION_CHANGED", caught.exception.code)
        self.assertEqual([], self.calls)

    def test_builder_snapshots_durable_definitions_against_later_mutation(self) -> None:
        port = self._ports()["maintenance_begin"]
        definition = self.definitions["maintenance_begin"]
        definition.action["expectedControlEpoch"] = 6

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            port.apply(definition)

        self.assertEqual("CONTROLLER_STEP_DEFINITION_CHANGED", caught.exception.code)
        self.assertEqual([], self.calls)

    def test_builder_rejects_non_normative_action_keys(self) -> None:
        definitions = copy.deepcopy(self.definitions)
        begin = definitions["maintenance_begin"]
        definitions["maintenance_begin"] = replace(
            begin,
            action={**begin.action, "unexpected": True},
        )

        with self.assertRaises(InstallerUpdateControllerPortsV2Error) as caught:
            build_update_controller_step_ports_v2(
                operation_id=OPERATION_ID,
                activation_proof_fingerprint="a" * 64,
                shutdown_cleanup_plan_fingerprint=(
                    SHUTDOWN_CLEANUP_PLAN_FINGERPRINT
                ),
                codex_home=self.codex_home,
                current_database_path=self.current_database,
                candidate_database_path=self.candidate_database,
                definitions=definitions,
                candidate_spawn_action=self.candidate_spawn_action,
                client_factory=self._client_factory,
                command_rehydrator=self._command_loader,
                controller_observer=lambda path: self.states[path],
                quiescence_observer=lambda _path, _operation_id: None,
                candidate_reconnect=self._candidate_reconnect,
                shutdown_orphan_prover=lambda _shutdown: None,
                shutdown_rehydrator=lambda **_arguments: None,
                acceptance_rehydrator=lambda **_arguments: None,
            )

        self.assertEqual("CONTROLLER_STEP_DEFINITIONS_INVALID", caught.exception.code)
        self.assertEqual([], self.calls)

    def test_default_observers_project_real_database_and_quiescence(self) -> None:
        state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        state_home.mkdir(parents=True, mode=0o700)
        database_path = state_home / "databases" / "observed.sqlite3"
        lock_path = state_home / "controller.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        socket_path = self.root / "observed-controller.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        socket_path.chmod(0o600)
        socket_info = socket_path.lstat()
        now = datetime(2026, 7, 19, 18, 0, tzinfo=timezone.utc)
        identity = store_database_identity()
        live_controller = replace(
            store_controller(),
            controller_pid=os.getpid(),
            controller_process_start_marker=system_process_start_marker_v2(os.getpid()),
            controller_process_group_id=os.getpgrp(),
            activation_id=identity.activation_id,
            socket_path=str(socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            updated_at=now,
        )
        try:
            store = SmartStoreV2(
                database_path,
                database_identity=identity,
                controller=live_controller,
            )
            store.close()

            accepting = observe_controller_database_v2(database_path)

            self.assertEqual("controller-state-v2", accepting.schema_id)
            self.assertEqual("ACCEPTING", accepting.value["state"])
            self.assertEqual(identity.database_id, accepting.value["databaseId"])
            self.assertEqual(socket_info.st_ino, accepting.value["socket"]["inode"])

            protocol = LifecycleControllerProtocolV2(
                database_path=database_path,
                codex_home=self.codex_home,
                controller_lock_path=lock_path,
                clock=lambda: now,
            )
            request = build_lifecycle_controller_request_v2(
                codex_home=self.codex_home,
                shell_session_id="installer-v2",
                method="maintenance_begin",
                controller_identity=live_controller.controller_identity,
                instance_id=live_controller.instance_id,
                controller_start_id=live_controller.controller_start_id,
                command_id="cc2_" + "d" * 32,
                expected_control_epoch=live_controller.control_epoch,
                operation_id=OPERATION_ID,
                params={"reasonCode": "UPGRADE"},
            )
            protocol.handle(request)

            quiescence = observe_runtime_quiescence_database_v2(
                database_path,
                OPERATION_ID,
            )

            self.assertIsNotNone(quiescence)
            assert quiescence is not None
            self.assertEqual("quiescence-proof-v2", quiescence.schema_id)
            self.assertTrue(quiescence.value["quiescent"])
            self.assertEqual({0}, set(quiescence.value["workCounts"].values()))
        finally:
            listener.close()

    def test_controller_database_connect_preserves_exact_root_deadline(self) -> None:
        deadline_error = OperationDeadlineExceededV2(
            code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            operation="recover",
            phase="controller-database-observation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=120_000_000_000,
            elapsed_monotonic_nanoseconds=120_000_000_000,
        )

        with (
            mock.patch(
                "codex_smart_subagents.installer_update_controller_ports_v2."
                "connect_sqlite_with_deadline_v2",
                side_effect=deadline_error,
            ),
            self.assertRaises(OperationDeadlineExceededV2) as raised,
        ):
            observe_controller_database_v2(self.current_database)

        self.assertIs(deadline_error, raised.exception)
        self.assertEqual(
            "RECOVERY_OPERATION_DEADLINE_TIMEOUT", raised.exception.code
        )

    def test_controller_database_close_does_not_mask_exact_read_deadline(
        self,
    ) -> None:
        from codex_smart_subagents import installer_update_controller_ports_v2 as ports

        deadline_error = OperationDeadlineExceededV2(
            code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            operation="recover",
            phase="controller-database-observation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=120_000_000_000,
            elapsed_monotonic_nanoseconds=120_000_000_000,
        )
        close_error = RuntimeError("controller observation close failed")

        class FakeConnection:
            row_factory = None
            in_transaction = False

            def execute(self, _statement: str):
                raise deadline_error

            def close(self) -> None:
                raise close_error

        with (
            mock.patch.object(
                ports,
                "connect_sqlite_with_deadline_v2",
                return_value=FakeConnection(),
            ),
            self.assertRaises(OperationDeadlineExceededV2) as raised,
        ):
            observe_controller_database_v2(self.current_database)

        self.assertIs(deadline_error, raised.exception)
        self.assertTrue(
            any(
                "controller observation close failed" in note
                for note in getattr(deadline_error, "__notes__", ())
            )
        )

    def test_controller_database_close_failure_is_primary_without_read_error(
        self,
    ) -> None:
        from codex_smart_subagents import installer_update_controller_ports_v2 as ports

        close_error = RuntimeError("controller observation close failed")

        class FakeConnection:
            def close(self) -> None:
                raise close_error

        with self.assertRaises(RuntimeError) as raised:
            ports._close_controller_database_preserving_primary_v2(
                FakeConnection(),
                primary=None,
            )

        self.assertIs(close_error, raised.exception)


if __name__ == "__main__":
    unittest.main()
