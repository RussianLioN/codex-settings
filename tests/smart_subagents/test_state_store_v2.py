from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    _CommitThenFail,
    _QUIESCENCE_QUERIES,
    _bounded_inline_terminal_result,
    AcceptingControllerV2,
    DatabaseIdentityV2,
    PlannedNodeV2,
    RequestContextV2,
    SmartStoreV2,
    StateStoreV2Error,
    attempt_id_for_evidence_job,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
HEX = {
    name: character * 64
    for name, character in {
        "activation": "a",
        "compatibility": "b",
        "routing": "c",
        "bundled": "d",
        "account_catalog": "e",
        "account_context": "f",
        "manifest": "1",
        "receipt": "2",
        "schema": "3",
        "absence": "4",
        "record": "5",
        "argv": "6",
        "snapshot": "7",
        "snapshot_identity": "8",
        "binary": "9",
        "token": "0",
    }.items()
}


def database_identity() -> DatabaseIdentityV2:
    return DatabaseIdentityV2(
        database_id="db2_" + "a" * 32,
        activation_binding_nonce="0" * 64,
        activation_id="act2_" + "b" * 64,
        activation_fingerprint=HEX["activation"],
        created_operation_id="op2_" + "c" * 32,
        created_at=NOW,
    )


def controller() -> AcceptingControllerV2:
    return AcceptingControllerV2(
        controller_identity="d" * 64,
        instance_id="ci2_" + "e" * 32,
        controller_start_id="cs2_" + "f" * 32,
        controller_pid=1001,
        controller_process_start_marker="pid-1001-start-7",
        controller_process_group_id=1001,
        control_epoch=7,
        activation_id=database_identity().activation_id,
        activation_fingerprint=HEX["activation"],
        compatibility_fingerprint=HEX["compatibility"],
        routing_policy_fingerprint=HEX["routing"],
        bundled_catalog_fingerprint=HEX["bundled"],
        socket_path="/tmp/codex-smart-v2.sock",
        socket_device=1,
        socket_inode=2,
        socket_owner_uid=os.getuid(),
        socket_owner_gid=os.getgid(),
        socket_mode="0600",
        updated_at=NOW,
    )


def request_context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/Users/test/repo",
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
        activation_fingerprint=HEX["activation"],
        compatibility_fingerprint=HEX["compatibility"],
        issued_control_epoch=7,
    )


def activation_gate() -> dict[str, object]:
    proof = {
        "schemaId": "absence-proof-v2",
        "schemaSha256": HEX["schema"],
        "value": {
            "proofId": "ap2_" + "a" * 32,
            "installationId": "ins2_" + "b" * 32,
            "operationId": "op2_" + "c" * 32,
            "entries": [
                {
                    "path": "/tmp/codex/install.transaction.json",
                    "basename": "install.transaction.json",
                    "parentDevice": 1,
                    "parentInode": 2,
                    "absent": True,
                }
            ],
            "directorySyncCompleted": True,
            "proofFingerprint": HEX["absence"],
        },
        "valueFingerprint": HEX["absence"],
    }
    projection = {
        "manifestSemanticFingerprint": HEX["manifest"],
        "activationReceiptFingerprint": HEX["receipt"],
        "journalAbsenceProof": proof,
    }
    return {
        **projection,
        "gateFingerprint": domain_fingerprint(
            "codex-smart/activation-gate/v2", projection
        ),
    }


def node(node_id: str = "node2_" + "a" * 32) -> PlannedNodeV2:
    return PlannedNodeV2(
        node_id=node_id,
        ordinal=0,
        role="researcher",
        mission="Проверить договор.",
        dependencies=(),
        context_refs=("request",),
        scope_id="scope-1",
        artifact_profile_id="report-v1",
        validation_profile_id="strict-v1",
        assessment={"q": 1, "p": 1, "v": 1, "o": 1},
        risk_flags=(),
        selected_model="gpt-5.6-luna",
        reasoning_effort="medium",
        permission_profile_id="reader-v1",
        disposition="delegate",
    )


class SmartStoreV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state" / "state-v2.sqlite3"
        self.store = SmartStoreV2(
            self.path,
            database_identity=database_identity(),
            controller=controller(),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def test_long_sql_preserves_the_exact_shared_deadline_error(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                observed = self.value
                self.value += 10_000
                return observed

        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.005,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=Clock(),
        )

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                self.store._connection.execute(
                    "with recursive n(x) as (values(1) union all "
                    "select x+1 from n where x<100000) select sum(x) from n"
                ).fetchone()

        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT",
            caught.exception.code,
        )

    def test_immediate_rolls_back_without_masking_an_expired_deadline(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock,
        )
        original = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="operation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1_000_000_000,
            elapsed_monotonic_nanoseconds=2_000_000_000,
        )

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                with self.store._immediate():
                    clock.value += 2_000_000_000
                    raise original

        self.assertIs(original, caught.exception)
        self.assertFalse(self.store._connection.in_transaction)
        self.assertEqual(
            1,
            self.store._connection.execute("select 1").fetchone()[0],
        )

    def test_immediate_rolls_back_when_deadline_expires_before_commit(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock,
        )

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                with self.store._immediate():
                    clock.value += 2_000_000_000

        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT",
            caught.exception.code,
        )
        self.assertFalse(self.store._connection.in_transaction)

    def test_commit_then_fail_rolls_back_if_deadline_blocks_commit(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock,
        )

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2):
                with self.store._immediate():
                    clock.value += 2_000_000_000
                    raise _CommitThenFail("EXPECTED", "expected")

        self.assertFalse(self.store._connection.in_transaction)

    def test_fresh_database_uses_normative_schema_and_reopens_strictly(self) -> None:
        manifest = json.loads(
            (
                PLUGIN_SRC
                / "codex_smart_subagents"
                / "schema"
                / "state-v2.manifest.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(0o700, stat.S_IMODE(self.path.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.path.stat().st_mode))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                1129529650, connection.execute("pragma application_id").fetchone()[0]
            )
            self.assertEqual(2, connection.execute("pragma user_version").fetchone()[0])
            self.assertEqual(
                "wal", connection.execute("pragma journal_mode").fetchone()[0]
            )
            identity_row = connection.execute(
                "select schema_fingerprint, schema_artifact_sha256 "
                "from database_identity"
            ).fetchone()
        self.assertEqual(
            (manifest["schemaFingerprint"], manifest["stateSqlSha256"]),
            identity_row,
        )

        self.store.close()
        self.store = SmartStoreV2(
            self.path,
            database_identity=database_identity(),
            controller=controller(),
        )
        self.assertTrue(self.path.exists())

    def test_reopen_rejects_identity_controller_or_schema_drift(self) -> None:
        self.store.close()
        for changed_identity, changed_controller, expected_code in (
            (
                replace(database_identity(), activation_binding_nonce="1" * 64),
                controller(),
                "DATABASE_IDENTITY_MISMATCH",
            ),
            (
                database_identity(),
                replace(controller(), control_epoch=8),
                "CONTROLLER_STATE_MISMATCH",
            ),
        ):
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(StateStoreV2Error) as caught:
                    SmartStoreV2(
                        self.path,
                        database_identity=changed_identity,
                        controller=changed_controller,
                    )
                self.assertEqual(expected_code, caught.exception.code)

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("create table injected(value text)")
        with self.assertRaises(StateStoreV2Error) as caught:
            SmartStoreV2(
                self.path,
                database_identity=database_identity(),
                controller=controller(),
            )
        self.assertEqual("DATABASE_SCHEMA_MISMATCH", caught.exception.code)

    def test_existing_shared_directory_is_rejected_without_chmod(self) -> None:
        self.store.close()
        shared = Path(self.directory.name) / "shared"
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        with self.assertRaises(StateStoreV2Error) as caught:
            SmartStoreV2(
                shared / "state-v2.sqlite3",
                database_identity=database_identity(),
                controller=controller(),
            )
        self.assertEqual("UNSAFE_DATABASE_DIRECTORY", caught.exception.code)
        self.assertEqual(0o755, stat.S_IMODE(shared.stat().st_mode))

    def test_turn_binding_is_context_bound_single_use_and_replay_safe(self) -> None:
        binding = self.store.issue_turn_binding(
            request_context(),
            ttl_seconds=120,
            request_key="idem2_" + "0" * 32,
            now=NOW,
        )
        self.assertRegex(binding.binding_id, r"^tb2_[0-9a-f]{32}$")
        self.assertEqual("ACTIVE", binding.state)

        changed = replace(request_context(), session_id="other-session")
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.consume_turn_binding(
                binding.binding_id,
                changed,
                request_key="idem2_" + "1" * 32,
                request_hash=HEX["record"],
                now=NOW + timedelta(seconds=1),
            )
        self.assertEqual("TURN_BINDING_CONTEXT_MISMATCH", caught.exception.code)

        pair = {
            "request_key": "idem2_" + "1" * 32,
            "request_hash": HEX["record"],
        }
        consumed = self.store.consume_turn_binding(
            binding.binding_id,
            request_context(),
            **pair,
            now=NOW + timedelta(seconds=1),
        )
        replayed = self.store.consume_turn_binding(
            binding.binding_id,
            request_context(),
            **pair,
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual("CONSUMED", consumed.state)
        self.assertEqual(consumed, replayed)
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.consume_turn_binding(
                binding.binding_id,
                request_context(),
                request_key="idem2_" + "2" * 32,
                request_hash=HEX["record"],
                now=NOW + timedelta(seconds=2),
            )
        self.assertEqual("TURN_BINDING_USED", caught.exception.code)
        reissued = self.store.issue_turn_binding(
            request_context(),
            ttl_seconds=120,
            request_key="idem2_" + "0" * 32,
            now=NOW + timedelta(seconds=3),
        )
        self.assertEqual(binding.binding_id, reissued.binding_id)
        self.assertEqual("CONSUMED", reissued.state)
        self.assertTrue(reissued.replayed)
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.issue_turn_binding(
                request_context(),
                ttl_seconds=121,
                request_key="idem2_" + "0" * 32,
                now=NOW + timedelta(seconds=3),
            )
        self.assertEqual("TURN_BINDING_REPLAY_CONFLICT", caught.exception.code)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                1,
                connection.execute("select count(*) from turn_bindings").fetchone()[0],
            )

    def test_direct_plan_has_no_nodes_and_replays_the_same_terminal_route(self) -> None:
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        arguments = {
            "binding_id": binding.binding_id,
            "request_context": context,
            "request_key": "idem2_" + "d" * 32,
            "request_hash": HEX["record"],
            "catalog_generation": "catalog-v2",
            "algorithm_version": "q+p+v+o-v2",
            "disposition": "DIRECT",
            "expires_at": NOW + timedelta(minutes=15),
            "plan_output": {"status": "ORDINARY", "reasonCode": "DIRECT_SELECTED"},
            "nodes": (),
        }
        first = self.store.create_planned_route(
            **arguments, now=NOW + timedelta(seconds=1)
        )
        second = self.store.create_planned_route(
            **arguments, now=NOW + timedelta(seconds=2)
        )
        self.assertEqual(first, second)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("DIRECT", "DIRECT")],
                connection.execute(
                    "select state,disposition from routes where route_id=?", (first,)
                ).fetchall(),
            )
            self.assertEqual(
                0,
                connection.execute(
                    "select count(*) from nodes where route_id=?", (first,)
                ).fetchone()[0],
            )

    def test_delegate_plan_replay_requires_the_exact_node_projection(self) -> None:
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        arguments = {
            "binding_id": binding.binding_id,
            "request_context": context,
            "request_key": "idem2_" + "c" * 32,
            "request_hash": HEX["record"],
            "catalog_generation": "catalog-v2",
            "algorithm_version": "q+p+v+o-v2",
            "disposition": "DELEGATE",
            "expires_at": NOW + timedelta(minutes=15),
            "plan_output": {"status": "PLANNED"},
        }
        first = self.store.create_planned_route(
            **arguments, nodes=(node(),), now=NOW + timedelta(seconds=1)
        )
        replayed = self.store.create_planned_route(
            **arguments, nodes=(node(),), now=NOW + timedelta(seconds=2)
        )
        self.assertEqual(first, replayed)
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_planned_route(
                **arguments,
                nodes=(replace(node(), selected_model="gpt-5.6-sol"),),
                now=NOW + timedelta(seconds=3),
            )
        self.assertEqual("ROUTE_REPLAY_CONFLICT", caught.exception.code)

    def test_runtime_artifact_is_reserved_activated_and_closed_exactly(self) -> None:
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "a" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(node(),),
            now=NOW + timedelta(seconds=1),
        )
        attempts_root = Path(self.directory.name) / "attempt-runtimes-v2"
        attempts_root.mkdir(mode=0o700)
        attempts_root = attempts_root.resolve(strict=True)
        attempt_path = attempts_root / ("attempt-att2_" + "b" * 32)

        artifact_id = self.store.reserve_runtime_artifact(
            route_id=route_id,
            node_id=node().node_id,
            kind="attempt_runtime_v2",
            path=attempt_path,
            allowed_root=attempts_root,
        )

        self.assertRegex(artifact_id, r"^ra2_[0-9a-f]{32}$")
        self.assertEqual(
            ["RESERVED"],
            [item["state"] for item in self.store.runtime_artifacts(route_id)],
        )

        attempt_path.mkdir(mode=0o700)
        active = self.store.seal_runtime_artifact(artifact_id, terminal=False)
        self.assertEqual("ACTIVE", active["state"])
        self.assertEqual(attempt_path.stat().st_dev, active["device"])
        self.assertEqual(attempt_path.stat().st_ino, active["inode"])

        attempt_path.rmdir()
        missing = self.store.seal_runtime_artifact(artifact_id, terminal=True)
        self.assertEqual("MISSING", missing["state"])
        self.assertIsNone(missing["device"])
        self.assertIsNone(missing["inode"])

    def test_runtime_artifact_rejects_unknown_node_and_nonfresh_path(self) -> None:
        attempts_root = Path(self.directory.name) / "attempt-runtimes-v2"
        attempts_root.mkdir(mode=0o700)
        attempts_root = attempts_root.resolve(strict=True)
        attempt_path = attempts_root / ("attempt-att2_" + "c" * 32)

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.reserve_runtime_artifact(
                route_id="route2_" + "d" * 32,
                node_id="node2_" + "e" * 32,
                kind="attempt_runtime_v2",
                path=attempt_path,
                allowed_root=attempts_root,
            )
        self.assertEqual("ROUTE_NODE_NOT_FOUND", caught.exception.code)

        attempt_path.mkdir(mode=0o700)
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.reserve_runtime_artifact(
                route_id="route2_" + "d" * 32,
                node_id="node2_" + "e" * 32,
                kind="attempt_runtime_v2",
                path=attempt_path,
                allowed_root=attempts_root,
            )
        self.assertEqual("RUNTIME_ARTIFACT_PATH_EXISTS", caught.exception.code)

    def test_plan_start_evidence_admission_and_launch_permit_are_durable(self) -> None:
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "3" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(node(),),
            now=NOW + timedelta(seconds=1),
        )
        self.assertRegex(route_id, r"^route2_[0-9a-f]{32}$")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [(None, None)],
                connection.execute(
                    "select account_catalog_fingerprint,account_context_fingerprint "
                    "from nodes where route_id=?",
                    (route_id,),
                ).fetchall(),
            )

        started = self.store.create_start_request(
            route_id=route_id,
            node_id=node().node_id,
            request_context=context,
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=2),
        )
        self.assertEqual("ATTESTING", started.state)
        self.assertRegex(started.start_request_id, r"^sr2_[0-9a-f]{32}$")
        self.assertRegex(started.evidence_job_id, r"^aej2_[0-9a-f]{32}$")
        self.assertRegex(started.attempt_id, r"^att2_[0-9a-f]{32}$")
        self.assertEqual(
            attempt_id_for_evidence_job(started.evidence_job_id), started.attempt_id
        )

        self.store.claim_account_evidence_job(
            started.evidence_job_id,
            owner_id="evidence-worker-1",
            pid=2001,
            process_start_marker="pid-2001-start",
            current_stage="requirements-a",
            now=NOW + timedelta(seconds=3),
        )
        self.store.complete_account_evidence_job(
            started.evidence_job_id,
            account_catalog_fingerprint=HEX["account_catalog"],
            account_context_fingerprint=HEX["account_context"],
            record_fingerprint=HEX["record"],
            now=NOW + timedelta(seconds=4),
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        self.assertRegex(admitted.admission_id, r"^adm2_[0-9a-f]{32}$")
        self.assertEqual("ADMITTED", admitted.state)
        admitted_plan = self.store.read_node_plan(
            route_id,
            node().node_id,
            context,
        )
        self.assertEqual(
            HEX["account_context"],
            admitted_plan.account_context_fingerprint,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [(HEX["account_catalog"], HEX["account_context"])],
                connection.execute(
                    "select account_catalog_fingerprint,account_context_fingerprint "
                    "from nodes where admission_id=?",
                    (admitted.admission_id,),
                ).fetchall(),
            )

        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.assertRegex(permit.permit_id, r"^lp2_[0-9a-f]{32}$")
        self.assertEqual("RESERVED", permit.state)

        guarded = self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )
        self.assertEqual("GUARDED", guarded.state)
        committed = self.store.commit_launch_permit(
            permit_id=permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            argv_fingerprint=HEX["argv"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            permission_probe_id="pc2_" + "a" * 32,
            codex_binary_sha256=HEX["binary"],
            now=NOW + timedelta(seconds=7),
        )
        self.assertEqual(started.attempt_id, committed.attempt_id)
        self.assertEqual("COMMIT_AUTHORIZED", committed.permit_state)

        self.store.close()
        self.store = SmartStoreV2(
            self.path,
            database_identity=database_identity(),
            controller=controller(),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("COMMIT_AUTHORIZED", 7)],
                connection.execute(
                    "select state, reserved_control_epoch from node_launch_permits"
                ).fetchall(),
            )
            self.assertEqual(
                [("STARTING", committed.attempt_id)],
                connection.execute("select state, attempt_id from attempts").fetchall(),
            )

    def test_gate_or_epoch_change_fails_closed_without_launch_attempt(self) -> None:
        route_id, started = self._succeeded_evidence()
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        changed_gate = activation_gate()
        changed_gate["manifestSemanticFingerprint"] = "a" * 64
        projection = {
            key: changed_gate[key]
            for key in (
                "manifestSemanticFingerprint",
                "activationReceiptFingerprint",
                "journalAbsenceProof",
            )
        }
        changed_gate["gateFingerprint"] = domain_fingerprint(
            "codex-smart/activation-gate/v2", projection
        )
        for gate, epoch, code in (
            (activation_gate(), 8, "CONTROL_EPOCH_MISMATCH"),
            (changed_gate, 7, "ACTIVATION_GATE_CHANGED"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(StateStoreV2Error) as caught:
                    self.store.reserve_launch_permit(
                        admission_id=admitted.admission_id,
                        activation_gate=gate,
                        expected_control_epoch=epoch,
                        argv_fingerprint=HEX["argv"],
                        codex_snapshot_sha256=HEX["snapshot"],
                        snapshot_identity_fingerprint=HEX["snapshot_identity"],
                        now=NOW + timedelta(seconds=6),
                    )
                self.assertEqual(code, caught.exception.code)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "select count(*) from node_launch_permits"
                ).fetchone()[0],
            )
            self.assertEqual(
                [
                    (
                        "ABORTED_ACTIVATION_GATE_CHANGED",
                        "ABORTED_ACTIVATION_GATE_CHANGED",
                    )
                ],
                connection.execute(
                    "select state,failure_code from node_launch_permits"
                ).fetchall(),
            )
            self.assertEqual(
                0,
                connection.execute("select count(*) from attempts").fetchone()[0],
            )
            self.assertEqual(
                [("STALE",)],
                connection.execute("select state from routes").fetchall(),
            )
            self.assertEqual(
                [("STALE", "ABORTED")],
                connection.execute(
                    "select state,admission_state from nodes"
                ).fetchall(),
            )
            self.assertEqual(
                [("STALE", "ACTIVATION_GATE_CHANGED")],
                connection.execute(
                    "select state,failure_code from start_requests"
                ).fetchall(),
            )

    def test_gate_change_at_commit_terminalizes_route_node_and_start(self) -> None:
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        route_id, started = self._succeeded_evidence(
            planned_nodes=(node(), peer),
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )
        changed_gate = activation_gate()
        changed_gate["manifestSemanticFingerprint"] = "a" * 64
        changed_gate["gateFingerprint"] = domain_fingerprint(
            "codex-smart/activation-gate/v2",
            {
                key: changed_gate[key]
                for key in (
                    "manifestSemanticFingerprint",
                    "activationReceiptFingerprint",
                    "journalAbsenceProof",
                )
            },
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.commit_launch_permit(
                permit_id=permit.permit_id,
                guard_pid=3001,
                guard_start_marker="pid-3001-start",
                one_time_token_hash=HEX["token"],
                argv_fingerprint=HEX["argv"],
                snapshot_identity_fingerprint=HEX["snapshot_identity"],
                activation_gate=changed_gate,
                expected_control_epoch=7,
                permission_probe_id="pc2_" + "a" * 32,
                codex_binary_sha256=HEX["binary"],
                now=NOW + timedelta(seconds=7),
            )

        self.assertEqual("ACTIVATION_GATE_CHANGED", caught.exception.code)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("ABORTED_ACTIVATION_GATE_CHANGED",)],
                connection.execute("select state from node_launch_permits").fetchall(),
            )
            self.assertEqual(
                [], connection.execute("select state from attempts").fetchall()
            )
            self.assertEqual(
                [("STALE",)], connection.execute("select state from routes").fetchall()
            )
            self.assertEqual(
                [("STALE", "ABORTED"), ("STALE", None)],
                connection.execute(
                    "select state,admission_state from nodes order by ordinal"
                ).fetchall(),
            )
            self.assertEqual(
                [("STALE", "ACTIVATION_GATE_CHANGED")],
                connection.execute(
                    "select state,failure_code from start_requests"
                ).fetchall(),
            )
        quiescence = self.store.quiescence_snapshot(barrier_held=True)
        self.assertEqual(0, quiescence.work_counts["nonterminalRoutes"])
        self.assertEqual(0, quiescence.work_counts["nonterminalNodes"])
        self.assertEqual(0, quiescence.work_counts["inflightLaunchPermits"])

    def test_record_start_stale_terminalizes_all_unstarted_route_roots(self) -> None:
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        route_id, started = self._succeeded_evidence(
            leave_running=True,
            planned_nodes=(node(), peer),
        )
        problem = {
            "category": "STALE",
            "code": "ROUTE_STALE",
            "message": "Договор маршрута изменился.",
            "retryable": False,
        }

        terminal = self.store.record_start_stale(
            started.start_request_id,
            request_context(),
            failure_code="ROUTE_POLICY_STALE",
            problem=problem,
            now=NOW + timedelta(seconds=5),
        )

        self.assertEqual("STALE", terminal.state)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [(node().node_id, "STALE"), (peer.node_id, "STALE")],
                connection.execute(
                    "select node_id,state from nodes where route_id=? order by ordinal",
                    (route_id,),
                ).fetchall(),
            )
            self.assertEqual(
                ("STALE",),
                connection.execute(
                    "select state from routes where route_id=?", (route_id,)
                ).fetchone(),
            )
        quiescence = self.store.quiescence_snapshot(barrier_held=True)
        self.assertEqual(0, quiescence.work_counts["nonterminalRoutes"])
        self.assertEqual(0, quiescence.work_counts["nonterminalNodes"])
        self.assertEqual(0, quiescence.work_counts["activeEvidenceJobs"])

    def test_route_expiry_boundary_allows_start_and_exact_replay(self) -> None:
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        expiration = NOW + timedelta(seconds=15)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "a" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=expiration,
            plan_output={"status": "PLANNED"},
            nodes=(node(),),
            now=NOW + timedelta(seconds=1),
        )
        start_key = "idem2_" + "b" * 32

        started = self.store.create_start_request(
            route_id=route_id,
            node_id=node().node_id,
            request_context=context,
            idempotency_key=start_key,
            activation_gate_fingerprint=activation_gate()["gateFingerprint"],
            deadline_at=expiration + timedelta(seconds=180),
            now=expiration,
        )
        replay = self.store.create_start_request(
            route_id=route_id,
            node_id=node().node_id,
            request_context=context,
            idempotency_key=start_key,
            activation_gate_fingerprint=activation_gate()["gateFingerprint"],
            deadline_at=expiration + timedelta(seconds=181),
            now=expiration + timedelta(seconds=1),
        )

        self.assertEqual(started.start_request_id, replay.start_request_id)
        self.assertTrue(replay.replayed)

    def test_expired_first_start_stales_every_unstarted_node_atomically(self) -> None:
        context = request_context()
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        expiration = NOW + timedelta(seconds=15)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "c" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=expiration,
            plan_output={"status": "PLANNED"},
            nodes=(node(), peer),
            now=NOW + timedelta(seconds=1),
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_start_request(
                route_id=route_id,
                node_id=node().node_id,
                request_context=context,
                idempotency_key="idem2_" + "d" * 32,
                activation_gate_fingerprint=activation_gate()["gateFingerprint"],
                deadline_at=expiration + timedelta(seconds=120),
                now=expiration + timedelta(microseconds=1),
            )

        self.assertEqual("ROUTE_EXPIRED", caught.exception.code)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [(node().node_id, "STALE"), (peer.node_id, "STALE")],
                connection.execute(
                    "select node_id,state from nodes where route_id=? order by ordinal",
                    (route_id,),
                ).fetchall(),
            )
            self.assertEqual(
                ("STALE",),
                connection.execute(
                    "select state from routes where route_id=?", (route_id,)
                ).fetchone(),
            )
            self.assertEqual(
                (0, 0, 0),
                (
                    connection.execute(
                        "select count(*) from start_requests where route_id=?", (route_id,)
                    ).fetchone()[0],
                    connection.execute(
                        "select count(*) from account_evidence_jobs where route_id=?",
                        (route_id,),
                    ).fetchone()[0],
                    connection.execute(
                        "select count(*) from intents where route_id=?", (route_id,)
                    ).fetchone()[0],
                ),
            )
        quiescence = self.store.quiescence_snapshot(barrier_held=True)
        self.assertTrue(quiescence.quiescent)

    def test_quiescence_counts_all_ten_contract_work_classes(self) -> None:
        empty = self.store.quiescence_snapshot(barrier_held=True)
        self.assertTrue(empty.quiescent)
        self.assertEqual(
            {
                "nonterminalRoutes",
                "nonterminalNodes",
                "activeAttempts",
                "activeLeases",
                "openIntents",
                "inflightLaunchPermits",
                "activeRuntimeArtifacts",
                "pendingCandidatePublications",
                "activeEvidenceJobs",
                "queuedEvidenceJobs",
            },
            set(empty.work_counts),
        )
        route_id, started = self._succeeded_evidence(leave_running=True)
        snapshot = self.store.quiescence_snapshot(barrier_held=True)
        self.assertFalse(snapshot.quiescent)
        self.assertEqual(1, snapshot.work_counts["nonterminalRoutes"])
        self.assertEqual(1, snapshot.work_counts["nonterminalNodes"])
        self.assertEqual(1, snapshot.work_counts["activeEvidenceJobs"])
        self.assertEqual(0, snapshot.work_counts["queuedEvidenceJobs"])
        self.assertNotEqual(
            empty.database_predicates_fingerprint,
            snapshot.database_predicates_fingerprint,
            "отпечаток обязан связывать фактические результаты запросов снимка",
        )
        expected_projection = {
            "predicates": [
                {
                    "name": name,
                    "sql": statement,
                    "parameters": [],
                    "result": snapshot.work_counts[name],
                }
                for name, statement in _QUIESCENCE_QUERIES.items()
            ]
        }
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/database-predicates/v2", expected_projection
            ),
            snapshot.database_predicates_fingerprint,
        )
        self.assertTrue(route_id)
        self.assertTrue(started.evidence_job_id)
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.quiescence_snapshot(barrier_held=False)
        self.assertEqual("LAUNCH_BARRIER_REQUIRED", caught.exception.code)

    def test_read_status_and_node_plan_are_owner_bound_paginated_and_read_only(
        self,
    ) -> None:
        route_id, started = self._succeeded_evidence(leave_running=True)
        with closing(sqlite3.connect(self.path)) as connection:
            before = connection.execute(
                "select updated_at from start_requests where start_request_id=?",
                (started.start_request_id,),
            ).fetchone()[0]
            before_events = connection.execute(
                "select count(*) from events where code=?", (started.start_request_id,)
            ).fetchone()[0]

        plan = self.store.read_node_plan(route_id, node().node_id, request_context())
        self.assertEqual("PLANNED", plan.node_state)
        self.assertEqual("gpt-5.6-luna", plan.node.selected_model)
        self.assertEqual({"status": "PLANNED"}, plan.plan_output)
        self.assertIsNone(plan.account_context_fingerprint)

        first = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=1,
        )
        self.assertEqual("ATTESTING", first.state)
        self.assertEqual("RUNNING", first.evidence_job_state)
        self.assertFalse(first.terminal)
        self.assertEqual(1, len(first.page.items))
        self.assertEqual("EVIDENCE_QUEUED", first.page.items[0].kind)
        self.assertRegex(first.page.next_cursor or "", r"^cur2_[0-9a-f]{32}$")
        second = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=first.page.next_cursor,
            page_size=10,
        )
        self.assertEqual(
            ["EVIDENCE_RUNNING"], [item.kind for item in second.page.items]
        )
        self.assertRegex(second.page.next_cursor or "", r"^cur2_[0-9a-f]{32}$")
        drained = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=second.page.next_cursor,
            page_size=10,
        )
        self.assertEqual((), drained.page.items)
        self.assertEqual(second.page.next_cursor, drained.page.next_cursor)

        foreign_owner = replace(request_context(), session_id="other-session")
        for action in (
            lambda: self.store.read_node_plan(route_id, node().node_id, foreign_owner),
            lambda: self.store.read_start_status(
                started.start_request_id,
                foreign_owner,
                cursor=None,
                page_size=10,
            ),
        ):
            with self.subTest(action=action):
                with self.assertRaises(StateStoreV2Error) as caught:
                    action()
                self.assertEqual("START_OWNER_MISMATCH", caught.exception.code)

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                before,
                connection.execute(
                    "select updated_at from start_requests where start_request_id=?",
                    (started.start_request_id,),
                ).fetchone()[0],
            )
            self.assertEqual(
                before_events,
                connection.execute(
                    "select count(*) from events where code=?",
                    (started.start_request_id,),
                ).fetchone()[0],
            )

    def test_cancel_queued_start_is_atomic_owner_bound_and_idempotent(self) -> None:
        route_id, started = self._queued_start()
        cancelled = self.store.cancel_start_request(
            started.start_request_id,
            request_context(),
            idempotency_key="idem2_" + "8" * 32,
            reason_code="USER_REQUESTED",
            now=NOW + timedelta(seconds=3),
        )
        replayed = self.store.cancel_start_request(
            started.start_request_id,
            request_context(),
            idempotency_key="idem2_" + "8" * 32,
            reason_code="USER_REQUESTED",
            now=NOW + timedelta(seconds=4),
        )
        self.assertEqual("CANCELLED", cancelled.status)
        self.assertEqual("COMMITTED", cancelled.idempotency_status)
        self.assertTrue(cancelled.terminal)
        self.assertEqual("REPLAYED", replayed.idempotency_status)
        self.assertEqual(cancelled.start_request_id, replayed.start_request_id)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("CANCELLED", "USER_REQUESTED")],
                connection.execute(
                    "select state,failure_code from start_requests where start_request_id=?",
                    (started.start_request_id,),
                ).fetchall(),
            )
            self.assertEqual(
                [("CANCELLED", "USER_REQUESTED")],
                connection.execute(
                    "select state,failure_code from account_evidence_jobs where evidence_job_id=?",
                    (started.evidence_job_id,),
                ).fetchall(),
            )
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.cancel_start_request(
                started.start_request_id,
                replace(request_context(), turn_id="other-turn"),
                idempotency_key="idem2_" + "8" * 32,
                reason_code="USER_REQUESTED",
                now=NOW + timedelta(seconds=5),
            )
        self.assertEqual("START_OWNER_MISMATCH", caught.exception.code)
        self.assertTrue(route_id)

    def test_evidence_queue_positions_are_bounded_and_reused(self) -> None:
        context = request_context()

        def enqueue(index: int):
            planned_node = node("node2_" + f"{index + 1:032x}")
            binding = self.store.issue_turn_binding(
                context,
                ttl_seconds=120,
                now=NOW,
            )
            route_id = self.store.create_planned_route(
                binding_id=binding.binding_id,
                request_context=context,
                request_key="idem2_" + f"{index + 1:032x}",
                request_hash=hashlib.sha256(f"route-{index}".encode()).hexdigest(),
                catalog_generation="catalog-v2",
                algorithm_version="q+p+v+o-v2",
                disposition="DELEGATE",
                expires_at=NOW + timedelta(minutes=15),
                plan_output={"status": "PLANNED"},
                nodes=(planned_node,),
                now=NOW + timedelta(seconds=1),
            )
            return self.store.create_start_request(
                route_id=route_id,
                node_id=planned_node.node_id,
                request_context=context,
                deadline_at=NOW + timedelta(seconds=180),
                now=NOW + timedelta(seconds=2),
            )

        active = [enqueue(index) for index in range(32)]
        self.assertEqual(list(range(1, 33)), [item.queue_position for item in active])
        queued_dispatches = self.store.queued_start_dispatches()
        self.assertEqual(32, len(queued_dispatches))
        self.assertEqual(
            [item.start_request_id for item in active],
            [item.start_request_id for item in queued_dispatches],
        )
        for item in queued_dispatches:
            self.assertEqual(
                item.start_request_id,
                self.store.read_start_request(
                    item.start_request_id,
                    item.request_context,
                ).start_request_id,
            )
        with self.assertRaises(StateStoreV2Error) as caught:
            enqueue(32)
        self.assertEqual("ACCOUNT_EVIDENCE_QUEUE_FULL", caught.exception.code)

        self.store.cancel_start_request(
            active[0].start_request_id,
            context,
            idempotency_key="idem2_" + "f" * 32,
            reason_code="USER_REQUESTED",
            now=NOW + timedelta(seconds=3),
        )
        replacement = enqueue(33)
        self.assertEqual(1, replacement.queue_position)
        self.assertLessEqual(replacement.queue_position, 32)

    def test_queued_start_dispatches_exclude_nonqueued_work_and_reject_bad_context(
        self,
    ) -> None:
        _, started = self._queued_start()
        self.assertEqual(
            [started.start_request_id],
            [item.start_request_id for item in self.store.queued_start_dispatches()],
        )
        self.store.claim_account_evidence_job(
            started.evidence_job_id,
            owner_id="evidence-worker-1",
            pid=2001,
            process_start_marker="pid-2001-start",
            current_stage="requirements-a",
            now=NOW + timedelta(seconds=3),
        )
        self.assertEqual((), self.store.queued_start_dispatches())

    def test_queued_start_dispatches_reject_noncanonical_route_context(self) -> None:
        route_id, _ = self._queued_start()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "update routes set context_json='{}' where route_id=?",
                (route_id,),
            )
            connection.commit()
        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.queued_start_dispatches()
        self.assertEqual("DATABASE_VALUE_INVALID", caught.exception.code)

    def test_cancel_running_evidence_replays_then_worker_finishes_cancel(self) -> None:
        _, started = self._succeeded_evidence(leave_running=True)
        arguments = {
            "idempotency_key": "idem2_" + "9" * 32,
            "reason_code": "USER_REQUESTED",
        }
        first = self.store.cancel_start_request(
            started.start_request_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=4),
        )
        replay = self.store.cancel_start_request(
            started.start_request_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=5),
        )
        self.assertEqual("CANCEL_REQUESTED", first.status)
        self.assertFalse(first.terminal)
        self.assertEqual("REPLAYED", replay.idempotency_status)
        terminal = self.store.record_account_evidence_terminal(
            started.evidence_job_id,
            request_context(),
            state="CANCELLED",
            failure_code="USER_REQUESTED",
            problem=None,
            now=NOW + timedelta(seconds=6),
        )
        self.assertEqual("CANCELLED", terminal.state)
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("CANCELLED", status.state)
        self.assertEqual("CANCELLED", status.evidence_job_state)

    def test_cancel_started_child_is_rejected_as_not_cancellable(self) -> None:
        committed, started = self._committed_launch()
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=self._attempt_attestation(committed.attempt_id),
            now=NOW + timedelta(seconds=8),
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.cancel_start_request(
                started.start_request_id,
                request_context(),
                idempotency_key="idem2_" + "8" * 32,
                reason_code="USER_REQUESTED",
                now=NOW + timedelta(seconds=9),
            )

        self.assertEqual("START_NOT_CANCELLABLE", caught.exception.code)
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("STARTED", status.state)
        self.assertFalse(status.terminal)

    def test_evidence_terminal_replay_does_not_duplicate_durable_events(self) -> None:
        _, started = self._succeeded_evidence(leave_running=True)
        arguments = {
            "state": "FAILED",
            "failure_code": "REQUEST_DEADLINE_EXCEEDED",
            "problem": {
                "category": "UNAVAILABLE",
                "code": "REQUEST_DEADLINE_EXCEEDED",
                "message": "Истёк общий срок запуска дочерней задачи.",
                "retryable": True,
            },
        }

        first = self.store.record_account_evidence_terminal(
            started.evidence_job_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=4),
        )
        replay = self.store.record_account_evidence_terminal(
            started.evidence_job_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=5),
        )
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )

        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual("FAILED", status.state)
        self.assertEqual(
            1,
            sum(item.kind == "EVIDENCE_FAILED" for item in status.page.items),
        )
        self.assertEqual(
            1,
            sum(item.kind == "ROUTE_COMPLETED" for item in status.page.items),
        )

    def test_evidence_terminal_keeps_internal_code_behind_public_projection(
        self,
    ) -> None:
        _, started = self._succeeded_evidence(leave_running=True)

        terminal = self.store.record_account_evidence_terminal(
            started.evidence_job_id,
            request_context(),
            state="FAILED",
            failure_code="ACTIVATION_GATE_UNAVAILABLE",
            problem={
                "category": "UNAVAILABLE",
                "code": "ADAPTIVE_ACTIVATION_UNCOMMITTED",
                "message": "Не удалось подтвердить действующую активацию умного режима.",
                "retryable": True,
            },
            now=NOW + timedelta(seconds=4),
        )
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )

        self.assertEqual("FAILED", terminal.state)
        event = next(
            item for item in status.page.items if item.kind == "EVIDENCE_FAILED"
        )
        self.assertEqual(
            "ADAPTIVE_ACTIVATION_UNCOMMITTED",
            event.problem["code"],
        )

    def test_evidence_and_attempt_terminal_results_are_durable_events(self) -> None:
        _, started = self._succeeded_evidence(leave_running=True)
        evidence = self.store.record_account_evidence_terminal(
            started.evidence_job_id,
            request_context(),
            state="FAILED",
            failure_code="ACCOUNT_EVIDENCE_UNAVAILABLE",
            problem={
                "category": "UNAVAILABLE",
                "code": "ACCOUNT_EVIDENCE_UNAVAILABLE",
                "message": "Свидетельство недоступно.",
                "retryable": True,
            },
            now=NOW + timedelta(seconds=4),
        )
        self.assertEqual("FAILED", evidence.state)
        self.assertTrue(evidence.terminal)
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=10,
        )
        self.assertEqual("FAILED", status.state)
        self.assertEqual("EVIDENCE_FAILED", status.page.items[-2].kind)
        self.assertEqual(
            "ACCOUNT_EVIDENCE_UNAVAILABLE",
            status.page.items[-2].problem["code"],
        )
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        self.assertEqual("FAILED", status.page.items[-1].start_state)

        committed, committed_start = self._committed_launch(
            route_request_key="idem2_" + "e" * 32,
        )
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            request_context(),
        )
        self.assertEqual(committed.attempt_id, identity.attempt_id)
        self.assertEqual("gpt-5.6-luna", identity.model)
        self.assertEqual(3001, identity.pid)
        attestation = {
            "disposition": "MATCH",
            "attemptId": committed.attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }
        running = self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )
        self.assertEqual("RUNNING", running.state)
        self.assertFalse(running.terminal)
        intermediate = self.store.read_start_status(
            committed_start.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("STARTED", intermediate.state)
        self.assertFalse(intermediate.terminal)
        self.assertIsNone(intermediate.terminal_result)
        attempt = self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result={
                "summary": "Готово.",
                "validationState": "passed",
                "artifactId": "",
            },
            attestation=attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=9),
        )
        self.assertEqual("SUCCEEDED", attempt.state)
        self.assertTrue(attempt.terminal)
        launch_status = self.store.read_start_status(
            committed_start.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("SUCCEEDED", launch_status.state)
        self.assertTrue(launch_status.terminal)
        self.assertIsNone(launch_status.page.next_cursor)
        self.assertEqual("ROUTE_COMPLETED", launch_status.page.items[-1].kind)
        self.assertEqual("SUCCEEDED", launch_status.page.items[-1].start_state)
        terminal = launch_status.terminal_result
        self.assertIsNotNone(terminal)
        self.assertEqual(committed.attempt_id, terminal.attempt_id)
        self.assertEqual("SUCCEEDED", terminal.state)
        self.assertEqual(
            {
                "summary": "Готово.",
                "validationState": "passed",
                "artifactId": "",
            },
            terminal.inline_result,
        )
        self.assertFalse(terminal.result_truncated)
        self.assertIsNone(terminal.error_code)
        self.assertRegex(terminal.result_fingerprint or "", r"^[0-9a-f]{64}$")
        self.assertGreater(terminal.result_bytes, 0)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [
                    (
                        "SUCCEEDED",
                        '{"artifactId":"","summary":"Готово.",'
                        '"validationState":"passed"}',
                    )
                ],
                connection.execute(
                    "select state,result_json from nodes where route_id=?",
                    (committed.route_id,),
                ).fetchall(),
            )
            route_state, encoded_route_result = connection.execute(
                "select state,terminal_result_json from routes where route_id=?",
                (committed.route_id,),
            ).fetchone()
            self.assertEqual("SUCCEEDED", route_state)
            route_result = json.loads(encoded_route_result)
            self.assertEqual(1, len(route_result["nodes"]))
            route_node_result = route_result["nodes"][0]
            self.assertEqual(
                {
                    "artifactId": "",
                    "summary": "Готово.",
                    "validationState": "passed",
                },
                route_node_result["inlineResult"],
            )
            self.assertFalse(route_node_result["resultTruncated"])
            self.assertEqual(
                len(
                    '{"artifactId":"","summary":"Готово.",'
                    '"validationState":"passed"}'.encode("utf-8")
                ),
                route_node_result["rawResultBytes"],
            )
        quiescence = self.store.quiescence_snapshot(barrier_held=True)
        self.assertEqual(0, quiescence.work_counts["activeAttempts"])
        self.assertEqual(0, quiescence.work_counts["nonterminalNodes"])
        self.assertEqual(0, quiescence.work_counts["nonterminalRoutes"])

    def test_terminal_start_paginates_every_remaining_event(self) -> None:
        committed, started = self._committed_launch()
        attestation = self._attempt_attestation(committed.attempt_id)
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )
        self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result={"summary": "Готово."},
            attestation=attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=9),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            expected_count = connection.execute(
                "select count(*) from events where route_id=? and code=?",
                (committed.route_id, started.start_request_id),
            ).fetchone()[0]

        cursor = None
        items = []
        while True:
            page = self.store.read_start_status(
                started.start_request_id,
                request_context(),
                cursor=cursor,
                page_size=1,
            )
            self.assertTrue(page.terminal)
            items.extend(page.page.items)
            if page.page.next_cursor is None:
                break
            cursor = page.page.next_cursor

        self.assertEqual(expected_count, len(items))
        self.assertEqual(
            sorted(item.sequence for item in items),
            [item.sequence for item in items],
        )
        self.assertEqual(len(items), len({item.sequence for item in items}))
        self.assertEqual("ROUTE_COMPLETED", items[-1].kind)

    def test_large_terminal_result_is_bounded_and_replay_adds_no_event(self) -> None:
        committed, started = self._committed_launch()
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            request_context(),
        )
        attestation = {
            "disposition": "MATCH",
            "attemptId": committed.attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )
        large_result = {"summary": "я" * 9000}
        arguments = {
            "state": "QUARANTINED",
            "result": large_result,
            "attestation": attestation,
            "error_code": "VALIDATION_FAILED",
            "error_message": "Кандидат помещён в карантин.",
        }
        first = self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=9),
        )
        replay = self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            **arguments,
            now=NOW + timedelta(seconds=10),
        )

        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("QUARANTINED", status.state)
        self.assertTrue(status.terminal)
        terminal = status.terminal_result
        self.assertIsNotNone(terminal)
        self.assertEqual(
            {"summary": "я" * 4000},
            terminal.inline_result,
        )
        self.assertTrue(terminal.result_truncated)
        self.assertEqual("VALIDATION_FAILED", terminal.error_code)
        self.assertGreater(terminal.result_bytes, 8192)
        self.assertEqual(
            1,
            sum(item.kind == "ROUTE_COMPLETED" for item in status.page.items),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            encoded_route_result = connection.execute(
                "select terminal_result_json from routes where route_id=?",
                (committed.route_id,),
            ).fetchone()[0]
        self.assertLess(len(encoded_route_result.encode("utf-8")), 4 * 1024)
        projected = json.loads(encoded_route_result)["nodes"][0]
        raw = canonical_json_v1(large_result).encode("utf-8")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), projected["rawResultFingerprint"])
        self.assertEqual(len(raw), projected["rawResultBytes"])
        self.assertTrue(projected["resultTruncated"])

    def test_writer_publication_is_returned_with_terminal_agent_message(
        self,
    ) -> None:
        publication = {
            "contractVersion": "writer-publication-v2",
            "state": "VERIFIED",
            "artifactId": "art1_" + "a" * 43,
            "ref": "refs/codex-smart/candidates/example",
            "refPublished": True,
        }
        inline, truncated = _bounded_inline_terminal_result(
            {
                "events": [
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": json.dumps(
                                {
                                    "summary": "Изменение подготовлено.",
                                    "validationState": "passed",
                                },
                                ensure_ascii=False,
                            ),
                        },
                    }
                ],
                "writerPublication": publication,
            }
        )

        self.assertFalse(truncated)
        self.assertEqual("Изменение подготовлено.", inline["summary"])
        self.assertEqual(publication, inline["writerPublication"])

    def test_node_completion_does_not_claim_route_completion_while_peer_is_planned(
        self,
    ) -> None:
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        committed, started = self._committed_launch(
            planned_nodes=(node(), peer),
        )
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            request_context(),
        )
        attestation = {
            "disposition": "MATCH",
            "attemptId": committed.attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )
        self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result={"summary": "Первый узел завершён."},
            attestation=attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=9),
        )

        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        kinds = [item.kind for item in status.page.items]
        self.assertIn("CHILD_SUCCEEDED", kinds)
        self.assertNotIn("ROUTE_COMPLETED", kinds)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("RUNNING",)],
                connection.execute("select state from routes").fetchall(),
            )

    def test_dependent_node_starts_only_after_all_dependencies_succeed(self) -> None:
        first_reader = node()
        second_reader = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
        )
        writer = replace(
            node("node2_" + "c" * 32),
            ordinal=2,
            role="implementer",
            dependencies=(first_reader.node_id, second_reader.node_id),
        )
        committed, _ = self._committed_launch(
            planned_nodes=(first_reader, second_reader, writer)
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_start_request(
                route_id=committed.route_id,
                node_id=writer.node_id,
                request_context=request_context(),
                deadline_at=NOW + timedelta(seconds=180),
                now=NOW + timedelta(seconds=8),
            )
        self.assertEqual("NODE_DEPENDENCIES_INCOMPLETE", caught.exception.code)

        attestation = self._attempt_attestation(committed.attempt_id)
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=9),
        )
        first_summary = "Первый читатель собрал доказательства."
        first_result = {
            "events": [
                {"type": "tool.output", "payload": "x" * (96 * 1024)},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps(
                            {"summary": first_summary},
                            ensure_ascii=False,
                        ),
                    },
                },
            ]
        }
        self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result=first_result,
            attestation=attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=10),
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_start_request(
                route_id=committed.route_id,
                node_id=writer.node_id,
                request_context=request_context(),
                deadline_at=NOW + timedelta(seconds=180),
                now=NOW + timedelta(seconds=11),
            )
        self.assertEqual("NODE_DEPENDENCIES_INCOMPLETE", caught.exception.code)

        second_committed, _ = self._commit_existing_node(
            route_id=committed.route_id,
            planned_node=second_reader,
            offset=12,
            pid=3002,
            process_marker="pid-3002-start",
            token_hash="1" * 64,
            permission_probe_id="pc2_" + "b" * 32,
        )
        second_attestation = self._attempt_attestation(second_committed.attempt_id)
        self.store.record_attempt_started(
            second_committed.attempt_id,
            request_context(),
            attestation=second_attestation,
            now=NOW + timedelta(seconds=18),
        )
        second_result = {
            "summary": "Второй читатель проверил независимый источник.",
            "evidenceRefs": ["repository:other.py:24"],
        }
        self.store.record_attempt_terminal(
            second_committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result=second_result,
            attestation=second_attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=19),
        )

        writer_start = self.store.create_start_request(
            route_id=committed.route_id,
            node_id=writer.node_id,
            request_context=request_context(),
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=20),
        )
        self.store.claim_account_evidence_job(
            writer_start.evidence_job_id,
            owner_id="evidence-worker-2",
            pid=2002,
            process_start_marker="pid-2002-start",
            current_stage="requirements-a",
            now=NOW + timedelta(seconds=21),
        )
        self.store.complete_account_evidence_job(
            writer_start.evidence_job_id,
            account_catalog_fingerprint=HEX["account_catalog"],
            account_context_fingerprint=HEX["account_context"],
            record_fingerprint=HEX["record"],
            now=NOW + timedelta(seconds=22),
        )

        plan = self.store.read_node_plan(
            committed.route_id,
            writer.node_id,
            request_context(),
        )
        self.assertEqual(
            (first_reader.node_id, second_reader.node_id),
            plan.node.dependencies,
        )
        self.assertEqual(
            [
                (first_reader.node_id, {"summary": first_summary}),
                (second_reader.node_id, second_result),
            ],
            [
                (dependency.node_id, dependency.result)
                for dependency in plan.dependency_results
            ],
        )
        first_dependency, second_dependency = plan.dependency_results
        first_raw = canonical_json_v1(first_result).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(first_raw).hexdigest(),
            first_dependency.raw_result_fingerprint,
        )
        self.assertEqual(len(first_raw), first_dependency.raw_result_bytes)
        self.assertTrue(first_dependency.result_truncated)
        self.assertLessEqual(
            len(canonical_json_v1(first_dependency.result).encode("utf-8")),
            2 * 1024,
        )
        self.assertFalse(second_dependency.result_truncated)
        for dependency in plan.dependency_results:
            projection = {
                "nodeId": dependency.node_id,
                "result": dependency.result,
                "rawResultFingerprint": dependency.raw_result_fingerprint,
                "rawResultBytes": dependency.raw_result_bytes,
                "resultTruncated": dependency.result_truncated,
            }
            self.assertEqual(
                domain_fingerprint(
                    "codex-smart/dependency-result-projection/v2",
                    projection,
                ),
                dependency.projection_fingerprint,
            )

    def test_start_request_key_replays_before_and_after_terminal_state(self) -> None:
        first_node = node()
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        idempotency_key = "idem2_" + "d" * 32
        committed, started = self._committed_launch(
            planned_nodes=(first_node, peer),
            idempotency_key=idempotency_key,
        )

        replay_before_terminal = self.store.create_start_request(
            route_id=committed.route_id,
            node_id=first_node.node_id,
            request_context=request_context(),
            idempotency_key=idempotency_key,
            activation_gate_fingerprint=activation_gate()["gateFingerprint"],
            deadline_at=NOW + timedelta(seconds=170),
            now=NOW + timedelta(seconds=8),
        )
        self.assertEqual(started.start_request_id, replay_before_terminal.start_request_id)
        self.assertEqual(started.evidence_job_id, replay_before_terminal.evidence_job_id)
        self.assertTrue(replay_before_terminal.replayed)

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_start_request(
                route_id=committed.route_id,
                node_id=peer.node_id,
                request_context=request_context(),
                idempotency_key=idempotency_key,
                activation_gate_fingerprint=activation_gate()["gateFingerprint"],
                deadline_at=NOW + timedelta(seconds=170),
                now=NOW + timedelta(seconds=8),
            )
        self.assertEqual("START_REQUEST_REPLAY_CONFLICT", caught.exception.code)

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.create_start_request(
                route_id=committed.route_id,
                node_id=first_node.node_id,
                request_context=request_context(),
                idempotency_key=idempotency_key,
                activation_gate_fingerprint="f" * 64,
                deadline_at=NOW + timedelta(seconds=170),
                now=NOW + timedelta(seconds=8),
            )
        self.assertEqual("START_REQUEST_REPLAY_CONFLICT", caught.exception.code)

        attestation = self._attempt_attestation(committed.attempt_id)
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=9),
        )
        self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result={"summary": "Первый узел завершён."},
            attestation=attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=10),
        )

        replay_after_terminal = self.store.create_start_request(
            route_id=committed.route_id,
            node_id=first_node.node_id,
            request_context=request_context(),
            idempotency_key=idempotency_key,
            activation_gate_fingerprint=activation_gate()["gateFingerprint"],
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=11),
        )
        self.assertEqual(started.start_request_id, replay_after_terminal.start_request_id)
        self.assertTrue(replay_after_terminal.replayed)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                (1, 1, 1),
                (
                    connection.execute("select count(*) from start_requests").fetchone()[0],
                    connection.execute(
                        "select count(*) from account_evidence_jobs"
                    ).fetchone()[0],
                    connection.execute(
                        "select count(*) from intents "
                        "where kind='START_REQUEST_IDEMPOTENCY_V2'"
                    ).fetchone()[0],
                ),
            )

    def test_resumed_owner_accepts_only_historical_or_current_epoch(self) -> None:
        historical = request_context()
        first_node = node()
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        binding = self.store.issue_turn_binding(
            historical,
            ttl_seconds=120,
            now=NOW,
        )
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=historical,
            request_key="idem2_" + "a" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(first_node, peer),
            now=NOW + timedelta(seconds=1),
        )
        start_key = "idem2_" + "b" * 32
        gate_fingerprint = str(activation_gate()["gateFingerprint"])
        first = self.store.create_start_request(
            route_id=route_id,
            node_id=first_node.node_id,
            request_context=historical,
            idempotency_key=start_key,
            activation_gate_fingerprint=gate_fingerprint,
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=2),
        )

        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "update controller_state set control_epoch=8 where singleton=1"
            )
            connection.commit()
        self.store = SmartStoreV2(
            self.path,
            database_identity=database_identity(),
            controller=replace(controller(), control_epoch=8),
        )
        current = replace(historical, issued_control_epoch=8)
        replay = self.store.create_start_request(
            route_id=route_id,
            node_id=first_node.node_id,
            request_context=current,
            idempotency_key=start_key,
            activation_gate_fingerprint=gate_fingerprint,
            deadline_at=NOW + timedelta(seconds=181),
            now=NOW + timedelta(seconds=3),
        )
        self.assertEqual(first.start_request_id, replay.start_request_id)
        self.assertTrue(replay.replayed)
        for accepted in (historical, current):
            self.assertEqual(
                "ATTESTING",
                self.store.read_start_status(
                    first.start_request_id,
                    accepted,
                    cursor=None,
                    page_size=20,
                ).state,
            )
        with patch.object(
            self.store,
            "_require_accepting_controller",
            side_effect=StateStoreV2Error(
                "CONTROLLER_NOT_ACCEPTING",
                "controller is not accepting work",
            ),
        ):
            self.assertEqual(
                "ATTESTING",
                self.store.read_start_status(
                    first.start_request_id,
                    historical,
                    cursor=None,
                    page_size=20,
                ).state,
            )
            with self.assertRaises(StateStoreV2Error) as caught:
                self.store.read_start_status(
                    first.start_request_id,
                    current,
                    cursor=None,
                    page_size=20,
                )
            self.assertEqual("CONTROLLER_NOT_ACCEPTING", caught.exception.code)
        for rejected in (
            replace(current, issued_control_epoch=9),
            replace(current, turn_id="another-turn"),
        ):
            with self.subTest(rejected=rejected):
                with self.assertRaises(StateStoreV2Error) as caught:
                    self.store.read_start_status(
                        first.start_request_id,
                        rejected,
                        cursor=None,
                        page_size=20,
                    )
                self.assertEqual("START_OWNER_MISMATCH", caught.exception.code)

        self.store.cancel_start_request(
            first.start_request_id,
            current,
            idempotency_key="idem2_" + "c" * 32,
            reason_code="USER_REQUESTED",
            now=NOW + timedelta(seconds=4),
        )
        second = self.store.create_start_request(
            route_id=route_id,
            node_id=peer.node_id,
            request_context=current,
            deadline_at=NOW + timedelta(seconds=184),
            now=NOW + timedelta(seconds=5),
        )
        self.assertEqual(peer.node_id, second.node_id)
        self.assertEqual("ATTESTING", second.state)

    def test_bound_resume_authorizer_can_read_old_start_without_rewriting_owner(self) -> None:
        historical = request_context()
        first_node = node()
        peer = replace(node("node2_" + "b" * 32), ordinal=1)
        binding = self.store.issue_turn_binding(
            historical,
            ttl_seconds=120,
            now=NOW,
        )
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=historical,
            request_key="idem2_" + "c" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(first_node, peer),
            now=NOW + timedelta(seconds=1),
        )
        start = self.store.create_start_request(
            route_id=route_id,
            node_id=first_node.node_id,
            request_context=historical,
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=2),
        )
        current = replace(
            historical,
            shell_session_id="cas2_resumed",
            turn_id="turn-resumed",
        )
        self.store.close()
        self.store = SmartStoreV2(
            self.path,
            database_identity=database_identity(),
            controller=controller(),
            resume_authorizer=lambda candidate_route, candidate, stored: (
                candidate_route == route_id
                and candidate.session_id == stored.session_id
                and candidate.repo_root == stored.repo_root
            ),
        )

        status = self.store.read_start_status(
            start.start_request_id,
            current,
            cursor=None,
            page_size=20,
        )

        self.assertEqual("ATTESTING", status.state)
        with closing(sqlite3.connect(self.path)) as connection:
            stored_owner = connection.execute(
                "select shell_session_id,session_id,turn_id from routes where route_id=?",
                (route_id,),
            ).fetchone()
        self.assertEqual(
            (
                historical.shell_session_id,
                historical.session_id,
                historical.turn_id,
            ),
            stored_owner,
        )

        self.store.cancel_start_request(
            start.start_request_id,
            current,
            idempotency_key="idem2_" + "d" * 32,
            reason_code="SUPERSEDED",
            now=NOW + timedelta(seconds=3),
        )
        resumed_start = self.store.create_start_request(
            route_id=route_id,
            node_id=peer.node_id,
            request_context=current,
            deadline_at=NOW + timedelta(seconds=181),
            now=NOW + timedelta(seconds=4),
        )
        dispatch = next(
            item
            for item in self.store.queued_start_dispatches()
            if item.start_request_id == resumed_start.start_request_id
        )
        self.assertEqual(historical, dispatch.request_context)

    def test_failed_node_terminalizes_unstarted_descendants_and_route(self) -> None:
        reader = node()
        validator = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
            dependencies=(reader.node_id,),
        )
        writer = replace(
            node("node2_" + "c" * 32),
            ordinal=2,
            role="implementer",
            dependencies=(validator.node_id,),
        )
        committed, started = self._committed_launch(
            planned_nodes=(reader, validator, writer),
        )
        attestation = self._attempt_attestation(committed.attempt_id)
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )

        self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="FAILED",
            result={"summary": "Корневой узел завершился ошибкой."},
            attestation=attestation,
            error_code="CHILD_FAILED",
            error_message="Корневой узел завершился ошибкой.",
            now=NOW + timedelta(seconds=9),
        )

        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute(
                "select node_id,state,result_json from nodes order by ordinal"
            ).fetchall()
            self.assertEqual(["FAILED", "FAILED", "FAILED"], [row[1] for row in rows])
            for row in rows[1:]:
                blocked_result = json.loads(row[2])
                self.assertEqual("DEPENDENCY_FAILED", blocked_result["errorCode"])
                self.assertEqual(reader.node_id, blocked_result["failedDependencyNodeId"])
            route = connection.execute(
                "select state,terminal_result_json from routes"
            ).fetchone()
            self.assertEqual("FAILED", route[0])
            self.assertEqual(3, len(json.loads(route[1])["nodes"]))
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)

    def test_route_completed_event_uses_aggregated_failed_route_state(self) -> None:
        first_reader = node()
        second_reader = replace(node("node2_" + "b" * 32), ordinal=1)
        first_committed, _ = self._committed_launch(
            planned_nodes=(first_reader, second_reader)
        )
        first_attestation = self._attempt_attestation(first_committed.attempt_id)
        self.store.record_attempt_started(
            first_committed.attempt_id,
            request_context(),
            attestation=first_attestation,
            now=NOW + timedelta(seconds=8),
        )
        self.store.record_attempt_terminal(
            first_committed.attempt_id,
            request_context(),
            state="FAILED",
            result={"summary": "Первая независимая ветвь не завершилась."},
            attestation=first_attestation,
            error_code="CHILD_FAILED",
            error_message="Первая независимая ветвь не завершилась.",
            now=NOW + timedelta(seconds=9),
        )
        second_committed, second_start = self._commit_existing_node(
            route_id=first_committed.route_id,
            planned_node=second_reader,
            offset=10,
            pid=3002,
            process_marker="pid-3002-start",
            token_hash="1" * 64,
            permission_probe_id="pc2_" + "b" * 32,
        )
        second_attestation = self._attempt_attestation(second_committed.attempt_id)
        self.store.record_attempt_started(
            second_committed.attempt_id,
            request_context(),
            attestation=second_attestation,
            now=NOW + timedelta(seconds=16),
        )

        self.store.record_attempt_terminal(
            second_committed.attempt_id,
            request_context(),
            state="SUCCEEDED",
            result={"summary": "Вторая независимая ветвь завершилась."},
            attestation=second_attestation,
            error_code=None,
            error_message=None,
            now=NOW + timedelta(seconds=17),
        )

        status = self.store.read_start_status(
            second_start.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        self.assertEqual("FAILED", status.page.items[-1].start_state)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("FAILED",)],
                connection.execute("select state from routes").fetchall(),
            )

    def test_stranded_attempt_recovery_uses_dependency_failure_cascade(self) -> None:
        reader = node()
        writer = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
            role="implementer",
            dependencies=(reader.node_id,),
        )
        committed, _ = self._committed_launch(planned_nodes=(reader, writer))
        self.store.begin_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=8),
        )

        self.store.complete_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=9),
        )

        with closing(sqlite3.connect(self.path)) as connection:
            nodes = connection.execute(
                "select state,result_json from nodes order by ordinal"
            ).fetchall()
            self.assertEqual(["FAILED", "FAILED"], [row[0] for row in nodes])
            blocked_result = json.loads(nodes[1][1])
            self.assertEqual("DEPENDENCY_FAILED", blocked_result["errorCode"])
            self.assertEqual(reader.node_id, blocked_result["failedDependencyNodeId"])
            route = connection.execute(
                "select state,terminal_result_json from routes"
            ).fetchone()
            self.assertEqual("FAILED", route[0])
            self.assertEqual(2, len(json.loads(route[1])["nodes"]))

    def test_guarded_permit_can_be_failed_before_commit_without_attempt(self) -> None:
        reader = node()
        writer = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
            role="implementer",
            dependencies=(reader.node_id,),
        )
        committed_route, started = self._succeeded_evidence(
            planned_nodes=(reader, writer)
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=committed_route,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )

        aborted = self.store.abort_launch_permit_before_commit(
            permit.permit_id,
            request_context(),
            failure_code="GUARD_HELLO_MISMATCH",
            message="Сторож сообщил другую идентичность снимка.",
            now=NOW + timedelta(seconds=7),
        )

        self.assertEqual("FAILED_BEFORE_START", aborted.state)
        self.assertTrue(aborted.terminal)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("FAILED_BEFORE_START", "GUARD_HELLO_MISMATCH")],
                connection.execute(
                    "select state,failure_code from node_launch_permits"
                ).fetchall(),
            )
            self.assertEqual(
                0, connection.execute("select count(*) from attempts").fetchone()[0]
            )
            self.assertEqual(
                [("FAILED",), ("FAILED",)],
                connection.execute("select state from nodes order by ordinal").fetchall(),
            )
            self.assertEqual(
                [("FAILED",)],
                connection.execute("select state from routes").fetchall(),
            )
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("FAILED", status.state)
        self.assertTrue(status.terminal)
        self.assertEqual("CHILD_FAILED_BEFORE_START", status.page.items[-2].kind)
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        self.assertEqual("FAILED", status.page.items[-1].start_state)

    def test_admission_can_be_idempotently_failed_before_any_permit(self) -> None:
        reader = node()
        writer = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
            role="implementer",
            dependencies=(reader.node_id,),
        )
        committed_route, started = self._succeeded_evidence(
            planned_nodes=(reader, writer)
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=committed_route,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )

        first = self.store.abort_admission_before_permit(
            admission_id=admitted.admission_id,
            request_context=request_context(),
            failure_code="CHILD_PREPARATION_FAILED",
            message="Не удалось материализовать запуск.",
            now=NOW + timedelta(seconds=6),
        )
        replay = self.store.abort_admission_before_permit(
            admission_id=admitted.admission_id,
            request_context=request_context(),
            failure_code="CHILD_PREPARATION_FAILED",
            message="Повтор не меняет результат.",
            now=NOW + timedelta(seconds=7),
        )

        self.assertEqual("FAILED_BEFORE_START", first.state)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(0, connection.execute(
                "select count(*) from node_launch_permits"
            ).fetchone()[0])
            self.assertEqual(0, connection.execute(
                "select count(*) from attempts"
            ).fetchone()[0])
            self.assertEqual(
                [("FAILED", "ABORTED"), ("FAILED", None)],
                connection.execute(
                    "select state,admission_state from nodes order by ordinal"
                ).fetchall(),
            )
            self.assertEqual(
                [("FAILED",)],
                connection.execute("select state from routes").fetchall(),
            )
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("FAILED", status.state)
        self.assertEqual("CHILD_FAILED_BEFORE_START", status.page.items[-2].kind)
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        self.assertEqual("FAILED", status.page.items[-1].start_state)

    def test_committed_process_failure_before_mission_has_exact_terminal_event(
        self,
    ) -> None:
        committed, started = self._committed_launch()
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            request_context(),
        )
        attestation = {
            "disposition": "STALE",
            "attemptId": committed.attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }

        terminal = self.store.record_attempt_terminal(
            committed.attempt_id,
            request_context(),
            state="FAILED",
            result=None,
            attestation=attestation,
            error_code="CHILD_PERMISSION_PROFILE_CHANGED",
            error_message="Наблюдён другой профиль разрешений.",
            now=NOW + timedelta(seconds=8),
        )

        self.assertEqual("FAILED", terminal.state)
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("FAILED", status.state)
        event = status.page.items[-2]
        self.assertEqual("CHILD_FAILED_BEFORE_START", event.kind)
        self.assertEqual("FAILED", event.start_state)
        self.assertEqual(attestation, event.attestation)
        self.assertEqual("INTERNAL_ERROR", event.problem["code"])
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        self.assertEqual("FAILED", status.page.items[-1].start_state)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("STARTED",)],
                connection.execute("select state from node_launch_permits").fetchall(),
            )
            self.assertEqual(
                [("FAILED", "CHILD_PERMISSION_PROFILE_CHANGED")],
                connection.execute("select state,error_code from attempts").fetchall(),
            )
            self.assertEqual(
                [("FAILED", "STARTED")],
                connection.execute(
                    "select state,admission_state from nodes"
                ).fetchall(),
            )
            self.assertEqual(
                [("FAILED",)],
                connection.execute("select state from routes").fetchall(),
            )

    def test_stranded_starting_attempt_recovery_is_atomic_and_idempotent(
        self,
    ) -> None:
        committed, started = self._committed_launch()
        expected = {
            "attemptId": committed.attempt_id,
            "routeId": committed.route_id,
            "nodeId": committed.node_id,
            "state": "STARTING",
            "pid": 3001,
            "processStartMarker": "pid-3001-start",
        }
        self.assertEqual([expected], self.store.stranded_attempts())

        begun = self.store.begin_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=8),
        )
        replayed_begin = self.store.begin_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=9),
        )

        self.assertEqual("PENDING", begun["state"])
        self.assertFalse(begun["replayed"])
        self.assertTrue(replayed_begin["replayed"])
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("STARTING", None)],
                connection.execute("select state,error_code from attempts").fetchall(),
            )
            self.assertEqual(
                [("PENDING",)],
                connection.execute("select state from intents").fetchall(),
            )

        completed = self.store.complete_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=10),
        )
        replayed_complete = self.store.complete_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=11),
        )

        self.assertEqual("FAILED", completed["state"])
        self.assertEqual("CONTROLLER_RESTARTED", completed["errorCode"])
        self.assertFalse(completed["replayed"])
        self.assertTrue(replayed_complete["replayed"])
        self.assertEqual([], self.store.stranded_attempts())
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertTrue(status.terminal)
        self.assertEqual("FAILED", status.state)
        self.assertEqual("ROUTE_COMPLETED", status.page.items[-1].kind)
        with closing(sqlite3.connect(self.path)) as connection:
            for table, expected_state in (
                ("node_launch_permits", "STARTED"),
                ("attempts", "FAILED"),
                ("nodes", "FAILED"),
                ("routes", "FAILED"),
                ("intents", "COMPLETED"),
            ):
                with self.subTest(table=table):
                    self.assertEqual(
                        [(expected_state,)],
                        connection.execute(f"select state from {table}").fetchall(),
                    )
            self.assertEqual(
                [("FAILED", "CONTROLLER_RESTARTED")],
                connection.execute(
                    "select state,failure_code from start_requests"
                ).fetchall(),
            )

    def test_stranded_reserved_permit_recovery_has_no_process_identity(self) -> None:
        reader = node()
        writer = replace(
            node("node2_" + "b" * 32),
            ordinal=1,
            role="implementer",
            dependencies=(reader.node_id,),
        )
        route_id, started = self._succeeded_evidence(
            planned_nodes=(reader, writer)
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.assertEqual(
            [
                {
                    "permitId": permit.permit_id,
                    "routeId": route_id,
                    "nodeId": node().node_id,
                    "state": "RESERVED",
                    "guardPid": None,
                    "guardStartMarker": None,
                }
            ],
            self.store.stranded_launch_permits(),
        )

        begun = self.store.begin_stranded_permit_recovery(
            permit.permit_id,
            guard_pid=None,
            guard_start_marker=None,
            now=NOW + timedelta(seconds=7),
        )
        completed = self.store.complete_stranded_permit_recovery(
            permit.permit_id,
            guard_pid=None,
            guard_start_marker=None,
            now=NOW + timedelta(seconds=8),
        )

        self.assertEqual("PENDING", begun["state"])
        self.assertEqual("FAILED_BEFORE_START", completed["state"])
        self.assertEqual([], self.store.stranded_launch_permits())
        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("FAILED", status.state)
        self.assertTrue(status.terminal)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("FAILED",), ("FAILED",)],
                connection.execute("select state from nodes order by ordinal").fetchall(),
            )
            self.assertEqual(
                [("FAILED",)],
                connection.execute("select state from routes").fetchall(),
            )

    def test_stranded_guarded_permit_recovery_requires_exact_guard_identity(
        self,
    ) -> None:
        route_id, started = self._succeeded_evidence()
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=node().node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.begin_stranded_permit_recovery(
                permit.permit_id,
                guard_pid=3001,
                guard_start_marker="another-start",
                now=NOW + timedelta(seconds=7),
            )
        self.assertEqual(
            "LAUNCH_PERMIT_RECOVERY_IDENTITY_MISMATCH",
            caught.exception.code,
        )
        self.store.begin_stranded_permit_recovery(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=8),
        )
        completed = self.store.complete_stranded_permit_recovery(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=9),
        )

        self.assertEqual("FAILED_BEFORE_START", completed["state"])
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                [("FAILED_BEFORE_START", "CONTROLLER_RESTARTED")],
                connection.execute(
                    "select state,failure_code from node_launch_permits"
                ).fetchall(),
            )
            self.assertEqual(0, connection.execute(
                "select count(*) from attempts"
            ).fetchone()[0])

    def test_stranded_running_attempt_recovery_preserves_stored_attestation(
        self,
    ) -> None:
        committed, started = self._committed_launch()
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            request_context(),
        )
        attestation = {
            "disposition": "MATCH",
            "attemptId": committed.attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }
        self.store.record_attempt_started(
            committed.attempt_id,
            request_context(),
            attestation=attestation,
            now=NOW + timedelta(seconds=8),
        )
        self.store.begin_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=9),
        )

        self.store.complete_stranded_attempt_recovery(
            committed.attempt_id,
            pid=3001,
            process_start_marker="pid-3001-start",
            now=NOW + timedelta(seconds=10),
        )

        status = self.store.read_start_status(
            started.start_request_id,
            request_context(),
            cursor=None,
            page_size=100,
        )
        self.assertTrue(status.terminal)
        self.assertEqual("FAILED", status.state)
        assert status.terminal_result is not None
        self.assertEqual("CONTROLLER_RESTARTED", status.terminal_result.error_code)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "select state,attestation_json,error_code from attempts"
            ).fetchone()
            self.assertEqual("FAILED", row[0])
            self.assertEqual(attestation, json.loads(row[1]))
            self.assertEqual("CONTROLLER_RESTARTED", row[2])
            self.assertEqual(
                [("FAILED", "CONTROLLER_RESTARTED")],
                connection.execute(
                    "select state,failure_code from start_requests"
                ).fetchall(),
            )

    def test_stranded_attempt_recovery_rejects_another_process_identity(
        self,
    ) -> None:
        committed, _ = self._committed_launch()

        with self.assertRaises(StateStoreV2Error) as caught:
            self.store.begin_stranded_attempt_recovery(
                committed.attempt_id,
                pid=3001,
                process_start_marker="another-start-marker",
                now=NOW + timedelta(seconds=8),
            )

        self.assertEqual(
            "ATTEMPT_RECOVERY_IDENTITY_MISMATCH",
            caught.exception.code,
        )
        self.assertEqual("STARTING", self.store.stranded_attempts()[0]["state"])

    def _succeeded_evidence(
        self,
        *,
        leave_running: bool = False,
        planned_nodes: tuple[PlannedNodeV2, ...] | None = None,
        idempotency_key: str | None = None,
        route_request_key: str = "idem2_" + "3" * 32,
    ):
        context = request_context()
        effective_nodes = planned_nodes or (node(),)
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key=route_request_key,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=effective_nodes,
            now=NOW + timedelta(seconds=1),
        )
        started = self.store.create_start_request(
            route_id=route_id,
            node_id=effective_nodes[0].node_id,
            request_context=context,
            idempotency_key=idempotency_key,
            activation_gate_fingerprint=(
                activation_gate()["gateFingerprint"]
                if idempotency_key is not None
                else None
            ),
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=2),
        )
        self.store.claim_account_evidence_job(
            started.evidence_job_id,
            owner_id="evidence-worker-1",
            pid=2001,
            process_start_marker="pid-2001-start",
            current_stage="requirements-a",
            now=NOW + timedelta(seconds=3),
        )
        if not leave_running:
            self.store.complete_account_evidence_job(
                started.evidence_job_id,
                account_catalog_fingerprint=HEX["account_catalog"],
                account_context_fingerprint=HEX["account_context"],
                record_fingerprint=HEX["record"],
                now=NOW + timedelta(seconds=4),
            )
        return route_id, started

    def _queued_start(self):
        context = request_context()
        binding = self.store.issue_turn_binding(context, ttl_seconds=120, now=NOW)
        route_id = self.store.create_planned_route(
            binding_id=binding.binding_id,
            request_context=context,
            request_key="idem2_" + "7" * 32,
            request_hash=HEX["record"],
            catalog_generation="catalog-v2",
            algorithm_version="q+p+v+o-v2",
            disposition="DELEGATE",
            expires_at=NOW + timedelta(minutes=15),
            plan_output={"status": "PLANNED"},
            nodes=(node(),),
            now=NOW + timedelta(seconds=1),
        )
        started = self.store.create_start_request(
            route_id=route_id,
            node_id=node().node_id,
            request_context=context,
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=2),
        )
        return route_id, started

    def _committed_launch(
        self,
        *,
        planned_nodes: tuple[PlannedNodeV2, ...] | None = None,
        idempotency_key: str | None = None,
        route_request_key: str = "idem2_" + "3" * 32,
    ):
        effective_nodes = planned_nodes or (node(),)
        route_id, started = self._succeeded_evidence(
            planned_nodes=effective_nodes,
            idempotency_key=idempotency_key,
            route_request_key=route_request_key,
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=effective_nodes[0].node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=5),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=6),
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )
        committed = self.store.commit_launch_permit(
            permit_id=permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-start",
            one_time_token_hash=HEX["token"],
            argv_fingerprint=HEX["argv"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            permission_probe_id="pc2_" + "a" * 32,
            codex_binary_sha256=HEX["binary"],
            now=NOW + timedelta(seconds=7),
        )
        return committed, started

    def _attempt_attestation(self, attempt_id: str) -> dict[str, str]:
        identity = self.store.read_attempt_launch_identity(
            attempt_id,
            request_context(),
        )
        return {
            "disposition": "MATCH",
            "attemptId": attempt_id,
            "routeId": identity.route_id,
            "nodeId": identity.node_id,
            "startRequestId": identity.start_request_id,
            "evidenceJobId": identity.evidence_job_id,
            "admissionId": identity.admission_id,
        }

    def _commit_existing_node(
        self,
        *,
        route_id: str,
        planned_node: PlannedNodeV2,
        offset: int,
        pid: int,
        process_marker: str,
        token_hash: str,
        permission_probe_id: str,
    ):
        started = self.store.create_start_request(
            route_id=route_id,
            node_id=planned_node.node_id,
            request_context=request_context(),
            deadline_at=NOW + timedelta(seconds=180),
            now=NOW + timedelta(seconds=offset),
        )
        self.store.claim_account_evidence_job(
            started.evidence_job_id,
            owner_id=f"evidence-worker-{pid}",
            pid=pid - 1000,
            process_start_marker=f"evidence-{process_marker}",
            current_stage="requirements-a",
            now=NOW + timedelta(seconds=offset + 1),
        )
        self.store.complete_account_evidence_job(
            started.evidence_job_id,
            account_catalog_fingerprint=HEX["account_catalog"],
            account_context_fingerprint=HEX["account_context"],
            record_fingerprint=HEX["record"],
            now=NOW + timedelta(seconds=offset + 2),
        )
        admitted = self.store.admit_node(
            start_request_id=started.start_request_id,
            evidence_job_id=started.evidence_job_id,
            route_id=route_id,
            node_id=planned_node.node_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            now=NOW + timedelta(seconds=offset + 3),
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admitted.admission_id,
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint=HEX["argv"],
            codex_snapshot_sha256=HEX["snapshot"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            now=NOW + timedelta(seconds=offset + 4),
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=pid,
            guard_start_marker=process_marker,
            one_time_token_hash=token_hash,
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
        )
        committed = self.store.commit_launch_permit(
            permit_id=permit.permit_id,
            guard_pid=pid,
            guard_start_marker=process_marker,
            one_time_token_hash=token_hash,
            argv_fingerprint=HEX["argv"],
            snapshot_identity_fingerprint=HEX["snapshot_identity"],
            activation_gate=activation_gate(),
            expected_control_epoch=7,
            permission_probe_id=permission_probe_id,
            codex_binary_sha256=HEX["binary"],
            now=NOW + timedelta(seconds=offset + 5),
        )
        return committed, started


if __name__ == "__main__":
    unittest.main()
