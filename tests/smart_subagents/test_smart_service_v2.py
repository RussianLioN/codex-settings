from __future__ import annotations

import copy
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.policy_bundle_v2 import load_policy_bundle_v2  # noqa: E402
from codex_smart_subagents.smart_service_v2 import (  # noqa: E402
    SmartServiceV2,
    SmartServiceV2Error,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.evidence import build_interface_evidence  # noqa: E402
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    RequestContextV2,
    SmartStoreV2,
    attempt_id_for_evidence_job,
)


NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
INTERFACE_VECTORS = json.loads(
    (ROOT / "docs/contracts/vectors/interface-evidence-v1.json").read_text(
        encoding="utf-8"
    )
)
INTERFACE = INTERFACE_VECTORS["base"]
BUNDLED_CATALOG_PROJECTION = INTERFACE_VECTORS["bundledCatalogFixture"]["projection"]


def _bundle():
    vectors = ROOT / "docs" / "contracts" / "vectors"
    return load_policy_bundle_v2(
        catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
        routing_vector_path=vectors / "routing-policy-v2.json",
        delegation_vector_path=vectors / "delegation-policy-v2.json",
        role_vector_path=vectors / "role-template-v1.json",
        child_profile_vector_path=vectors / "child-profile-v1.json",
    )


def _identity() -> DatabaseIdentityV2:
    return DatabaseIdentityV2(
        database_id="db2_" + "a" * 32,
        activation_binding_nonce="0" * 64,
        activation_id="act2_" + "b" * 64,
        activation_fingerprint="a" * 64,
        created_operation_id="op2_" + "c" * 32,
        created_at=NOW,
    )


def _controller(bundle) -> AcceptingControllerV2:
    return AcceptingControllerV2(
        controller_identity="d" * 64,
        instance_id="ci2_" + "e" * 32,
        controller_start_id="cs2_" + "f" * 32,
        controller_pid=1001,
        controller_process_start_marker="pid-1001-start-7",
        controller_process_group_id=1001,
        control_epoch=7,
        activation_id=_identity().activation_id,
        activation_fingerprint="a" * 64,
        compatibility_fingerprint=INTERFACE["compatibilityFingerprint"],
        routing_policy_fingerprint=bundle.router.policy_fingerprint,
        bundled_catalog_fingerprint="d" * 64,
        socket_path="/tmp/codex-smart-v2-service.sock",
        socket_device=1,
        socket_inode=2,
        socket_owner_uid=os.getuid(),
        socket_owner_gid=os.getgid(),
        socket_mode="0600",
        updated_at=NOW,
    )


def _context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/Users/test/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
        activation_fingerprint="a" * 64,
        compatibility_fingerprint=INTERFACE["compatibilityFingerprint"],
        issued_control_epoch=7,
    )


def _routing_input() -> dict[str, object]:
    internal = json.loads(
        (ROOT / "docs/contracts/vectors/routing-input-v2.json").read_text(
            encoding="utf-8"
        )
    )["baseInput"]
    task_facts = internal["taskFacts"]
    return {
        "taskFacts": {
            "taskText": task_facts["taskText"],
            "evidence": task_facts["evidence"],
            "workShape": task_facts["workShape"],
            "factorClaims": task_facts["factorClaims"],
            "delegation": {
                "objectivelyVerifiable": task_facts["delegation"][
                    "objectivelyVerifiable"
                ],
                "independentWorkUnits": task_facts["delegation"][
                    "independentWorkUnits"
                ],
            },
            "hardFloorReasons": task_facts["hardFloorReasons"],
            "hardBanReasons": task_facts["hardBanReasons"],
        },
        "contextBundle": internal["contextBundle"],
        "roleTemplateId": internal["roleTemplateId"],
    }


def _routing_for_role(template_id: str) -> dict[str, object]:
    value = _routing_input()
    value["roleTemplateId"] = template_id
    required_kinds = {
        "researcher-v1": ("task-request", "source-excerpt", "dependency-summary"),
        "diagnostician-v1": (
            "task-request",
            "source-excerpt",
            "validation-result",
        ),
        "validator-v1": (
            "task-request",
            "validation-result",
            "dependency-summary",
        ),
        "risk_auditor-v1": (
            "task-request",
            "policy-excerpt",
            "dependency-summary",
        ),
        "implementer-v1": (
            "task-request",
            "repository-instruction",
            "dependency-summary",
        ),
    }[template_id]
    for entry, kind in zip(value["contextBundle"]["entries"], required_kinds):
        entry["kind"] = kind
    return value


def _sol_max_routing(template_id: str = "implementer-v1") -> dict[str, object]:
    value = _routing_for_role(template_id)
    work_shape = value["taskFacts"]["workShape"]
    for field, amount in (
        ("scopeUnits", 8),
        ("workUnits", 8),
        ("boundaries", 2),
        ("workstreams", 2),
    ):
        work_shape[field]["value"] = amount
    claims = value["taskFacts"]["factorClaims"]
    claims["q"]["q2-cross-boundary-invariant"] = {
        "state": "true",
        "evidenceRefIds": ["scope"],
    }
    claims["v"]["v2-release-or-migration"] = {
        "state": "true",
        "evidenceRefIds": ["scope"],
    }
    claims["o"]["o2-uncontracted-interface"] = {
        "state": "true",
        "evidenceRefIds": ["scope"],
    }
    return value


def _plan_node(
    client_node_id: str,
    routing_input: dict[str, object],
    *,
    dependencies: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "clientNodeId": client_node_id,
        "dependencyIds": list(dependencies),
        "routingInput": routing_input,
    }


def _single_plan_node(routing_input: dict[str, object]) -> list[dict[str, object]]:
    return [_plan_node("writer_a", routing_input)]


def _activation_gate() -> dict[str, object]:
    proof = {
        "schemaId": "absence-proof-v2",
        "schemaSha256": "1" * 64,
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
            "proofFingerprint": "2" * 64,
        },
        "valueFingerprint": "2" * 64,
    }
    projection = {
        "manifestSemanticFingerprint": "3" * 64,
        "activationReceiptFingerprint": "4" * 64,
        "journalAbsenceProof": proof,
    }
    return {
        **projection,
        "gateFingerprint": domain_fingerprint(
            "codex-smart/activation-gate/v2", projection
        ),
    }


class _AccountExecutor:
    def __init__(self, pairs: list[dict[str, str]]) -> None:
        self.pairs = copy.deepcopy(pairs)
        self.requirements: object = None
        self.calls: list[str] = []
        self.on_first_call = None

    def execute(self, stage: str, **_kwargs: object) -> object:
        self.calls.append(stage)
        if len(self.calls) == 1 and self.on_first_call is not None:
            self.on_first_call()
        if stage.startswith("requirements-"):
            return copy.deepcopy(self.requirements)
        return copy.deepcopy(self.pairs)


class SmartServiceV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = _bundle()
        self.path = Path(self.temporary.name) / "state" / "state-v2.sqlite3"
        self.store = SmartStoreV2(
            self.path,
            database_identity=_identity(),
            controller=_controller(self.bundle),
        )
        self.interface = copy.deepcopy(INTERFACE)
        self.account_executor = _AccountExecutor(list(self.bundle.policy_pairs))
        self.service = SmartServiceV2(
            store=self.store,
            policy_bundle=self.bundle,
            bundled_catalog_projection=BUNDLED_CATALOG_PROJECTION,
            activation_gate_verifier=lambda gate: dict(gate),
            clock=lambda: NOW,
            interface_evidence=self.interface,
            account_evidence_executor=self.account_executor,
            verify_snapshot_subject=lambda _subject: None,
            account_home="/private/home",
            account_tmpdir="/private/tmp",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _binding(self):
        return self.service.issue_turn_binding(_context(), ttl_seconds=120)

    def test_delegate_plan_selects_and_durably_records_exact_pair(self) -> None:
        binding = self._binding()
        routing = _routing_input()

        result = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "1" * 32,
            nodes=_single_plan_node(routing),
        )

        self.assertEqual("DELEGATE", result.disposition)
        self.assertEqual(
            {"model": "gpt-5.6-luna", "reasoningEffort": "low"},
            result.node_decisions[0].selected_pair,
        )
        self.assertEqual(1, len(result.node_decisions))
        self.assertRegex(result.route_id, r"^route2_[0-9a-f]{32}$")
        with closing(sqlite3.connect(self.path)) as connection:
            stored = connection.execute(
                "select selected_model,reasoning_effort,account_context_fingerprint,"
                "account_catalog_fingerprint from nodes where route_id=?",
                (result.route_id,),
            ).fetchone()
        self.assertEqual(("gpt-5.6-luna", "low", None, None), stored)

    def test_minimal_public_input_is_enriched_before_one_router_evaluation(
        self,
    ) -> None:
        binding = self._binding()
        public = _routing_input()
        observed: list[dict[str, object]] = []
        original_evaluate = self.bundle.router.evaluate

        def observe(candidate: dict[str, object]) -> dict[str, object]:
            observed.append(copy.deepcopy(candidate))
            return original_evaluate(candidate)

        self.bundle.router.evaluate = observe
        try:
            result = self.service.smart_plan(
                binding_id=binding.binding_id,
                request_context=_context(),
                request_key="idem2_" + "e" * 32,
                nodes=_single_plan_node(public),
            )
        finally:
            self.bundle.router.evaluate = original_evaluate

        self.assertEqual("DELEGATE", result.disposition)
        self.assertEqual(1, len(observed))
        enriched = observed[0]
        self.assertEqual("smart-plan", enriched["phase"])
        self.assertEqual(
            self.bundle.delegation_policy["policyId"],
            enriched["delegationPolicyRef"],
        )
        self.assertEqual([], enriched["accountEvidenceJobs"])
        self.assertEqual("initial", enriched["reassessment"]["mode"])
        self.assertEqual(
            "allow",
            enriched["taskFacts"]["delegation"]["permission"]["value"],
        )
        self.assertEqual(
            list(self.bundle.policy_pairs), enriched["catalogs"]["policyPairs"]
        )
        self.assertNotIn("permission", public["taskFacts"]["delegation"])

    def test_service_fields_are_rejected_before_router_evaluation(self) -> None:
        original_evaluate = self.bundle.router.evaluate
        calls = 0

        def observe(candidate: dict[str, object]) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return original_evaluate(candidate)

        self.bundle.router.evaluate = observe
        try:
            attackers: list[dict[str, object]] = []
            for field, value in (
                ("model", "attacker-choice"),
                ("reasoningEffort", "max"),
                ("catalogs", {}),
                ("accountEvidenceJobs", []),
                ("reassessment", {}),
            ):
                candidate = _routing_input()
                candidate[field] = value
                attackers.append(candidate)
            permission = _routing_input()
            permission["taskFacts"]["delegation"]["permission"] = {
                "value": "forbid",
                "evidenceRefIds": ["policy"],
            }
            attackers.append(permission)
            missing_permission = _routing_input()
            missing_permission["taskFacts"]["hardBanReasons"] = [
                {
                    "reason": "delegation-not-explicitly-allowed",
                    "decision": "direct",
                    "evidenceRefIds": ["policy"],
                }
            ]
            attackers.append(missing_permission)

            for index, candidate in enumerate(attackers):
                binding = self._binding()
                with self.subTest(index=index):
                    with self.assertRaises(SmartServiceV2Error):
                        self.service.smart_plan(
                            binding_id=binding.binding_id,
                            request_context=_context(),
                            request_key="idem2_" + f"{index + 1:x}" * 32,
                            nodes=_single_plan_node(candidate),
                        )
        finally:
            self.bundle.router.evaluate = original_evaluate

        self.assertEqual(0, calls)

    def test_entire_public_schema_is_enforced_before_router_evaluation(self) -> None:
        original_evaluate = self.bundle.router.evaluate
        calls = 0

        def observe(candidate: dict[str, object]) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return original_evaluate(candidate)

        invalid: list[tuple[str, dict[str, object]]] = []

        bogus_state = _routing_input()
        bogus_state["taskFacts"]["factorClaims"]["q"]["q2-cross-boundary-invariant"][
            "state"
        ] = "bogus"
        invalid.append(("criterion-state", bogus_state))

        for label, amount in (
            ("negative-count", -1),
            ("boolean-count", True),
            ("oversized-count", 10001),
        ):
            bad_count = _routing_input()
            bad_count["taskFacts"]["workShape"]["scopeUnits"]["value"] = amount
            invalid.append((label, bad_count))

        bad_kind = _routing_input()
        bad_kind["taskFacts"]["evidence"][0]["kind"] = "bogus"
        invalid.append(("evidence-kind", bad_kind))

        bad_evidence_field = _routing_input()
        bad_evidence_field["taskFacts"]["evidence"][0]["extra"] = True
        invalid.append(("evidence-extra-field", bad_evidence_field))

        bad_context_boolean = _routing_input()
        bad_context_boolean["contextBundle"]["entries"][0]["required"] = "yes"
        invalid.append(("context-boolean", bad_context_boolean))

        empty_task = _routing_input()
        empty_task["taskFacts"]["taskText"] = ""
        invalid.append(("empty-task", empty_task))

        bad_sha = _routing_input()
        bad_sha["taskFacts"]["evidence"][0]["sha256"] = "not-a-sha256"
        invalid.append(("evidence-sha", bad_sha))

        bad_delegation_boolean = _routing_input()
        bad_delegation_boolean["taskFacts"]["delegation"]["objectivelyVerifiable"][
            "value"
        ] = "yes"
        invalid.append(("delegation-boolean", bad_delegation_boolean))

        self.bundle.router.evaluate = observe
        try:
            for index, (label, candidate) in enumerate(invalid, start=1):
                binding = self._binding()
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        SmartServiceV2Error,
                        "PUBLIC_SCHEMA_INVALID",
                    ):
                        self.service.smart_plan(
                            binding_id=binding.binding_id,
                            request_context=_context(),
                            request_key="idem2_" + f"{index:032x}",
                            nodes=_single_plan_node(candidate),
                        )
        finally:
            self.bundle.router.evaluate = original_evaluate

        self.assertEqual(0, calls)

    def test_server_enrichment_fills_reserved_sixty_fourth_evidence_slot(
        self,
    ) -> None:
        public = _routing_input()
        evidence = public["taskFacts"]["evidence"]
        for index in range(60):
            evidence.append(
                {
                    "evidenceRefId": f"extra-{index:02d}",
                    "kind": "repository-file",
                    "statement": f"Дополнительный факт {index}.",
                    "sha256": f"{index + 16:064x}",
                }
            )
        observed_counts: list[int] = []
        original_evaluate = self.bundle.router.evaluate

        def observe(candidate: dict[str, object]) -> dict[str, object]:
            observed_counts.append(len(candidate["taskFacts"]["evidence"]))
            return original_evaluate(candidate)

        self.bundle.router.evaluate = observe
        try:
            binding = self._binding()
            result = self.service.smart_plan(
                binding_id=binding.binding_id,
                request_context=_context(),
                request_key="idem2_" + "f" * 32,
                nodes=_single_plan_node(public),
            )
        finally:
            self.bundle.router.evaluate = original_evaluate

        self.assertEqual("DELEGATE", result.disposition)
        self.assertEqual([64], observed_counts)

    def test_direct_plan_is_terminal_and_never_collects_account_evidence(self) -> None:
        binding = self._binding()
        routing = _routing_input()
        routing["taskFacts"]["hardBanReasons"] = [
            {
                "reason": "delegation-explicitly-forbidden",
                "decision": "direct",
                "evidenceRefIds": ["policy"],
            }
        ]

        result = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "2" * 32,
            nodes=_single_plan_node(routing),
        )

        self.assertEqual("DIRECT", result.disposition)
        self.assertIsNone(result.node_decisions[0].selected_pair)
        with closing(sqlite3.connect(self.path)) as connection:
            route = connection.execute(
                "select state,startable from routes where route_id=?",
                (result.route_id,),
            ).fetchone()
            evidence_count = connection.execute(
                "select count(*) from account_evidence_jobs"
            ).fetchone()[0]
        self.assertEqual(("DIRECT", 0), route)
        self.assertEqual(0, evidence_count)

    def test_deadline_after_evidence_claim_keeps_exact_terminal_code(self) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "0" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        times = iter(
            (
                started.deadline_at - timedelta(microseconds=1),
                started.deadline_at + timedelta(microseconds=1),
                started.deadline_at + timedelta(microseconds=2),
            )
        )
        self.service.clock = lambda: next(times)

        with self.assertRaises(SmartServiceV2Error) as caught:
            self.service.process_account_evidence(
                start_request=started,
                request_context=_context(),
                activation_gate=_activation_gate(),
                owner_id="evidence-worker-deadline",
                pid=4321,
                process_start_marker="pid-4321-deadline",
            )

        status = self.store.read_start_status(
            started.start_request_id,
            _context(),
            cursor=None,
            page_size=20,
        )
        self.assertEqual("REQUEST_DEADLINE_EXCEEDED", caught.exception.code)
        self.assertEqual("FAILED", status.state)
        event = next(
            item for item in status.page.items if item.kind == "EVIDENCE_FAILED"
        )
        self.assertEqual("REQUEST_DEADLINE_EXCEEDED", event.problem["code"])
        self.assertEqual([], self.account_executor.calls)

    def test_same_request_is_idempotent_with_deterministic_node_identity(self) -> None:
        binding = self._binding()
        arguments = {
            "binding_id": binding.binding_id,
            "request_context": _context(),
            "request_key": "idem2_" + "3" * 32,
            "nodes": _single_plan_node(_routing_input()),
        }
        first = self.service.smart_plan(**arguments)
        started = self.service.route_start(
            route_id=first.route_id,
            node_id=first.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        admission = self.service.process_account_evidence(
            start_request=started,
            request_context=_context(),
            activation_gate=_activation_gate(),
            owner_id="evidence-worker-replay",
            pid=4321,
            process_start_marker="pid-4321-replay",
        )
        permit = self.store.reserve_launch_permit(
            admission_id=admission.admission_id,
            activation_gate=_activation_gate(),
            expected_control_epoch=7,
            argv_fingerprint="6" * 64,
            codex_snapshot_sha256="7" * 64,
            snapshot_identity_fingerprint="8" * 64,
            now=NOW,
        )
        self.store.record_guard_hello(
            permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-replay",
            one_time_token_hash="0" * 64,
            snapshot_identity_fingerprint="8" * 64,
        )
        committed = self.store.commit_launch_permit(
            permit_id=permit.permit_id,
            guard_pid=3001,
            guard_start_marker="pid-3001-replay",
            one_time_token_hash="0" * 64,
            argv_fingerprint="6" * 64,
            snapshot_identity_fingerprint="8" * 64,
            activation_gate=_activation_gate(),
            expected_control_epoch=7,
            permission_probe_id="pc2_" + "a" * 32,
            codex_binary_sha256="9" * 64,
            now=NOW,
        )
        identity = self.store.read_attempt_launch_identity(
            committed.attempt_id,
            _context(),
        )
        self.store.record_attempt_started(
            committed.attempt_id,
            _context(),
            attestation={
                "disposition": "MATCH",
                "attemptId": committed.attempt_id,
                "routeId": identity.route_id,
                "nodeId": identity.node_id,
                "startRequestId": identity.start_request_id,
                "evidenceJobId": identity.evidence_job_id,
                "admissionId": identity.admission_id,
            },
            now=NOW,
        )
        self.service.clock = lambda: NOW.replace(minute=1)

        second = self.service.smart_plan(**arguments)

        self.assertEqual(first.route_id, second.route_id)
        self.assertEqual(first.disposition, second.disposition)
        self.assertEqual(first.node_decisions, second.node_decisions)
        self.assertEqual(first.plan_fingerprint, second.plan_fingerprint)
        self.assertFalse(first.replayed)
        self.assertEqual("PLANNED", first.route_state)
        self.assertTrue(second.replayed)
        self.assertEqual("RUNNING", second.route_state)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                1,
                connection.execute("select count(*) from routes").fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute("select count(*) from nodes").fetchone()[0],
            )
            self.assertEqual(
                [("RUNNING",)],
                connection.execute("select state from routes").fetchall(),
            )

    def test_repeated_plan_binding_key_does_not_create_consumed_binding_rows(
        self,
    ) -> None:
        binding_key = "idem2_" + "a" * 32
        plan_key = "idem2_" + "b" * 32
        nodes = _single_plan_node(_routing_input())
        first_binding = self.service.issue_turn_binding(
            _context(),
            ttl_seconds=120,
            request_key=binding_key,
        )
        first = self.service.smart_plan(
            binding_id=first_binding.binding_id,
            request_context=_context(),
            request_key=plan_key,
            nodes=nodes,
        )

        second_binding = self.service.issue_turn_binding(
            _context(),
            ttl_seconds=120,
            request_key=binding_key,
        )
        second = self.service.smart_plan(
            binding_id=second_binding.binding_id,
            request_context=_context(),
            request_key=plan_key,
            nodes=nodes,
        )

        self.assertEqual(first_binding.binding_id, second_binding.binding_id)
        self.assertTrue(second_binding.replayed)
        self.assertEqual("CONSUMED", second_binding.state)
        self.assertEqual(first.route_id, second.route_id)
        self.assertTrue(second.replayed)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                (1, 1),
                (
                    connection.execute("select count(*) from turn_bindings").fetchone()[
                        0
                    ],
                    connection.execute("select count(*) from routes").fetchone()[0],
                ),
            )

    def test_route_start_only_queues_fresh_evidence_and_creates_no_admission(
        self,
    ) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "4" * 32,
            nodes=_single_plan_node(_routing_input()),
        )

        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate={"gateFingerprint": "f" * 64},
        )

        self.assertEqual("ATTESTING", started.state)
        self.assertRegex(started.start_request_id, r"^sr2_[0-9a-f]{32}$")
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "select s.admission_id,j.state,j.account_context_fingerprint "
                "from start_requests s join account_evidence_jobs j "
                "on j.evidence_job_id=s.evidence_job_id "
                "where s.start_request_id=?",
                (started.start_request_id,),
            ).fetchone()
        self.assertEqual((None, "QUEUED", None), row)

    def test_restarted_controller_admits_historical_queued_owner_with_live_epoch(
        self,
    ) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "d" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "update controller_state set control_epoch=8 where singleton=1"
            )
            connection.commit()
        self.store = SmartStoreV2(
            self.path,
            database_identity=_identity(),
            controller=replace(_controller(self.bundle), control_epoch=8),
        )
        self.service = SmartServiceV2(
            store=self.store,
            policy_bundle=self.bundle,
            bundled_catalog_projection=BUNDLED_CATALOG_PROJECTION,
            activation_gate_verifier=lambda gate: dict(gate),
            live_control_epoch_provider=lambda: 8,
            clock=lambda: NOW,
            interface_evidence=self.interface,
            account_evidence_executor=self.account_executor,
            verify_snapshot_subject=lambda _subject: None,
            account_home="/private/home",
            account_tmpdir="/private/tmp",
        )

        admission = self.service.process_account_evidence(
            start_request=started,
            request_context=_context(),
            activation_gate=_activation_gate(),
            owner_id="evidence-worker-restart",
            pid=4321,
            process_start_marker="pid-4321-restart",
        )

        self.assertEqual("ADMITTED", admission.state)
        self.assertEqual(7, _context().issued_control_epoch)
        self.assertEqual(
            "READY",
            self.store.read_start_request(
                started.start_request_id,
                _context(),
            ).state,
        )

    def test_evidence_worker_reassesses_exact_pair_and_admits_node(self) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "5" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        barrier_depth = 0
        barrier_trace: list[str] = []

        @contextmanager
        def admission_barrier():
            nonlocal barrier_depth
            self.assertEqual(0, barrier_depth)
            barrier_depth = 1
            barrier_trace.append("enter")
            try:
                yield
            finally:
                barrier_depth = 0
                barrier_trace.append("exit")

        self.account_executor.on_first_call = lambda: self.assertEqual(
            0,
            barrier_depth,
            "долгий сбор доказательств не должен удерживать барьер допуска",
        )

        admission = self.service.process_account_evidence(
            start_request=started,
            request_context=_context(),
            activation_gate=_activation_gate(),
            owner_id="evidence-worker-1",
            pid=4321,
            process_start_marker="pid-4321-start-1",
            admission_barrier=admission_barrier,
        )

        self.assertEqual(
            started.attempt_id,
            attempt_id_for_evidence_job(started.evidence_job_id),
        )
        self.assertEqual("ADMITTED", admission.state)
        self.assertEqual(["enter", "exit"], barrier_trace)
        self.assertEqual(
            [
                "requirements-a",
                "catalog-a",
                "requirements-b",
                "catalog-b",
                "requirements-c",
            ],
            self.account_executor.calls,
        )
        status = self.store.read_start_status(
            started.start_request_id,
            _context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("READY", status.state)
        self.assertIsNone(status.admission_id)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "select n.selected_model,n.reasoning_effort,n.account_context_fingerprint,"
                "j.state from nodes n join account_evidence_jobs j "
                "on j.evidence_job_id=n.evidence_job_id "
                "where n.node_id=?",
                (plan.node_decisions[0].node_id,),
            ).fetchone()
        self.assertEqual(plan.node_decisions[0].selected_pair["model"], row[0])
        self.assertEqual(
            plan.node_decisions[0].selected_pair["reasoningEffort"], row[1]
        )
        self.assertRegex(row[2], r"^[0-9a-f]{64}$")
        self.assertEqual("SUCCEEDED", row[3])

    def test_evidence_worker_rejects_forged_start_request_projection(self) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "7" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        second_binding = self._binding()
        second_plan = self.service.smart_plan(
            binding_id=second_binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "9" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        second = self.service.route_start(
            route_id=second_plan.route_id,
            node_id=second_plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        forged = replace(
            second,
            route_id=started.route_id,
            node_id=started.node_id,
        )

        with self.assertRaisesRegex(Exception, "START_REQUEST_OWNERSHIP_MISMATCH"):
            self.service.process_account_evidence(
                start_request=forged,
                request_context=_context(),
                activation_gate=_activation_gate(),
                owner_id="evidence-worker-1",
                pid=4321,
                process_start_marker="pid-4321-start-1",
            )

        self.assertEqual([], self.account_executor.calls)
        with closing(sqlite3.connect(self.path)) as connection:
            states = connection.execute(
                "select evidence_job_id,state from account_evidence_jobs order by queued_at"
            ).fetchall()
        self.assertEqual(
            [(started.evidence_job_id, "QUEUED"), (second.evidence_job_id, "QUEUED")],
            states,
        )

    def test_reassessment_rejects_stored_policy_generation_drift_before_claim(
        self,
    ) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "a" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "update routes set catalog_generation=? where route_id=?",
                ("f" * 64, plan.route_id),
            )
            connection.commit()

        with self.assertRaisesRegex(Exception, "ROUTE_POLICY_STALE"):
            self.service.process_account_evidence(
                start_request=started,
                request_context=_context(),
                activation_gate=_activation_gate(),
                owner_id="evidence-worker-1",
                pid=4321,
                process_start_marker="pid-4321-start-1",
            )

        with closing(sqlite3.connect(self.path)) as connection:
            state = connection.execute(
                "select s.state,j.state from start_requests s join account_evidence_jobs j "
                "on j.evidence_job_id=s.evidence_job_id where j.evidence_job_id=?",
                (started.evidence_job_id,),
            ).fetchone()
        self.assertEqual(("STALE", "FAILED"), state)

    def test_service_closes_interface_policy_and_bundled_catalog_fingerprints(
        self,
    ) -> None:
        semantic = copy.deepcopy(self.interface["semantic"])
        semantic["routingPolicyFingerprint"] = "f" * 64
        changed = build_interface_evidence(
            subject=self.interface["subject"],
            semantic=semantic,
            extensions=self.interface.get("extensions"),
        )
        with self.assertRaisesRegex(Exception, "ROUTING_POLICY_INTERFACE_DRIFT"):
            SmartServiceV2(
                store=self.store,
                policy_bundle=self.bundle,
                bundled_catalog_projection=BUNDLED_CATALOG_PROJECTION,
                activation_gate_verifier=lambda gate: dict(gate),
                clock=lambda: NOW,
                interface_evidence=changed,
                account_evidence_executor=self.account_executor,
                verify_snapshot_subject=lambda _subject: None,
                account_home="/private/home",
                account_tmpdir="/private/tmp",
            )

        semantic = copy.deepcopy(self.interface["semantic"])
        semantic["bundledCatalogFingerprint"] = "f" * 64
        changed = build_interface_evidence(
            subject=self.interface["subject"],
            semantic=semantic,
            extensions=self.interface.get("extensions"),
        )
        with self.assertRaisesRegex(Exception, "BUNDLED_CATALOG_INTERFACE_DRIFT"):
            SmartServiceV2(
                store=self.store,
                policy_bundle=self.bundle,
                bundled_catalog_projection=BUNDLED_CATALOG_PROJECTION,
                activation_gate_verifier=lambda gate: dict(gate),
                clock=lambda: NOW,
                interface_evidence=changed,
                account_evidence_executor=self.account_executor,
                verify_snapshot_subject=lambda _subject: None,
                account_home="/private/home",
                account_tmpdir="/private/tmp",
            )

    def test_evidence_progress_tracks_all_five_stages(self) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "8" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )

        self.service.process_account_evidence(
            start_request=started,
            request_context=_context(),
            activation_gate=_activation_gate(),
            owner_id="evidence-worker-1",
            pid=4321,
            process_start_marker="pid-4321-start-1",
        )

        with closing(sqlite3.connect(self.path)) as connection:
            stage = connection.execute(
                "select current_stage from account_evidence_jobs where evidence_job_id=?",
                (started.evidence_job_id,),
            ).fetchone()[0]
            progress = connection.execute(
                "select count(*) from events where code=? and event='EVIDENCE_PROGRESS'",
                (started.start_request_id,),
            ).fetchone()[0]
        self.assertEqual("requirements-c", stage)
        self.assertEqual(4, progress)

    def test_active_cancellation_stops_later_stages_and_finishes_cancelled(
        self,
    ) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "b" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        self.account_executor.on_first_call = lambda: self.store.cancel_start_request(
            started.start_request_id,
            _context(),
            idempotency_key="idem2_" + "c" * 32,
            reason_code="USER_REQUESTED",
            now=NOW,
        )

        with self.assertRaisesRegex(Exception, "ACCOUNT_EVIDENCE_CANCELLED"):
            self.service.process_account_evidence(
                start_request=started,
                request_context=_context(),
                activation_gate=_activation_gate(),
                owner_id="evidence-worker-1",
                pid=4321,
                process_start_marker="pid-4321-start-1",
            )

        self.assertEqual(["requirements-a"], self.account_executor.calls)
        status = self.store.read_start_status(
            started.start_request_id,
            _context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual("CANCELLED", status.state)
        self.assertEqual("CANCELLED", status.evidence_job_state)
        self.assertTrue(status.terminal)

    def test_incompatible_managed_requirements_fail_without_admission(self) -> None:
        binding = self._binding()
        plan = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "6" * 32,
            nodes=_single_plan_node(_routing_input()),
        )
        started = self.service.route_start(
            route_id=plan.route_id,
            node_id=plan.node_decisions[0].node_id,
            request_context=_context(),
            activation_gate=_activation_gate(),
        )
        self.account_executor.requirements = {"allowedSandboxModes": ["read-only"]}

        with self.assertRaisesRegex(Exception, "MANAGED_REQUIREMENT_INCOMPATIBLE"):
            self.service.process_account_evidence(
                start_request=started,
                request_context=_context(),
                activation_gate=_activation_gate(),
                owner_id="evidence-worker-1",
                pid=4321,
                process_start_marker="pid-4321-start-1",
            )

        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "select s.state,s.admission_id,j.state,j.failure_code "
                "from start_requests s join account_evidence_jobs j "
                "on j.evidence_job_id=s.evidence_job_id "
                "where s.start_request_id=?",
                (started.start_request_id,),
            ).fetchone()
        self.assertEqual(
            (
                "FAILED",
                None,
                "FAILED",
                "MANAGED_REQUIREMENT_INCOMPATIBLE",
            ),
            row,
        )
        status = self.store.read_start_status(
            started.start_request_id,
            _context(),
            cursor=None,
            page_size=100,
        )
        self.assertEqual(
            {
                "category": "UNAVAILABLE",
                "code": "ACCOUNT_EVIDENCE_UNAVAILABLE",
                "message": "Не удалось получить согласованное доказательство учётной среды.",
                "retryable": True,
            },
            status.page.items[-1].problem,
        )

    def test_multi_node_plan_records_per_node_pairs_and_graph_dependencies(
        self,
    ) -> None:
        binding = self._binding()

        result = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "a" * 32,
            nodes=[
                _plan_node("reader_a", _routing_for_role("validator-v1")),
                _plan_node(
                    "writer_a",
                    _sol_max_routing(),
                    dependencies=("reader_a",),
                ),
            ],
        )

        self.assertEqual("DELEGATE", result.disposition)
        self.assertEqual(2, len(result.node_decisions))
        by_client_id = {
            decision.client_node_id: decision for decision in result.node_decisions
        }
        self.assertEqual(
            {"model": "gpt-5.6-luna", "reasoningEffort": "low"},
            by_client_id["reader_a"].selected_pair,
        )
        self.assertEqual(
            {"model": "gpt-5.6-sol", "reasoningEffort": "max"},
            by_client_id["writer_a"].selected_pair,
        )
        self.assertEqual(
            (by_client_id["reader_a"].node_id,),
            by_client_id["writer_a"].dependency_node_ids,
        )
        self.assertRegex(by_client_id["reader_a"].node_id, r"^node2_[0-9a-f]{32}$")
        with closing(sqlite3.connect(self.path)) as connection:
            stored = connection.execute(
                "select node_id,dependencies_json,selected_model,reasoning_effort "
                "from nodes where route_id=? order by ordinal",
                (result.route_id,),
            ).fetchall()
        self.assertEqual(
            [
                (
                    by_client_id["reader_a"].node_id,
                    "[]",
                    "gpt-5.6-luna",
                    "low",
                ),
                (
                    by_client_id["writer_a"].node_id,
                    json.dumps(
                        [by_client_id["reader_a"].node_id],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    "gpt-5.6-sol",
                    "max",
                ),
            ],
            stored,
        )

    def test_mixed_plan_is_not_partially_startable(self) -> None:
        binding = self._binding()
        direct = _routing_for_role("implementer-v1")
        direct["taskFacts"]["delegation"]["objectivelyVerifiable"] = {
            "value": False,
            "evidenceRefIds": ["scope"],
        }

        result = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "b" * 32,
            nodes=[
                _plan_node("reader_a", _routing_for_role("validator-v1")),
                _plan_node("writer_a", direct, dependencies=("reader_a",)),
            ],
        )

        self.assertEqual("DIRECT", result.disposition)
        self.assertEqual(
            ["DELEGATE", "DIRECT"],
            [decision.disposition for decision in result.node_decisions],
        )
        self.assertIsNotNone(result.node_decisions[0].selected_pair)
        self.assertIsNone(result.node_decisions[1].selected_pair)
        with closing(sqlite3.connect(self.path)) as connection:
            route = connection.execute(
                "select state,startable from routes where route_id=?",
                (result.route_id,),
            ).fetchone()
            node_count = connection.execute(
                "select count(*) from nodes where route_id=?",
                (result.route_id,),
            ).fetchone()[0]
        self.assertEqual(("DIRECT", 0), route)
        self.assertEqual(0, node_count)

    def test_any_clarify_node_takes_precedence_over_direct(self) -> None:
        binding = self._binding()
        clarify = _routing_for_role("implementer-v1")
        clarify["taskFacts"]["hardBanReasons"] = [
            {
                "reason": "authority-conflict",
                "decision": "clarify",
                "evidenceRefIds": ["request", "policy"],
            }
        ]

        result = self.service.smart_plan(
            binding_id=binding.binding_id,
            request_context=_context(),
            request_key="idem2_" + "c" * 32,
            nodes=[
                _plan_node("reader_a", _routing_for_role("validator-v1")),
                _plan_node("writer_a", clarify, dependencies=("reader_a",)),
            ],
        )

        self.assertEqual("CLARIFY", result.disposition)
        self.assertTrue(result.clarification)

    def test_service_applies_closed_graph_limits_and_writer_sink_rule(self) -> None:
        cases = {
            "TOO_MANY_NODES": [
                _plan_node(
                    f"reader_{index:02d}",
                    _routing_for_role("validator-v1"),
                )
                for index in range(21)
            ],
            "GRAPH_CYCLE": [
                _plan_node(
                    "reader_a",
                    _routing_for_role("validator-v1"),
                    dependencies=("writer_a",),
                ),
                _plan_node(
                    "writer_a",
                    _routing_for_role("implementer-v1"),
                    dependencies=("reader_a",),
                ),
            ],
            "GRAPH_TOO_DEEP": [
                _plan_node(
                    f"reader_{index}",
                    _routing_for_role("validator-v1"),
                    dependencies=(() if index == 0 else (f"reader_{index - 1}",)),
                )
                for index in range(6)
            ],
            "WRITER_NOT_SINK": [
                _plan_node(
                    "writer_a",
                    _routing_for_role("implementer-v1"),
                ),
                _plan_node(
                    "reader_a",
                    _routing_for_role("validator-v1"),
                    dependencies=("writer_a",),
                ),
            ],
            "MULTIPLE_WRITERS": [
                _plan_node("writer_a", _routing_for_role("implementer-v1")),
                _plan_node("writer_b", _routing_for_role("implementer-v1")),
            ],
        }
        for index, (code, nodes) in enumerate(cases.items()):
            with self.subTest(code=code):
                binding = self._binding()
                with self.assertRaisesRegex(Exception, code):
                    self.service.smart_plan(
                        binding_id=binding.binding_id,
                        request_context=_context(),
                        request_key="idem2_" + format(index + 13, "032x"),
                        nodes=nodes,
                    )

    def test_graph_rejects_more_than_sixty_edges(self) -> None:
        binding = self._binding()
        nodes = []
        for index in range(12):
            dependencies = tuple(f"reader_{dependency}" for dependency in range(index))
            nodes.append(
                _plan_node(
                    f"reader_{index}",
                    _routing_for_role("validator-v1"),
                    dependencies=dependencies,
                )
            )

        with self.assertRaisesRegex(Exception, "TOO_MANY_EDGES"):
            self.service.smart_plan(
                binding_id=binding.binding_id,
                request_context=_context(),
                request_key="idem2_" + "d" * 32,
                nodes=nodes,
            )


if __name__ == "__main__":
    unittest.main()
