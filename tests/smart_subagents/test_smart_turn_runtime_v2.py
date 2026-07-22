from __future__ import annotations

import copy
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.smart_service_v2 import (  # noqa: E402
    SmartPlanNodeDecisionV2,
    SmartPlanResultV2,
    SmartServiceV2Error,
)
from codex_smart_subagents.smart_turn_runtime_v2 import (  # noqa: E402
    SmartTurnRuntimeV2,
    SmartTurnRuntimeV2Error,
    build_public_request_v2,
    owner_for_context_v2,
    verify_public_response_v2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    CancellationV2,
    RequestContextV2,
    StartEventPageV2,
    StartEventV2,
    StartRequestV2,
    StartStatusV2,
    StartTerminalResultV2,
    StateStoreV2Error,
    TurnBindingV2,
)


NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)


def _context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/Users/test/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
        activation_fingerprint="3" * 64,
        compatibility_fingerprint="4" * 64,
        issued_control_epoch=13,
    )


def _binding() -> TurnBindingV2:
    return TurnBindingV2(
        binding_id="tb2_" + "a" * 32,
        context_fingerprint="5" * 64,
        issued_control_epoch=13,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=120),
        state="ACTIVE",
    )


def _start() -> StartRequestV2:
    return StartRequestV2(
        start_request_id="sr2_" + "b" * 32,
        evidence_job_id="aej2_" + "c" * 32,
        attempt_id="att2_" + "d" * 32,
        route_id="route2_" + "e" * 32,
        node_id="node2_" + "f" * 32,
        queue_position=1,
        deadline_at=NOW + timedelta(seconds=180),
        state="ATTESTING",
    )


class _Service:
    def __init__(self) -> None:
        self.plan_error: Exception | None = None
        self.start_error: Exception | None = None
        self.plan_result = SmartPlanResultV2(
            route_id="route2_" + "e" * 32,
            disposition="DELEGATE",
            node_decisions=(
                SmartPlanNodeDecisionV2(
                    client_node_id="reader_a",
                    node_id="node2_" + "f" * 32,
                    dependency_node_ids=(),
                    disposition="DELEGATE",
                    selected_pair={
                        "model": "model-luna",
                        "reasoningEffort": "medium",
                    },
                    score=2,
                    factors={"q": 1, "p": 1, "v": 0, "o": 0},
                ),
            ),
            clarification=(),
            plan_fingerprint="6" * 64,
        )
        self.binding = _binding()
        self.start = _start()

    def issue_turn_binding(
        self,
        request_context: RequestContextV2,
        *,
        ttl_seconds: int,
        request_key: str | None = None,
    ) -> TurnBindingV2:
        if request_context != _context() or ttl_seconds != 120:
            raise AssertionError("неавторитетный контекст привязки")
        if request_key != "idem2_" + "a" * 32:
            raise AssertionError("неавторитетный ключ привязки")
        return self.binding

    def smart_plan(self, **kwargs: object) -> SmartPlanResultV2:
        if kwargs["request_context"] != _context():
            raise AssertionError("неавторитетный контекст плана")
        if self.plan_error is not None:
            raise self.plan_error
        return self.plan_result

    def route_start(self, **kwargs: object) -> StartRequestV2:
        if kwargs["request_context"] != _context():
            raise AssertionError("неавторитетный контекст запуска")
        if kwargs["activation_gate"] != {"gateFingerprint": "7" * 64}:
            raise AssertionError("неавторитетный шлюз")
        if self.start_error is not None:
            raise self.start_error
        return self.start


class _Store:
    def read_start_status(self, *args: object, **kwargs: object) -> StartStatusV2:
        event = StartEventV2(
            sequence=7,
            event_at=NOW,
            kind="EVIDENCE_RUNNING",
            start_state="ATTESTING",
            evidence_job_id="aej2_" + "c" * 32,
            admission_id=None,
            attestation=None,
            problem=None,
        )
        return StartStatusV2(
            start_request_id="sr2_" + "b" * 32,
            state="ATTESTING",
            evidence_job_state="RUNNING",
            admission_id=None,
            terminal=False,
            page=StartEventPageV2(
                cursor=None,
                next_cursor="cur2_" + "8" * 32,
                items=(event,),
            ),
        )

    def cancel_start_request(self, *args: object, **kwargs: object) -> CancellationV2:
        return CancellationV2(
            status="CANCEL_REQUESTED",
            start_request_id="sr2_" + "b" * 32,
            state="ATTESTING",
            terminal=False,
            idempotency_key=str(kwargs["idempotency_key"]),
            idempotency_status="COMMITTED",
        )


def _request(
    method: str,
    params: dict[str, object],
    *,
    turn_binding: dict[str, object] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, object]:
    return build_public_request_v2(
        method,
        request_id="strq2_" + "9" * 32,
        owner=owner_for_context_v2(_context()),
        turn_binding=turn_binding,
        idempotency_key=idempotency_key,
        request_deadline_at=NOW + timedelta(seconds=30),
        params=params,
    )


def _plan_nodes() -> list[dict[str, object]]:
    return [
        {
            "clientNodeId": "reader_a",
            "dependencyIds": [],
            "routingInput": _public_routing_input(),
        }
    ]


def _public_routing_input() -> dict[str, object]:
    internal = json.loads(
        (ROOT / "docs/contracts/vectors/routing-input-v2.json").read_text(
            encoding="utf-8"
        )
    )["baseInput"]
    facts = internal["taskFacts"]
    return {
        "taskFacts": {
            "taskText": facts["taskText"],
            "evidence": facts["evidence"],
            "workShape": facts["workShape"],
            "factorClaims": facts["factorClaims"],
            "delegation": {
                "objectivelyVerifiable": facts["delegation"]["objectivelyVerifiable"],
                "independentWorkUnits": facts["delegation"]["independentWorkUnits"],
            },
            "hardFloorReasons": facts["hardFloorReasons"],
            "hardBanReasons": facts["hardBanReasons"],
        },
        "contextBundle": internal["contextBundle"],
        "roleTemplateId": internal["roleTemplateId"],
    }


class SmartTurnRuntimeV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = _Service()
        self.store = _Store()
        self.runtime = SmartTurnRuntimeV2(
            service=self.service,
            store=self.store,
            clock=lambda: NOW,
        )

    def test_issue_binding_returns_closed_fingerprinted_response(self) -> None:
        request = _request(
            "issue_turn_binding",
            {"requestContext": _context().contract_value(), "ttlSeconds": 120},
            idempotency_key="idem2_" + "a" * 32,
        )

        response = self.runtime.issue_turn_binding(
            request,
            request_context=_context(),
        )

        verified = verify_public_response_v2(response)
        self.assertEqual("SUCCESS", verified["responseKind"])
        self.assertEqual("ISSUED", verified["payload"]["status"])
        self.assertEqual(
            {
                "messageType",
                "protocolVersion",
                "release",
                "requestId",
                "owner",
                "method",
                "responseKind",
                "requestFingerprint",
                "payload",
                "responseFingerprint",
                "extensions",
            },
            set(verified),
        )
        self.assertEqual(
            "TURN_BINDING",
            verified["payload"]["effect"]["result"]["resultKind"],
        )

    def test_replayed_turn_binding_reports_read_effect(self) -> None:
        self.service.binding = replace(
            self.service.binding,
            state="CONSUMED",
            replayed=True,
        )
        response = self.runtime.issue_turn_binding(
            _request(
                "issue_turn_binding",
                {"requestContext": _context().contract_value(), "ttlSeconds": 120},
                idempotency_key="idem2_" + "a" * 32,
            ),
            request_context=_context(),
        )

        self.assertEqual("CONSUMED", response["payload"]["turnBinding"]["state"])
        self.assertEqual("READ", response["payload"]["effect"]["operation"])
        self.assertEqual("READ_ONLY", response["payload"]["effect"]["transactionMode"])
        self.assertEqual([], response["payload"]["effect"]["transitions"])
        verify_public_response_v2(response)

    def test_smart_plan_projects_the_pair_for_each_node(self) -> None:
        binding = self.runtime.issue_turn_binding(
            _request(
                "issue_turn_binding",
                {"requestContext": _context().contract_value(), "ttlSeconds": 120},
                idempotency_key="idem2_" + "a" * 32,
            ),
            request_context=_context(),
        )["payload"]["turnBinding"]
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding=binding,
            idempotency_key="idem2_" + "b" * 32,
        )

        response = self.runtime.smart_plan(request, request_context=_context())

        self.assertEqual("SUCCESS", response["responseKind"])
        self.assertEqual("DELEGATE", response["payload"]["disposition"])
        self.assertEqual(
            {
                "clientNodeId": "reader_a",
                "nodeId": "node2_" + "f" * 32,
                "dependencyNodeIds": [],
                "disposition": "DELEGATE",
                "selectedPair": {
                    "model": "model-luna",
                    "reasoningEffort": "medium",
                },
                "score": 2,
                "factors": {"q": 1, "p": 1, "v": 0, "o": 0},
            },
            response["payload"]["nodeDecisions"][0],
        )
        self.assertNotIn("selectedPair", response["payload"])
        verify_public_response_v2(response)

    def test_smart_plan_rejects_invalid_node_decision_score_factors(self) -> None:
        binding = _binding()
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding={
                "bindingId": binding.binding_id,
                "owner": owner_for_context_v2(_context()),
                "contextFingerprint": binding.context_fingerprint,
                "issuedControlEpoch": binding.issued_control_epoch,
                "issuedAt": "2026-07-18T12:00:00Z",
                "expiresAt": "2026-07-18T12:02:00Z",
                "state": "ACTIVE",
            },
            idempotency_key="idem2_" + "b" * 32,
        )
        invalid_decisions = (
            replace(
                self.service.plan_result.node_decisions[0],
                score=1,
                factors={"q": 1, "p": 0, "v": 0, "o": -1},
            ),
            replace(
                self.service.plan_result.node_decisions[0],
                score=-1,
                factors={"q": 0, "p": 0, "v": 0, "o": 0},
            ),
            replace(
                self.service.plan_result.node_decisions[0],
                score=1,
                factors={"q": 1, "p": 1, "v": 0, "o": 0},
            ),
        )

        for decision in invalid_decisions:
            with self.subTest(score=decision.score, factors=decision.factors):
                self.service.plan_result = replace(
                    self.service.plan_result,
                    node_decisions=(decision,),
                )
                with self.assertRaisesRegex(
                    SmartTurnRuntimeV2Error,
                    "INVALID_RESPONSE",
                ):
                    self.runtime.smart_plan(request, request_context=_context())

    def test_replayed_smart_plan_reports_read_effect_without_false_transitions(
        self,
    ) -> None:
        self.service.plan_result = replace(
            self.service.plan_result,
            route_state="RUNNING",
            replayed=True,
        )
        binding = _binding()
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding={
                "bindingId": binding.binding_id,
                "owner": owner_for_context_v2(_context()),
                "contextFingerprint": binding.context_fingerprint,
                "issuedControlEpoch": binding.issued_control_epoch,
                "issuedAt": "2026-07-18T12:00:00Z",
                "expiresAt": "2026-07-18T12:02:00Z",
                "state": "ACTIVE",
            },
            idempotency_key="idem2_" + "b" * 32,
        )

        response = self.runtime.smart_plan(request, request_context=_context())

        effect = response["payload"]["effect"]
        self.assertEqual("READ", effect["operation"])
        self.assertEqual("READ_ONLY", effect["transactionMode"])
        self.assertEqual([], effect["transitions"])
        verify_public_response_v2(response)

    def test_direct_and_clarify_plans_return_node_decisions_without_starting(
        self,
    ) -> None:
        for disposition in ("DIRECT", "CLARIFY"):
            with self.subTest(disposition=disposition):
                decision = replace(
                    self.service.plan_result.node_decisions[0],
                    disposition=disposition,
                    selected_pair=None,
                    score=None,
                    factors=None,
                )
                self.service.plan_result = replace(
                    self.service.plan_result,
                    disposition=disposition,
                    node_decisions=(decision,),
                    clarification=("Нужно уточнение",)
                    if disposition == "CLARIFY"
                    else (),
                )
                binding = _binding()
                request = _request(
                    "smart_plan",
                    {"nodes": _plan_nodes()},
                    turn_binding={
                        "bindingId": binding.binding_id,
                        "owner": owner_for_context_v2(_context()),
                        "contextFingerprint": binding.context_fingerprint,
                        "issuedControlEpoch": binding.issued_control_epoch,
                        "issuedAt": "2026-07-18T12:00:00Z",
                        "expiresAt": "2026-07-18T12:02:00Z",
                        "state": "ACTIVE",
                    },
                    idempotency_key="idem2_" + "b" * 32,
                )

                response = self.runtime.smart_plan(
                    request,
                    request_context=_context(),
                )

                self.assertEqual("SUCCESS", response["responseKind"])
                self.assertEqual(disposition, response["payload"]["disposition"])
                self.assertIsNone(
                    response["payload"]["nodeDecisions"][0]["selectedPair"]
                )
                verify_public_response_v2(response)

    def test_server_generated_pair_is_closed_but_not_tied_to_model_names(self) -> None:
        binding = _binding()
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding={
                "bindingId": binding.binding_id,
                "owner": owner_for_context_v2(_context()),
                "contextFingerprint": binding.context_fingerprint,
                "issuedControlEpoch": binding.issued_control_epoch,
                "issuedAt": "2026-07-18T12:00:00Z",
                "expiresAt": "2026-07-18T12:02:00Z",
                "state": "ACTIVE",
            },
            idempotency_key="idem2_" + "b" * 32,
        )
        self.service.plan_result.node_decisions[0].selected_pair["model"] = 7  # type: ignore[index,assignment]

        with self.assertRaisesRegex(SmartTurnRuntimeV2Error, "INVALID_RESPONSE"):
            self.runtime.smart_plan(request, request_context=_context())

    def test_internal_validation_error_is_normalized_without_leaking_detail(
        self,
    ) -> None:
        binding = _binding()
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding={
                "bindingId": binding.binding_id,
                "owner": owner_for_context_v2(_context()),
                "contextFingerprint": binding.context_fingerprint,
                "issuedControlEpoch": binding.issued_control_epoch,
                "issuedAt": "2026-07-18T12:00:00Z",
                "expiresAt": "2026-07-18T12:02:00Z",
                "state": "ACTIVE",
            },
            idempotency_key="idem2_" + "b" * 32,
        )
        self.service.plan_error = SmartServiceV2Error(
            "ROUTING_INPUT_INVALID",
            "секретная внутренняя причина",
        )

        response = self.runtime.smart_plan(request, request_context=_context())

        self.assertEqual("ERROR", response["responseKind"])
        self.assertEqual("INVALID", response["payload"]["problem"]["category"])
        self.assertEqual("INVALID_REQUEST", response["payload"]["problem"]["code"])
        self.assertNotIn("секретная", str(response))

    def test_graph_validation_errors_are_public_invalid_requests(self) -> None:
        binding = _binding()
        request = _request(
            "smart_plan",
            {"nodes": _plan_nodes()},
            turn_binding={
                "bindingId": binding.binding_id,
                "owner": owner_for_context_v2(_context()),
                "contextFingerprint": binding.context_fingerprint,
                "issuedControlEpoch": binding.issued_control_epoch,
                "issuedAt": "2026-07-18T12:00:00Z",
                "expiresAt": "2026-07-18T12:02:00Z",
                "state": "ACTIVE",
            },
            idempotency_key="idem2_" + "b" * 32,
        )
        for code in (
            "PLAN_GRAPH_INVALID",
            "GRAPH_CYCLE",
            "GRAPH_TOO_DEEP",
            "WRITER_NOT_SINK",
            "WRITER_MISSING_READER_DEPENDENCY",
        ):
            with self.subTest(code=code):
                self.service.plan_error = SmartServiceV2Error(code, "внутренняя деталь")
                response = self.runtime.smart_plan(request, request_context=_context())
                self.assertEqual("ERROR", response["responseKind"])
                self.assertEqual("INVALID", response["payload"]["problem"]["category"])
                self.assertEqual(
                    "INVALID_REQUEST",
                    response["payload"]["problem"]["code"],
                )
                verify_public_response_v2(response)

    def test_route_start_domain_errors_have_noninternal_public_mapping(self) -> None:
        gate = {"gateFingerprint": "7" * 64}
        request = _request(
            "route_start",
            {
                "routeId": "route2_" + "e" * 32,
                "nodeId": "node2_" + "f" * 32,
                "activationGate": copy.deepcopy(gate),
            },
            idempotency_key="idem2_" + "c" * 32,
        )
        expected = {
            "ROUTE_EXPIRED": ("STALE", "ROUTE_STALE"),
            "START_REQUEST_REPLAY_CONFLICT": (
                "CONFLICT",
                "IDEMPOTENCY_CONFLICT",
            ),
            "INVALID_START_REQUEST_IDEMPOTENCY": ("INVALID", "INVALID_REQUEST"),
            "NODE_DEPENDENCIES_INCOMPLETE": ("INVALID", "INVALID_REQUEST"),
            "DEPENDENCY_RESULT_MISSING": ("INVALID", "INVALID_REQUEST"),
        }
        for code, (category, public_code) in expected.items():
            with self.subTest(code=code):
                self.service.start_error = (
                    StateStoreV2Error(
                        code,
                        "внутренняя деталь",
                        committed_transitions=(
                            {
                                "table": "routes",
                                "entityId": "route2_" + "e" * 32,
                                "beforeState": "PLANNED",
                                "afterState": "STALE",
                            },
                        ),
                    )
                    if code == "ROUTE_EXPIRED"
                    else SmartServiceV2Error(code, "внутренняя деталь")
                )
                response = self.runtime.route_start(
                    request,
                    request_context=_context(),
                    activation_gate=gate,
                )
                self.assertEqual(
                    "STALE" if category == "STALE" else "ERROR",
                    response["responseKind"],
                )
                self.assertEqual(category, response["payload"]["problem"]["category"])
                self.assertEqual(public_code, response["payload"]["problem"]["code"])
                self.assertNotIn("внутренняя деталь", str(response))
                effect = response["payload"]["effect"]
                if code == "ROUTE_EXPIRED":
                    self.assertEqual("TRANSITION", effect["operation"])
                    self.assertEqual("BEGIN_IMMEDIATE", effect["transactionMode"])
                    self.assertEqual("STALE", effect["transitions"][0]["afterState"])
                else:
                    self.assertEqual("READ", effect["operation"])
                verify_public_response_v2(response)

    def test_route_start_uses_injected_activation_gate_not_untrusted_params(
        self,
    ) -> None:
        gate = {"gateFingerprint": "7" * 64}
        request = _request(
            "route_start",
            {
                "routeId": "route2_" + "e" * 32,
                "nodeId": "node2_" + "f" * 32,
                "activationGate": copy.deepcopy(gate),
            },
            idempotency_key="idem2_" + "c" * 32,
        )

        response = self.runtime.route_start(
            request,
            request_context=_context(),
            activation_gate=gate,
        )

        self.assertEqual("ATTESTING", response["payload"]["status"])
        self.assertIsNone(response["payload"]["admissionId"])
        self.assertEqual(1, response["payload"]["evidenceJob"]["queuePosition"])
        verify_public_response_v2(response)

        changed = copy.deepcopy(request)
        changed["params"]["activationGate"] = {"gateFingerprint": "0" * 64}
        with self.assertRaisesRegex(
            SmartTurnRuntimeV2Error,
            "REQUEST_FINGERPRINT_MISMATCH|AUTHORITATIVE_ACTIVATION_GATE_MISMATCH",
        ):
            self.runtime.route_start(
                changed,
                request_context=_context(),
                activation_gate=gate,
            )

    def test_replayed_route_start_reports_read_effect(self) -> None:
        self.service.start = replace(self.service.start, replayed=True)
        gate = {"gateFingerprint": "7" * 64}
        response = self.runtime.route_start(
            _request(
                "route_start",
                {
                    "routeId": "route2_" + "e" * 32,
                    "nodeId": "node2_" + "f" * 32,
                    "activationGate": copy.deepcopy(gate),
                },
                idempotency_key="idem2_" + "c" * 32,
            ),
            request_context=_context(),
            activation_gate=gate,
        )

        effect = response["payload"]["effect"]
        self.assertEqual("READ", effect["operation"])
        self.assertEqual("READ_ONLY", effect["transactionMode"])
        self.assertEqual([], effect["transitions"])
        verify_public_response_v2(response)

    def test_wait_and_cancel_project_store_results_and_fingerprints(self) -> None:
        wait = self.runtime.smart_wait(
            _request(
                "smart_wait",
                {
                    "startRequestId": "sr2_" + "b" * 32,
                    "cursor": None,
                    "pageSize": 20,
                    "waitDeadlineAt": "2026-07-18T12:00:15Z",
                },
            ),
            request_context=_context(),
        )
        self.assertEqual("READ", wait["payload"]["effect"]["operation"])
        self.assertEqual(7, wait["payload"]["page"]["items"][0]["sequence"])
        verify_public_response_v2(wait)

        cancel = self.runtime.smart_cancel(
            _request(
                "smart_cancel",
                {
                    "startRequestId": "sr2_" + "b" * 32,
                    "reasonCode": "USER_REQUESTED",
                },
                idempotency_key="idem2_" + "d" * 32,
            ),
            request_context=_context(),
        )
        self.assertEqual("CANCEL_REQUESTED", cancel["payload"]["status"])
        self.assertEqual("COMMITTED", cancel["payload"]["idempotencyStatus"])
        verify_public_response_v2(cancel)

    def test_wait_projects_bounded_terminal_child_result(self) -> None:
        class TerminalStore(_Store):
            def read_start_status(
                self, *args: object, **kwargs: object
            ) -> StartStatusV2:
                del args, kwargs
                event = StartEventV2(
                    sequence=8,
                    event_at=NOW,
                    kind="ROUTE_COMPLETED",
                    start_state="SUCCEEDED",
                    evidence_job_id="aej2_" + "c" * 32,
                    admission_id="adm2_" + "a" * 32,
                    attestation=None,
                    problem=None,
                )
                return StartStatusV2(
                    start_request_id="sr2_" + "b" * 32,
                    state="SUCCEEDED",
                    evidence_job_state="SUCCEEDED",
                    admission_id="adm2_" + "a" * 32,
                    terminal=True,
                    page=StartEventPageV2(
                        cursor="cur2_" + "7" * 32,
                        next_cursor="cur2_" + "8" * 32,
                        items=(event,),
                    ),
                    terminal_result=StartTerminalResultV2(
                        attempt_id="att2_" + "d" * 32,
                        state="SUCCEEDED",
                        result_fingerprint="a" * 64,
                        result_bytes=93,
                        inline_result={
                            "summary": "Проверка завершена.",
                            "validationState": "passed",
                            "artifactId": "",
                        },
                        result_truncated=False,
                        error_code=None,
                    ),
                )

        runtime = SmartTurnRuntimeV2(
            service=self.service,
            store=TerminalStore(),
            clock=lambda: NOW,
        )
        response = runtime.smart_wait(
            _request(
                "smart_wait",
                {
                    "startRequestId": "sr2_" + "b" * 32,
                    "cursor": "cur2_" + "7" * 32,
                    "pageSize": 20,
                    "waitDeadlineAt": "2026-07-18T12:00:15Z",
                },
            ),
            request_context=_context(),
        )

        terminal = response["payload"]["terminalResult"]
        self.assertEqual("SUCCEEDED", response["payload"]["state"])
        self.assertTrue(response["payload"]["terminal"])
        self.assertEqual("Проверка завершена.", terminal["inlineResult"]["summary"])
        self.assertFalse(terminal["resultTruncated"])
        verify_public_response_v2(response)

    def test_wait_polls_until_an_event_arrives_within_the_bounded_deadline(
        self,
    ) -> None:
        class PollingStore(_Store):
            def __init__(self) -> None:
                self.calls = 0

            def read_start_status(
                self, *args: object, **kwargs: object
            ) -> StartStatusV2:
                self.calls += 1
                status = super().read_start_status(*args, **kwargs)
                if self.calls == 1:
                    return replace(
                        status,
                        page=StartEventPageV2(
                            cursor=None,
                            next_cursor=None,
                            items=(),
                        ),
                    )
                return status

        store = PollingStore()
        sleeps: list[float] = []
        monotonic_values = iter((0.0, 0.0, 0.05, 0.05))
        runtime = SmartTurnRuntimeV2(
            service=self.service,
            store=store,
            clock=lambda: NOW,
            monotonic=lambda: next(monotonic_values),
            sleeper=sleeps.append,
        )

        response = runtime.smart_wait(
            _request(
                "smart_wait",
                {
                    "startRequestId": "sr2_" + "b" * 32,
                    "cursor": None,
                    "pageSize": 20,
                    "waitDeadlineAt": "2026-07-18T12:00:15Z",
                },
            ),
            request_context=_context(),
        )

        self.assertEqual(2, store.calls)
        self.assertEqual([0.05], sleeps)
        self.assertEqual(7, response["payload"]["page"]["items"][0]["sequence"])

    def test_extra_request_field_and_wrong_authoritative_context_are_rejected(
        self,
    ) -> None:
        request = _request(
            "smart_wait",
            {
                "startRequestId": "sr2_" + "b" * 32,
                "cursor": None,
                "pageSize": 20,
                "waitDeadlineAt": "2026-07-18T12:00:15Z",
            },
        )
        request["surprise"] = True
        with self.assertRaisesRegex(SmartTurnRuntimeV2Error, "INVALID_REQUEST"):
            self.runtime.smart_wait(request, request_context=_context())

        valid = _request(
            "smart_wait",
            {
                "startRequestId": "sr2_" + "b" * 32,
                "cursor": None,
                "pageSize": 20,
                "waitDeadlineAt": "2026-07-18T12:00:15Z",
            },
        )
        other = replace(_context(), turn_id="turn-2")
        with self.assertRaisesRegex(
            SmartTurnRuntimeV2Error,
            "AUTHORITATIVE_CONTEXT_MISMATCH",
        ):
            self.runtime.smart_wait(valid, request_context=other)


if __name__ == "__main__":
    unittest.main()
