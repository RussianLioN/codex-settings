from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.mcp_contracts_v2 import (  # noqa: E402
    MCPContractV2Error,
    get_tool_definitions_v2,
    validate_tool_input_v2,
    validate_tool_output_v2,
)
from codex_smart_subagents.mcp_server_v2 import MCPServerV2  # noqa: E402
from codex_smart_subagents.execution_dispatcher_v2 import (  # noqa: E402
    ExecutionDispatcherV2,
)
from codex_smart_subagents.smart_service_v2 import (  # noqa: E402
    SmartPlanNodeDecisionV2,
    SmartPlanResultV2,
)
from codex_smart_subagents.smart_turn_runtime_v2 import (  # noqa: E402
    SmartTurnRuntimeV2,
    verify_public_response_v2,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    CancellationV2,
    RequestContextV2,
    StartEventPageV2,
    StartRequestV2,
    StartStatusV2,
    StartTerminalResultV2,
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


class _Service:
    def issue_turn_binding(
        self,
        request_context: RequestContextV2,
        *,
        ttl_seconds: int,
        request_key: str | None = None,
    ) -> TurnBindingV2:
        if request_key is None:
            raise AssertionError("приватная привязка должна быть идемпотентной")
        return TurnBindingV2(
            binding_id="tb2_" + "a" * 32,
            context_fingerprint="5" * 64,
            issued_control_epoch=request_context.issued_control_epoch,
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=ttl_seconds),
            state="ACTIVE",
        )

    def smart_plan(self, **_kwargs: object) -> SmartPlanResultV2:
        return SmartPlanResultV2(
            route_id="route2_" + "b" * 32,
            disposition="DELEGATE",
            node_decisions=(
                SmartPlanNodeDecisionV2(
                    client_node_id="reader_a",
                    node_id="node2_" + "c" * 32,
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

    def route_start(self, **kwargs: object) -> StartRequestV2:
        if kwargs["activation_gate"] != {"gateFingerprint": "7" * 64}:
            raise AssertionError("сервер передал неавторитетный шлюз")
        return StartRequestV2(
            start_request_id="sr2_" + "d" * 32,
            evidence_job_id="aej2_" + "e" * 32,
            attempt_id="att2_" + "f" * 32,
            route_id=str(kwargs["route_id"]),
            node_id=str(kwargs["node_id"]),
            queue_position=1,
            deadline_at=NOW + timedelta(seconds=180),
            state="ATTESTING",
        )


class _Store:
    def read_start_status(self, *args: object, **_kwargs: object) -> StartStatusV2:
        return StartStatusV2(
            start_request_id=str(args[0]),
            state="ATTESTING",
            evidence_job_state="QUEUED",
            admission_id=None,
            terminal=False,
            page=StartEventPageV2(cursor=None, next_cursor=None, items=()),
        )

    def cancel_start_request(self, *args: object, **kwargs: object) -> CancellationV2:
        return CancellationV2(
            status="CANCELLED",
            start_request_id=str(args[0]),
            state="CANCELLED",
            terminal=True,
            idempotency_key=str(kwargs["idempotency_key"]),
            idempotency_status="COMMITTED",
        )


def _server(*, gate_provider=None, start_dispatcher=None) -> MCPServerV2:
    runtime = SmartTurnRuntimeV2(
        service=_Service(),
        store=_Store(),
        clock=lambda: NOW,
    )
    return MCPServerV2(
        runtime=runtime,
        request_context_provider=_context,
        activation_gate_provider=(
            gate_provider
            if gate_provider is not None
            else lambda: {"gateFingerprint": "7" * 64}
        ),
        clock=lambda: NOW,
        start_dispatcher=start_dispatcher,
    )


def _call(name: str, arguments: dict[str, object], request_id: int = 1):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


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


class MCPContractsV2Tests(unittest.TestCase):
    def test_definitions_expose_exact_four_tools_without_authoritative_fields(
        self,
    ) -> None:
        definitions = get_tool_definitions_v2()

        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [item["name"] for item in definitions],
        )
        by_name = {item["name"]: item for item in definitions}
        self.assertNotIn(
            "activationGate",
            by_name["route_start"]["inputSchema"]["properties"],
        )
        self.assertNotIn(
            "requestContext",
            by_name["smart_plan"]["inputSchema"]["properties"],
        )
        self.assertEqual(
            {"nodes"},
            set(by_name["smart_plan"]["inputSchema"]["properties"]),
        )
        nodes_schema = by_name["smart_plan"]["inputSchema"]["properties"]["nodes"]
        self.assertEqual(1, nodes_schema["minItems"])
        self.assertEqual(20, nodes_schema["maxItems"])
        self.assertEqual(
            {"clientNodeId", "dependencyIds", "routingInput"},
            set(nodes_schema["items"]["properties"]),
        )
        public_input = nodes_schema["items"]["properties"]["routingInput"]
        self.assertEqual(
            {"taskFacts", "contextBundle", "roleTemplateId"},
            set(public_input["properties"]),
        )
        serialized_input = json.dumps(
            by_name["smart_plan"]["inputSchema"],
            ensure_ascii=False,
            sort_keys=True,
        )
        for forbidden in (
            '"model"',
            '"reasoningEffort"',
            '"permission"',
            '"permissionProfileId"',
            '"catalogs"',
            '"accountEvidenceJobs"',
            '"reassessment"',
        ):
            self.assertNotIn(forbidden, serialized_input)
        rubric = public_input["description"]
        for marker in ("q=0", "q=1", "q=2", "p=0", "p=1", "p=2"):
            self.assertIn(marker, rubric)
        for criterion in (
            "q1-dependent-chain",
            "q1-bounded-tradeoff",
            "q2-cross-boundary-invariant",
            "q2-adversarial-concurrency",
            "q2-conflict-synthesis",
            "v1-reversible-persistent",
            "v1-user-visible-isolated",
            "v2-shared-or-production",
            "v2-destructive-or-unproven-rollback",
            "v2-trust-secret-permission",
            "v2-high-stakes",
            "v2-release-or-migration",
            "o1-discoverable-missing-fact",
            "o1-mutable-current-state",
            "o1-explicit-reversible-assumption",
            "o2-authority-conflict",
            "o2-undiscoverable-required-fact",
            "o2-unreproducible-conflict",
            "o2-uncontracted-interface",
        ):
            self.assertIn(criterion, serialized_input)
        for definition in definitions:
            self.assertFalse(definition["inputSchema"]["additionalProperties"])
            self.assertFalse(definition["outputSchema"]["additionalProperties"])
        Draft202012Validator(by_name["smart_plan"]["inputSchema"]).validate(
            {"nodes": _plan_nodes()}
        )

        external_refs: list[str] = []

        def collect(value: object) -> None:
            if isinstance(value, dict):
                reference = value.get("$ref")
                if isinstance(reference, str) and not reference.startswith("#"):
                    external_refs.append(reference)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        for definition in definitions:
            collect(definition["inputSchema"])
            collect(definition["outputSchema"])
        self.assertEqual([], external_refs)

    def test_input_contract_rejects_extra_fields_and_invalid_identifiers(self) -> None:
        with self.assertRaisesRegex(MCPContractV2Error, "неожиданные поля"):
            validate_tool_input_v2(
                "smart_plan",
                {"routingInput": {"phase": "smart-plan"}},
            )
        with self.assertRaisesRegex(MCPContractV2Error, "dependencyIds"):
            validate_tool_input_v2(
                "smart_plan",
                {
                    "nodes": [
                        {
                            "clientNodeId": "reader_a",
                            "dependencyIds": ["missing_a"],
                            "routingInput": _public_routing_input(),
                        }
                    ]
                },
            )
        with self.assertRaisesRegex(MCPContractV2Error, "неожиданные поля"):
            validate_tool_input_v2(
                "route_start",
                {
                    "routeId": "route2_" + "b" * 32,
                    "nodeId": "node2_" + "c" * 32,
                    "activationGate": {"gateFingerprint": "0" * 64},
                },
            )
        with self.assertRaisesRegex(MCPContractV2Error, "startRequestId"):
            validate_tool_input_v2(
                "smart_wait",
                {
                    "startRequestId": "чужой",
                    "cursor": None,
                    "pageSize": 20,
                    "waitSeconds": 15,
                },
            )

    def test_public_plan_input_accepts_semantics_and_rejects_service_fields(
        self,
    ) -> None:
        public = _public_routing_input()

        accepted = validate_tool_input_v2(
            "smart_plan",
            {
                "nodes": [
                    {
                        "clientNodeId": "reader_a",
                        "dependencyIds": [],
                        "routingInput": public,
                    }
                ]
            },
        )
        self.assertEqual(public, accepted["nodes"][0]["routingInput"])

        attackers = []
        for field, value in (
            ("model", "attacker-choice"),
            ("reasoningEffort", "max"),
            ("catalogs", {}),
            ("accountEvidenceJobs", []),
            ("reassessment", {}),
        ):
            candidate = json.loads(json.dumps(public))
            candidate[field] = value
            attackers.append(candidate)
        permission = json.loads(json.dumps(public))
        permission["taskFacts"]["delegation"]["permission"] = {
            "value": "allow",
            "evidenceRefIds": ["request"],
        }
        attackers.append(permission)

        for candidate in attackers:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(MCPContractV2Error, "routingInput"):
                    validate_tool_input_v2(
                        "smart_plan",
                        {
                            "nodes": [
                                {
                                    "clientNodeId": "reader_a",
                                    "dependencyIds": [],
                                    "routingInput": candidate,
                                }
                            ]
                        },
                    )

    def test_public_evidence_reserves_one_server_slot(self) -> None:
        public = _public_routing_input()
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
        self.assertEqual(63, len(evidence))
        validate_tool_input_v2(
            "smart_plan",
            {
                "nodes": [
                    {
                        "clientNodeId": "reader_a",
                        "dependencyIds": [],
                        "routingInput": public,
                    }
                ]
            },
        )

        evidence.append(
            {
                "evidenceRefId": "extra-overflow",
                "kind": "repository-file",
                "statement": "Лишний факт.",
                "sha256": "f" * 64,
            }
        )
        with self.assertRaisesRegex(MCPContractV2Error, "evidence"):
            validate_tool_input_v2(
                "smart_plan",
                {
                    "nodes": [
                        {
                            "clientNodeId": "reader_a",
                            "dependencyIds": [],
                            "routingInput": public,
                        }
                    ]
                },
            )

    def test_public_schema_reserves_server_evidence_namespace_everywhere(
        self,
    ) -> None:
        arguments = {"nodes": _plan_nodes()}
        arguments["nodes"][0]["routingInput"]["contextBundle"]["entries"][0][
            "sourceEvidenceRefs"
        ][0]["evidenceRefId"] = "server.delegation-policy"
        schema = next(
            item["inputSchema"]
            for item in get_tool_definitions_v2()
            if item["name"] == "smart_plan"
        )

        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(arguments)
        with self.assertRaisesRegex(MCPContractV2Error, "зарезервированную"):
            validate_tool_input_v2("smart_plan", arguments)

    def test_valid_public_plan_is_checked_by_system_python_without_site_packages(
        self,
    ) -> None:
        interpreter = next(
            (
                path
                for path in (
                    Path("/opt/homebrew/bin/python3"),
                    Path("/usr/bin/python3"),
                )
                if path.is_file()
            ),
            None,
        )
        if interpreter is None:
            self.skipTest("системный python3 отсутствует")
        script = """
import json
import sys
sys.path.insert(0, sys.argv[1])
from codex_smart_subagents.mcp_contracts_v2 import validate_tool_input_v2
validate_tool_input_v2("smart_plan", json.load(sys.stdin))
print("PUBLIC_CONTRACT_OK")
"""
        completed = subprocess.run(
            [str(interpreter), "-I", "-S", "-c", script, str(PLUGIN_SRC)],
            input=json.dumps({"nodes": _plan_nodes()}),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env={"PATH": os.defpath, "PYTHONPATH": ""},
            timeout=10,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("PUBLIC_CONTRACT_OK", completed.stdout.strip())


class MCPServerV2Tests(unittest.TestCase):
    def test_private_controller_handler_can_call_a_tool_without_json_rpc(self) -> None:
        output = _server().call_tool(
            "smart_plan",
            {"nodes": _plan_nodes()},
        )
        self.assertEqual("smart_plan", output["method"])
        self.assertEqual("SUCCESS", output["responseKind"])
        validate_tool_output_v2("smart_plan", output)

    def test_initialize_and_list_tools_have_no_fifth_user_tool(self) -> None:
        server = _server()
        initialized = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        )
        listed = server.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )

        self.assertEqual("0.2.0", initialized["result"]["serverInfo"]["version"])
        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [item["name"] for item in listed["result"]["tools"]],
        )
        plan = next(
            item for item in listed["result"]["tools"] if item["name"] == "smart_plan"
        )
        public_input = plan["inputSchema"]["properties"]["nodes"]["items"][
            "properties"
        ]["routingInput"]
        self.assertIn("q=0", public_input["description"])
        self.assertIn("p=2", public_input["description"])

    def test_smart_plan_issues_private_binding_and_returns_fingerprinted_protocol(
        self,
    ) -> None:
        response = _server().handle(_call("smart_plan", {"nodes": _plan_nodes()}))

        result = response["result"]
        structured = result["structuredContent"]
        self.assertFalse(result["isError"])
        self.assertEqual("smart_plan", structured["method"])
        self.assertEqual("SUCCESS", structured["responseKind"])
        self.assertEqual("DELEGATE", structured["payload"]["disposition"])
        self.assertEqual(
            {"model": "model-luna", "reasoningEffort": "medium"},
            structured["payload"]["nodeDecisions"][0]["selectedPair"],
        )
        self.assertNotIn("selectedPair", structured["payload"])
        self.assertEqual(
            structured,
            json.loads(result["content"][0]["text"]),
        )
        verify_public_response_v2(structured)
        validate_tool_output_v2("smart_plan", structured)
        plan_schema = next(
            item["outputSchema"]
            for item in _server().tool_definitions
            if item["name"] == "smart_plan"
        )
        Draft202012Validator(plan_schema).validate(structured)

    def test_route_start_injects_gate_and_never_accepts_it_from_model(self) -> None:
        dispatched: list[tuple[str, RequestContextV2]] = []
        server = _server(
            start_dispatcher=lambda start_request_id, context: dispatched.append(
                (start_request_id, context)
            )
        )
        response = server.handle(
            _call(
                "route_start",
                {
                    "routeId": "route2_" + "b" * 32,
                    "nodeId": "node2_" + "c" * 32,
                },
            )
        )
        self.assertEqual(
            "ATTESTING",
            response["result"]["structuredContent"]["payload"]["status"],
        )
        self.assertEqual([("sr2_" + "d" * 32, _context())], dispatched)

        rejected = server.handle(
            _call(
                "route_start",
                {
                    "routeId": "route2_" + "b" * 32,
                    "nodeId": "node2_" + "c" * 32,
                    "activationGate": {"gateFingerprint": "0" * 64},
                },
                request_id=2,
            )
        )
        self.assertEqual(-32602, rejected["error"]["code"])

    def test_route_start_submit_failure_preserves_success_and_retries_same_start(
        self,
    ) -> None:
        dispatched: list[str] = []

        def fail_once(start_request_id: str, _context: RequestContextV2) -> None:
            dispatched.append(start_request_id)
            if len(dispatched) == 1:
                raise RuntimeError("временный отказ внутрипроцессной очереди")

        server = _server(start_dispatcher=fail_once)
        arguments = {
            "routeId": "route2_" + "b" * 32,
            "nodeId": "node2_" + "c" * 32,
        }

        with self.assertLogs(
            "codex_smart_subagents.mcp_server_v2",
            level="ERROR",
        ):
            first = server.handle(_call("route_start", arguments))
            replay = server.handle(_call("route_start", arguments, request_id=2))

        self.assertNotIn("error", first)
        self.assertNotIn("error", replay)
        self.assertEqual(
            "SUCCESS",
            first["result"]["structuredContent"]["responseKind"],
        )
        self.assertEqual(
            ["sr2_" + "d" * 32, "sr2_" + "d" * 32],
            dispatched,
        )

    def test_gate_provider_failure_returns_ordinary_mode_without_leaking_detail(
        self,
    ) -> None:
        def unavailable():
            raise RuntimeError("секретная внутренняя причина")

        response = _server(gate_provider=unavailable).handle(
            _call(
                "route_start",
                {
                    "routeId": "route2_" + "b" * 32,
                    "nodeId": "node2_" + "c" * 32,
                },
            )
        )

        result = response["result"]
        structured = result["structuredContent"]
        self.assertFalse(result["isError"])
        self.assertEqual("ORDINARY", structured["responseKind"])
        self.assertEqual("SMART_DISABLED", structured["payload"]["reasonCode"])
        self.assertNotIn("секретная", json.dumps(structured, ensure_ascii=False))
        verify_public_response_v2(structured)

    def test_wait_and_cancel_use_only_authoritative_context(self) -> None:
        server = _server()
        waited = server.handle(
            _call(
                "smart_wait",
                {
                    "startRequestId": "sr2_" + "d" * 32,
                    "cursor": None,
                    "pageSize": 20,
                    "waitSeconds": 0,
                },
            )
        )["result"]["structuredContent"]
        cancelled = server.handle(
            _call(
                "smart_cancel",
                {
                    "startRequestId": "sr2_" + "d" * 32,
                    "reasonCode": "USER_REQUESTED",
                },
                request_id=2,
            )
        )["result"]["structuredContent"]

        self.assertEqual("smart_wait", waited["method"])
        self.assertEqual("READ", waited["payload"]["effect"]["operation"])
        self.assertEqual("CANCELLED", cancelled["payload"]["status"])
        verify_public_response_v2(waited)
        verify_public_response_v2(cancelled)

    def test_child_completion_reaches_wait_and_replayed_start_does_not_rerun(
        self,
    ) -> None:
        class DispatchStore(_Store):
            def __init__(self) -> None:
                self.state = "ATTESTING"
                self.execution_started = threading.Event()
                self.execution_release = threading.Event()
                self.calls = 0

            def read_start_request(
                self,
                start_request_id: str,
                request_context: RequestContextV2,
            ) -> StartRequestV2:
                del request_context
                return StartRequestV2(
                    start_request_id=start_request_id,
                    evidence_job_id="aej2_" + "e" * 32,
                    attempt_id="att2_" + "f" * 32,
                    route_id="route2_" + "b" * 32,
                    node_id="node2_" + "c" * 32,
                    queue_position=0,
                    deadline_at=NOW + timedelta(seconds=180),
                    state=self.state,
                )

            def read_start_status(
                self, *args: object, **kwargs: object
            ) -> StartStatusV2:
                del args, kwargs
                terminal = self.state == "SUCCEEDED"
                return StartStatusV2(
                    start_request_id="sr2_" + "d" * 32,
                    state=self.state,
                    evidence_job_state="SUCCEEDED",
                    admission_id="adm2_" + "a" * 32,
                    terminal=terminal,
                    page=StartEventPageV2(
                        cursor=None,
                        next_cursor=None,
                        items=(),
                    ),
                    terminal_result=(
                        StartTerminalResultV2(
                            attempt_id="att2_" + "f" * 32,
                            state="SUCCEEDED",
                            result_fingerprint="8" * 64,
                            result_bytes=96,
                            inline_result={
                                "summary": "Дочерняя задача завершена.",
                                "validationState": "passed",
                                "artifactId": "",
                            },
                            result_truncated=False,
                            error_code=None,
                        )
                        if terminal
                        else None
                    ),
                )

        class Execution:
            def __init__(self, store: DispatchStore) -> None:
                self.store = store

            def run(
                self,
                start_request: StartRequestV2,
                request_context: RequestContextV2,
            ) -> object:
                del start_request, request_context
                self.store.calls += 1
                self.store.state = "STARTED"
                self.store.execution_started.set()
                if not self.store.execution_release.wait(2):
                    raise TimeoutError("испытание не разрешило завершение")
                self.store.state = "SUCCEEDED"
                return object()

        store = DispatchStore()
        dispatcher_errors: list[BaseException] = []
        runtime = SmartTurnRuntimeV2(
            service=_Service(),
            store=store,
            clock=lambda: NOW,
        )
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=Execution(store),
            max_workers=1,
            clock=lambda: NOW,
            error_sink=lambda _identifier, error: dispatcher_errors.append(error),
        )
        dispatch_attempts = 0

        def submit_after_first_failure(
            identifier: str,
            context: RequestContextV2,
        ) -> bool:
            nonlocal dispatch_attempts
            dispatch_attempts += 1
            if dispatch_attempts == 1:
                raise RuntimeError("первичная постановка временно недоступна")
            return dispatcher.submit(identifier, context)

        server = MCPServerV2(
            runtime=runtime,
            request_context_provider=_context,
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            clock=lambda: NOW,
            start_dispatcher=submit_after_first_failure,
        )
        try:
            with self.assertLogs(
                "codex_smart_subagents.mcp_server_v2",
                level="ERROR",
            ):
                server.handle(
                    _call(
                        "route_start",
                        {
                            "routeId": "route2_" + "b" * 32,
                            "nodeId": "node2_" + "c" * 32,
                        },
                    )
                )
            self.assertFalse(store.execution_started.wait(0.05))
            server.handle(
                _call(
                    "smart_wait",
                    {
                        "startRequestId": "sr2_" + "d" * 32,
                        "cursor": None,
                        "pageSize": 20,
                        "waitSeconds": 0,
                    },
                    request_id=2,
                )
            )
            self.assertTrue(store.execution_started.wait(1))
            intermediate = server.handle(
                _call(
                    "smart_wait",
                    {
                        "startRequestId": "sr2_" + "d" * 32,
                        "cursor": None,
                        "pageSize": 20,
                        "waitSeconds": 0,
                    },
                    request_id=3,
                )
            )["result"]["structuredContent"]
            self.assertEqual("STARTED", intermediate["payload"]["state"])
            self.assertFalse(intermediate["payload"]["terminal"])
            self.assertIsNone(intermediate["payload"]["terminalResult"])

            store.execution_release.set()
            completed = server.handle(
                _call(
                    "smart_wait",
                    {
                        "startRequestId": "sr2_" + "d" * 32,
                        "cursor": None,
                        "pageSize": 20,
                        "waitSeconds": 1,
                    },
                    request_id=4,
                )
            )["result"]["structuredContent"]
            self.assertEqual("SUCCEEDED", completed["payload"]["state"])
            self.assertEqual(
                "Дочерняя задача завершена.",
                completed["payload"]["terminalResult"]["inlineResult"]["summary"],
            )
            validate_tool_output_v2("smart_wait", completed)
            wait_schema = next(
                item["outputSchema"]
                for item in get_tool_definitions_v2()
                if item["name"] == "smart_wait"
            )
            Draft202012Validator(wait_schema).validate(completed)
            self.assertTrue(dispatcher.wait_idle(2))

            server.handle(
                _call(
                    "route_start",
                    {
                        "routeId": "route2_" + "b" * 32,
                        "nodeId": "node2_" + "c" * 32,
                    },
                    request_id=5,
                )
            )
            self.assertTrue(dispatcher.wait_idle(2))
            self.assertEqual(1, store.calls)
            self.assertGreaterEqual(dispatch_attempts, 3)
            self.assertEqual([], dispatcher_errors)
        finally:
            store.execution_release.set()
            dispatcher.close()

    def test_repeated_and_parallel_wait_never_executes_expired_start(self) -> None:
        class ExpiredDispatchStore(_Store):
            def __init__(self) -> None:
                self.state = "ATTESTING"
                self._lock = threading.Lock()
                self.terminal_mutations = 0
                self.terminal_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

            def read_start_request(
                self,
                start_request_id: str,
                request_context: RequestContextV2,
            ) -> StartRequestV2:
                del request_context
                with self._lock:
                    state = self.state
                return StartRequestV2(
                    start_request_id=start_request_id,
                    evidence_job_id="aej2_" + "e" * 32,
                    attempt_id="att2_" + "f" * 32,
                    route_id="route2_" + "b" * 32,
                    node_id="node2_" + "c" * 32,
                    queue_position=0,
                    deadline_at=NOW - timedelta(microseconds=1),
                    state=state,
                )

            def record_account_evidence_terminal(
                self, *args: object, **kwargs: object
            ) -> object:
                with self._lock:
                    self.terminal_calls.append((args, kwargs))
                    replayed = self.state == "FAILED"
                    if not replayed:
                        self.state = "FAILED"
                        self.terminal_mutations += 1
                return type(
                    "Terminal",
                    (),
                    {"state": "FAILED", "terminal": True, "replayed": replayed},
                )()

            def read_start_status(
                self, *args: object, **kwargs: object
            ) -> StartStatusV2:
                del args, kwargs
                with self._lock:
                    state = self.state
                return StartStatusV2(
                    start_request_id="sr2_" + "d" * 32,
                    state=state,
                    evidence_job_state="FAILED" if state == "FAILED" else "QUEUED",
                    admission_id=None,
                    terminal=state == "FAILED",
                    page=StartEventPageV2(cursor=None, next_cursor=None, items=()),
                )

        class ForbiddenExecution:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, *_args: object) -> object:
                self.calls += 1
                raise AssertionError("просроченная заявка дошла до исполнителя")

        store = ExpiredDispatchStore()
        execution = ForbiddenExecution()
        dispatcher_errors: list[BaseException] = []
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=2,
            clock=lambda: NOW,
            error_sink=lambda _identifier, error: dispatcher_errors.append(error),
        )
        runtime = SmartTurnRuntimeV2(
            service=_Service(),
            store=store,
            clock=lambda: NOW,
        )
        server = MCPServerV2(
            runtime=runtime,
            request_context_provider=_context,
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            clock=lambda: NOW,
            start_dispatcher=dispatcher.submit,
        )
        arguments = {
            "startRequestId": "sr2_" + "d" * 32,
            "cursor": None,
            "pageSize": 20,
            "waitSeconds": 0,
        }
        try:
            with ThreadPoolExecutor(max_workers=8) as callers:
                responses = tuple(
                    callers.map(
                        lambda request_id: server.handle(
                            _call(
                                "smart_wait",
                                arguments,
                                request_id=request_id,
                            )
                        ),
                        range(1, 17),
                    )
                )
            self.assertTrue(dispatcher.wait_idle(2))
            repeated = server.handle(
                _call("smart_wait", arguments, request_id=17)
            )["result"]["structuredContent"]
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()

        self.assertTrue(all("error" not in response for response in responses))
        self.assertEqual("FAILED", repeated["payload"]["state"])
        self.assertTrue(repeated["payload"]["terminal"])
        self.assertEqual(0, execution.calls)
        self.assertEqual(1, store.terminal_mutations)
        self.assertEqual([], dispatcher_errors)
        self.assertTrue(store.terminal_calls)
        self.assertTrue(
            all(
                options["failure_code"] == "REQUEST_DEADLINE_EXCEEDED"
                for _, options in store.terminal_calls
            )
        )


if __name__ == "__main__":
    unittest.main()
