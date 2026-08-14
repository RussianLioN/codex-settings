from __future__ import annotations

import hashlib
import json
import sys
import unittest
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_execution_v2 import (  # noqa: E402
    ChildExecutionV2,
    ChildExecutionV2Error,
    materialize_child_prompt_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    DependencyResultV2,
    PlannedNodeV2,
    RequestContextV2,
    StateStoreV2Error,
    StartRequestV2,
)


def _context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell",
        session_id="session",
        turn_id="turn",
        codex_home="/private/codex-home",
        repo_root="/private/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
        activation_fingerprint="3" * 64,
        compatibility_fingerprint="4" * 64,
        issued_control_epoch=1,
    )


def _start() -> StartRequestV2:
    from datetime import datetime, timezone

    return StartRequestV2(
        start_request_id="sr2_" + "1" * 32,
        evidence_job_id="aej2_" + "2" * 32,
        attempt_id="att2_" + "3" * 32,
        route_id="route2_" + "4" * 32,
        node_id="node2_" + "5" * 32,
        queue_position=0,
        deadline_at=datetime(2026, 7, 18, 12, 3, tzinfo=timezone.utc),
        state="ATTESTING",
    )


def _plan(*, content: str = "проверь файл"):
    encoded = content.encode("utf-8")
    node = PlannedNodeV2(
        node_id="node2_" + "5" * 32,
        ordinal=0,
        role="researcher",
        mission="Найти проверяемый факт",
        dependencies=(),
        context_refs=("request",),
        scope_id="scope-v2",
        artifact_profile_id="reader-artifact-v2",
        validation_profile_id="reader-validation-v2",
        assessment={"q": 0, "p": 0, "v": 0, "o": 0},
        risk_flags=(),
        selected_model="model-from-policy",
        reasoning_effort="effort-from-policy",
        permission_profile_id="codex-smart-reader",
        disposition="DELEGATE",
    )
    return SimpleNamespace(
        route_id="route2_" + "4" * 32,
        node_id=node.node_id,
        node=node,
        node_state="PLANNED",
        account_context_fingerprint="8" * 64,
        plan_output={
            "nodes": [
                {
                    "clientNodeId": "other_a",
                    "nodeId": "node2_" + "9" * 32,
                    "dependencyNodeIds": [],
                    "routingInput": {
                        "roleTemplateId": "implementer-v1",
                        "contextBundle": {},
                    },
                },
                {
                    "clientNodeId": "reader_a",
                    "nodeId": node.node_id,
                    "dependencyNodeIds": [],
                    "routingInput": {
                        "roleTemplateId": "researcher-v1",
                        "contextBundle": {
                            "schemaVersion": 1,
                            "contractVersion": "codex-context-bundle-v1",
                            "bundleId": "bundle",
                            "maxBytes": max(1024, len(encoded)),
                            "totalBytes": len(encoded),
                            "entries": [
                                {
                                    "contextRefId": "request",
                                    "kind": "task-request",
                                    "required": True,
                                    "sourceEvidenceRefs": [
                                        {
                                            "evidenceRefId": "request",
                                            "evidenceSha256": "a" * 64,
                                        }
                                    ],
                                    "sha256": hashlib.sha256(encoded).hexdigest(),
                                    "byteLength": len(encoded),
                                    "content": content,
                                }
                            ],
                        },
                    },
                },
            ]
        },
    )


def _dependency_result(
    node_id: str,
    result: dict[str, object],
    *,
    raw_result: dict[str, object] | None = None,
) -> DependencyResultV2:
    raw = canonical_json_v1(raw_result or result).encode("utf-8")
    projection = {
        "nodeId": node_id,
        "result": result,
        "rawResultFingerprint": hashlib.sha256(raw).hexdigest(),
        "rawResultBytes": len(raw),
        "resultTruncated": raw_result is not None and raw_result != result,
    }
    return DependencyResultV2(
        node_id=node_id,
        result=result,
        raw_result_fingerprint=projection["rawResultFingerprint"],
        raw_result_bytes=projection["rawResultBytes"],
        result_truncated=projection["resultTruncated"],
        projection_fingerprint=domain_fingerprint(
            "codex-smart/dependency-result-projection/v2",
            projection,
        ),
    )


ROLE = {
    "schemaVersion": 1,
    "contractVersion": "codex-role-template-v1",
    "templateId": "researcher-v1",
    "semanticRole": "researcher",
    "executionProfile": "reader",
    "objective": "Найти факты.",
    "requiredContextKinds": ["task-request"],
    "requiredEvidenceKinds": ["repository-file"],
    "requiredOutputFields": ["findings"],
    "completionConditions": ["Указать доказательства."],
}


class _Service:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def process_account_evidence(self, **kwargs: object):
        self.calls.append("evidence")
        return SimpleNamespace(admission_id="adm2_" + "6" * 32)


class _Store:
    def __init__(self, calls: list[str], plan: object) -> None:
        self.calls = calls
        self.plan = plan

    def read_node_plan(self, *args: object):
        self.calls.append("plan")
        return self.plan

    def abort_admission_before_permit(self, *args: object, **kwargs: object):
        self.calls.append("terminalize")
        self.terminalization = (args, kwargs)
        return SimpleNamespace(state="FAILED_BEFORE_START")

    def record_account_evidence_terminal(
        self, *args: object, **kwargs: object
    ) -> object:
        self.calls.append("terminalize-request")
        self.request_terminalization = (args, kwargs)
        return SimpleNamespace(state="FAILED", terminal=True, replayed=False)


class _Coordinator:
    def __init__(self, calls: list[str], error: Exception | None = None) -> None:
        self.calls = calls
        self.error = error
        self.observed: dict[str, object] = {}

    def run(self, **kwargs: object):
        self.calls.append("launch")
        self.observed = kwargs
        if self.error is not None:
            raise self.error
        return SimpleNamespace(state="SUCCEEDED", result={"findings": ["ok"]})


class ChildExecutionV2Tests(unittest.TestCase):
    def test_timezone_without_offset_is_rejected_as_invalid_clock(self) -> None:
        class MissingOffset(tzinfo):
            def utcoffset(self, _value: datetime | None) -> None:
                return None

        worker = object.__new__(ChildExecutionV2)
        worker.clock = lambda: datetime(
            2026,
            7,
            18,
            12,
            0,
            tzinfo=MissingOffset(),
        )

        with self.assertRaisesRegex(ChildExecutionV2Error, "CLOCK_INVALID"):
            worker._now()

    def test_successful_admission_gets_full_child_timeout_near_evidence_deadline(
        self,
    ) -> None:
        calls: list[str] = []
        coordinator = _Coordinator(calls)
        start = _start()
        evidence_completed_at = start.deadline_at - timedelta(microseconds=1)
        worker = ChildExecutionV2(
            service=_Service(calls),
            store=_Store(calls, _plan()),
            launch_coordinator=coordinator,
            launch_preparer=lambda _plan, _prompt, _context, _start: object(),
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            child_timeout_seconds=900,
            clock=lambda: evidence_completed_at,
        )

        worker.run(start, _context())

        self.assertEqual(900, coordinator.observed["timeout_seconds"])

    def test_one_node_runs_evidence_then_durable_plan_then_exact_launch(self) -> None:
        calls: list[str] = []
        coordinator = _Coordinator(calls)
        prepared = object()

        def prepare(
            plan: object,
            prompt: str,
            context: RequestContextV2,
            start_request: StartRequestV2,
        ):
            calls.append("prepare")
            self.assertIn("Найти проверяемый факт", prompt)
            self.assertIn("проверь файл", prompt)
            self.assertEqual("model-from-policy", plan.node.selected_model)
            self.assertEqual("8" * 64, plan.account_context_fingerprint)
            self.assertEqual(_context(), context)
            self.assertEqual(_start(), start_request)
            return prepared

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=_Store(calls, _plan()),
            launch_coordinator=coordinator,
            launch_preparer=prepare,
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
        )

        outcome = worker.run(_start(), _context())

        self.assertEqual(["evidence", "plan", "prepare", "launch"], calls)
        self.assertEqual("SUCCEEDED", outcome.state)
        self.assertIs(prepared, coordinator.observed["prepared"])
        self.assertEqual("adm2_" + "6" * 32, coordinator.observed["admission_id"])

    def test_changed_context_content_is_rejected_before_preparation(self) -> None:
        plan = _plan()
        plan.plan_output["nodes"][1]["routingInput"]["contextBundle"]["entries"][
            0
        ]["content"] = "изменено"
        with self.assertRaisesRegex(ChildExecutionV2Error, "CONTEXT_CONTENT_MISMATCH"):
            materialize_child_prompt_v2(plan, ROLE)

    def test_dependency_results_are_materialized_with_verified_fingerprints(
        self,
    ) -> None:
        plan = _plan()
        dependency_node_id = "node2_" + "d" * 32
        result = {
            "summary": "Найдено подтверждённое ограничение.",
            "evidenceRefs": ["repository:file.py:12"],
        }
        plan.node = replace(plan.node, dependencies=(dependency_node_id,))
        plan.plan_output["nodes"][1]["dependencyNodeIds"] = [dependency_node_id]
        plan.dependency_results = (
            _dependency_result(dependency_node_id, result),
        )

        prompt = json.loads(materialize_child_prompt_v2(plan, ROLE))

        self.assertEqual(
            [
                {
                    "nodeId": dependency_node_id,
                    "result": result,
                    "rawResultFingerprint": plan.dependency_results[
                        0
                    ].raw_result_fingerprint,
                    "rawResultBytes": plan.dependency_results[0].raw_result_bytes,
                    "resultTruncated": False,
                    "projectionFingerprint": plan.dependency_results[
                        0
                    ].projection_fingerprint,
                }
            ],
            prompt["dependencyResults"],
        )

    def test_dependency_result_with_unverified_fingerprint_is_rejected(self) -> None:
        plan = _plan()
        dependency_node_id = "node2_" + "d" * 32
        plan.node = replace(plan.node, dependencies=(dependency_node_id,))
        plan.plan_output["nodes"][1]["dependencyNodeIds"] = [dependency_node_id]
        plan.dependency_results = (
            replace(
                _dependency_result(
                    dependency_node_id,
                    {"summary": "Подменённый результат."},
                ),
                projection_fingerprint="f" * 64,
            ),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "DEPENDENCY_RESULT_MISMATCH",
        ):
            materialize_child_prompt_v2(plan, ROLE)

    def test_large_dependency_uses_bounded_verified_projection(self) -> None:
        plan = _plan()
        dependency_node_id = "node2_" + "d" * 32
        summary = "Найдено ограничение в договоре."
        raw_result = {
            "events": [
                {"type": "tool.output", "payload": "x" * (96 * 1024)},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps({"summary": summary}, ensure_ascii=False),
                    },
                },
            ]
        }
        plan.node = replace(plan.node, dependencies=(dependency_node_id,))
        plan.plan_output["nodes"][1]["dependencyNodeIds"] = [dependency_node_id]
        plan.dependency_results = (
            _dependency_result(
                dependency_node_id,
                {"summary": summary},
                raw_result=raw_result,
            ),
        )

        encoded_prompt = materialize_child_prompt_v2(plan, ROLE)
        prompt = json.loads(encoded_prompt)

        self.assertLess(len(encoded_prompt.encode("utf-8")), 64 * 1024)
        self.assertEqual({"summary": summary}, prompt["dependencyResults"][0]["result"])
        self.assertTrue(prompt["dependencyResults"][0]["resultTruncated"])
        self.assertGreater(prompt["dependencyResults"][0]["rawResultBytes"], 64 * 1024)

    def test_maximum_graph_dependencies_fit_with_bounded_context_budget(self) -> None:
        plan = _plan(content="x" * (24 * 1024))
        dependency_node_ids = tuple(
            "node2_" + f"{index:032x}" for index in range(1, 20)
        )
        plan.node = replace(plan.node, dependencies=dependency_node_ids)
        plan.plan_output["nodes"][1]["dependencyNodeIds"] = list(
            dependency_node_ids
        )
        plan.dependency_results = tuple(
            _dependency_result(node_id, {"summary": "x" * 400})
            for node_id in dependency_node_ids
        )

        prompt = materialize_child_prompt_v2(plan, ROLE)

        self.assertLessEqual(len(prompt.encode("utf-8")), 64 * 1024)

    def test_child_context_budget_reserves_space_for_prompt_envelope(self) -> None:
        plan = _plan(content="x" * (24 * 1024 + 1))

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "CHILD_CONTEXT_INVALID",
        ):
            materialize_child_prompt_v2(plan, ROLE)

    def test_preparation_failure_after_admission_is_terminalized_once(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())

        def fail_prepare(
            _plan: object,
            _prompt: str,
            _context: RequestContextV2,
            _start_request: StartRequestV2,
        ):
            calls.append("prepare")
            raise RuntimeError("prepare exploded")

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=fail_prepare,
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(ChildExecutionV2Error, "CHILD_PREPARATION_FAILED"):
            worker.run(_start(), _context())

        self.assertEqual(
            ["evidence", "plan", "prepare", "terminalize"],
            calls,
        )
        _, arguments = store.terminalization
        self.assertEqual("adm2_" + "6" * 32, arguments["admission_id"])
        self.assertEqual("CHILD_PREPARATION_FAILED", arguments["failure_code"])

    def test_coordinator_error_is_not_terminalized_twice(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())
        coordinator = _Coordinator(calls, RuntimeError("coordinator owns failure"))
        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=coordinator,
            launch_preparer=lambda _plan, _prompt, _context, _start: object(),
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(RuntimeError, "coordinator owns failure"):
            worker.run(_start(), _context())

        self.assertEqual(["evidence", "plan", "launch"], calls)

    def test_invalid_clock_still_terminalizes_admission(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())
        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda _plan, _prompt, _context, _start: object(),
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0),
        )

        with self.assertRaisesRegex(ChildExecutionV2Error, "CLOCK_INVALID"):
            worker.run(_start(), _context())

        self.assertEqual(["terminalize-request"], calls)
        _, arguments = store.request_terminalization
        self.assertEqual("CLOCK_INVALID", arguments["failure_code"])
        self.assertEqual("INTERNAL", arguments["problem"]["category"])
        self.assertEqual("INTERNAL_ERROR", arguments["problem"]["code"])
        self.assertIsNotNone(arguments["now"].tzinfo)

    def test_clock_exception_before_gate_is_terminalized(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())

        def failed_clock() -> datetime:
            raise RuntimeError("clock callback failed")

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda _plan, _prompt, _context, _start: object(),
            activation_gate_provider=lambda: calls.append("gate") or {},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=failed_clock,
        )

        with self.assertRaisesRegex(ChildExecutionV2Error, "CLOCK_INVALID"):
            worker.run(_start(), _context())

        self.assertEqual(["terminalize-request"], calls)
        _, arguments = store.request_terminalization
        self.assertEqual("CLOCK_INVALID", arguments["failure_code"])
        self.assertEqual("INTERNAL", arguments["problem"]["category"])
        self.assertEqual("INTERNAL_ERROR", arguments["problem"]["code"])
        self.assertIsNotNone(arguments["now"].tzinfo)

    def test_expired_request_never_enters_launch_preparation(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())
        start = StartRequestV2(
            **{
                **_start().__dict__,
                "deadline_at": datetime(
                    2026,
                    7,
                    18,
                    11,
                    59,
                    tzinfo=timezone.utc,
                ),
            }
        )
        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda *_args: calls.append("prepare"),
            activation_gate_provider=lambda: {"gateFingerprint": "7" * 64},
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "REQUEST_DEADLINE_EXCEEDED",
        ):
            worker.run(start, _context())

        self.assertEqual(["terminalize-request"], calls)
        arguments, options = store.request_terminalization
        self.assertEqual((start.evidence_job_id, _context()), arguments)
        self.assertEqual("FAILED", options["state"])
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["failure_code"],
        )

    def test_gate_failure_before_admission_is_terminalized_once(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())

        def unavailable_gate() -> dict[str, object]:
            calls.append("gate")
            raise RuntimeError("gate unavailable")

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda *_args: calls.append("prepare"),
            activation_gate_provider=unavailable_gate,
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "ACTIVATION_GATE_UNAVAILABLE",
        ):
            worker.run(_start(), _context())

        self.assertEqual(["gate", "terminalize-request"], calls)
        arguments, options = store.request_terminalization
        self.assertEqual((_start().evidence_job_id, _context()), arguments)
        self.assertEqual("FAILED", options["state"])
        self.assertEqual("ACTIVATION_GATE_UNAVAILABLE", options["failure_code"])
        self.assertEqual("UNAVAILABLE", options["problem"]["category"])
        self.assertEqual(
            "ADAPTIVE_ACTIVATION_UNCOMMITTED",
            options["problem"]["code"],
        )

    def test_gate_error_after_deadline_uses_deadline_terminal(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())
        times = iter(
            (
                datetime(2026, 7, 18, 12, 2, 59, tzinfo=timezone.utc),
                datetime(2026, 7, 18, 12, 3, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 18, 12, 3, 1, tzinfo=timezone.utc),
            )
        )

        def slow_failed_gate() -> dict[str, object]:
            calls.append("gate")
            raise RuntimeError("gate timed out after the request deadline")

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda *_args: calls.append("prepare"),
            activation_gate_provider=slow_failed_gate,
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: next(times),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "REQUEST_DEADLINE_EXCEEDED",
        ):
            worker.run(_start(), _context())

        self.assertEqual(["gate", "terminalize-request"], calls)
        _, options = store.request_terminalization
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["failure_code"],
        )

    def test_deadline_after_successful_gate_still_prevents_admission(self) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())
        times = iter(
            (
                datetime(2026, 7, 18, 12, 2, 59, tzinfo=timezone.utc),
                datetime(2026, 7, 18, 12, 3, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 18, 12, 3, 1, tzinfo=timezone.utc),
            )
        )

        def slow_gate() -> dict[str, object]:
            calls.append("gate")
            return {"gateFingerprint": "7" * 64}

        worker = ChildExecutionV2(
            service=_Service(calls),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda *_args: calls.append("prepare"),
            activation_gate_provider=slow_gate,
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: next(times),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "REQUEST_DEADLINE_EXCEEDED",
        ):
            worker.run(_start(), _context())

        self.assertEqual(["gate", "terminalize-request"], calls)
        _, options = store.request_terminalization
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["failure_code"],
        )

    def test_deadline_at_evidence_claim_is_terminalized_before_future_exit(
        self,
    ) -> None:
        calls: list[str] = []
        store = _Store(calls, _plan())

        class DeadlineAtClaimService:
            def process_account_evidence(self, **_kwargs: object) -> object:
                calls.append("evidence")
                raise StateStoreV2Error(
                    "ACCOUNT_EVIDENCE_DEADLINE",
                    "evidence deadline elapsed",
                )

        def gate() -> dict[str, object]:
            calls.append("gate")
            return {"gateFingerprint": "7" * 64}

        worker = ChildExecutionV2(
            service=DeadlineAtClaimService(),
            store=store,
            launch_coordinator=_Coordinator(calls),
            launch_preparer=lambda *_args: calls.append("prepare"),
            activation_gate_provider=gate,
            launch_barrier=nullcontext,
            role_templates=(ROLE,),
            owner_id="worker-1",
            pid=123,
            process_start_marker="pid-123-start",
            clock=lambda: datetime(2026, 7, 18, 12, 2, 59, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(
            ChildExecutionV2Error,
            "REQUEST_DEADLINE_EXCEEDED",
        ):
            worker.run(_start(), _context())

        self.assertEqual(["gate", "evidence", "terminalize-request"], calls)
        _, options = store.request_terminalization
        self.assertEqual("FAILED", options["state"])
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["failure_code"],
        )
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["problem"]["code"],
        )


if __name__ == "__main__":
    unittest.main()
