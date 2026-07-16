from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.execution import (  # noqa: E402
    ExecutionEngine,
    NodeExecutionError,
    NodeExecutionOutcome,
)
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.service import SmartService  # noqa: E402
from codex_smart_subagents.state import RouteState  # noqa: E402
from codex_smart_subagents.store import SmartStore  # noqa: E402

from tests.smart_subagents.fixtures import valid_plan


def context() -> RequestContext:
    return RequestContext(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root=str(REPO),
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
    )


def three_node_plan(catalog: Catalog, store: SmartStore) -> dict[str, object]:
    template = valid_plan()["nodes"][0]
    first = copy.deepcopy(template)
    first["clientNodeId"] = "reader_a"
    first["mission"] = "Проверить область A."
    second = copy.deepcopy(template)
    second["clientNodeId"] = "reader_b"
    second["mission"] = "Проверить область B."
    writer = copy.deepcopy(template)
    writer["clientNodeId"] = "writer"
    writer["mission"] = "Собрать проверенный кандидат."
    writer["role"] = "implementer"
    writer["dependencyIds"] = ["reader_a", "reader_b"]
    writer["artifactProfileId"] = "artifact_candidate"
    writer["riskFlags"] = ["writer_final_validation"]
    writer["assessment"]["delegation"] = {
        "q": {"min": 2, "max": 2},
        "p": {"min": 1, "max": 2},
        "v": {"min": 2, "max": 2},
        "o": {"min": 0, "max": 0},
    }
    return {
        "schemaVersion": "1",
        "turnBinding": store.issue_turn_binding(context()),
        "requestKey": "engine-route-1",
        "catalogGeneration": catalog.generation,
        "nodes": [first, second, writer],
    }


class FakeNodeExecutor:
    def __init__(self, store: SmartStore, *, fail_node: str = "") -> None:
        self.store = store
        self.fail_node = fail_node
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.completed: list[str] = []
        self.started: list[str] = []
        self.started_event = threading.Event()

    def execute(self, request, cancellation):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.started.append(request.node.node_id)
            self.started_event.set()
            self.assert_dependencies(request)
            pending = self.store.pending_intents(request.route_id)
            if not any(
                intent["nodeId"] == request.node.node_id
                and intent["kind"] == "execute_node"
                for intent in pending
            ):
                raise AssertionError("external execution started without intent")
        try:
            deadline = time.monotonic() + 0.12
            while time.monotonic() < deadline:
                if cancellation.is_set():
                    raise NodeExecutionError("CANCELLED", "cancelled")
                time.sleep(0.005)
            if request.node.node_id == self.fail_node:
                raise NodeExecutionError("FAKE_FAILURE", "bounded failure")
            summary = f"Готово: {request.node.node_id}"
            artifact_id = (
                "art1_" + "A" * 43
                if request.node.role == "implementer"
                else ""
            )
            return NodeExecutionOutcome(
                summary=summary,
                fingerprint=hashlib.sha256(summary.encode()).hexdigest(),
                validation_state="passed",
                artifact_id=artifact_id,
                attestation={
                    "observedModel": request.node.selected_model,
                    "observedEffort": request.node.reasoning_effort,
                },
                permission_probe_id="pc1_" + "A" * 43,
                argv_fingerprint="c" * 64,
            )
        finally:
            with self.lock:
                self.active -= 1
                if request.node.node_id != self.fail_node:
                    self.completed.append(request.node.node_id)

    def assert_dependencies(self, request) -> None:
        if request.node.node_id == "writer":
            if set(request.dependency_results) != {"reader_a", "reader_b"}:
                raise AssertionError("writer started before reader results")


class ExecutionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = SmartStore(Path(self.directory.name) / "state")
        self.catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.service = SmartService(self.store, self.catalog)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def start_route(self) -> str:
        plan = self.service.smart_plan(
            three_node_plan(self.catalog, self.store),
            context(),
        )
        self.service.smart_start(
            {"schemaVersion": "1", "routeId": plan["routeId"]},
            context(),
        )
        return plan["routeId"]

    def test_executes_ready_readers_in_parallel_then_writer_candidate(self) -> None:
        route_id = self.start_route()
        executor = FakeNodeExecutor(self.store)
        engine = ExecutionEngine(
            self.store,
            executor,
            max_workers=2,
            max_sol_workers=1,
            lease_seconds=45,
            heartbeat_seconds=1,
        )

        self.assertTrue(engine.run_once())

        route = self.store.execution_bundle(route_id).route
        self.assertEqual(RouteState.CANDIDATE_READY, route.state)
        self.assertEqual("art1_" + "A" * 43, route.terminal_result["artifactId"])
        self.assertEqual("passed", route.terminal_result["validationState"])
        self.assertEqual(2, executor.max_active)
        self.assertGreater(
            executor.started.index("writer"),
            executor.started.index("reader_a"),
        )
        self.assertGreater(
            executor.started.index("writer"),
            executor.started.index("reader_b"),
        )
        self.assertEqual([], self.store.pending_intents(route_id))
        self.assertEqual(3, len(self.store.attempts_for_route(route_id)))

    def test_node_failure_fails_route_without_starting_dependents(self) -> None:
        route_id = self.start_route()
        executor = FakeNodeExecutor(self.store, fail_node="reader_b")
        engine = ExecutionEngine(
            self.store,
            executor,
            max_workers=2,
            max_sol_workers=1,
            lease_seconds=45,
            heartbeat_seconds=1,
        )

        self.assertTrue(engine.run_once())

        route = self.store.execution_bundle(route_id).route
        self.assertEqual(RouteState.FAILED, route.state)
        self.assertNotIn("writer", executor.started)
        self.assertEqual("failed", route.terminal_result["validationState"])
        attempts = self.store.attempts_for_route(route_id)
        self.assertIn("FAILED", {attempt["state"] for attempt in attempts})

    def test_empty_queue_returns_without_work(self) -> None:
        engine = ExecutionEngine(
            self.store,
            FakeNodeExecutor(self.store),
            max_workers=2,
            max_sol_workers=1,
            lease_seconds=45,
            heartbeat_seconds=1,
        )
        self.assertFalse(engine.run_once())

    def test_smart_cancel_propagates_to_running_node_and_process_contract(
        self,
    ) -> None:
        route_id = self.start_route()
        executor = FakeNodeExecutor(self.store)
        engine = ExecutionEngine(
            self.store,
            executor,
            max_workers=2,
            max_sol_workers=1,
            lease_seconds=45,
            heartbeat_seconds=1,
        )
        thread = threading.Thread(target=engine.run_once)
        thread.start()
        self.assertTrue(executor.started_event.wait(2))

        cancelled = self.service.smart_cancel(
            {
                "schemaVersion": "1",
                "routeId": route_id,
                "reasonCode": "user_requested",
            },
            context(),
        )
        thread.join(timeout=3)

        self.assertFalse(thread.is_alive())
        self.assertTrue(cancelled["accepted"])
        route = self.store.execution_bundle(route_id).route
        self.assertEqual(RouteState.CANCELLED, route.state)
        self.assertEqual(
            "not_applicable",
            route.terminal_result["validationState"],
        )


if __name__ == "__main__":
    unittest.main()
