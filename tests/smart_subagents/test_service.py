from __future__ import annotations

import copy
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.routing import (  # noqa: E402
    DelegationAssessment,
    Interval,
)
from codex_smart_subagents import service as service_module  # noqa: E402
from codex_smart_subagents.service import ServiceError, SmartService  # noqa: E402
from codex_smart_subagents.store import SmartStore  # noqa: E402

from tests.smart_subagents.fixtures import valid_plan


def context(session_id: str = "session-1") -> RequestContext:
    return RequestContext(
        shell_session_id="shell-1",
        session_id=session_id,
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root=str(REPO),
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
    )


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = SmartStore(Path(self.directory.name) / "state")
        self.catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.service = SmartService(self.store, self.catalog)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def test_plan_is_idempotent_and_selects_model_and_effort(self) -> None:
        payload = self._bound_plan()
        first = self.service.smart_plan(payload, context())
        second_payload = copy.deepcopy(payload)
        second = self.service.smart_plan(second_payload, context())

        self.assertEqual(first["routeId"], second["routeId"])
        self.assertEqual("delegate", first["overallDisposition"])
        self.assertTrue(first["startable"])
        decision = first["nodeDecisions"][0]
        self.assertEqual("gpt-5.6-luna", decision["selectedModel"])
        self.assertEqual("medium", decision["reasoningEffort"])

    def test_consumed_plan_binding_rejects_another_request_pair(self) -> None:
        payload = self._bound_plan()
        self.service.smart_plan(payload, context())
        changed_key = copy.deepcopy(payload)
        changed_key["requestKey"] = "request-0002"
        changed_hash = copy.deepcopy(payload)
        changed_hash["nodes"][0]["mission"] = "Другая задача."

        for changed in (changed_key, changed_hash):
            with self.subTest(request_key=changed["requestKey"]):
                with self.assertRaises(ServiceError) as caught:
                    self.service.smart_plan(changed, context())
                self.assertEqual(
                    "TURN_BINDING_USED",
                    caught.exception.code,
                )

    def test_same_request_key_with_different_plan_conflicts(self) -> None:
        payload = self._bound_plan()
        self.service.smart_plan(payload, context())
        changed = self._bound_plan()
        changed["nodes"][0]["mission"] = "Другая задача."
        with self.assertRaises(ServiceError) as caught:
            self.service.smart_plan(changed, context())
        self.assertEqual("IDEMPOTENCY_CONFLICT", caught.exception.code)

    def test_plan_rejects_unknown_or_role_incompatible_catalog_ids(
        self,
    ) -> None:
        cases = []

        unknown_scope = self._bound_plan()
        unknown_scope["nodes"][0]["scopeId"] = "scope_0123456789abcdef"
        cases.append(unknown_scope)

        reader_candidate = self._bound_plan()
        reader_candidate["nodes"][0][
            "artifactProfileId"
        ] = self.catalog.opaque_id("artifact", "candidate")
        cases.append(reader_candidate)

        reader_validation = self._bound_plan()
        reader_validation["nodes"][0][
            "validationProfileId"
        ] = self.catalog.opaque_id("validation", "python")
        cases.append(reader_validation)

        for payload in cases:
            with self.subTest(node=payload["nodes"][0]):
                with self.assertRaises(ServiceError) as caught:
                    self.service.smart_plan(payload, context())
                self.assertEqual(
                    "CATALOG_REFERENCE_INVALID",
                    caught.exception.code,
                )
                self.store.consume_turn_binding(
                    payload["turnBinding"],
                    context(),
                )

    def test_start_is_idempotent_and_forbidden_cross_session(self) -> None:
        plan = self.service.smart_plan(self._bound_plan(), context())
        payload = {"schemaVersion": "1", "routeId": plan["routeId"]}
        first = self.service.smart_start(payload, context())
        second = self.service.smart_start(payload, context())
        self.assertEqual(first["runId"], second["runId"])
        self.assertEqual("QUEUED", first["state"])

        with self.assertRaises(ServiceError) as caught:
            self.service.smart_start(payload, context("other-session"))
        self.assertEqual("ROUTE_FORBIDDEN", caught.exception.code)

    def test_wait_and_cancel_are_bounded_and_idempotent(self) -> None:
        plan = self.service.smart_plan(self._bound_plan(), context())
        route_id = plan["routeId"]
        self.service.smart_start(
            {"schemaVersion": "1", "routeId": route_id},
            context(),
        )
        waited = self.service.smart_wait(
            {
                "schemaVersion": "1",
                "routeId": route_id,
                "afterSequence": 0,
                "timeoutSeconds": 0,
            },
            context(),
        )
        self.assertEqual("QUEUED", waited["state"])
        self.assertGreaterEqual(waited["sequence"], 1)

        cancel_payload = {
            "schemaVersion": "1",
            "routeId": route_id,
            "reasonCode": "user_requested",
        }
        first = self.service.smart_cancel(cancel_payload, context())
        second = self.service.smart_cancel(cancel_payload, context())
        self.assertEqual("CANCELLED", first["newState"])
        self.assertEqual("CANCELLED", second["newState"])
        self.assertTrue(first["accepted"])
        self.assertFalse(second["accepted"])

    def test_direct_plan_cannot_start(self) -> None:
        payload = self._bound_plan()
        delegation = payload["nodes"][0]["assessment"]["delegation"]
        delegation.update(
            {
                "q": {"min": 0, "max": 0},
                "p": {"min": 0, "max": 0},
                "v": {"min": 0, "max": 0},
                "o": {"min": 2, "max": 2},
            }
        )
        plan = self.service.smart_plan(payload, context())
        self.assertEqual("direct", plan["overallDisposition"])
        self.assertFalse(plan["startable"])
        with self.assertRaises(ServiceError) as caught:
            self.service.smart_start(
                {"schemaVersion": "1", "routeId": plan["routeId"]},
                context(),
            )
        self.assertEqual("ROUTE_NOT_STARTABLE", caught.exception.code)

    def test_hard_ban_can_require_user_clarification(self) -> None:
        payload = self._bound_plan()
        payload["nodes"][0]["hardBan"] = "clarify"
        payload["nodes"][0]["clarificationQuestion"] = (
            "Разрешено ли изменять публичный контракт?"
        )

        plan = self.service.smart_plan(payload, context())

        self.assertEqual("clarify", plan["overallDisposition"])
        self.assertFalse(plan["startable"])
        self.assertEqual(
            ["Разрешено ли изменять публичный контракт?"],
            plan["clarificationQuestions"],
        )
        self.assertEqual("hard_ban", plan["nodeDecisions"][0]["reasonCode"])

    def test_each_boundary_is_reclassified_once_with_bounded_parallelism(
        self,
    ) -> None:
        payload = valid_plan(self.catalog)
        template = payload["nodes"][0]
        template["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 1, "max": 2},
            "o": {"min": 0, "max": 1},
        }
        payload["nodes"] = []
        for index in range(3):
            node = copy.deepcopy(template)
            node["clientNodeId"] = f"boundary-{index}"
            payload["nodes"].append(node)
        payload["turnBinding"] = self.store.issue_turn_binding(context())
        payload["catalogGeneration"] = self.catalog.generation

        calls: list[str] = []
        active = 0
        maximum_active = 0
        lock = threading.Lock()
        first_wave = threading.Barrier(2)

        def reclassify(node: dict[str, object]) -> DelegationAssessment:
            nonlocal active, maximum_active
            with lock:
                calls.append(str(node["clientNodeId"]))
                active += 1
                maximum_active = max(maximum_active, active)
                call_number = len(calls)
            try:
                if call_number <= 2:
                    first_wave.wait(timeout=2)
                return DelegationAssessment(
                    q=Interval(1, 2),
                    p=Interval(0, 1),
                    v=Interval(2, 2),
                    o=Interval(0, 1),
                )
            finally:
                with lock:
                    active -= 1

        service = SmartService(
            self.store,
            self.catalog,
            reclassifier=reclassify,
            max_reclassifier_workers=2,
        )
        plan = service.smart_plan(payload, context())

        self.assertEqual("delegate", plan["overallDisposition"])
        self.assertCountEqual(
            ["boundary-0", "boundary-1", "boundary-2"],
            calls,
        )
        self.assertEqual(3, len(calls))
        self.assertEqual(2, maximum_active)

    def test_parallel_exact_plan_retry_runs_boundary_reclassification_once(
        self,
    ) -> None:
        payload = self._bound_plan()
        payload["nodes"][0]["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 1, "max": 2},
            "o": {"min": 0, "max": 1},
        }
        second_store = SmartStore(self.store.state_dir)
        calls = 0
        calls_lock = threading.Lock()

        def reclassify(_node: dict[str, object]) -> DelegationAssessment:
            nonlocal calls
            with calls_lock:
                calls += 1
            threading.Event().wait(0.15)
            return DelegationAssessment(
                q=Interval(1, 2),
                p=Interval(0, 1),
                v=Interval(2, 2),
                o=Interval(0, 1),
            )

        services = (
            SmartService(
                self.store,
                self.catalog,
                reclassifier=reclassify,
            ),
            SmartService(
                second_store,
                self.catalog,
                reclassifier=reclassify,
            ),
        )
        barrier = threading.Barrier(2)
        routes: list[str] = []
        failures: list[BaseException] = []
        result_lock = threading.Lock()

        def plan(service: SmartService) -> None:
            try:
                barrier.wait(timeout=2)
                result = service.smart_plan(
                    copy.deepcopy(payload),
                    context(),
                )
                with result_lock:
                    routes.append(result["routeId"])
            except BaseException as exc:
                with result_lock:
                    failures.append(exc)

        threads = [
            threading.Thread(target=plan, args=(service,))
            for service in services
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual([], failures)
            self.assertEqual(1, calls)
            self.assertEqual(2, len(routes))
            self.assertEqual(1, len(set(routes)))
            self.assertEqual({}, service_module._PLAN_FLIGHTS)
        finally:
            second_store.close()

    def test_same_binding_different_parallel_keys_launches_boundary_once(
        self,
    ) -> None:
        first = self._bound_plan()
        first["nodes"][0]["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 2},
            "p": {"min": 0, "max": 1},
            "v": {"min": 1, "max": 2},
            "o": {"min": 0, "max": 1},
        }
        second = copy.deepcopy(first)
        second["requestKey"] = "different-request-key"
        calls = 0
        calls_lock = threading.Lock()

        def reclassify(_node: dict[str, object]) -> DelegationAssessment:
            nonlocal calls
            with calls_lock:
                calls += 1
            threading.Event().wait(0.15)
            return DelegationAssessment(
                q=Interval(1, 2),
                p=Interval(0, 1),
                v=Interval(2, 2),
                o=Interval(0, 1),
            )

        service = SmartService(
            self.store,
            self.catalog,
            reclassifier=reclassify,
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        outcome_lock = threading.Lock()

        def plan(payload: dict[str, object]) -> None:
            try:
                barrier.wait(timeout=2)
                service.smart_plan(payload, context())
                outcome = "planned"
            except ServiceError as exc:
                outcome = exc.code
            with outcome_lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(
                target=plan,
                args=(copy.deepcopy(payload),),
            )
            for payload in (first, second)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertCountEqual(["planned", "TURN_BINDING_USED"], outcomes)
        self.assertEqual(1, calls)
        self.assertEqual({}, service_module._PLAN_FLIGHTS)

    def test_implementer_is_always_routed_to_sol_high_or_above(self) -> None:
        payload = self._bound_plan()
        payload["nodes"][0]["role"] = "implementer"
        payload["nodes"][0]["artifactProfileId"] = self.catalog.opaque_id(
            "artifact",
            "candidate",
        )

        plan = self.service.smart_plan(payload, context())
        decision = plan["nodeDecisions"][0]

        self.assertEqual("delegate", decision["disposition"])
        self.assertEqual("gpt-5.6-sol", decision["selectedModel"])
        self.assertEqual("high", decision["reasoningEffort"])

    def test_account_model_visibility_promotes_without_downgrading_effort(
        self,
    ) -> None:
        service = SmartService(
            self.store,
            self.catalog,
            available_model_efforts={
                "gpt-5.6-terra": frozenset({"medium", "high"}),
                "gpt-5.6-sol": frozenset({"high", "xhigh", "max"}),
            },
        )
        plan = service.smart_plan(self._bound_plan(), context())
        self.assertEqual(
            "gpt-5.6-terra",
            plan["nodeDecisions"][0]["selectedModel"],
        )
        self.assertEqual(
            "medium",
            plan["nodeDecisions"][0]["reasoningEffort"],
        )

        payload = self._bound_plan()
        payload["requestKey"] = "high-reasoning-fallback"
        payload["nodes"][0]["assessment"]["reasoning"] = {
            "evidence": 2,
            "verification": 1,
            "harm": 1,
        }
        service = SmartService(
            self.store,
            self.catalog,
            available_model_efforts={
                "gpt-5.6-luna": frozenset({"low", "medium"}),
                "gpt-5.6-sol": frozenset({"high", "xhigh", "max"}),
            },
        )
        plan = service.smart_plan(payload, context())
        self.assertEqual(
            ("gpt-5.6-sol", "high"),
            (
                plan["nodeDecisions"][0]["selectedModel"],
                plan["nodeDecisions"][0]["reasoningEffort"],
            ),
        )

    def test_missing_required_sol_pair_fails_closed(self) -> None:
        service = SmartService(
            self.store,
            self.catalog,
            available_model_efforts={
                "gpt-5.6-luna": frozenset({"low", "medium"}),
                "gpt-5.6-terra": frozenset({"medium", "high", "xhigh"}),
            },
        )
        payload = self._bound_plan()
        payload["nodes"][0]["role"] = "implementer"
        payload["nodes"][0]["artifactProfileId"] = self.catalog.opaque_id(
            "artifact",
            "candidate",
        )

        with self.assertRaises(ServiceError) as caught:
            service.smart_plan(payload, context())

        self.assertEqual("MODEL_UNAVAILABLE", caught.exception.code)

    def test_mixed_direct_and_delegate_graph_is_not_startable(self) -> None:
        payload = valid_plan(self.catalog)
        direct = payload["nodes"][0]
        direct["clientNodeId"] = "reader_direct"
        direct["assessment"]["delegation"] = {
            "q": {"min": 0, "max": 0},
            "p": {"min": 0, "max": 0},
            "v": {"min": 0, "max": 0},
            "o": {"min": 2, "max": 2},
        }
        delegated = copy.deepcopy(payload["nodes"][0])
        delegated["clientNodeId"] = "reader_delegate"
        delegated["assessment"]["delegation"] = {
            "q": {"min": 2, "max": 2},
            "p": {"min": 2, "max": 2},
            "v": {"min": 2, "max": 2},
            "o": {"min": 0, "max": 0},
        }
        payload["nodes"] = [direct, delegated]
        payload["turnBinding"] = self.store.issue_turn_binding(context())
        payload["requestKey"] = "mixed-disposition"
        payload["catalogGeneration"] = self.catalog.generation

        plan = self.service.smart_plan(payload, context())

        self.assertEqual("direct", plan["overallDisposition"])
        self.assertFalse(plan["startable"])

    def test_queue_node_limit_fails_before_consuming_turn_binding(self) -> None:
        self.catalog.limits["queue_nodes"] = 1
        self.service.smart_plan(self._bound_plan(), context())
        blocked = self._bound_plan()
        blocked["requestKey"] = "second-route"

        with self.assertRaises(ServiceError) as caught:
            self.service.smart_plan(blocked, context())

        self.assertEqual("QUEUE_FULL", caught.exception.code)
        self.store.consume_turn_binding(blocked["turnBinding"], context())

    def test_expired_planned_route_becomes_stale_and_releases_capacity(
        self,
    ) -> None:
        now = [datetime(2026, 7, 16, tzinfo=timezone.utc)]
        self.catalog.limits["queue_nodes"] = 1
        service = SmartService(
            self.store,
            self.catalog,
            clock=lambda: now[0],
        )
        first = service.smart_plan(self._bound_plan(), context())
        now[0] += timedelta(minutes=16)
        second_payload = self._bound_plan()
        second_payload["requestKey"] = "after-expiry"

        second = service.smart_plan(second_payload, context())

        self.assertTrue(second["startable"])
        self.assertEqual(
            "STALE",
            self.store.get_route(first["routeId"], context()).state.value,
        )
        with self.assertRaises(ServiceError) as caught:
            service.smart_start(
                {"schemaVersion": "1", "routeId": first["routeId"]},
                context(),
            )
        self.assertEqual("ROUTE_EXPIRED", caught.exception.code)

    def test_parallel_plans_cannot_exceed_atomic_node_quota(self) -> None:
        self.catalog.limits["queue_nodes"] = 1
        second_store = SmartStore(self.store.state_dir)
        services = (
            SmartService(self.store, self.catalog),
            SmartService(second_store, self.catalog),
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def plan(index: int) -> None:
            payload = valid_plan(self.catalog)
            payload["requestKey"] = f"parallel-{index}"
            payload["turnBinding"] = services[
                index
            ].store.issue_turn_binding(context())
            payload["catalogGeneration"] = self.catalog.generation
            barrier.wait()
            try:
                services[index].smart_plan(payload, context())
                outcome = "planned"
            except ServiceError as exc:
                outcome = exc.code
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=plan, args=(index,))
            for index in range(2)
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertCountEqual(["planned", "QUEUE_FULL"], outcomes)
            self.assertEqual(1, self.store.active_node_count())
        finally:
            second_store.close()

    def _bound_plan(self) -> dict[str, object]:
        payload = valid_plan(self.catalog)
        payload["turnBinding"] = self.store.issue_turn_binding(context())
        payload["catalogGeneration"] = self.catalog.generation
        return payload


if __name__ == "__main__":
    unittest.main()
