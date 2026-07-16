from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
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


class ExecutionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = SmartStore(Path(self.directory.name) / "state")
        self.catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.service = SmartService(self.store, self.catalog)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def queued_route(self) -> str:
        payload = valid_plan()
        payload["turnBinding"] = self.store.issue_turn_binding(context())
        payload["catalogGeneration"] = self.catalog.generation
        plan = self.service.smart_plan(payload, context())
        self.service.smart_start(
            {"schemaVersion": "1", "routeId": plan["routeId"]},
            context(),
        )
        return plan["routeId"]

    def test_claim_is_atomic_context_bound_and_contains_full_node_contract(
        self,
    ) -> None:
        route_id = self.queued_route()
        now = datetime.now(timezone.utc)

        claim = self.store.claim_next_route(
            owner_id="controller-1",
            pid=123,
            start_marker="boot-1",
            now=now,
            lease_seconds=45,
        )

        self.assertIsNotNone(claim)
        self.assertEqual(route_id, claim.route.route_id)
        self.assertEqual(context(), claim.context)
        self.assertEqual(RouteState.LEASED, claim.route.state)
        self.assertRegex(claim.lease_token, r"^lease1_[A-Za-z0-9_-]{43}$")
        self.assertEqual(1, len(claim.nodes))
        node = claim.nodes[0]
        self.assertEqual("node-1", node.node_id)
        self.assertEqual((), node.context_refs)
        self.assertEqual("artifact_report", node.artifact_profile_id)
        self.assertEqual("validation_none", node.validation_profile_id)
        self.assertEqual((), node.risk_flags)
        self.assertIsNone(
            self.store.claim_next_route(
                owner_id="controller-2",
                pid=456,
                start_marker="boot-2",
                now=now,
                lease_seconds=45,
            )
        )

    def test_node_attempt_intent_and_terminal_result_are_durable(self) -> None:
        route_id = self.queued_route()
        claim = self.store.claim_next_route(
            owner_id="controller-1",
            pid=123,
            start_marker="boot-1",
            now=datetime.now(timezone.utc),
            lease_seconds=45,
        )
        node_id = claim.nodes[0].node_id
        self.store.transition_route(
            route_id,
            claim.context,
            RouteState.PREPARING,
            event="route_preparing",
            code="PREPARING",
            message="",
        )
        self.store.transition_route(
            route_id,
            claim.context,
            RouteState.RUNNING,
            event="route_running",
            code="RUNNING",
            message="",
        )
        self.store.transition_node(
            route_id,
            node_id,
            RouteState.LEASED,
            event="node_leased",
            code="LEASED",
            message="",
        )
        self.store.transition_node(
            route_id,
            node_id,
            RouteState.PREPARING,
            event="node_preparing",
            code="PREPARING",
            message="",
        )
        self.store.transition_node(
            route_id,
            node_id,
            RouteState.RUNNING,
            event="node_running",
            code="RUNNING",
            message="",
        )
        intent_id = self.store.record_intent(
            route_id=route_id,
            node_id=node_id,
            kind="spawn_child",
            payload={"argvFingerprint": "c" * 64},
        )
        attempt_id = self.store.begin_attempt(
            route_id=route_id,
            node_id=node_id,
            model="gpt-5.6-luna",
            reasoning_effort="medium",
            permission_profile_id="permission_reader",
            pid=789,
            argv_fingerprint="c" * 64,
            permission_probe_id="pc1_" + "A" * 43,
        )
        self.store.complete_intent(intent_id)
        self.store.complete_attempt(
            attempt_id,
            state="SUCCEEDED",
            result={"summary": "Проверено."},
            attestation={"observedModel": "gpt-5.6-luna"},
        )
        for state, event in (
            (RouteState.COLLECTING, "node_collecting"),
            (RouteState.ATTESTING, "node_attesting"),
            (RouteState.VALIDATING, "node_validating"),
        ):
            self.store.transition_node(
                route_id,
                node_id,
                state,
                event=event,
                code=state.value,
                message="",
            )
        self.store.complete_node(
            route_id,
            node_id,
            result={"summary": "Проверено.", "fingerprint": "d" * 64},
        )
        self.store.transition_route(
            route_id,
            claim.context,
            RouteState.COLLECTING,
            event="route_collecting",
            code="COLLECTING",
            message="",
        )
        self.store.transition_route(
            route_id,
            claim.context,
            RouteState.ATTESTING,
            event="route_attesting",
            code="ATTESTING",
            message="",
        )
        self.store.transition_route(
            route_id,
            claim.context,
            RouteState.VALIDATING,
            event="route_validating",
            code="VALIDATING",
            message="",
        )
        terminal = {
            "artifactId": "report_reader",
            "fingerprint": "e" * 64,
            "summary": "Маршрут проверен.",
            "validationState": "passed",
        }
        route = self.store.finish_route(
            route_id,
            claim.context,
            RouteState.SUCCEEDED,
            terminal_result=terminal,
            event="route_succeeded",
            code="SUCCEEDED",
            message="",
        )

        self.assertEqual(terminal, route.terminal_result)
        self.assertEqual([], self.store.pending_intents(route_id))
        attempts = self.store.attempts_for_route(route_id)
        self.assertEqual("SUCCEEDED", attempts[0]["state"])
        self.assertEqual(
            {"summary": "Проверено."},
            attempts[0]["result"],
        )
        nodes = self.store.execution_bundle(route_id).nodes
        self.assertEqual(RouteState.SUCCEEDED, nodes[0].state)
        self.assertEqual("Проверено.", nodes[0].result["summary"])

    def test_stale_lease_can_be_requeued_and_claimed_again(self) -> None:
        route_id = self.queued_route()
        now = datetime.now(timezone.utc)
        first = self.store.claim_next_route(
            owner_id="controller-1",
            pid=123,
            start_marker="boot-1",
            now=now,
            lease_seconds=1,
        )
        self.assertIsNotNone(first)

        recovered = self.store.recover_stale_leases(
            now=now + timedelta(seconds=2),
        )
        self.assertEqual([route_id], recovered)
        self.store.requeue_recovering(route_id)
        second = self.store.claim_next_route(
            owner_id="controller-2",
            pid=456,
            start_marker="boot-2",
            now=now + timedelta(seconds=3),
            lease_seconds=45,
        )
        self.assertEqual(route_id, second.route.route_id)
        self.assertNotEqual(first.lease_token, second.lease_token)

    def test_heartbeat_requires_the_active_lease_identity(self) -> None:
        self.queued_route()
        now = datetime.now(timezone.utc)
        claim = self.store.claim_next_route(
            owner_id="controller-1",
            pid=123,
            start_marker="boot-1",
            now=now,
            lease_seconds=45,
        )
        extended = self.store.heartbeat_route_lease(
            route_id=claim.route.route_id,
            owner_id="controller-1",
            lease_token=claim.lease_token,
            now=now + timedelta(seconds=10),
            lease_seconds=45,
        )
        self.assertEqual(now + timedelta(seconds=55), extended)
        with self.assertRaisesRegex(Exception, "LEASE_FORBIDDEN"):
            self.store.heartbeat_route_lease(
                route_id=claim.route.route_id,
                owner_id="controller-1",
                lease_token="lease1_" + "B" * 43,
                now=now,
                lease_seconds=45,
            )


if __name__ == "__main__":
    unittest.main()
