from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.identity import RequestContext  # noqa: E402
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
        second_payload["turnBinding"] = self.store.issue_turn_binding(context())
        second = self.service.smart_plan(second_payload, context())

        self.assertEqual(first["routeId"], second["routeId"])
        self.assertEqual("delegate", first["overallDisposition"])
        self.assertTrue(first["startable"])
        decision = first["nodeDecisions"][0]
        self.assertEqual("gpt-5.6-luna", decision["selectedModel"])
        self.assertEqual("medium", decision["reasoningEffort"])

    def test_same_request_key_with_different_plan_conflicts(self) -> None:
        payload = self._bound_plan()
        self.service.smart_plan(payload, context())
        changed = self._bound_plan()
        changed["nodes"][0]["mission"] = "Другая задача."
        with self.assertRaises(ServiceError) as caught:
            self.service.smart_plan(changed, context())
        self.assertEqual("IDEMPOTENCY_CONFLICT", caught.exception.code)

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

    def test_mixed_direct_and_delegate_graph_is_not_startable(self) -> None:
        payload = valid_plan()
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

    def _bound_plan(self) -> dict[str, object]:
        payload = valid_plan()
        payload["turnBinding"] = self.store.issue_turn_binding(context())
        payload["catalogGeneration"] = self.catalog.generation
        return payload


if __name__ == "__main__":
    unittest.main()
