from __future__ import annotations

import sys
import unittest
from pathlib import Path


PLUGIN_SRC = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "codex-smart-subagents"
    / "src"
)
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.graph import GraphError, TaskNode, validate_graph  # noqa: E402


class GraphValidationTests(unittest.TestCase):
    def test_valid_reader_graph_and_writer_sink(self) -> None:
        nodes = [
            TaskNode("research", "researcher"),
            TaskNode("diagnose", "diagnostician", ("research",)),
            TaskNode("risk", "risk_auditor", ("research",)),
            TaskNode(
                "write",
                "implementer",
                ("diagnose", "risk"),
            ),
        ]
        validated = validate_graph(nodes)
        self.assertEqual(("research", "diagnose", "risk", "write"), validated.order)
        self.assertEqual(2, validated.depth)

    def test_cycle_is_rejected_by_kahn_validation(self) -> None:
        nodes = [
            TaskNode("a", "researcher", ("b",)),
            TaskNode("b", "validator", ("a",)),
        ]
        self._assert_code("GRAPH_CYCLE", nodes)

    def test_unknown_dependency_and_self_dependency_are_rejected(self) -> None:
        self._assert_code(
            "UNKNOWN_DEPENDENCY",
            [TaskNode("a", "researcher", ("missing",))],
        )
        self._assert_code(
            "SELF_DEPENDENCY",
            [TaskNode("a", "researcher", ("a",))],
        )

    def test_writer_must_be_unique_final_sink_and_cover_all_readers(self) -> None:
        self._assert_code(
            "MULTIPLE_WRITERS",
            [
                TaskNode("a", "implementer"),
                TaskNode("b", "implementer"),
            ],
        )
        self._assert_code(
            "WRITER_NOT_SINK",
            [
                TaskNode("write", "implementer"),
                TaskNode("check", "validator", ("write",)),
            ],
        )
        self._assert_code(
            "WRITER_MISSING_READER_DEPENDENCY",
            [
                TaskNode("read-a", "researcher"),
                TaskNode("read-b", "validator"),
                TaskNode("write", "implementer", ("read-a",)),
            ],
        )

    def test_node_edge_depth_and_split_limits_are_enforced(self) -> None:
        too_many_nodes = [TaskNode(f"n{index}", "researcher") for index in range(21)]
        self._assert_code("TOO_MANY_NODES", too_many_nodes)

        dense = [
            TaskNode(
                f"n{index}",
                "researcher",
                tuple(f"n{dependency}" for dependency in range(index)),
            )
            for index in range(12)
        ]
        self._assert_code("TOO_MANY_EDGES", dense)

        deep = [
            TaskNode("n0", "researcher"),
            TaskNode("n1", "researcher", ("n0",)),
            TaskNode("n2", "researcher", ("n1",)),
            TaskNode("n3", "researcher", ("n2",)),
            TaskNode("n4", "researcher", ("n3",)),
            TaskNode("n5", "researcher", ("n4",)),
        ]
        self._assert_code("GRAPH_TOO_DEEP", deep)

        with self.assertRaises(GraphError) as caught:
            validate_graph([TaskNode("a", "researcher")], split_generation=3)
        self.assertEqual("SPLIT_GENERATION_EXCEEDED", caught.exception.code)

    def _assert_code(self, code: str, nodes: list[TaskNode]) -> None:
        with self.assertRaises(GraphError) as caught:
            validate_graph(nodes)
        self.assertEqual(code, caught.exception.code)


if __name__ == "__main__":
    unittest.main()

