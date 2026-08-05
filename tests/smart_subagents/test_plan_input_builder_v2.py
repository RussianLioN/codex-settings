from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "plugins"
    / "codex-smart-subagents"
    / "scripts"
    / "prepare_smart_plan.py"
)
SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(SRC))

from codex_smart_subagents.public_routing_input_v2 import (  # noqa: E402
    validate_public_routing_input_v2,
)


def _valid_spec() -> dict[str, Any]:
    return {
        "nodes": [
            {
                "clientNodeId": "simple-check",
                "dependencyIds": [],
                "taskText": "Ответить одним словом: проверка.",
                "roleTemplateId": "researcher-v1",
                "evidence": [
                    {
                        "evidenceRefId": "request",
                        "kind": "user-request",
                        "statement": "Пользователь просит ответить одним словом.",
                    },
                    {
                        "evidenceRefId": "policy",
                        "kind": "explicit-policy",
                        "statement": "Независимое исполнение не требуется.",
                    },
                    {
                        "evidenceRefId": "scope",
                        "kind": "repository-file",
                        "statement": "Работа состоит из одной простой единицы.",
                    },
                ],
                "workShape": {
                    "scopeUnits": 1,
                    "workUnits": 1,
                    "boundaries": 1,
                    "workstreams": 1,
                },
                "delegation": {
                    "objectivelyVerifiable": True,
                    "independentWorkUnits": 0,
                },
                "contextEntries": [
                    {
                        "contextRefId": "request",
                        "kind": "task-request",
                        "evidenceRefIds": ["request"],
                        "content": "Ответь одним словом: проверка.",
                    },
                    {
                        "contextRefId": "scope",
                        "kind": "source-excerpt",
                        "evidenceRefIds": ["scope"],
                        "content": "Один короткий ответ без изменения файлов.",
                    },
                ],
            }
        ]
    }


class PlanInputBuilderV2Tests(unittest.TestCase):
    def test_cli_builds_a_valid_plan_and_computes_integrity_fields(self) -> None:
        spec = _valid_spec()

        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--spec-json", json.dumps(spec)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        plan = json.loads(completed.stdout)
        self.assertEqual({"nodes"}, set(plan))
        node = plan["nodes"][0]
        routing_input = validate_public_routing_input_v2(node["routingInput"])
        evidence = {
            item["evidenceRefId"]: item
            for item in routing_input["taskFacts"]["evidence"]
        }
        for item in evidence.values():
            expected = hashlib.sha256(item["statement"].encode("utf-8")).hexdigest()
            self.assertEqual(expected, item["sha256"])
        total = 0
        for entry in routing_input["contextBundle"]["entries"]:
            encoded = entry["content"].encode("utf-8")
            total += len(encoded)
            self.assertEqual(len(encoded), entry["byteLength"])
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), entry["sha256"])
            for reference in entry["sourceEvidenceRefs"]:
                self.assertEqual(
                    evidence[reference["evidenceRefId"]]["sha256"],
                    reference["evidenceSha256"],
                )
        self.assertEqual(total, routing_input["contextBundle"]["totalBytes"])
        self.assertGreaterEqual(
            routing_input["contextBundle"]["maxBytes"], total
        )

    def test_cli_rejects_dependency_cycles_before_smart_plan(self) -> None:
        spec = _valid_spec()
        first = spec["nodes"][0]
        second = copy.deepcopy(first)
        first["clientNodeId"] = "first-check"
        first["dependencyIds"] = ["second-check"]
        second["clientNodeId"] = "second-check"
        second["dependencyIds"] = ["first-check"]
        spec["nodes"].append(second)

        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--spec-json", json.dumps(spec)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("цикл", completed.stderr)

    def test_cli_preserves_acyclic_forward_dependencies(self) -> None:
        spec = _valid_spec()
        first = spec["nodes"][0]
        second = copy.deepcopy(first)
        first["clientNodeId"] = "dependent-check"
        first["dependencyIds"] = ["foundation-check"]
        second["clientNodeId"] = "foundation-check"
        spec["nodes"].append(second)

        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--spec-json", json.dumps(spec)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
