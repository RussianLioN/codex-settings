from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from tests.smart_subagents.fixtures import valid_plan


PLUGIN_ROOT = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "codex-smart-subagents"
)
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.contracts import (  # noqa: E402
    ContractError,
    get_tool_definitions,
    validate_tool_input,
)


class ContractTests(unittest.TestCase):
    def test_server_exposes_exactly_four_tools(self) -> None:
        definitions = get_tool_definitions()
        self.assertEqual(
            ["smart_plan", "smart_start", "smart_wait", "smart_cancel"],
            [tool["name"] for tool in definitions],
        )

    def test_all_object_schemas_are_recursively_strict(self) -> None:
        for tool in get_tool_definitions():
            for schema_name in ("inputSchema", "outputSchema"):
                with self.subTest(tool=tool["name"], schema=schema_name):
                    self._assert_object_schemas_strict(tool[schema_name])

    def test_plan_rejects_extra_fields_at_every_level(self) -> None:
        cases: list[dict[str, object]] = []

        root = valid_plan()
        root["cwd"] = "/tmp"
        cases.append(root)

        node = valid_plan()
        node["nodes"][0]["model"] = "gpt-5.6-sol"  # type: ignore[index]
        cases.append(node)

        assessment = valid_plan()
        assessment["nodes"][0]["assessment"]["permissions"] = "full"  # type: ignore[index]
        cases.append(assessment)

        interval = valid_plan()
        interval["nodes"][0]["assessment"]["delegation"]["q"]["path"] = "/tmp"  # type: ignore[index]
        cases.append(interval)

        for payload in cases:
            with self.subTest(payload=json.dumps(payload, ensure_ascii=False)):
                with self.assertRaises(ContractError) as caught:
                    validate_tool_input("smart_plan", payload)
                self.assertEqual("INVALID_INPUT", caught.exception.code)

    def test_plan_enforces_size_and_count_limits(self) -> None:
        too_long = valid_plan()
        too_long["nodes"][0]["mission"] = "x" * 2001  # type: ignore[index]
        with self.assertRaises(ContractError):
            validate_tool_input("smart_plan", too_long)

        too_many = valid_plan()
        template = too_many["nodes"][0]  # type: ignore[index]
        too_many["nodes"] = []
        for index in range(21):
            node = copy.deepcopy(template)
            node["clientNodeId"] = f"node-{index}"
            too_many["nodes"].append(node)  # type: ignore[union-attr]
        with self.assertRaises(ContractError):
            validate_tool_input("smart_plan", too_many)

    def test_other_tool_inputs_are_strict_and_bounded(self) -> None:
        valid = {
            "smart_start": {
                "schemaVersion": "1",
                "routeId": "rt1_" + "A" * 43,
            },
            "smart_wait": {
                "schemaVersion": "1",
                "routeId": "rt1_" + "A" * 43,
                "afterSequence": 0,
                "timeoutSeconds": 60,
            },
            "smart_cancel": {
                "schemaVersion": "1",
                "routeId": "rt1_" + "A" * 43,
                "reasonCode": "user_requested",
            },
        }
        for name, payload in valid.items():
            self.assertEqual(payload, validate_tool_input(name, payload))
            extra = dict(payload, env={"TOKEN": "secret"})
            with self.assertRaises(ContractError):
                validate_tool_input(name, extra)

        invalid_wait = dict(valid["smart_wait"], timeoutSeconds=61)
        with self.assertRaises(ContractError):
            validate_tool_input("smart_wait", invalid_wait)

    def test_input_property_names_do_not_expose_process_controls(self) -> None:
        forbidden = {
            "argv",
            "command",
            "cwd",
            "env",
            "environment",
            "model",
            "reasoningeffort",
            "permissions",
            "path",
        }
        for tool in get_tool_definitions():
            names = self._property_names(tool["inputSchema"])
            self.assertFalse(
                forbidden & {name.lower() for name in names},
                (tool["name"], names),
            )

    def _assert_object_schemas_strict(self, schema: object) -> None:
        if isinstance(schema, dict):
            if schema.get("type") == "object":
                self.assertIs(schema.get("additionalProperties"), False, schema)
            for value in schema.values():
                self._assert_object_schemas_strict(value)
        elif isinstance(schema, list):
            for value in schema:
                self._assert_object_schemas_strict(value)

    def _property_names(self, schema: object) -> set[str]:
        names: set[str] = set()
        if isinstance(schema, dict):
            properties = schema.get("properties")
            if isinstance(properties, dict):
                names.update(properties)
            for value in schema.values():
                names.update(self._property_names(value))
        elif isinstance(schema, list):
            for value in schema:
                names.update(self._property_names(value))
        return names


if __name__ == "__main__":
    unittest.main()
