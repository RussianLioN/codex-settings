from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.closed_json_schema_v2 import (  # noqa: E402
    ClosedJsonSchemaV2Error,
    build_closed_json_schema_validator_v2,
)


SCHEMA_DIR = ROOT / "docs" / "contracts" / "schemas"
VECTOR_PATH = ROOT / "docs" / "contracts" / "vectors" / "lifecycle-v2.json"
_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_JOURNAL_FIXTURES = (
    "migrationDiscoveredJournal",
    "migrationExitPendingJournal",
    "migrationFencedJournal",
    "activationFencedJournal",
    "abortReversibleJournal",
    "abortTerminalJournal",
    "recoveryOverlayJournal",
)
_LIFECYCLE_SCHEMA_CASES = frozenset(
    {
        "lifecycle-projection-v2",
        "operation-journal-v2",
        "operation-step-v2",
    }
)


def _reference_validator(
    schema_directory: Path,
    root_name: str,
) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in schema_directory.glob("*.json")
    }
    resources = [
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
    ]
    return Draft202012Validator(
        schemas[root_name],
        registry=Registry().with_resources(resources),
        format_checker=FormatChecker(),
    )


def _patched(document: Any, mutation: dict[str, Any]) -> Any:
    result = copy.deepcopy(document)
    tokens = mutation["path"].removeprefix("/").split("/")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in tokens]
    parent = result
    for token in tokens[:-1]:
        parent = parent[int(token)] if type(parent) is list else parent[token]
    token = tokens[-1]
    operation = mutation["operation"]
    if operation == "remove":
        if type(parent) is list:
            parent.pop(int(token))
        else:
            del parent[token]
    elif operation == "replace":
        if type(parent) is list:
            parent[int(token)] = copy.deepcopy(mutation["value"])
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        if type(parent) is list:
            index = len(parent) if token == "-" else int(token)
            parent.insert(index, copy.deepcopy(mutation["value"]))
        else:
            parent[token] = copy.deepcopy(mutation["value"])
    else:  # pragma: no cover - нормативная схема набора закрывает этот случай
        raise AssertionError(operation)
    return result


class ClosedJsonSchemaV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.validate_journal = staticmethod(
            build_closed_json_schema_validator_v2(
                SCHEMA_DIR,
                "operation-journal-v2.schema.json",
            )
        )
        cls.reference_journal = _reference_validator(
            SCHEMA_DIR,
            "operation-journal-v2.schema.json",
        )

    def _temporary_validator(
        self,
        schemas: dict[str, dict[str, Any]],
        *,
        root_name: str = "root.json",
    ):
        temporary = tempfile.TemporaryDirectory(prefix="closed-schema-v2-")
        directory = Path(temporary.name).resolve()
        for name, schema in schemas.items():
            (directory / name).write_text(
                json.dumps(schema, ensure_ascii=False),
                encoding="utf-8",
            )
        validator = build_closed_json_schema_validator_v2(directory, root_name)
        reference = _reference_validator(directory, root_name)
        self.addCleanup(temporary.cleanup)
        return validator, reference

    def assertMatchesReference(
        self,
        validator,
        reference: Draft202012Validator,
        value: Any,
    ) -> None:
        expected = reference.is_valid(value)
        try:
            validator(value)
        except ClosedJsonSchemaV2Error:
            observed = False
        else:
            observed = True
        self.assertEqual(expected, observed, value)

    def test_all_normative_operation_journals_match_reference_validator(
        self,
    ) -> None:
        fixtures = self.vectors["fixtures"]
        for name in _JOURNAL_FIXTURES:
            with self.subTest(name=name):
                journal = fixtures[name]
                self.assertTrue(self.reference_journal.is_valid(journal))
                self.validate_journal(journal)

    def test_all_lifecycle_step_projection_and_journal_cases_match_reference(
        self,
    ) -> None:
        local_validators = {
            schema: build_closed_json_schema_validator_v2(
                SCHEMA_DIR,
                f"{schema}.schema.json",
            )
            for schema in _LIFECYCLE_SCHEMA_CASES
        }
        reference_validators = {
            schema: _reference_validator(SCHEMA_DIR, f"{schema}.schema.json")
            for schema in _LIFECYCLE_SCHEMA_CASES
        }
        fixtures = self.vectors["fixtures"]
        selected_positive = [
            case
            for case in self.vectors["positiveCases"]
            if case["schema"] in _LIFECYCLE_SCHEMA_CASES
        ]
        selected_negative = [
            case
            for case in self.vectors["negativeCases"]
            if case["schema"] in _LIFECYCLE_SCHEMA_CASES
        ]

        self.assertEqual(31, len(selected_positive))
        self.assertEqual(38, len(selected_negative))
        for case in selected_positive:
            with self.subTest(kind="positive", name=case["name"]):
                value = fixtures[case["fixture"]]
                self.assertMatchesReference(
                    local_validators[case["schema"]],
                    reference_validators[case["schema"]],
                    value,
                )
                self.assertTrue(
                    reference_validators[case["schema"]].is_valid(value)
                )
        for case in selected_negative:
            with self.subTest(kind="negative", name=case["name"]):
                value = _patched(
                    fixtures[case["fixture"]],
                    case["mutation"],
                )
                self.assertMatchesReference(
                    local_validators[case["schema"]],
                    reference_validators[case["schema"]],
                    value,
                )
                self.assertFalse(
                    reference_validators[case["schema"]].is_valid(value)
                )

    def test_normative_nested_mutations_match_reference_validator(self) -> None:
        fixtures = self.vectors["fixtures"]
        mutations: list[tuple[str, dict[str, Any]]] = []

        extra = copy.deepcopy(fixtures["activationFencedJournal"])
        extra["unexpected"] = True
        mutations.append(("closed-root", extra))

        missing = copy.deepcopy(fixtures["activationFencedJournal"])
        missing.pop("operationId")
        mutations.append(("required", missing))

        invalid_date = copy.deepcopy(fixtures["activationFencedJournal"])
        invalid_date["createdAt"] = "2026-02-29T00:00:00Z"
        mutations.append(("date-time", invalid_date))

        prefix_sibling = copy.deepcopy(fixtures["activationFencedJournal"])
        prefix_sibling["steps"][0]["ordinal"] = 1
        mutations.append(("prefix-ref-sibling", prefix_sibling))

        conditional = copy.deepcopy(fixtures["activationFencedJournal"])
        conditional["operation"] = "rollback"
        mutations.append(("if-then", conditional))

        contains = copy.deepcopy(fixtures["abortTerminalJournal"])
        contains["steps"][-1]["kind"] = "maintenance_resume"
        mutations.append(("contains", contains))

        for name, journal in mutations:
            with self.subTest(name=name):
                self.assertFalse(self.reference_journal.is_valid(journal))
                with self.assertRaises(ClosedJsonSchemaV2Error):
                    self.validate_journal(journal)

    def test_uninstall_manifest_action_requires_the_owned_receipt_path(
        self,
    ) -> None:
        fixtures = self.vectors["fixtures"]
        source = next(
            copy.deepcopy(step)
            for step in fixtures["abortTerminalJournal"]["steps"]
            if step["kind"] == "staged_generation_retire"
        )
        manifest = copy.deepcopy(
            fixtures["manifestCommitStep"]["expectedAfter"]
        )
        source["kind"] = "uninstall_manifest_remove"
        source["before"] = manifest
        source["action"] = {
            "actionKind": "owned-object-delete",
            "objectKind": "manifest",
            "path": manifest["value"]["file"]["path"],
            "ownershipFingerprint": "a" * 64,
            "durability": "UNLINKAT_FSYNC_PARENT",
        }
        validator = build_closed_json_schema_validator_v2(
            SCHEMA_DIR,
            "operation-step-v2.schema.json",
        )
        reference = _reference_validator(
            SCHEMA_DIR,
            "operation-step-v2.schema.json",
        )

        self.assertMatchesReference(validator, reference, source)
        self.assertFalse(reference.is_valid(source))

        source["action"]["installerReceiptPath"] = (
            "/private/codex/manifests/installer-receipt.json"
        )
        self.assertMatchesReference(validator, reference, source)
        self.assertTrue(reference.is_valid(source))

    def test_cross_file_ref_keeps_its_sibling_constraints(self) -> None:
        child = {
            "$schema": _DRAFT,
            "$id": "https://closed.test/child.json",
            "type": "object",
            "additionalProperties": False,
            "required": ["kind"],
            "properties": {"kind": {"enum": ["ordinary", "special"]}},
        }
        root = {
            "$schema": _DRAFT,
            "$id": "https://closed.test/root.json",
            "$ref": "child.json",
            "properties": {"kind": {"const": "special"}},
        }
        validator, reference = self._temporary_validator(
            {"root.json": root, "child.json": child}
        )

        self.assertMatchesReference(validator, reference, {"kind": "special"})
        self.assertMatchesReference(validator, reference, {"kind": "ordinary"})
        validator({"kind": "special"})
        with self.assertRaises(ClosedJsonSchemaV2Error) as raised:
            validator({"kind": "ordinary"})
        self.assertEqual(("kind",), raised.exception.path)

    def test_supported_keyword_subset_matches_reference_validator(self) -> None:
        root = {
            "$schema": _DRAFT,
            "$id": "https://closed.test/root.json",
            "title": "closed-subset",
            "description": "Exercises every assertion needed by journals.",
            "type": "object",
            "additionalProperties": False,
            "required": [
                "code",
                "count",
                "values",
                "variant",
                "forbidden",
                "mode",
                "flag",
                "metadata",
            ],
            "properties": {
                "code": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 4,
                    "pattern": "^[a-z]+$",
                },
                "count": {"type": "integer", "minimum": 1, "maximum": 9},
                "values": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "prefixItems": [{"const": "head"}],
                    "items": {"type": "integer"},
                    "contains": {"const": 7},
                    "minContains": 1,
                    "maxContains": 1,
                },
                "variant": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
                "forbidden": {"not": {"const": "blocked"}},
                "mode": {"enum": ["strict", "relaxed"]},
                "flag": {"type": "boolean"},
                "metadata": {
                    "type": "object",
                    "minProperties": 1,
                    "maxProperties": 2,
                    "additionalProperties": {"type": "integer"},
                },
            },
            "allOf": [
                {
                    "if": {
                        "properties": {"mode": {"const": "strict"}},
                        "required": ["mode"],
                    },
                    "then": {"properties": {"flag": {"const": True}}},
                    "else": {"properties": {"flag": {"const": False}}},
                }
            ],
        }
        validator, reference = self._temporary_validator({"root.json": root})
        valid = {
            "code": "ab",
            "count": 3,
            "values": ["head", 7, 2],
            "variant": "chosen",
            "forbidden": "allowed",
            "mode": "strict",
            "flag": True,
            "metadata": {"first": 1},
        }
        invalid_values = (
            {**valid, "code": "A"},
            {**valid, "count": 10},
            {**valid, "values": ["head", 7, 7]},
            {**valid, "values": ["wrong", 7]},
            {**valid, "variant": None},
            {**valid, "forbidden": "blocked"},
            {**valid, "flag": False},
            {**valid, "unexpected": 1},
            {**valid, "metadata": {}},
            {**valid, "metadata": {"first": 1, "second": 2, "third": 3}},
        )

        self.assertMatchesReference(validator, reference, valid)
        for value in invalid_values:
            with self.subTest(value=value):
                self.assertMatchesReference(validator, reference, value)

    def test_date_time_format_matches_reference_checker(self) -> None:
        root = {
            "$schema": _DRAFT,
            "$id": "https://closed.test/root.json",
            "type": "string",
            "format": "date-time",
        }
        validator, reference = self._temporary_validator({"root.json": root})
        for value in (
            "2026-07-20T12:34:56Z",
            "2026-07-20t12:34:56.123z",
            "2024-02-29T23:59:59+03:00",
            "2026-02-29T00:00:00Z",
            "2026-07-20 12:34:56Z",
            "2026-07-20T12:34:60Z",
            "0000-01-01T00:00:00Z",
        ):
            with self.subTest(value=value):
                self.assertMatchesReference(validator, reference, value)

    def test_permissive_schema_still_rejects_non_json_values(self) -> None:
        root = {
            "$schema": _DRAFT,
            "$id": "https://closed.test/root.json",
        }
        validator, _reference = self._temporary_validator({"root.json": root})
        cyclic: list[Any] = []
        cyclic.append(cyclic)

        for value in (float("nan"), float("inf"), object(), {1: "value"}, cyclic):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(ClosedJsonSchemaV2Error):
                    validator(value)

        validator(
            {
                "null": None,
                "boolean": True,
                "integer": 1,
                "number": 1.5,
                "string": "значение",
                "array": [1, 2],
                "object": {"nested": False},
            }
        )

    def test_unknown_keyword_format_and_reference_fail_closed(self) -> None:
        cases = {
            "keyword": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "type": "string",
                "minBytes": 1,
            },
            "format": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "type": "string",
                "format": "email",
            },
            "reference": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "$ref": "missing.json",
            },
            "reference-fragment": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "$defs": {},
                "$ref": "#/$defs/missing",
            },
            "external-reference": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "$ref": "https://outside.test/child.json",
            },
            "empty-prefix": {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "prefixItems": [],
            },
        }
        for name, schema in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="closed-schema-v2-fail-"
            ) as directory:
                root = Path(directory).resolve()
                (root / "root.json").write_text(
                    json.dumps(schema), encoding="utf-8"
                )
                with self.assertRaises(ClosedJsonSchemaV2Error):
                    build_closed_json_schema_validator_v2(root, "root.json")

    def test_object_property_bounds_definition_fails_closed(self) -> None:
        invalid_bounds = {
            "negative-min": {"minProperties": -1},
            "boolean-max": {"maxProperties": True},
            "reversed": {"minProperties": 2, "maxProperties": 1},
        }
        for name, bounds in invalid_bounds.items():
            schema = {
                "$schema": _DRAFT,
                "$id": "https://closed.test/root.json",
                "type": "object",
                **bounds,
            }
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="closed-schema-v2-object-bounds-"
            ) as directory:
                root = Path(directory).resolve()
                (root / "root.json").write_text(
                    json.dumps(schema), encoding="utf-8"
                )
                with self.assertRaises(ClosedJsonSchemaV2Error) as raised:
                    build_closed_json_schema_validator_v2(root, "root.json")
                self.assertEqual("SCHEMA_BOUND_INVALID", raised.exception.code)

    def test_validator_runs_without_site_packages(self) -> None:
        program = r"""
import importlib.util
import json
import sys
from pathlib import Path

assert importlib.util.find_spec("jsonschema") is None
assert importlib.util.find_spec("referencing") is None
sys.path.insert(0, sys.argv[1])
from codex_smart_subagents.lifecycle_operation_v2 import build_operation_journal_validator_v2

root = Path(sys.argv[2])
vectors = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
validate = build_operation_journal_validator_v2(root)
validate(vectors["fixtures"]["activationFencedJournal"])
print("CLOSED_SCHEMA_OK")
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                program,
                str(PLUGIN_SRC),
                str(SCHEMA_DIR),
                str(VECTOR_PATH),
            ],
            cwd=ROOT,
            env={"PATH": os.defpath, "PYTHONPATH": ""},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("CLOSED_SCHEMA_OK", completed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
