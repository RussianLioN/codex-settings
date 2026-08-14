from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from tests.smart_subagents.test_activation_preparation_v2 import (
    _CrashOnce,
    _Fixture,
)

from codex_smart_subagents.activation_preparation_v2 import (
    ActivationPreparationFailurePointV2,
    ActivationPreparationIntegrityErrorV2,
    ActivationPreparationIntentV2,
    InjectedActivationPreparationCrashV2,
)
from codex_smart_subagents.canonical_json import domain_fingerprint


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "docs/contracts/schemas"


def _validators() -> dict[str, Draft202012Validator]:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in SCHEMA_DIR.glob("*.json")
    }
    registry = Registry().with_resources(
        [
            (schema["$id"], Resource.from_contents(schema))
            for schema in schemas.values()
        ]
    )
    checker = FormatChecker()
    return {
        name: Draft202012Validator(
            schemas[schema_name],
            registry=registry,
            format_checker=checker,
        )
        for name, schema_name in {
            "journal": "activation-preparation-journal-v2.schema.json",
            "receipt": "activation-preparation-receipt-v2.schema.json",
        }.items()
    }


class ActivationPreparationRuntimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validators = _validators()

    def test_runtime_receipt_conforms_to_tracked_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            document = fixture.executor().execute().to_document()

            errors = list(self.validators["receipt"].iter_errors(document))

            self.assertEqual([], errors, errors[0].message if errors else "")

    def test_runtime_frozen_journal_conforms_to_tracked_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            crash = _CrashOnce(
                ActivationPreparationFailurePointV2.AFTER_PREPARATION_FREEZE
            )
            with self.assertRaises(InjectedActivationPreparationCrashV2):
                fixture.executor(failure_injector=crash).execute()
            document = json.loads(
                fixture.definition.journal_path.read_text(encoding="utf-8")
            )

            errors = list(self.validators["journal"].iter_errors(document))

            self.assertEqual([], errors, errors[0].message if errors else "")

    def test_owned_nested_intent_documents_are_closed(self) -> None:
        def activation_extra(document: dict[str, object]) -> None:
            document["activationDocument"]["unexpected"] = True

        def activation_version(document: dict[str, object]) -> None:
            document["activationDocument"]["schemaVersion"] = 3

        def source_extra(document: dict[str, object]) -> None:
            document["sourceLocator"]["unexpected"] = True

        def source_policy(document: dict[str, object]) -> None:
            document["sourceLocator"]["argv0Policy"] = "resolved"

        def interface_version(document: dict[str, object]) -> None:
            document["interfaceEvidence"]["schemaVersion"] = 2

        with tempfile.TemporaryDirectory() as raw:
            fixture = _Fixture(Path(raw))
            for change in (
                activation_extra,
                activation_version,
                source_extra,
                source_policy,
                interface_version,
            ):
                with self.subTest(change=change.__name__):
                    document = fixture.intent.to_document()
                    change(document)
                    value = {
                        key: item
                        for key, item in document.items()
                        if key != "activationIntentFingerprint"
                    }
                    document["activationIntentFingerprint"] = domain_fingerprint(
                        "codex-smart/activation-preparation-intent/v2", value
                    )

                    with self.assertRaises(
                        ActivationPreparationIntegrityErrorV2
                    ):
                        ActivationPreparationIntentV2.from_document(document)


if __name__ == "__main__":
    unittest.main()
