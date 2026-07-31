from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.coordinator_selection_v2 import (  # noqa: E402
    CoordinatorSelectionV2,
    collect_coordinator_selection_v2,
    coordinator_selection_from_health_v2,
    inspect_coordinator_selection_v2,
)
from codex_smart_subagents.model_catalog import ModelCatalogError  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)


CANDIDATES = (
    {
        "model": "gpt-5.6-sol",
        "reasoningEffort": "medium",
    },
    {
        "model": "gpt-5.6-terra",
        "reasoningEffort": "medium",
    },
)
ACTIVE_CONTEXT = "7" * 64


def _expired_deadline() -> OperationDeadlineExceededV2:
    return OperationDeadlineExceededV2(
        code="ROOT_OPERATION_EXPIRED",
        operation="controller-bootstrap",
        phase="model-list-cleanup",
        deadline_kind="root",
        configured_timeout_nanoseconds=5_000_000_000,
        elapsed_monotonic_nanoseconds=5_000_000_001,
    )


class _Inspector:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def inspect(self):
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class CoordinatorSelectionV2Tests(unittest.TestCase):
    def collect(self, result) -> tuple[CoordinatorSelectionV2, _Inspector]:
        inspector = _Inspector(result)
        selection = collect_coordinator_selection_v2(
            selection="first-verified-available",
            candidates=CANDIDATES,
            inspector=inspector,
            active_context_fingerprint=ACTIVE_CONTEXT,
        )
        return selection, inspector

    def test_selects_first_verified_sol_pair_from_one_inspection(self) -> None:
        selection, inspector = self.collect(
            {
                "gpt-5.6-sol": frozenset({"medium", "high"}),
                "gpt-5.6-terra": frozenset({"medium"}),
            }
        )

        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            {
                "selection": "first-verified-available",
                "status": "SELECTED",
                "reasonCode": "COORDINATOR_PAIR_SELECTED",
                "selectedPair": {
                    "model": "gpt-5.6-sol",
                    "reasoningEffort": "medium",
                },
                "candidateIndex": 0,
                "accountCatalogFingerprint": selection.account_catalog_fingerprint,
                "accountContextFingerprint": selection.account_context_fingerprint,
            },
            selection.to_document(),
        )
        self.assertRegex(selection.account_catalog_fingerprint or "", r"^[0-9a-f]{64}$")
        self.assertRegex(selection.account_context_fingerprint or "", r"^[0-9a-f]{64}$")

    def test_selects_terra_fallback_by_order(self) -> None:
        selection, inspector = self.collect(
            {
                "gpt-5.6-sol": frozenset({"high"}),
                "gpt-5.6-terra": frozenset({"medium"}),
            }
        )

        self.assertEqual(1, inspector.calls)
        self.assertEqual("SELECTED", selection.status)
        self.assertEqual(1, selection.candidate_index)
        self.assertEqual(CANDIDATES[1], selection.selected_pair)

    def test_read_catalog_without_candidates_keeps_both_fingerprints(self) -> None:
        selection, inspector = self.collect(
            {
                "gpt-5.6-sol": frozenset({"high"}),
                "gpt-5.6-terra": frozenset({"high"}),
            }
        )

        self.assertEqual(1, inspector.calls)
        self.assertEqual("UNAVAILABLE", selection.status)
        self.assertEqual("COORDINATOR_PAIR_UNAVAILABLE", selection.reason_code)
        self.assertIsNone(selection.selected_pair)
        self.assertIsNone(selection.candidate_index)
        self.assertRegex(selection.account_catalog_fingerprint or "", r"^[0-9a-f]{64}$")
        self.assertRegex(selection.account_context_fingerprint or "", r"^[0-9a-f]{64}$")

    def test_failed_catalog_read_has_null_catalog_and_exact_reason(self) -> None:
        selection, inspector = self.collect(
            ModelCatalogError(
                "MODEL_LIST_UNAVAILABLE",
                "account catalog could not be read",
            )
        )

        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            {
                "selection": "first-verified-available",
                "status": "UNAVAILABLE",
                "reasonCode": "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
                "selectedPair": None,
                "candidateIndex": None,
                "accountCatalogFingerprint": None,
                "accountContextFingerprint": selection.account_context_fingerprint,
            },
            selection.to_document(),
        )
        self.assertRegex(
            selection.account_context_fingerprint or "",
            r"^[0-9a-f]{64}$",
        )

    def test_malformed_catalog_has_exact_coordinator_reason(self) -> None:
        selection, inspector = self.collect(
            ModelCatalogError(
                "MODEL_LIST_INVALID",
                "account catalog was malformed",
            )
        )

        self.assertEqual(1, inspector.calls)
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_INVALID",
            selection.reason_code,
        )
        self.assertIsNone(selection.account_catalog_fingerprint)
        self.assertRegex(
            selection.account_context_fingerprint or "",
            r"^[0-9a-f]{64}$",
        )

    def test_inspection_deadline_becomes_exact_catalog_unavailable(self) -> None:
        try:
            selection, inspector = self.collect(_expired_deadline())
        except OperationDeadlineExceededV2:
            self.fail("inspection deadline escaped coordinator selection")

        self.assertEqual(1, inspector.calls)
        self.assertEqual("UNAVAILABLE", selection.status)
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            selection.reason_code,
        )
        self.assertIsNone(selection.account_catalog_fingerprint)
        self.assertRegex(
            selection.account_context_fingerprint or "",
            r"^[0-9a-f]{64}$",
        )

    def test_inspector_factory_deadline_becomes_catalog_unavailable(self) -> None:
        factory_calls = 0

        def expired_factory(**_arguments):
            nonlocal factory_calls
            factory_calls += 1
            raise _expired_deadline()

        try:
            selection = inspect_coordinator_selection_v2(
                codex_executable=Path("/private/codex"),
                codex_home=Path("/private/codex-home"),
                runtime_parent=Path("/private/runtime"),
                selection="first-verified-available",
                candidates=CANDIDATES,
                active_context_fingerprint=ACTIVE_CONTEXT,
                inspector_factory=expired_factory,
            )
        except OperationDeadlineExceededV2:
            self.fail("factory deadline escaped coordinator selection")

        self.assertEqual(1, factory_calls)
        self.assertEqual("UNAVAILABLE", selection.status)
        self.assertEqual(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            selection.reason_code,
        )
        self.assertIsNone(selection.account_catalog_fingerprint)
        self.assertRegex(
            selection.account_context_fingerprint or "",
            r"^[0-9a-f]{64}$",
        )

    def test_selection_uses_coordinator_domains_not_account_evidence_domains(
        self,
    ) -> None:
        selection, _inspector = self.collect(
            {"gpt-5.6-sol": frozenset({"medium"})}
        )

        self.assertEqual(
            selection.account_catalog_fingerprint,
            selection.recompute_account_catalog_fingerprint(),
        )
        self.assertEqual(
            selection.account_context_fingerprint,
            selection.recompute_account_context_fingerprint(),
        )
        changed_result = replace(
            selection,
            selected_pair=dict(CANDIDATES[1]),
            candidate_index=1,
        )
        self.assertNotEqual(
            selection.account_context_fingerprint,
            changed_result.recompute_account_context_fingerprint(),
        )
        self.assertNotEqual(
            selection.account_context_fingerprint,
            selection.recompute_account_context_fingerprint(
                active_context_fingerprint="8" * 64,
            ),
        )
        self.assertIn("coordinator", selection.ACCOUNT_CATALOG_DOMAIN)
        self.assertIn("coordinator", selection.ACCOUNT_CONTEXT_DOMAIN)
        self.assertNotIn("account-evidence", selection.ACCOUNT_CATALOG_DOMAIN)
        self.assertNotIn("account-evidence", selection.ACCOUNT_CONTEXT_DOMAIN)

    def test_live_inspector_is_constructed_and_inspected_exactly_once(self) -> None:
        constructed: list[dict[str, object]] = []
        inspector = _Inspector(
            {"gpt-5.6-sol": frozenset({"medium"})}
        )

        def factory(**arguments):
            constructed.append(arguments)
            return inspector

        selection = inspect_coordinator_selection_v2(
            codex_executable=Path("/private/codex"),
            codex_home=Path("/private/codex-home"),
            runtime_parent=Path("/private/runtime"),
            selection="first-verified-available",
            candidates=CANDIDATES,
            active_context_fingerprint=ACTIVE_CONTEXT,
            inspector_factory=factory,
        )

        self.assertEqual(1, len(constructed))
        self.assertEqual(1, inspector.calls)
        self.assertEqual("SELECTED", selection.status)

    def test_catalog_v1_temporarily_accepts_health_without_selection(self) -> None:
        selection, pair = coordinator_selection_from_health_v2(
            {},
            catalog_schema_version=1,
            candidates=(
                {
                    "model": "gpt-5.6-terra",
                    "reasoningEffort": "medium",
                },
            ),
        )

        self.assertIsNone(selection)
        self.assertEqual(
            {
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
            pair,
        )

    def test_catalog_v2_requires_selection_and_rejects_candidate_substitution(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "catalog v2"):
            coordinator_selection_from_health_v2(
                {},
                catalog_schema_version=2,
                candidates=CANDIDATES,
            )

        selected, _inspector = self.collect(
            {
                "gpt-5.6-sol": frozenset({"medium"}),
                "gpt-5.6-terra": frozenset({"medium"}),
            }
        )
        tampered = selected.to_document()
        tampered["selectedPair"] = dict(CANDIDATES[1])
        with self.assertRaisesRegex(ValueError, "candidate"):
            coordinator_selection_from_health_v2(
                {
                    "activationFingerprint": ACTIVE_CONTEXT,
                    "coordinatorSelection": tampered,
                },
                catalog_schema_version=2,
                candidates=CANDIDATES,
            )

        untampered = selected.to_document()
        with self.assertRaisesRegex(ValueError, "context fingerprint"):
            coordinator_selection_from_health_v2(
                {
                    "activationFingerprint": "8" * 64,
                    "coordinatorSelection": untampered,
                },
                catalog_schema_version=2,
                candidates=CANDIDATES,
            )


if __name__ == "__main__":
    unittest.main()
