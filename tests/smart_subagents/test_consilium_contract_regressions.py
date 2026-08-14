from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class ConsiliumContractRegressionTests(unittest.TestCase):
    def test_codesign_requirement_is_a_literal_not_a_file_path(self) -> None:
        contract = (
            ROOT / "docs" / "contracts" / "codex-interface-v1.md"
        ).read_text(encoding="utf-8")
        self.assertIn("`REQUIREMENT_ARG` начинается с обязательного знака `=`", contract)
        self.assertIn('`=identifier "codex" and anchor apple', contract)

    def test_activation_receipt_uses_stable_binding_and_absence_target(self) -> None:
        schema = load_json(
            "docs/contracts/schemas/activation-commit-receipt-v2.schema.json"
        )

        self.assertIn("databaseBinding", schema["required"])
        self.assertIn("journalAbsenceTarget", schema["required"])
        self.assertNotIn("database", schema["properties"])
        self.assertEqual(
            schema["properties"]["databaseBinding"]["properties"]["schemaId"],
            {"const": "database-binding-v2"},
        )
        self.assertEqual(
            schema["properties"]["journalAbsenceTarget"]["properties"]["schemaId"],
            {"const": "absence-proof-v2"},
        )

    def test_database_binding_excludes_mutable_database_content(self) -> None:
        schema = load_json(
            "docs/contracts/schemas/lifecycle-projection-v2.schema.json"
        )
        self.assertIn("database-binding-v2", schema["properties"]["schemaId"]["enum"])
        binding = schema["$defs"]["databaseBinding"]
        required = set(binding["required"])

        self.assertTrue(
            {
                "path",
                "device",
                "inode",
                "databaseId",
                "databaseIdentity",
                "databaseIdentityFingerprint",
                "activationIdentity",
                "databaseVersion",
                "schemaVersion",
                "userVersion",
                "schemaFingerprint",
                "schemaArtifactSha256",
            }.issubset(required)
        )
        self.assertTrue(
            {"size", "sha256", "sidecars", "backup"}.isdisjoint(
                binding["properties"]
            )
        )

    def test_runtime_quiescence_counts_account_evidence_jobs(self) -> None:
        lifecycle = load_json(
            "docs/contracts/schemas/lifecycle-projection-v2.schema.json"
        )
        protocol = load_json(
            "docs/contracts/schemas/controller-protocol-v2.schema.json"
        )

        for work_counts in (
            lifecycle["$defs"]["workCounts"],
            protocol["$defs"]["workCounts"],
        ):
            self.assertIn("activeEvidenceJobs", work_counts["required"])
            self.assertIn("queuedEvidenceJobs", work_counts["required"])
            self.assertIn("activeEvidenceJobs", work_counts["properties"])
            self.assertIn("queuedEvidenceJobs", work_counts["properties"])

        zero_counts = lifecycle["$defs"]["zeroWorkCounts"]["const"]
        self.assertEqual(zero_counts["activeEvidenceJobs"], 0)
        self.assertEqual(zero_counts["queuedEvidenceJobs"], 0)

    def test_activation_fixture_preserves_revalidation_material(self) -> None:
        vectors = load_json("docs/contracts/vectors/lifecycle-v2.json")
        receipt = vectors["fixtures"]["activationCommitReceipt"]

        self.assertNotIn("database", receipt)
        self.assertEqual(receipt["databaseBinding"]["schemaId"], "database-binding-v2")
        self.assertEqual(
            receipt["journalAbsenceTarget"]["schemaId"], "absence-proof-v2"
        )

    def test_state_contract_creates_start_request_before_admission(self) -> None:
        text = (
            ROOT / "docs/contracts/adaptive-subagents-state-v2.md"
        ).read_text(encoding="utf-8")

        self.assertIn("startRequestId", text)
        self.assertIn("activeEvidenceJobs", text)
        self.assertIn("queuedEvidenceJobs", text)
        self.assertIn("`admissionId` создаётся только после", text)

    def test_uninstall_retains_data_and_permanent_recovery_entrypoint(self) -> None:
        automaton = load_json(
            "docs/contracts/schemas/lifecycle-automaton-v2.schema.json"
        )
        ordered = automaton["properties"]["machines"]["properties"][
            "uninstall"
        ]["properties"]["orderedSteps"]["const"]

        self.assertNotIn("uninstall_database_remove", ordered)
        self.assertNotIn("uninstall_fallback_remove", ordered)
        self.assertNotIn("uninstall_admin_remove", ordered)
        self.assertEqual(
            ordered[-4:],
            [
                "terminal_journal_freeze",
                "uninstall_receipt_publish",
                "uninstall_tombstone_publish",
                "uninstall_journal_close",
            ],
        )

        receipt = load_json(
            "docs/contracts/schemas/installation-uninstall-receipt-v2.schema.json"
        )
        self.assertIn("retainedData", receipt["required"])
        self.assertIn("databaseBinding", receipt["properties"]["retainedData"]["required"])

        lifecycle_text = (
            ROOT / "docs/contracts/adaptive-subagents-lifecycle-v2.md"
        ).read_text(encoding="utf-8")
        self.assertIn("uninstall --retain-data", lifecycle_text)
        self.assertIn("постоянная точка восстановления", lifecycle_text)


if __name__ == "__main__":
    unittest.main()
