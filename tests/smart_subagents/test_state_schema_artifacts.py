from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
SCHEMA_DIR = PLUGIN_SRC / "codex_smart_subagents" / "schema"
sys.path.insert(0, str(PLUGIN_SRC))


class StateSchemaArtifactTests(unittest.TestCase):
    def test_file_hash_checks_the_shared_deadline_between_blocks(self) -> None:
        from codex_smart_subagents import schema_projection

        with mock.patch.object(
            schema_projection,
            "checkpoint_current_operation_deadline_if_scoped_v2",
            return_value=None,
        ) as checkpoint:
            digest = schema_projection.sha256_file(
                SCHEMA_DIR / "state-v2.sql"
            )

        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(checkpoint.call_count, 1)

    def test_sql_normalizer_preserves_quoted_whitespace_and_rejects_comments(
        self,
    ) -> None:
        from codex_smart_subagents.schema_projection import (
            SchemaProjectionError,
            normalize_schema_sql,
        )

        self.assertEqual(
            "SELECT 'a  b' FROM [x y]",
            normalize_schema_sql("\r\n SELECT\t'a  b' \r\n FROM  [x y] \n"),
        )
        self.assertEqual(
            'SELECT "a"" b"',
            normalize_schema_sql('SELECT  "a"" b"'),
        )
        for value in ("SELECT 1 -- comment", "SELECT /* comment */ 1"):
            with self.subTest(value=value):
                with self.assertRaises(SchemaProjectionError):
                    normalize_schema_sql(value)

    def test_canonical_json_v1_uses_contract_escapes_and_utf8_key_order(
        self,
    ) -> None:
        from codex_smart_subagents.schema_projection import (
            SchemaProjectionError,
            canonical_json_v1,
        )

        self.assertEqual(
            b'{"a":"\\u0008\\u0009\\u000a\\u000c\\u000d","z":1,"\xc3\xa9":2}',
            canonical_json_v1({"é": 2, "z": 1, "a": "\b\t\n\f\r"}),
        )
        for value in (1.0, 2**53, {1: "not-a-string-key"}):
            with self.subTest(value=value):
                with self.assertRaises(SchemaProjectionError):
                    canonical_json_v1(value)

    def test_normative_sql_and_manifest_reproduce_schema_v2(self) -> None:
        from codex_smart_subagents.schema_projection import (
            create_database_from_schema_artifact,
            database_schema_fingerprint,
            sha256_file,
        )

        sql_path = SCHEMA_DIR / "state-v2.sql"
        manifest_path = SCHEMA_DIR / "state-v2.manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(2, manifest["schemaVersion"])
        self.assertEqual(sha256_file(sql_path), manifest["stateSqlSha256"])
        with create_database_from_schema_artifact(sql_path) as connection:
            result = database_schema_fingerprint(connection, version=2)
        self.assertEqual(result.fingerprint, manifest["schemaFingerprint"])
        self.assertEqual(result.canonical_size, manifest["schemaCanonicalSize"])

    def test_normative_sql_contains_the_closed_v2_object_set(self) -> None:
        from codex_smart_subagents.schema_projection import (
            create_database_from_schema_artifact,
        )

        expected_tables = {
            "account_evidence_jobs",
            "attempts",
            "candidate_publication_intents",
            "candidate_registry",
            "controller_command_receipts",
            "controller_state",
            "database_identity",
            "events",
            "intents",
            "leases",
            "node_launch_permits",
            "nodes",
            "quarantine_repositories",
            "routes",
            "runtime_artifacts",
            "schema_migrations",
            "sqlite_sequence",
            "start_requests",
            "turn_bindings",
        }
        expected_named_indexes = {
            "attempts_route_started",
            "candidate_intents_state",
            "candidate_registry_route",
            "controller_command_receipts_created",
            "events_route_sequence",
            "node_launch_permits_one_inflight",
            "node_launch_permits_route",
            "node_launch_permits_state",
            "routes_state_created",
            "runtime_artifacts_route",
            "schema_migrations_applied",
        }
        with create_database_from_schema_artifact(
            SCHEMA_DIR / "state-v2.sql"
        ) as connection:
            objects = connection.execute(
                "select type, name from sqlite_schema"
            ).fetchall()
            tables = {name for object_type, name in objects if object_type == "table"}
            named_indexes = {
                name
                for object_type, name in objects
                if object_type == "index" and not name.startswith("sqlite_autoindex_")
            }
            self.assertEqual([(1129529650,)], connection.execute("pragma application_id").fetchall())
            self.assertEqual([(2,)], connection.execute("pragma user_version").fetchall())
            self.assertEqual([("ok",)], connection.execute("pragma quick_check").fetchall())
            self.assertEqual([], connection.execute("pragma foreign_key_check").fetchall())
        self.assertEqual(expected_tables, tables)
        self.assertEqual(expected_named_indexes, named_indexes)
        self.assertFalse(
            {object_type for object_type, _ in objects}.intersection({"trigger", "view"})
        )

    def test_manifest_pins_exactly_38_reproducible_legacy_shapes(self) -> None:
        manifest = json.loads(
            (SCHEMA_DIR / "state-v2.manifest.json").read_text(encoding="utf-8")
        )

        legacy = manifest["legacyShapes"]
        self.assertEqual(19, len(legacy["userVersion0"]))
        self.assertEqual(19, len(legacy["userVersion1"]))
        names = {
            item["name"]
            for group in (legacy["userVersion0"], legacy["userVersion1"])
            for item in group
        }
        self.assertEqual(38, len(names))
        for name, commit in manifest["sourceCommits"].items():
            with self.subTest(name=name):
                self.assertRegex(commit, r"^[0-9a-f]{40}$")
        self.assertEqual(
            {
                "all-application-tables-empty",
                "candidate-prefix-empty",
                "legacy-quiescence-v2",
                "runtime-artifacts-empty",
            },
            set(manifest["legacyDataPredicates"]),
        )

    def test_v2_links_start_request_evidence_job_and_admission(self) -> None:
        from codex_smart_subagents.schema_projection import (
            create_database_from_schema_artifact,
        )

        with create_database_from_schema_artifact(
            SCHEMA_DIR / "state-v2.sql"
        ) as connection:
            node_targets = {
                row[2] for row in connection.execute("pragma foreign_key_list(nodes)")
            }
            start_targets = {
                row[2]
                for row in connection.execute("pragma foreign_key_list(start_requests)")
            }
        self.assertIn("account_evidence_jobs", node_targets)
        self.assertIn("account_evidence_jobs", start_targets)
        self.assertIn("nodes", start_targets)

    def test_planning_does_not_claim_account_evidence_and_direct_is_terminal(self) -> None:
        from codex_smart_subagents.schema_projection import (
            create_database_from_schema_artifact,
        )

        with create_database_from_schema_artifact(
            SCHEMA_DIR / "state-v2.sql"
        ) as connection:
            route_columns = {
                row[1]: row for row in connection.execute("pragma table_info(routes)")
            }
            node_columns = {
                row[1]: row for row in connection.execute("pragma table_info(nodes)")
            }
            candidate_intent_columns = {
                row[1]: row
                for row in connection.execute(
                    "pragma table_info(candidate_publication_intents)"
                )
            }
            route_sql = str(
                connection.execute(
                    "select sql from sqlite_schema where type='table' and name='routes'"
                ).fetchone()[0]
            )

        self.assertNotIn("account_catalog_fingerprint", route_columns)
        self.assertNotIn("account_context_fingerprint", route_columns)
        self.assertEqual(0, node_columns["account_catalog_fingerprint"][3])
        self.assertEqual(0, node_columns["account_context_fingerprint"][3])
        self.assertIn("validation_proof_sha256", candidate_intent_columns)
        self.assertIn("'DIRECT'", route_sql)
        self.assertIn("'CLARIFY'", route_sql)

    def test_narrow_validator_rebuilds_v2_and_all_legacy_shapes(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "validate_state_schema_artifacts.py"),
            ],
            cwd=REPO,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertEqual(38, summary["legacyShapes"])
        self.assertEqual(19, summary["userVersion0"])
        self.assertEqual(19, summary["userVersion1"])
        self.assertEqual("ok", summary["status"])


if __name__ == "__main__":
    unittest.main()
