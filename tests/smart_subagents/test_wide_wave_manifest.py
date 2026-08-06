from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate_wide_wave_manifest.py"
SCHEMA = ROOT / "schemas" / "codex-wide-wave-manifest.schema.json"


class WideWaveManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="wide-wave-manifest-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.skill = self.root / "SKILL.md"
        self.skill.write_text("---\nname: trusted-wide\n---\n", encoding="utf-8")
        self.registry = self.root / "trusted.json"
        self.manifest = self.root / "manifest.json"
        self.write_registry(
            {
                "skill_id": "trusted-wide",
                "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                "max_live_wave": 12,
                "execution_kind": "wide-wave",
                "fallback": "block",
            }
        )
        self.write_manifest(
            participants=[
                {"id": "reader-1", "access": "read-only", "owned_write_scope": []},
                {"id": "reader-2", "access": "read-only", "owned_write_scope": []},
                {"id": "reader-3", "access": "read-only", "owned_write_scope": []},
                {"id": "reader-4", "access": "read-only", "owned_write_scope": []},
                {"id": "reader-5", "access": "read-only", "owned_write_scope": []},
                {"id": "reader-6", "access": "read-only", "owned_write_scope": []},
                {"id": "writer-1", "access": "workspace-write", "owned_write_scope": ["src/a"]},
                {"id": "writer-2", "access": "workspace-write", "owned_write_scope": ["src/b"]},
            ]
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_registry(self, *entries: dict[str, object]) -> None:
        self.registry.write_text(
            json.dumps({"schema_version": 1, "trusted_skills": list(entries)}),
            encoding="utf-8",
        )

    def write_manifest(self, **overrides: object) -> None:
        payload = {
            "schema_version": 1,
            "skill_id": "trusted-wide",
            "wave_size": 8,
            "repository_root": str(self.repo),
            "base_commit": "1318542fb00df4eaef4fc4e8abfa8cd99e656bb3",
            "participants": [],
        }
        payload.update(overrides)
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--manifest",
                str(self.manifest),
                "--skill-id",
                "trusted-wide",
                "--skill-file",
                str(self.skill),
                "--trusted-registry",
                str(self.registry),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_schema_file_exists_and_is_closed(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual("object", schema["type"])
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("participants", schema["required"])

    def test_accepts_trusted_hash_and_disjoint_write_scopes(self) -> None:
        completed = self.run_validator()

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)

    def test_blocks_unknown_skill(self) -> None:
        self.write_registry()

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("unknown_skill", completed.stdout)

    def test_blocks_hash_mismatch(self) -> None:
        self.write_registry(
            {
                "skill_id": "trusted-wide",
                "sha256": "0" * 64,
                "max_live_wave": 12,
                "execution_kind": "wide-wave",
                "fallback": "block",
            }
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("skill_hash_mismatch", completed.stdout)

    def test_blocks_wave_above_trusted_maximum(self) -> None:
        self.write_registry(
            {
                "skill_id": "trusted-wide",
                "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                "max_live_wave": 7,
                "execution_kind": "wide-wave",
                "fallback": "block",
            }
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("wave_size_exceeds_trusted_max", completed.stdout)

    def test_rejects_absolute_scope(self) -> None:
        self.write_manifest(
            participants=[
                {"id": "writer-1", "access": "workspace-write", "owned_write_scope": [str(self.repo / "src")]},
            ]
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("absolute_write_scope", completed.stdout)

    def test_rejects_parent_escape_scope(self) -> None:
        self.write_manifest(
            participants=[
                {"id": "writer-1", "access": "workspace-write", "owned_write_scope": ["../outside"]},
            ]
        )

        completed = self.run_validator()
        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("write_scope_escapes_repository", completed.stdout)

    def test_rejects_duplicate_and_nested_write_scopes(self) -> None:
        for scopes in (["src/a", "src/a"], ["src", "src/a"]):
            with self.subTest(scopes=scopes):
                self.write_manifest(
                    participants=[
                        {"id": "writer-1", "access": "workspace-write", "owned_write_scope": [scopes[0]]},
                        {"id": "writer-2", "access": "workspace-write", "owned_write_scope": [scopes[1]]},
                    ]
                )

                completed = self.run_validator()
                self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
                self.assertIn("write_scope_overlap", completed.stdout)

    def test_rejects_participant_count_that_does_not_match_wave_size(self) -> None:
        self.write_manifest(
            wave_size=3,
            participants=[
                {"id": "writer-1", "access": "workspace-write", "owned_write_scope": ["src/a"]},
                {"id": "writer-2", "access": "workspace-write", "owned_write_scope": ["src/b"]},
            ],
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("participant_count_mismatch_wave_size", completed.stdout)

    def test_rejects_empty_writer_scope_and_readonly_scope(self) -> None:
        self.write_manifest(
            participants=[
                {"id": "reader-1", "access": "read-only", "owned_write_scope": ["docs"]},
                {"id": "writer-1", "access": "workspace-write", "owned_write_scope": []},
            ]
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("readonly_write_scope_forbidden", completed.stdout)
        self.assertIn("writer_write_scope_required", completed.stdout)

    def test_missing_skill_file_returns_managed_block(self) -> None:
        self.skill.unlink()

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=BLOCK", completed.stdout)
        self.assertIn("skill_file_missing", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
