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
        self.skill.write_text("---\nname: consilium\n---\n", encoding="utf-8")
        self.registry = self.root / "trusted.json"
        self.manifest = self.root / "manifest.json"
        self.default_participants = [
            {"id": "reader-1", "access": "read-only", "owned_write_scope": []},
            {"id": "reader-2", "access": "read-only", "owned_write_scope": []},
            {"id": "reader-3", "access": "read-only", "owned_write_scope": []},
            {"id": "reader-4", "access": "read-only", "owned_write_scope": []},
            {"id": "reader-5", "access": "read-only", "owned_write_scope": []},
            {"id": "reader-6", "access": "read-only", "owned_write_scope": []},
            {"id": "writer-1", "access": "workspace-write", "owned_write_scope": ["src/a"]},
            {"id": "writer-2", "access": "workspace-write", "owned_write_scope": ["src/b"]},
        ]
        self.write_registry(
            {
                "skill_id": "consilium",
                "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                "max_live_wave": 19,
                "execution_kind": "flat-trusted-wide-wave",
                "fallback": "6+6+6+1",
            }
        )
        self.write_manifest()

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
            "skill_id": "consilium",
            "wave_size": 8,
            "repository_root": str(self.repo),
            "base_commit": "1318542fb00df4eaef4fc4e8abfa8cd99e656bb3",
            "participants": list(getattr(self, "default_participants", [])),
        }
        payload.update(overrides)
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")

    def run_validator(self, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [
                sys.executable,
                str(VALIDATOR),
                "--manifest",
                str(self.manifest),
                "--skill-id",
                "consilium",
                "--skill-file",
                str(self.skill),
                "--trusted-registry",
                str(self.registry),
                *extra,
            ]
        return subprocess.run(
            command,
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

    def unversioned_readers(self) -> None:
        self.write_manifest(base_commit=None, wave_size=19, participants=[
            {"id": f"reader-{i}", "access": "read-only", "owned_write_scope": []}
            for i in range(19)
        ])

    def test_accepts_unversioned_read_only_panel_without_creating_git(self) -> None:
        self.unversioned_readers()
        completed = self.run_validator("--expected-wave-size", "19")
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertFalse((self.repo / ".git").exists())

    def test_unversioned_panel_forbids_writers(self) -> None:
        for access in ("workspace-write", "danger-full-access"):
            with self.subTest(access=access):
                participants = [dict(p) for p in self.default_participants]
                participants[-1]["access"] = access
                self.write_manifest(base_commit=None, participants=participants)
                completed = self.run_validator()
                self.assertEqual(2, completed.returncode)
                self.assertIn("unversioned_requires_read_only", completed.stdout)

    def test_unversioned_panel_rejects_git_markers_in_root_or_parent(self) -> None:
        self.unversioned_readers()
        for marker in (self.repo / ".git", self.root / ".git"):
            with self.subTest(marker=marker.name, parent=marker.parent.name):
                marker.write_text("gitdir: /unavailable/worktree\n", encoding="utf-8")
                completed = self.run_validator()
                self.assertEqual(2, completed.returncode)
                self.assertIn("base_commit_required_for_git_project", completed.stdout)
                marker.unlink()

    def test_unversioned_panel_preserves_skill_hash_check(self) -> None:
        self.unversioned_readers()
        self.skill.write_bytes(self.skill.read_bytes() + b"changed")
        completed = self.run_validator()
        self.assertEqual(2, completed.returncode)
        self.assertIn("skill_hash_mismatch", completed.stdout)

    def test_parallel_review_wave_accepts_seven_through_nineteen(self) -> None:
        entry = {
            "skill_id": "parallel-review-wave",
            "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
            "max_live_wave": 19,
            "execution_kind": "flat-trusted-wide-wave",
            "fallback": "chunks<=6",
        }
        self.write_registry(entry)
        for size in (7, 8, 19):
            with self.subTest(size=size):
                self.write_manifest(skill_id="parallel-review-wave", wave_size=size, participants=[
                    {"id": f"reader-{i}", "access": "read-only", "owned_write_scope": []}
                    for i in range(size)
                ])
                result = self.run_validator("--skill-id", "parallel-review-wave", "--expected-wave-size", str(size))
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_blocks_unknown_skill(self) -> None:
        self.write_registry()

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("unknown_skill", completed.stdout)

    def test_blocks_hash_mismatch(self) -> None:
        self.skill.write_bytes(self.skill.read_bytes() + b"mutated-byte\n")

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("skill_hash_mismatch", completed.stdout)

    def test_blocks_registry_hash_mismatch(self) -> None:
        self.write_registry(
            {
                "skill_id": "consilium",
                "sha256": "0" * 64,
                "max_live_wave": 19,
                "execution_kind": "flat-trusted-wide-wave",
                "fallback": "6+6+6+1",
            }
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("skill_hash_mismatch", completed.stdout)

    def test_accepts_explicit_compatible_skill_hash_for_existing_sessions(self) -> None:
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        entry = registry["trusted_skills"][0]
        entry["compatible_sha256"] = [entry["sha256"]]
        entry["sha256"] = hashlib.sha256(b"new skill release").hexdigest()
        self.write_registry(entry)

        completed = self.run_validator()

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_compatible_hash_does_not_accept_modified_skill(self) -> None:
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        entry = registry["trusted_skills"][0]
        entry["compatible_sha256"] = [entry["sha256"]]
        entry["sha256"] = hashlib.sha256(b"new skill release").hexdigest()
        self.write_registry(entry)
        self.skill.write_bytes(self.skill.read_bytes() + b"mutated-byte\n")

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("skill_hash_mismatch", completed.stdout)

    def test_rejects_malformed_compatible_hashes_even_when_primary_matches(self) -> None:
        for compatible in ("*", ["*"], ["z" * 64], [None]):
            with self.subTest(compatible=compatible):
                self.write_registry(
                    {
                        "skill_id": "consilium",
                        "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                        "compatible_sha256": compatible,
                        "max_live_wave": 19,
                        "execution_kind": "flat-trusted-wide-wave",
                        "fallback": "6+6+6+1",
                    }
                )

                completed = self.run_validator()

                self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
                self.assertIn("trusted_compatible_sha256_invalid", completed.stdout)

    def test_blocks_consilium_wave_above_trusted_maximum(self) -> None:
        self.write_manifest(
            wave_size=20,
            participants=[
                {"id": f"reader-{index}", "access": "read-only", "owned_write_scope": []}
                for index in range(1, 21)
            ],
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("wave_size_exceeds_trusted_max", completed.stdout)

    def test_blocks_unknown_execution_kind_for_known_skill(self) -> None:
        self.write_registry(
            {
                "skill_id": "consilium",
                "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                "max_live_wave": 19,
                "execution_kind": "unknown-execution-kind",
                "fallback": "6+6+6+1",
            }
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("trusted_execution_kind_invalid", completed.stdout)

    def test_blocks_unknown_fallback_for_known_skill(self) -> None:
        self.write_registry(
            {
                "skill_id": "consilium",
                "sha256": hashlib.sha256(self.skill.read_bytes()).hexdigest(),
                "max_live_wave": 19,
                "execution_kind": "flat-trusted-wide-wave",
                "fallback": "unknown-fallback",
            }
        )

        completed = self.run_validator()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("trusted_fallback_invalid", completed.stdout)

    def test_blocks_expected_wave_size_mismatch(self) -> None:
        completed = self.run_validator("--expected-wave-size", "20")

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("expected_wave_size_mismatch", completed.stdout)

    def test_rejects_invalid_base_commit(self) -> None:
        for base_commit in ("123456", "g" * 40, "1" * 65):
            with self.subTest(base_commit=base_commit):
                self.write_manifest(base_commit=base_commit)

                completed = self.run_validator()

                self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
                self.assertIn("base_commit_invalid", completed.stdout)

    def test_rejects_relative_or_missing_repository_root(self) -> None:
        for repository_root, reason in (
            ("relative/repo", "repository_root_not_absolute"),
            (str(self.root / "missing"), "repository_root_missing"),
        ):
            with self.subTest(repository_root=repository_root):
                self.write_manifest(repository_root=repository_root)

                completed = self.run_validator()

                self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
                self.assertIn(reason, completed.stdout)

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
