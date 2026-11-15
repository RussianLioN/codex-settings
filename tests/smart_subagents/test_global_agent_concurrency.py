from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import apply_runtime_fd_guardrails as installer
import validate_wide_wave_manifest as validator


class GlobalAgentConcurrencyTests(unittest.TestCase):
    def test_cap_and_preserved_configuration(self):
        text = '[agents]\nmax_concurrent_threads_per_session = 20\nmax_depth = 1\n'
        result = installer.desired_config(text)
        self.assertIn("max_concurrent_threads_per_session = 19", result)
        self.assertIn("max_depth = 1", result)

    def test_backend_is_registered_and_macos_cannot_bypass_doctor(self):
        with patch.object(installer.platform, "system", return_value="Darwin"):
            self.assertIn("admission_backend=fd-doctor", installer.concurrency_policy())
            with self.assertRaises(ValueError):
                installer.concurrency_policy("native")
        for system in ("Linux", "Windows"):
            with patch.object(installer.platform, "system", return_value=system):
                self.assertIn("admission_backend=native", installer.concurrency_policy())
        with self.assertRaises(ValueError):
            installer.concurrency_policy("unknown")

    def test_replaces_legacy_and_canonical_blocks_idempotently(self):
        old = "before\n" + installer.POLICY_START + "\nold six\n" + installer.POLICY_END + "\nafter\n"
        result = installer.desired_agents(old)
        self.assertIn("before", result)
        self.assertIn("after", result)
        self.assertNotIn("old six", result)
        self.assertEqual(result, installer.desired_agents(result))
        self.assertEqual(1, result.count(installer.CONCURRENCY_POLICY_START))

    def test_rejects_broken_managed_markers(self):
        for text in (installer.POLICY_START, installer.CONCURRENCY_POLICY_END):
            with self.assertRaises(ValueError):
                installer.desired_agents(text)

    def test_parallel_review_hash_and_contract(self):
        registry = json.loads((ROOT / "config/trusted-wide-wave-skills.json").read_text())
        entry = next(e for e in registry["trusted_skills"] if e["skill_id"] == "parallel-review-wave")
        source = ROOT / "config/skills/parallel-review-wave/SKILL.md"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), entry["sha256"])
        self.assertEqual(19, entry["max_live_wave"])
        self.assertEqual((entry["execution_kind"], entry["fallback"]), validator.TRUSTED_EXECUTION_CONTRACTS["parallel-review-wave"])
        self.assertEqual(19, validator.MAX_WAVE_SIZE)

    def test_delivery_payload_pins_actual_bytes_and_backend_dependencies(self):
        payload = json.loads((ROOT / "config/global-agent-concurrency-payload.json").read_text())
        for entry in [payload["template"], *payload["files"]]:
            self.assertEqual(hashlib.sha256((ROOT / entry["source"]).read_bytes()).hexdigest(), entry["sha256"])
        native = [e["source"] for e in payload["files"] if "native" in e["backends"]]
        self.assertNotIn("scripts/codex-highfd", native)
        self.assertIn("scripts/validate_wide_wave_manifest.py", native)
