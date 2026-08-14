from __future__ import annotations

import sys
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.permissions import (  # noqa: E402
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    CanaryRequest,
    PermissionDenied,
    PermissionGate,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def request(**overrides: object) -> CanaryRequest:
    values: dict[str, object] = {
        "codex_version": "0.144.4",
        "permission_profile": "adaptive_reader",
        "profile_sha256": "a" * 64,
        "managed_config_sha256": "b" * 64,
    }
    values.update(overrides)
    return CanaryRequest(**values)


def evidence(
    requested: CanaryRequest,
    *,
    verified_at: datetime = NOW,
    checks: dict[str, bool] | None = None,
    legacy_sandbox_mode: bool = False,
) -> CanaryEvidence:
    return CanaryEvidence(
        probe_id="pc1_" + "A" * 43,
        codex_version=requested.codex_version,
        permission_profile=requested.permission_profile,
        profile_sha256=requested.profile_sha256,
        managed_config_sha256=requested.managed_config_sha256,
        verified_at=verified_at,
        legacy_sandbox_mode=legacy_sandbox_mode,
        checks=checks or {name: True for name in REQUIRED_CANARY_CHECKS},
    )


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class RecordingCanary:
    def __init__(self) -> None:
        self.calls: list[CanaryRequest] = []
        self.result_factory = evidence
        self.error: Exception | None = None

    def verify(self, requested: CanaryRequest) -> CanaryEvidence:
        self.calls.append(requested)
        if self.error is not None:
            raise self.error
        return self.result_factory(requested)


class PermissionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.canary = RecordingCanary()
        self.gate = PermissionGate(self.canary, clock=self.clock)

    def test_accepts_complete_evidence_and_caches_it_for_fifteen_minutes(self) -> None:
        requested = request()

        first = self.gate.require_verified(requested)
        self.clock.now += timedelta(minutes=14, seconds=59)
        second = self.gate.require_verified(requested)

        self.assertEqual(first, second)
        self.assertEqual("pc1_" + "A" * 43, first.probe_id)
        self.assertEqual([requested], self.canary.calls)

        self.clock.now += timedelta(seconds=1)
        self.canary.result_factory = lambda value: evidence(
            value,
            verified_at=self.clock.now,
        )
        refreshed = self.gate.require_verified(requested)
        self.assertEqual(2, len(self.canary.calls))
        self.assertEqual(self.clock.now, refreshed.verified_at)

    def test_cache_is_bound_to_all_profile_inputs(self) -> None:
        first = request()
        second = request(profile_sha256="c" * 64)

        self.gate.require_verified(first)
        self.gate.require_verified(second)

        self.assertEqual([first, second], self.canary.calls)

    def test_fails_closed_on_missing_or_failed_negative_check(self) -> None:
        requested = request()
        scenarios = {
            "missing": {
                name: True
                for name in REQUIRED_CANARY_CHECKS
                if name != "external_network_denied"
            },
            "failed": {
                name: name != "snapshot_write_denied"
                for name in REQUIRED_CANARY_CHECKS
            },
        }
        for name, checks in scenarios.items():
            with self.subTest(name=name):
                canary = RecordingCanary()
                canary.result_factory = lambda value, checks=checks: evidence(
                    value,
                    checks=checks,
                )
                gate = PermissionGate(canary, clock=self.clock)
                with self.assertRaisesRegex(
                    PermissionDenied,
                    "PERMISSION_CANARY_FAILED",
                ):
                    gate.require_verified(requested)

    def test_fails_closed_on_legacy_sandbox_mismatch_stale_or_future_evidence(
        self,
    ) -> None:
        requested = request()
        scenarios = (
            replace(evidence(requested), legacy_sandbox_mode=True),
            replace(evidence(requested), codex_version="0.144.3"),
            replace(evidence(requested), profile_sha256="c" * 64),
            replace(evidence(requested), verified_at=NOW - timedelta(minutes=15)),
            replace(evidence(requested), verified_at=NOW + timedelta(seconds=6)),
        )
        for result in scenarios:
            with self.subTest(result=result):
                canary = RecordingCanary()
                canary.result_factory = lambda value, result=result: result
                gate = PermissionGate(canary, clock=self.clock)
                with self.assertRaises(PermissionDenied):
                    gate.require_verified(requested)

    def test_canary_exception_is_a_denial_and_is_not_cached(self) -> None:
        requested = request()
        self.canary.error = RuntimeError("probe unavailable")

        with self.assertRaisesRegex(
            PermissionDenied,
            "PERMISSION_CANARY_UNAVAILABLE",
        ):
            self.gate.require_verified(requested)
        with self.assertRaises(PermissionDenied):
            self.gate.require_verified(requested)

        self.assertEqual(2, len(self.canary.calls))

    def test_malformed_evidence_is_a_structured_denial(self) -> None:
        self.canary.result_factory = lambda value: object()
        with self.assertRaisesRegex(
            PermissionDenied,
            "PERMISSION_CANARY_INVALID",
        ):
            self.gate.require_verified(request())

    def test_cached_checks_cannot_be_mutated_after_verification(self) -> None:
        verified = self.gate.require_verified(request())
        with self.assertRaises(TypeError):
            verified.checks["snapshot_write_denied"] = False

    def test_concurrent_admission_runs_one_canary_for_the_same_identity(self) -> None:
        class SlowCanary(RecordingCanary):
            def verify(self, requested: CanaryRequest) -> CanaryEvidence:
                self.calls.append(requested)
                time.sleep(0.05)
                return evidence(requested)

        canary = SlowCanary()
        gate = PermissionGate(canary, clock=self.clock)
        failures: list[BaseException] = []

        def admit() -> None:
            try:
                gate.require_verified(request())
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=admit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], failures)
        self.assertEqual(1, len(canary.calls))

    def test_request_rejects_unsafe_or_unverifiable_identity(self) -> None:
        invalid = (
            {"codex_version": ""},
            {"permission_profile": "../reader"},
            {"profile_sha256": "not-a-hash"},
            {"managed_config_sha256": "not-a-hash"},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    request(**overrides)


if __name__ == "__main__":
    unittest.main()
