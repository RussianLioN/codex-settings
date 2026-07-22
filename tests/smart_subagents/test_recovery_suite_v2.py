from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from codex_smart_subagents.recovery_suite_v2 import RecoverySuiteV2  # noqa: E402


@dataclass(frozen=True)
class _Report:
    ok: bool
    applied: bool
    actions: tuple[str, ...]
    blockers: tuple[str, ...]


class _Runner:
    def __init__(
        self,
        name: str,
        order: list[str],
        *,
        blocker: str | None = None,
    ) -> None:
        self.name = name
        self.order = order
        self.blocker = blocker

    def run(self, *, apply: bool) -> _Report:
        self.order.append(f"{self.name}:{'apply' if apply else 'plan'}")
        blockers = () if self.blocker is None else (self.blocker,)
        return _Report(
            ok=not blockers,
            applied=apply and not blockers,
            actions=(self.name,),
            blockers=blockers,
        )


class RecoverySuiteV2Tests(unittest.TestCase):
    def _suite(
        self,
        order: list[str],
        *,
        blocker_at: str | None = None,
    ) -> RecoverySuiteV2:
        def factory(name: str):
            return lambda **kwargs: _Runner(
                name,
                order,
                blocker="BLOCKED" if blocker_at == name else None,
            )

        return RecoverySuiteV2(
            store=object(),
            attempts_root=Path("/tmp/attempts"),
            permit_recovery_factory=factory("permits"),
            execution_recovery_factory=factory("executions"),
            runtime_recovery_factory=factory("artifacts"),
            candidate_recovery_factory=factory("candidates"),
        )

    def test_apply_preflights_every_domain_before_first_write(self) -> None:
        order: list[str] = []

        report = self._suite(order).run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertEqual(
            [
                "permits:plan",
                "executions:plan",
                "artifacts:plan",
                "candidates:plan",
                "permits:apply",
                "executions:apply",
                "artifacts:apply",
                "candidates:apply",
            ],
            order,
        )

    def test_any_preflight_blocker_prevents_all_writes(self) -> None:
        order: list[str] = []

        report = self._suite(order, blocker_at="candidates").run(apply=True)

        self.assertFalse(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual(
            [
                "permits:plan",
                "executions:plan",
                "artifacts:plan",
                "candidates:plan",
            ],
            order,
        )
        self.assertEqual(("candidates:BLOCKED",), report.blockers)

    def test_dry_run_returns_all_plans_without_writes(self) -> None:
        order: list[str] = []

        report = self._suite(order).run(apply=False)

        self.assertTrue(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual(4, len(report.reports))
        self.assertTrue(all(item.mode == "plan" for item in report.reports))


if __name__ == "__main__":
    unittest.main()
