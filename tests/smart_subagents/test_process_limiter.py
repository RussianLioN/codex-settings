from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.process_limiter import (  # noqa: E402
    CompositeProcessLimiter,
    ProcessLimitError,
    ProcessLimiter,
)


class ProcessLimiterTests(unittest.TestCase):
    def test_parallel_holders_never_exceed_the_global_limit(self) -> None:
        limiter = ProcessLimiter(2)
        release = threading.Event()
        entered = threading.Barrier(3)
        failures: list[BaseException] = []

        def hold() -> None:
            try:
                with limiter.hold(timeout_seconds=1):
                    entered.wait(timeout=1)
                    release.wait(timeout=2)
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=hold, daemon=True)
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        entered.wait(timeout=1)

        self.assertEqual(2, limiter.active)
        with self.assertRaises(ProcessLimitError) as caught:
            with limiter.hold(timeout_seconds=0.05):
                self.fail("exhausted limiter admitted another workflow")
        self.assertEqual(
            "PROCESS_CAPACITY_EXHAUSTED",
            caught.exception.code,
        )
        self.assertEqual(2, limiter.active)

        release.set()
        for thread in threads:
            thread.join(timeout=2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], failures)
        self.assertEqual(0, limiter.active)

    def test_composite_releases_earlier_domain_when_later_domain_times_out(
        self,
    ) -> None:
        boundary = ProcessLimiter(1)
        global_limit = ProcessLimiter(1)
        composite = CompositeProcessLimiter(boundary, global_limit)

        with global_limit.hold(timeout_seconds=1):
            started = time.monotonic()
            with self.assertRaises(ProcessLimitError):
                with composite.hold(timeout_seconds=0.05):
                    self.fail("composite limiter ignored global exhaustion")
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(0, boundary.active)
            self.assertEqual(1, global_limit.active)


if __name__ == "__main__":
    unittest.main()
