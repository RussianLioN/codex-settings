"""Shared fail-open helpers for bounded lifecycle hooks."""

from __future__ import annotations

import time
from typing import Mapping


SMART_HOOK_DEFERRED_CODE = "SMART_HOOK_DEFERRED"
STOP_HOOK_BUDGET_SECONDS = 1.5
STOP_HOOK_STARTED_MONOTONIC_NS_ENV = "CODEX_SMART_HOOK_STARTED_MONOTONIC_NS"
STOP_HOOK_DEADLINE_MONOTONIC_NS_ENV = "CODEX_SMART_HOOK_DEADLINE_MONOTONIC_NS"
_NANOSECONDS_PER_SECOND = 1_000_000_000


class HookDeadlineExceeded(RuntimeError):
    """Raised when a lifecycle hook exhausted its local deadline."""


def stop_deadline_from_environ(
    environ: Mapping[str, str],
    *,
    fallback_budget_seconds: float = STOP_HOOK_BUDGET_SECONDS,
) -> float:
    raw = environ.get(STOP_HOOK_DEADLINE_MONOTONIC_NS_ENV)
    if raw is not None:
        try:
            deadline_ns = int(raw)
        except ValueError:
            deadline_ns = 0
        if deadline_ns > 0:
            return deadline_ns / _NANOSECONDS_PER_SECOND
    return time.monotonic() + fallback_budget_seconds


def require_time_remaining(deadline: float, reason: str) -> None:
    if deadline - time.monotonic() <= 0:
        raise HookDeadlineExceeded(reason)


def fail_open_response(reason: str) -> dict[str, object]:
    return {
        "continue": True,
        "code": SMART_HOOK_DEFERRED_CODE,
        "reason": reason,
        "systemMessage": f"{SMART_HOOK_DEFERRED_CODE}: {reason}",
    }
