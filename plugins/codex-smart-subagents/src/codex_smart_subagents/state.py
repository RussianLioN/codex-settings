"""Route state machine for the adaptive-subagent controller."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RouteState(StrEnum):
    PLANNED = "PLANNED"
    BLOCKED = "BLOCKED"
    QUEUED = "QUEUED"
    LEASED = "LEASED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    COLLECTING = "COLLECTING"
    ATTESTING = "ATTESTING"
    VALIDATING = "VALIDATING"
    CANDIDATE_BUILDING = "CANDIDATE_BUILDING"
    SUCCEEDED = "SUCCEEDED"
    CANDIDATE_READY = "CANDIDATE_READY"
    QUARANTINED = "QUARANTINED"
    RETRYABLE = "RETRYABLE"
    RECOVERING = "RECOVERING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    STALE = "STALE"
    SKIPPED = "SKIPPED"
    SPLIT = "SPLIT"


TERMINAL_STATES = frozenset(
    {
        RouteState.SUCCEEDED,
        RouteState.CANDIDATE_READY,
        RouteState.QUARANTINED,
        RouteState.CANCELLED,
        RouteState.FAILED,
        RouteState.STALE,
        RouteState.SKIPPED,
    }
)

ALLOWED_TRANSITIONS: dict[RouteState, frozenset[RouteState]] = {
    RouteState.PLANNED: frozenset(
        {
            RouteState.BLOCKED,
            RouteState.QUEUED,
            RouteState.CANCELLED,
            RouteState.FAILED,
            RouteState.STALE,
        }
    ),
    RouteState.BLOCKED: frozenset(
        {
            RouteState.QUEUED,
            RouteState.CANCELLED,
            RouteState.FAILED,
            RouteState.STALE,
        }
    ),
    RouteState.QUEUED: frozenset(
        {
            RouteState.LEASED,
            RouteState.CANCELLING,
            RouteState.CANCELLED,
            RouteState.FAILED,
            RouteState.STALE,
        }
    ),
    RouteState.LEASED: frozenset(
        {
            RouteState.PREPARING,
            RouteState.RECOVERING,
            RouteState.CANCELLING,
            RouteState.RETRYABLE,
            RouteState.FAILED,
        }
    ),
    RouteState.PREPARING: frozenset(
        {
            RouteState.RUNNING,
            RouteState.RECOVERING,
            RouteState.CANCELLING,
            RouteState.RETRYABLE,
            RouteState.FAILED,
        }
    ),
    RouteState.RUNNING: frozenset(
        {
            RouteState.COLLECTING,
            RouteState.RECOVERING,
            RouteState.CANCELLING,
            RouteState.RETRYABLE,
            RouteState.FAILED,
        }
    ),
    RouteState.COLLECTING: frozenset(
        {
            RouteState.ATTESTING,
            RouteState.RECOVERING,
            RouteState.CANCELLING,
            RouteState.FAILED,
        }
    ),
    RouteState.ATTESTING: frozenset(
        {
            RouteState.VALIDATING,
            RouteState.QUARANTINED,
            RouteState.FAILED,
        }
    ),
    RouteState.VALIDATING: frozenset(
        {
            RouteState.CANDIDATE_BUILDING,
            RouteState.SUCCEEDED,
            RouteState.QUARANTINED,
            RouteState.FAILED,
        }
    ),
    RouteState.CANDIDATE_BUILDING: frozenset(
        {
            RouteState.CANDIDATE_READY,
            RouteState.QUARANTINED,
            RouteState.RECOVERING,
            RouteState.FAILED,
        }
    ),
    RouteState.RETRYABLE: frozenset(
        {
            RouteState.QUEUED,
            RouteState.CANCELLED,
            RouteState.FAILED,
        }
    ),
    RouteState.RECOVERING: frozenset(
        {
            RouteState.QUEUED,
            RouteState.RETRYABLE,
            RouteState.CANCELLING,
            RouteState.FAILED,
        }
    ),
    RouteState.CANCELLING: frozenset(
        {RouteState.CANCELLED, RouteState.FAILED}
    ),
    RouteState.SPLIT: frozenset(
        {RouteState.QUEUED, RouteState.SKIPPED, RouteState.FAILED}
    ),
    **{state: frozenset() for state in TERMINAL_STATES},
}


@dataclass
class StateTransitionError(ValueError):
    before: RouteState
    after: RouteState

    def __str__(self) -> str:
        return f"invalid route transition: {self.before} -> {self.after}"


def assert_transition(before: RouteState, after: RouteState) -> None:
    if after not in ALLOWED_TRANSITIONS[before]:
        raise StateTransitionError(before, after)


def is_terminal(state: RouteState) -> bool:
    return state in TERMINAL_STATES
