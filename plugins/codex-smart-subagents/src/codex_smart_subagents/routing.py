"""Pure deterministic routing rules for adaptive Codex subagents."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import AbstractSet


LUNA = "gpt-5.6-luna"
TERRA = "gpt-5.6-terra"
SOL = "gpt-5.6-sol"
MODEL_ORDER = (LUNA, TERRA, SOL)


class Disposition(StrEnum):
    DIRECT = "direct"
    DELEGATE = "delegate"
    CLARIFY = "clarify"
    BOUNDARY = "boundary"


@dataclass(frozen=True, order=True)
class Interval:
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if self.minimum not in range(3) or self.maximum not in range(3):
            raise ValueError("interval endpoints must be integers in 0..2")
        if self.minimum > self.maximum:
            raise ValueError("interval minimum must not exceed maximum")


ALLOWED_INTERVALS = tuple(
    Interval(minimum, maximum)
    for minimum in range(3)
    for maximum in range(minimum, 3)
)


@dataclass(frozen=True)
class DelegationAssessment:
    q: Interval
    p: Interval
    v: Interval
    o: Interval
    hard_ban: Disposition | None = None
    writer: bool = False

    def __post_init__(self) -> None:
        if self.hard_ban not in {None, Disposition.DIRECT, Disposition.CLARIFY}:
            raise ValueError("hard_ban must be direct, clarify, or absent")


@dataclass(frozen=True)
class DelegationDecision:
    disposition: Disposition
    score_min: int
    score_max: int
    reason: str
    reclassified: bool = False


def classify_delegation(assessment: DelegationAssessment) -> DelegationDecision:
    """Apply the formal interval routing rules without external judgment."""

    score_min = (
        assessment.q.minimum
        + assessment.p.minimum
        + assessment.v.minimum
        - assessment.o.maximum
    )
    score_max = (
        assessment.q.maximum
        + assessment.p.maximum
        + assessment.v.maximum
        - assessment.o.minimum
    )
    if assessment.hard_ban is not None:
        return DelegationDecision(
            assessment.hard_ban,
            score_min,
            score_max,
            "hard_ban",
        )
    if assessment.v.maximum == 0:
        return DelegationDecision(
            Disposition.DIRECT,
            score_min,
            score_max,
            "not_verifiable",
        )
    if score_max < 2:
        return DelegationDecision(
            Disposition.DIRECT,
            score_min,
            score_max,
            "insufficient_upper_gain",
        )
    if assessment.v.minimum >= 1 and score_min >= 2:
        if assessment.writer and assessment.v.minimum != 2:
            return DelegationDecision(
                Disposition.BOUNDARY,
                score_min,
                score_max,
                "writer_verifiability_uncertain",
            )
        return DelegationDecision(
            Disposition.DELEGATE,
            score_min,
            score_max,
            "certain_gain",
        )
    return DelegationDecision(
        Disposition.BOUNDARY,
        score_min,
        score_max,
        "uncertain_gain",
    )


def resolve_boundary(
    primary: DelegationAssessment,
    secondary: DelegationAssessment | None,
) -> DelegationDecision:
    """Resolve one boundary with exactly one independent reclassification."""

    first = classify_delegation(primary)
    if first.disposition is not Disposition.BOUNDARY:
        return first
    if secondary is None:
        return replace(
            first,
            disposition=Disposition.DIRECT,
            reason="reclassification_failed",
            reclassified=True,
        )
    if secondary.hard_ban is not None:
        return replace(classify_delegation(secondary), reclassified=True)

    combined = DelegationAssessment(
        q=_merge_interval(primary.q, secondary.q),
        p=_merge_interval(primary.p, secondary.p),
        v=_merge_interval(primary.v, secondary.v),
        o=_merge_interval(primary.o, secondary.o),
        writer=primary.writer or secondary.writer,
    )
    result = classify_delegation(combined)
    if result.disposition is Disposition.BOUNDARY:
        return replace(
            result,
            disposition=Disposition.DIRECT,
            reason="reclassification_unresolved",
            reclassified=True,
        )
    return replace(result, reclassified=True)


def _merge_interval(left: Interval, right: Interval) -> Interval:
    intersection_min = max(left.minimum, right.minimum)
    intersection_max = min(left.maximum, right.maximum)
    if intersection_min <= intersection_max:
        return Interval(intersection_min, intersection_max)
    return Interval(
        min(left.minimum, right.minimum),
        max(left.maximum, right.maximum),
    )


@dataclass(frozen=True)
class ComplexityFactors:
    ambiguity: int
    dependency_depth: int
    breadth: int
    novelty: int
    harm: int
    cross_domain: int

    def __post_init__(self) -> None:
        _validate_factors(vars(self))

    @property
    def score(self) -> int:
        return sum(vars(self).values())


TERRA_FLOOR_FLAGS = frozenset(
    {"security", "architecture", "public_contract", "risky_migration"}
)
SOL_FLOOR_FLAGS = frozenset(
    {"irreversible", "critical_incident", "writer_final_validation"}
)


class ModelUnavailable(RuntimeError):
    """Raised when no allowed model at or above the selected tier is available."""


def select_model(
    factors: ComplexityFactors,
    *,
    risk_flags: AbstractSet[str] = frozenset(),
    available: AbstractSet[str] = frozenset(MODEL_ORDER),
) -> str:
    """Choose the lowest allowed model that satisfies score, floors, and availability."""

    if factors.score <= 3:
        selected_index = 0
    elif factors.score <= 7:
        selected_index = 1
    else:
        selected_index = 2

    if risk_flags & SOL_FLOOR_FLAGS:
        selected_index = max(selected_index, 2)
    elif risk_flags & TERRA_FLOOR_FLAGS:
        selected_index = max(selected_index, 1)

    for model in MODEL_ORDER[selected_index:]:
        if model in available:
            return model
    raise ModelUnavailable(
        f"no model available at or above {MODEL_ORDER[selected_index]}"
    )


@dataclass(frozen=True)
class ReasoningFactors:
    evidence: int
    verification: int
    harm: int

    def __post_init__(self) -> None:
        _validate_factors(vars(self))

    @property
    def score(self) -> int:
        return sum(vars(self).values())


def select_reasoning_effort(factors: ReasoningFactors) -> str:
    """Map evidence, verification, and harm to a reasoning effort."""

    if factors.score <= 1:
        return "low"
    if factors.score <= 3:
        return "medium"
    if factors.score == 4:
        return "high"
    if factors.score == 5:
        return "xhigh"
    return "max"


def normalize_model_effort(model: str, effort: str) -> tuple[str, str]:
    """Promote incompatible pairs using the exact v1 normalization table."""

    if model not in MODEL_ORDER:
        raise ValueError(f"unsupported model: {model}")
    if effort not in {"low", "medium", "high", "xhigh", "max"}:
        raise ValueError(f"unsupported reasoning effort: {effort}")

    promotions = {
        (LUNA, "high"): (TERRA, "high"),
        (LUNA, "xhigh"): (TERRA, "xhigh"),
        (LUNA, "max"): (SOL, "max"),
        (TERRA, "low"): (TERRA, "medium"),
        (TERRA, "max"): (SOL, "max"),
        (SOL, "low"): (SOL, "high"),
        (SOL, "medium"): (SOL, "high"),
    }
    return promotions.get((model, effort), (model, effort))


def _validate_factors(values: dict[str, int]) -> None:
    for name, value in values.items():
        if type(value) is not int or value not in range(3):
            raise ValueError(f"{name} must be an integer in 0..2")

