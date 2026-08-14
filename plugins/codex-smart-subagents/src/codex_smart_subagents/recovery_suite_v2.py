"""Единый предварительно проверяемый набор восстановлений версии 2."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .candidate_recovery_v2 import CandidateRecoveryV2
from .execution_recovery_v2 import ExecutionRecoveryV2, LaunchPermitRecoveryV2
from .runtime_recovery_v2 import RuntimeRecoveryV2


RecoveryFactoryV2 = Callable[..., Any]


@dataclass(frozen=True)
class RecoveryDomainReportV2:
    domain: str
    mode: str
    report: Any


@dataclass(frozen=True)
class RecoverySuiteReportV2:
    ok: bool
    applied: bool
    reports: tuple[RecoveryDomainReportV2, ...]
    blockers: tuple[str, ...]

    @property
    def actions(self) -> tuple[Any, ...]:
        """Возвращает действия всех доменов в порядке безопасного применения."""

        return tuple(
            action
            for item in self.reports
            for action in getattr(item.report, "actions", ())
        )


class RecoverySuiteV2:
    """Не начинает запись, пока каждый домен не построил закрытый план."""

    def __init__(
        self,
        *,
        store: Any,
        attempts_root: Path,
        permit_recovery_factory: RecoveryFactoryV2 = LaunchPermitRecoveryV2,
        execution_recovery_factory: RecoveryFactoryV2 = ExecutionRecoveryV2,
        runtime_recovery_factory: RecoveryFactoryV2 = RuntimeRecoveryV2,
        candidate_recovery_factory: RecoveryFactoryV2 = CandidateRecoveryV2,
    ) -> None:
        if not isinstance(attempts_root, Path) or not attempts_root.is_absolute():
            raise ValueError("attempts_root must be an absolute Path")
        for factory, name in (
            (permit_recovery_factory, "permit_recovery_factory"),
            (execution_recovery_factory, "execution_recovery_factory"),
            (runtime_recovery_factory, "runtime_recovery_factory"),
            (candidate_recovery_factory, "candidate_recovery_factory"),
        ):
            if not callable(factory):
                raise TypeError(f"{name} must be callable")
        self.store = store
        self.attempts_root = attempts_root
        self.factories = (
            ("permits", permit_recovery_factory),
            ("executions", execution_recovery_factory),
            ("artifacts", runtime_recovery_factory),
            ("candidates", candidate_recovery_factory),
        )

    def run(self, *, apply: bool) -> RecoverySuiteReportV2:
        if type(apply) is not bool:
            raise TypeError("apply должен быть bool")
        planned = tuple(self._run_domain(name, factory, apply=False) for name, factory in self.factories)
        blockers = _suite_blockers(planned)
        if blockers or not apply:
            return RecoverySuiteReportV2(
                ok=not blockers,
                applied=False,
                reports=planned,
                blockers=blockers,
            )

        applied_reports: list[RecoveryDomainReportV2] = []
        for name, factory in self.factories:
            completed = self._run_domain(name, factory, apply=True)
            applied_reports.append(completed)
            current_blockers = _suite_blockers(tuple(applied_reports))
            if current_blockers:
                return RecoverySuiteReportV2(
                    ok=False,
                    applied=any(
                        bool(getattr(item.report, "applied", False))
                        for item in applied_reports
                    ),
                    reports=tuple(applied_reports),
                    blockers=current_blockers,
                )
        return RecoverySuiteReportV2(
            ok=True,
            applied=any(
                bool(getattr(item.report, "applied", False))
                for item in applied_reports
            ),
            reports=tuple(applied_reports),
            blockers=(),
        )

    def _run_domain(
        self,
        name: str,
        factory: RecoveryFactoryV2,
        *,
        apply: bool,
    ) -> RecoveryDomainReportV2:
        arguments = {"store": self.store}
        if name == "artifacts":
            arguments["attempts_root"] = self.attempts_root
        runner = factory(**arguments)
        run = getattr(runner, "run", None)
        if not callable(run):
            raise TypeError(f"{name} recovery must provide run()")
        report = run(apply=apply)
        for attribute in ("ok", "applied", "actions", "blockers"):
            if not hasattr(report, attribute):
                raise TypeError(f"{name} recovery report lacks {attribute}")
        return RecoveryDomainReportV2(
            domain=name,
            mode="apply" if apply else "plan",
            report=report,
        )


def _suite_blockers(
    reports: tuple[RecoveryDomainReportV2, ...],
) -> tuple[str, ...]:
    blockers: list[str] = []
    for item in reports:
        values = getattr(item.report, "blockers", ())
        if not isinstance(values, tuple):
            raise TypeError(f"{item.domain} blockers must be a tuple")
        blockers.extend(f"{item.domain}:{value}" for value in values)
        if getattr(item.report, "ok", None) is not (not values):
            raise TypeError(f"{item.domain} recovery report is inconsistent")
    return tuple(dict.fromkeys(blockers))


__all__ = [
    "RecoveryDomainReportV2",
    "RecoverySuiteReportV2",
    "RecoverySuiteV2",
]
