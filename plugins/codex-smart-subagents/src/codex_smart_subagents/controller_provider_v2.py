"""Контекст запроса для единого долгоживущего контроллера версии 2."""

from __future__ import annotations

import copy
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping

from .state_store_v2 import RequestContextV2


_SHELL_SESSION = re.compile(r"^cas2_[A-Za-z0-9_-]{32,128}$")


@dataclass
class ControllerProviderV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ScopedControllerProviderV2:
    """Связывает один внутренний вызов с записью конкретного корневого хода.

    Клиент передаёт только идентификатор сеанса оболочки. Сам контекст хода,
    шлюз и привязка активации заново читаются доверенными поставщиками внутри
    процесса контроллера.
    """

    def __init__(
        self,
        *,
        runtime_binding_provider: Callable[[], Any],
        activation_gate_provider: Callable[[], Mapping[str, Any]],
        turn_context_loader: Callable[[str], Any],
    ) -> None:
        for value, name in (
            (runtime_binding_provider, "runtime_binding_provider"),
            (activation_gate_provider, "activation_gate_provider"),
            (turn_context_loader, "turn_context_loader"),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        self._runtime_binding_provider = runtime_binding_provider
        self._activation_gate_provider = activation_gate_provider
        self._turn_context_loader = turn_context_loader
        self._shell_scope: ContextVar[str | None] = ContextVar(
            f"codex_smart_shell_scope_{id(self)}",
            default=None,
        )

    @contextmanager
    def bind(self, shell_session_id: str) -> Iterator[None]:
        """Устанавливает область ровно на время одного внутреннего вызова."""

        self._validate_shell(shell_session_id)
        token = self._shell_scope.set(shell_session_id)
        try:
            yield
        finally:
            self._shell_scope.reset(token)

    def request_context(self) -> RequestContextV2:
        shell_session_id = self._shell_scope.get()
        if shell_session_id is None:
            self._fail("SCOPE_MISSING", "вызов не связан с сеансом оболочки")
        record = self._turn_context_loader(shell_session_id)
        if getattr(record, "shell_session_id", None) != shell_session_id:
            self._fail(
                "CONTEXT_OWNER_MISMATCH",
                "запись контекста принадлежит другому сеансу оболочки",
            )
        binding = self.runtime_binding()
        try:
            return RequestContextV2(
                shell_session_id=shell_session_id,
                session_id=str(record.session_id),
                turn_id=str(record.turn_id),
                codex_home=str(record.codex_home),
                repo_root=str(record.repo_root),
                base_sha=str(record.base_sha),
                worktree_fingerprint=str(record.worktree_fingerprint),
                activation_fingerprint=str(binding.activation_fingerprint),
                compatibility_fingerprint=str(binding.compatibility_fingerprint),
                issued_control_epoch=int(binding.control_epoch),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ControllerProviderV2Error(
                "CONTEXT_INVALID",
                "запись хода или привязка активации неполна",
            ) from exc

    def activation_gate(self) -> dict[str, Any]:
        try:
            value = self._activation_gate_provider()
            if type(value) is not dict:
                raise TypeError("activation gate must be an exact object")
            return copy.deepcopy(value)
        except ControllerProviderV2Error:
            raise
        except Exception as exc:
            raise ControllerProviderV2Error(
                "ACTIVATION_GATE_UNAVAILABLE",
                "не удалось заново доказать шлюз активации",
            ) from exc

    def runtime_binding(self) -> Any:
        try:
            binding = self._runtime_binding_provider()
            for name in (
                "activation_fingerprint",
                "compatibility_fingerprint",
                "control_epoch",
            ):
                if not hasattr(binding, name):
                    raise TypeError(f"runtime binding has no {name}")
            return binding
        except ControllerProviderV2Error:
            raise
        except Exception as exc:
            raise ControllerProviderV2Error(
                "ACTIVATION_BINDING_UNAVAILABLE",
                "не удалось заново доказать привязку активации",
            ) from exc

    @staticmethod
    def _validate_shell(value: str) -> None:
        if not isinstance(value, str) or _SHELL_SESSION.fullmatch(value) is None:
            ScopedControllerProviderV2._fail(
                "SCOPE_INVALID",
                "идентификатор сеанса оболочки неверен",
            )

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise ControllerProviderV2Error(code, message)


class PinnedControllerProviderV2(ScopedControllerProviderV2):
    """Повторно доказывает одну активацию и одного владельца контроллера."""

    def __init__(
        self,
        *,
        launch_decision: Any,
        decision_provider: Callable[[], Any],
        turn_context_loader: Callable[[str], Any],
    ) -> None:
        if not callable(decision_provider):
            raise TypeError("decision_provider must be callable")
        self._decision_provider = decision_provider
        self._pinned = self._decision_identity(launch_decision, initial=True)
        super().__init__(
            runtime_binding_provider=self._fresh_binding,
            activation_gate_provider=self._fresh_gate,
            turn_context_loader=turn_context_loader,
        )

    def _fresh_binding(self) -> Any:
        decision = self._fresh_decision()
        return decision.runtime_binding

    def _fresh_gate(self) -> Mapping[str, Any]:
        decision = self._fresh_decision()
        return decision.activation_gate

    def _fresh_decision(self) -> Any:
        try:
            decision = self._decision_provider()
        except ControllerProviderV2Error:
            raise
        except Exception as exc:
            raise ControllerProviderV2Error(
                "ACTIVATION_CHANGED",
                "не удалось повторно доказать закреплённую активацию",
            ) from exc
        observed = self._decision_identity(decision, initial=False)
        if observed != self._pinned:
            self._fail(
                "ACTIVATION_CHANGED",
                "активация или владелец контроллера изменились",
            )
        return decision

    @classmethod
    def _decision_identity(cls, decision: Any, *, initial: bool) -> tuple[Any, ...]:
        code = "LAUNCH_DECISION_INVALID" if initial else "ACTIVATION_CHANGED"
        try:
            state = getattr(decision, "state")
            if getattr(state, "value", state) != "READY":
                raise ValueError("decision is not READY")
            binding = decision.runtime_binding
            if binding is None or type(decision.activation_gate) is not dict:
                raise ValueError("READY decision is incomplete")
            controller_row = binding.controller_row
            controller_start_id = controller_row["controller_start_id"]
            values = (
                decision.activation_id,
                decision.gate_fingerprint,
                str(decision.catalog_path),
                binding.activation_id,
                binding.activation_fingerprint,
                binding.compatibility_fingerprint,
                binding.control_epoch,
                str(binding.state_home),
                controller_start_id,
            )
            if any(value is None for value in values):
                raise ValueError("decision identity is incomplete")
            if decision.activation_gate.get("gateFingerprint") != decision.gate_fingerprint:
                raise ValueError("activation gate differs")
            return values
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ControllerProviderV2Error(
                code,
                "решение шлюза не содержит полной закрепляемой идентичности",
            ) from exc


__all__ = [
    "ControllerProviderV2Error",
    "PinnedControllerProviderV2",
    "ScopedControllerProviderV2",
]
