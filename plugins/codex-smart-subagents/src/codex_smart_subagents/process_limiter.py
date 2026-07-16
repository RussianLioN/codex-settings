"""Shared process-slot accounting for execution and route planning."""

from __future__ import annotations

import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


@dataclass
class ProcessLimitError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ProcessLimiter:
    """Bound all external child workflows across controller subsystems."""

    def __init__(self, limit: int) -> None:
        if type(limit) is not int or limit <= 0:
            raise ValueError("process limit must be a positive integer")
        self.limit = limit
        self._semaphore = threading.BoundedSemaphore(limit)
        self._lock = threading.Lock()
        self._active = 0

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    @contextmanager
    def hold(
        self,
        *,
        timeout_seconds: float,
    ) -> Iterator[None]:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise ValueError("slot timeout must be in (0, 3600]")
        acquired = self._semaphore.acquire(
            timeout=float(timeout_seconds)
        )
        if not acquired:
            raise ProcessLimitError(
                "PROCESS_CAPACITY_EXHAUSTED",
                "global child process capacity is exhausted",
            )
        with self._lock:
            self._active += 1
            if self._active > self.limit:
                raise AssertionError("process limiter exceeded its capacity")
        try:
            yield
        finally:
            with self._lock:
                self._active -= 1
            self._semaphore.release()


class CompositeProcessLimiter:
    """Acquire several accounting domains under one monotonic deadline."""

    def __init__(self, *limiters: ProcessLimiter) -> None:
        if not limiters:
            raise ValueError("at least one process limiter is required")
        self.limiters = tuple(limiters)

    @contextmanager
    def hold(
        self,
        *,
        timeout_seconds: float,
    ) -> Iterator[None]:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise ValueError("slot timeout must be in (0, 3600]")
        deadline = time.monotonic() + float(timeout_seconds)
        with ExitStack() as stack:
            for limiter in self.limiters:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProcessLimitError(
                        "PROCESS_CAPACITY_EXHAUSTED",
                        "global child process capacity is exhausted",
                    )
                stack.enter_context(
                    limiter.hold(timeout_seconds=remaining)
                )
            yield


class ProcessLimitedNodeExecutor:
    """Reserve one global slot around each external node workflow."""

    def __init__(
        self,
        delegate: Any,
        limiter: ProcessLimiter,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.delegate = delegate
        self.limiter = limiter
        self.timeout_seconds = float(timeout_seconds)

    def execute(
        self,
        request: Any,
        cancellation: threading.Event,
    ) -> Any:
        with self.limiter.hold(
            timeout_seconds=self.timeout_seconds
        ):
            return self.delegate.execute(request, cancellation)
