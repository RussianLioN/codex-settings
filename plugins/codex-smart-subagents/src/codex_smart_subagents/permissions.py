"""Fail-closed admission gate for live Codex permission-profile canaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from types import MappingProxyType
from typing import Callable, Mapping, Protocol


CANARY_VALIDITY = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(seconds=5)
REQUIRED_CANARY_CHECKS = (
    "catalog_syntax_loaded",
    "sandbox_negative_probe",
    "exec_negative_probe",
    "snapshot_read_allowed",
    "snapshot_write_denied",
    "secret_read_denied",
    "source_git_read_denied",
    "controller_database_read_denied",
    "source_worktree_write_denied",
    "external_network_denied",
    "dns_denied",
    "udp_denied",
    "loopback_denied",
    "controller_socket_denied",
)

_PROFILE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CODEX_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_PROBE_ID = re.compile(r"pc1_[A-Za-z0-9_-]{43}")


@dataclass
class PermissionDenied(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class CanaryRequest:
    codex_version: str
    permission_profile: str
    profile_sha256: str
    managed_config_sha256: str

    def __post_init__(self) -> None:
        if _CODEX_VERSION.fullmatch(self.codex_version) is None:
            raise ValueError("codex_version must be a concrete semantic version")
        if _PROFILE_NAME.fullmatch(self.permission_profile) is None:
            raise ValueError("permission_profile must be a safe custom name")
        if _SHA256.fullmatch(self.profile_sha256) is None:
            raise ValueError("profile_sha256 must be a lowercase SHA-256")
        if _SHA256.fullmatch(self.managed_config_sha256) is None:
            raise ValueError(
                "managed_config_sha256 must be a lowercase SHA-256"
            )


@dataclass(frozen=True)
class CanaryEvidence:
    probe_id: str
    codex_version: str
    permission_profile: str
    profile_sha256: str
    managed_config_sha256: str
    verified_at: datetime
    legacy_sandbox_mode: bool
    checks: Mapping[str, bool]

    def __post_init__(self) -> None:
        if type(self.legacy_sandbox_mode) is not bool:
            raise ValueError("legacy_sandbox_mode must be boolean")
        try:
            copied = dict(self.checks)
        except (TypeError, ValueError) as exc:
            raise ValueError("checks must be a string-to-boolean mapping") from exc
        if not all(
            isinstance(name, str) and type(value) is bool
            for name, value in copied.items()
        ):
            raise ValueError("checks must be a string-to-boolean mapping")
        object.__setattr__(self, "checks", MappingProxyType(copied))


class PermissionCanary(Protocol):
    def verify(self, request: CanaryRequest) -> CanaryEvidence:
        """Run the real syntax, sandbox, exec, filesystem, and network probes."""


class PermissionGate:
    """Cache only complete, fresh, identity-bound successful canary evidence."""

    def __init__(
        self,
        canary: PermissionCanary,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._canary = canary
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._cache: dict[CanaryRequest, CanaryEvidence] = {}
        self._lock = RLock()

    def require_verified(self, request: CanaryRequest) -> CanaryEvidence:
        with self._lock:
            now = _aware_utc(self._clock(), "gate clock")
            cached = self._cache.get(request)
            if cached is not None and _is_fresh(cached.verified_at, now):
                self._validate_evidence(request, cached, now)
                return cached

            try:
                candidate = self._canary.verify(request)
            except Exception as exc:
                raise PermissionDenied(
                    "PERMISSION_CANARY_UNAVAILABLE",
                    "permission-profile canary could not produce evidence",
                ) from exc
            if not isinstance(candidate, CanaryEvidence):
                raise PermissionDenied(
                    "PERMISSION_CANARY_INVALID",
                    "permission-profile canary returned malformed evidence",
                )
            self._validate_evidence(request, candidate, now)
            self._cache[request] = candidate
            return candidate

    @staticmethod
    def _validate_evidence(
        request: CanaryRequest,
        evidence: CanaryEvidence,
        now: datetime,
    ) -> None:
        identity = (
            evidence.codex_version,
            evidence.permission_profile,
            evidence.profile_sha256,
            evidence.managed_config_sha256,
        )
        requested_identity = (
            request.codex_version,
            request.permission_profile,
            request.profile_sha256,
            request.managed_config_sha256,
        )
        if identity != requested_identity:
            raise PermissionDenied(
                "PERMISSION_CANARY_MISMATCH",
                "canary evidence belongs to another runtime or profile",
            )
        if _PROBE_ID.fullmatch(evidence.probe_id) is None:
            raise PermissionDenied(
                "PERMISSION_CANARY_INVALID",
                "canary evidence has an invalid probe identifier",
            )
        if evidence.legacy_sandbox_mode:
            raise PermissionDenied(
                "LEGACY_SANDBOX_ACTIVE",
                "legacy sandbox_mode disables permission-profile enforcement",
            )
        verified_at = _aware_utc(evidence.verified_at, "verified_at")
        if not _is_fresh(verified_at, now):
            raise PermissionDenied(
                "PERMISSION_CANARY_STALE",
                "canary evidence is stale or from the future",
            )
        if set(evidence.checks) != set(REQUIRED_CANARY_CHECKS):
            raise PermissionDenied(
                "PERMISSION_CANARY_FAILED",
                "canary evidence does not contain the complete required check set",
            )
        if any(evidence.checks[name] is not True for name in REQUIRED_CANARY_CHECKS):
            raise PermissionDenied(
                "PERMISSION_CANARY_FAILED",
                "one or more permission-profile checks did not pass",
            )


def _is_fresh(verified_at: datetime, now: datetime) -> bool:
    verified_at = _aware_utc(verified_at, "verified_at")
    age = now - verified_at
    return -MAX_CLOCK_SKEW <= age < CANARY_VALIDITY


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PermissionDenied(
            "PERMISSION_CANARY_INVALID",
            f"{label} must be timezone-aware",
        )
    return value.astimezone(timezone.utc)
