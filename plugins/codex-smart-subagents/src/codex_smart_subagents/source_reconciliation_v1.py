"""Закрытая квитанция и конечный однократный согласователь источника."""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Mapping, Protocol

from .activation_gateway_v2 import SourceDriftV1
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .finite_file_lock_v2 import (
    FileLockTimeoutV2,
    acquire_flock_v2,
    lock_budget_v2,
)
from .installer_command_v2 import (
    _DEFAULT_SCHEMA_PATH,
    _validate_result,
    exit_code_v2,
)


_RECEIPT_DOMAIN = "codex-smart/source-reconciliation/v1"
_RECEIPT_NAME = "source-reconciliation-v1.json"
_LOCK_NAME = "source-reconciliation-v1.lock"
_RETRY_SECONDS = 300
_LOCK_TIMEOUT_SECONDS = 30.0
_PROCESS_TIMEOUT_SECONDS = 180.0
_MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_INCOMPATIBILITY_CODES = frozenset(
    {
        "CODEX_VERSION_INCOMPATIBLE",
        "MODEL_CATALOG_INVALID",
        "MODEL_UNAVAILABLE",
        "MODEL_EFFORT_UNAVAILABLE",
        "INTERFACE_EVIDENCE_INVALID",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "schemaVersion",
        "source",
        "updater",
        "outcome",
        "reasonCode",
        "retryAfterEpochSeconds",
        "acceptedActivationId",
        "receiptFingerprint",
    }
)


class _ProcessResultV1(Protocol):
    returncode: int
    stdout: bytes | str
    stderr: bytes | str


RunProcessV1 = Callable[..., _ProcessResultV1]


@dataclass(frozen=True, slots=True)
class SourceReconciliationRequestV1:
    """Полностью связанный запрос одного согласования внешнего Codex."""

    drift: SourceDriftV1
    updater_activation_id: str
    updater_release: str
    updater_source_digest: str
    source_root: Path
    installer_path: Path
    python_executable: Path
    codex_home: Path
    bin_dir: Path
    state_home: Path

    def __post_init__(self) -> None:
        if not isinstance(self.drift, SourceDriftV1):
            raise TypeError("drift must be SourceDriftV1")
        for name in (
            "source_root",
            "installer_path",
            "python_executable",
            "codex_home",
            "bin_dir",
            "state_home",
        ):
            _absolute_path(getattr(self, name), name)
        if (
            type(self.updater_activation_id) is not str
            or not self.updater_activation_id.startswith("act2_")
        ):
            raise ValueError("updater_activation_id must start with act2_")
        if (
            type(self.updater_release) is not str
            or not self.updater_release
            or "\0" in self.updater_release
            or len(self.updater_release) > 256
        ):
            raise ValueError("updater_release must be a bounded string")
        if (
            type(self.updater_source_digest) is not str
            or _SHA256.fullmatch(self.updater_source_digest) is None
        ):
            raise ValueError("updater_source_digest must be a SHA-256 digest")
        expected_installer = (
            self.source_root / "scripts" / "install_adaptive_subagents.py"
        )
        if (
            len(self.installer_path.parents) < 2
            or self.source_root != self.installer_path.parents[1]
            or self.installer_path != expected_installer
        ):
            raise ValueError("installer_path is not bound to source_root")
        if (
            self.source_root.name != "marketplace"
            or self.source_root.parent.name != self.updater_activation_id
            or self.source_root.parent.parent.name != "activations"
        ):
            raise ValueError("source_root is not the updater activation marketplace")


@dataclass(frozen=True, slots=True)
class SourceReconciliationAcceptanceV1:
    """Повторно доказанные факты новой принятой активации."""

    activation_id: str
    source_lexical_path: Path
    source_resolved_path: Path
    source_sha256: str
    snapshot_sha256: str
    installer_receipt_activation_id: str

    def __post_init__(self) -> None:
        for name in ("activation_id", "installer_receipt_activation_id"):
            value = getattr(self, name)
            if type(value) is not str or _ACTIVATION_ID.fullmatch(value) is None:
                raise ValueError(f"{name} must be a version 2 activation id")
        for name in ("source_lexical_path", "source_resolved_path"):
            _absolute_path(getattr(self, name), name)
        for name in ("source_sha256", "snapshot_sha256"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a SHA-256 digest")


@dataclass(frozen=True, slots=True)
class SourceReconciliationResultV1:
    """Закрытый исход согласования, не являющийся разрешением сам по себе."""

    outcome: Literal["ACCEPTED", "INCOMPATIBLE", "RETRY_AFTER"]
    reason_code: str
    restart: bool
    retry_after_epoch_seconds: int | None
    accepted_activation_id: str | None

    def __post_init__(self) -> None:
        if self.outcome not in {"ACCEPTED", "INCOMPATIBLE", "RETRY_AFTER"}:
            raise ValueError("outcome is outside the closed result set")
        if (
            type(self.reason_code) is not str
            or _REASON_CODE.fullmatch(self.reason_code) is None
        ):
            raise ValueError("reason_code is invalid")
        if type(self.restart) is not bool:
            raise TypeError("restart must be a bool")
        if self.outcome == "ACCEPTED":
            if (
                self.restart is not True
                or type(self.accepted_activation_id) is not str
                or _ACTIVATION_ID.fullmatch(self.accepted_activation_id) is None
                or self.retry_after_epoch_seconds is not None
            ):
                raise ValueError("ACCEPTED result is incomplete")
            return
        if self.restart or self.accepted_activation_id is not None:
            raise ValueError("non-ACCEPTED result cannot authorize restart")
        if self.outcome == "INCOMPATIBLE":
            if self.retry_after_epoch_seconds is not None:
                raise ValueError("INCOMPATIBLE result cannot carry retryAfter")
            return
        if (
            type(self.retry_after_epoch_seconds) is not int
            or self.retry_after_epoch_seconds < 0
        ):
            raise ValueError("RETRY_AFTER result requires an epoch second")


class _ReceiptInvalidV1(ValueError):
    pass


def reconcile_source_drift_v1(
    request: SourceReconciliationRequestV1,
    *,
    verify_accepted: Callable[[], SourceReconciliationAcceptanceV1 | None],
    run_process: RunProcessV1,
    now_epoch_seconds: Callable[[], int | float] = time.time,
) -> SourceReconciliationResultV1:
    """Выполнить не более одного конечного запуска для одной личности."""

    if not isinstance(request, SourceReconciliationRequestV1):
        raise TypeError("request must be SourceReconciliationRequestV1")
    if not callable(verify_accepted):
        raise TypeError("verify_accepted must be callable")
    if not callable(run_process):
        raise TypeError("run_process must be callable")
    if not callable(now_epoch_seconds):
        raise TypeError("now_epoch_seconds must be callable")
    directory_descriptor = -1
    lock_descriptor = -1
    try:
        directory_descriptor = _open_private_state_directory(request.state_home)
        lock_descriptor = _open_private_lock(directory_descriptor)
        with lock_budget_v2(
            timeout_seconds=_LOCK_TIMEOUT_SECONDS,
            timeout_code="SOURCE_RECONCILIATION_LOCK_TIMEOUT",
        ):
            acquire_flock_v2(
                lock_descriptor,
                exclusive=True,
                timeout_seconds=_LOCK_TIMEOUT_SECONDS,
                timeout_code="SOURCE_RECONCILIATION_LOCK_TIMEOUT",
            )
        try:
            receipt = _read_receipt(directory_descriptor)
        except _ReceiptInvalidV1:
            return _retry_result(
                "SOURCE_RECONCILIATION_RECEIPT_INVALID",
                _retry_after(now_epoch_seconds),
            )

        if receipt is not None and _receipt_matches_request(receipt, request):
            cached = _cached_result(
                request=request,
                receipt=receipt,
                verify_accepted=verify_accepted,
                now_epoch_seconds=now_epoch_seconds,
            )
            if cached is not None:
                return cached

        return _run_once(
            directory_descriptor=directory_descriptor,
            request=request,
            verify_accepted=verify_accepted,
            run_process=run_process,
            now_epoch_seconds=now_epoch_seconds,
        )
    except FileLockTimeoutV2:
        return _retry_result(
            "SOURCE_RECONCILIATION_LOCK_TIMEOUT",
            _retry_after(now_epoch_seconds),
        )
    except (OSError, ValueError):
        return _retry_result(
            "SOURCE_RECONCILIATION_INTERNAL_ERROR",
            _retry_after(now_epoch_seconds),
        )
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _cached_result(
    *,
    request: SourceReconciliationRequestV1,
    receipt: Mapping[str, object],
    verify_accepted: Callable[[], SourceReconciliationAcceptanceV1 | None],
    now_epoch_seconds: Callable[[], int | float],
) -> SourceReconciliationResultV1 | None:
    outcome = str(receipt["outcome"])
    reason_code = str(receipt["reasonCode"])
    if outcome == "INCOMPATIBLE":
        return SourceReconciliationResultV1(
            outcome="INCOMPATIBLE",
            reason_code=reason_code,
            restart=False,
            retry_after_epoch_seconds=None,
            accepted_activation_id=None,
        )
    if outcome == "RETRY_AFTER":
        retry_after = int(receipt["retryAfterEpochSeconds"])
        now = _epoch_second(now_epoch_seconds())
        if now < retry_after:
            return _retry_result(reason_code, retry_after)
        return None

    accepted_id = str(receipt["acceptedActivationId"])
    acceptance = _verified_acceptance(verify_accepted)
    if (
        acceptance is not None
        and acceptance.activation_id == accepted_id
        and _acceptance_matches_request(request, acceptance)
    ):
        return SourceReconciliationResultV1(
            outcome="ACCEPTED",
            reason_code=reason_code,
            restart=True,
            retry_after_epoch_seconds=None,
            accepted_activation_id=accepted_id,
        )
    return _retry_result(
        "SOURCE_RECONCILIATION_ACCEPTANCE_UNVERIFIED",
        _retry_after(now_epoch_seconds),
    )


def _run_once(
    *,
    directory_descriptor: int,
    request: SourceReconciliationRequestV1,
    verify_accepted: Callable[[], SourceReconciliationAcceptanceV1 | None],
    run_process: RunProcessV1,
    now_epoch_seconds: Callable[[], int | float],
) -> SourceReconciliationResultV1:
    argv = (
        str(request.python_executable),
        "-B",
        str(request.installer_path),
        "--source-root",
        str(request.source_root),
        "--codex-home",
        str(request.codex_home),
        "--bin-dir",
        str(request.bin_dir),
        "--state-home",
        str(request.state_home),
        "--codex-binary",
        str(request.drift.lexical_path),
        "--apply",
        "--json",
    )
    try:
        completed = run_process(
            argv,
            timeout_seconds=_PROCESS_TIMEOUT_SECONDS,
            max_output_bytes=_MAX_PROCESS_OUTPUT_BYTES,
        )
    except Exception:
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_PROCESS_FAILED",
            now_epoch_seconds,
        )

    result = _installer_result(completed)
    if result is None:
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_RESULT_INVALID",
            now_epoch_seconds,
        )
    if result["command"] != "apply":
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_RESULT_INVALID",
            now_epoch_seconds,
        )
    if completed.returncode != exit_code_v2(result):
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_RESULT_INVALID",
            now_epoch_seconds,
        )
    error_codes = tuple(
        problem["code"]
        for problem in result["problems"]
        if problem["severity"] == "error"
    )
    incompatibility = next(
        (code for code in error_codes if code in _INCOMPATIBILITY_CODES), None
    )
    if incompatibility is not None:
        return _persist_result(
            directory_descriptor,
            request,
            outcome="INCOMPATIBLE",
            reason_code=incompatibility,
            retry_after_epoch_seconds=None,
            accepted_activation_id=None,
        )
    if (
        completed.returncode != 0
        or result["readiness"] != "READY"
        or result["status"] == "failed"
        or error_codes
    ):
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_PROCESS_FAILED",
            now_epoch_seconds,
        )

    acceptance = _verified_acceptance(verify_accepted)
    if acceptance is None or not _acceptance_matches_request(request, acceptance):
        return _persist_retry(
            directory_descriptor,
            request,
            "SOURCE_RECONCILIATION_ACCEPTANCE_UNVERIFIED",
            now_epoch_seconds,
        )
    return _persist_result(
        directory_descriptor,
        request,
        outcome="ACCEPTED",
        reason_code="SOURCE_RECONCILIATION_ACCEPTED",
        retry_after_epoch_seconds=None,
        accepted_activation_id=acceptance.activation_id,
    )


def _acceptance_matches_request(
    request: SourceReconciliationRequestV1,
    acceptance: SourceReconciliationAcceptanceV1,
) -> bool:
    return (
        acceptance.activation_id != request.updater_activation_id
        and acceptance.source_lexical_path == request.drift.lexical_path
        and acceptance.source_resolved_path == request.drift.resolved_path
        and acceptance.source_sha256 == request.drift.observed_sha256
        and acceptance.snapshot_sha256 == request.drift.observed_sha256
        and acceptance.installer_receipt_activation_id == acceptance.activation_id
    )


def _verified_acceptance(
    verify_accepted: Callable[[], SourceReconciliationAcceptanceV1 | None],
) -> SourceReconciliationAcceptanceV1 | None:
    try:
        value = verify_accepted()
    except Exception:
        return None
    return value if isinstance(value, SourceReconciliationAcceptanceV1) else None


def _installer_result(completed: object) -> dict[str, object] | None:
    returncode = getattr(completed, "returncode", None)
    stdout = _output_bytes(getattr(completed, "stdout", None))
    stderr = _output_bytes(getattr(completed, "stderr", None))
    if (
        type(returncode) is not int
        or stdout is None
        or stderr is None
        or len(stdout) + len(stderr) > _MAX_PROCESS_OUTPUT_BYTES
    ):
        return None
    try:
        text = stdout.decode("utf-8", "strict")
        decoder = json.JSONDecoder()
        start = len(text) - len(text.lstrip())
        value, end = decoder.raw_decode(text, start)
        if text[end:].strip() or type(value) is not dict:
            return None
        _validate_result(value, schema_path=_DEFAULT_SCHEMA_PATH)
    except (UnicodeError, ValueError, TypeError, KeyError):
        return None
    return value


def _output_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if type(value) is str:
        try:
            return value.encode("utf-8", "strict")
        except UnicodeError:
            return None
    return None


def _receipt_document(
    request: SourceReconciliationRequestV1,
    *,
    outcome: str,
    reason_code: str,
    retry_after_epoch_seconds: int | None,
    accepted_activation_id: str | None,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "schemaVersion": 1,
        "source": {
            "lexicalPath": str(request.drift.lexical_path),
            "resolvedPath": str(request.drift.resolved_path),
            "sha256": request.drift.observed_sha256,
        },
        "updater": {
            "activationId": request.updater_activation_id,
            "release": request.updater_release,
            "sourceDigest": request.updater_source_digest,
        },
        "outcome": outcome,
        "reasonCode": reason_code,
        "retryAfterEpochSeconds": retry_after_epoch_seconds,
        "acceptedActivationId": accepted_activation_id,
    }
    return {
        **projection,
        "receiptFingerprint": domain_fingerprint(_RECEIPT_DOMAIN, projection),
    }


def _persist_retry(
    directory_descriptor: int,
    request: SourceReconciliationRequestV1,
    reason_code: str,
    now_epoch_seconds: Callable[[], int | float],
) -> SourceReconciliationResultV1:
    retry_at = _retry_after(now_epoch_seconds)
    return _persist_result(
        directory_descriptor,
        request,
        outcome="RETRY_AFTER",
        reason_code=reason_code,
        retry_after_epoch_seconds=retry_at,
        accepted_activation_id=None,
    )


def _persist_result(
    directory_descriptor: int,
    request: SourceReconciliationRequestV1,
    *,
    outcome: Literal["ACCEPTED", "INCOMPATIBLE", "RETRY_AFTER"],
    reason_code: str,
    retry_after_epoch_seconds: int | None,
    accepted_activation_id: str | None,
) -> SourceReconciliationResultV1:
    document = _receipt_document(
        request,
        outcome=outcome,
        reason_code=reason_code,
        retry_after_epoch_seconds=retry_after_epoch_seconds,
        accepted_activation_id=accepted_activation_id,
    )
    _atomic_write_receipt(directory_descriptor, document)
    restart = outcome == "ACCEPTED"
    return SourceReconciliationResultV1(
        outcome=outcome,
        reason_code=reason_code,
        restart=restart,
        retry_after_epoch_seconds=retry_after_epoch_seconds,
        accepted_activation_id=accepted_activation_id,
    )


def _retry_result(reason_code: str, retry_at: int) -> SourceReconciliationResultV1:
    return SourceReconciliationResultV1(
        outcome="RETRY_AFTER",
        reason_code=reason_code,
        restart=False,
        retry_after_epoch_seconds=retry_at,
        accepted_activation_id=None,
    )


def _read_receipt(directory_descriptor: int) -> dict[str, object] | None:
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                _RECEIPT_NAME,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            return None
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o600
            or information.st_size > _MAX_RECEIPT_BYTES
        ):
            raise _ReceiptInvalidV1("receipt metadata is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            total += len(block)
            if total > _MAX_RECEIPT_BYTES:
                raise _ReceiptInvalidV1("receipt is too large")
            chunks.append(block)
        raw = b"".join(chunks)
        value = json.loads(raw.decode("utf-8", "strict"))
        if type(value) is not dict or canonical_json_bytes(value) != raw:
            raise _ReceiptInvalidV1("receipt is not canonical JSON")
        _validate_receipt(value)
        return value
    except _ReceiptInvalidV1:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        raise _ReceiptInvalidV1("receipt cannot be read") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_receipt(document: Mapping[str, object]) -> None:
    if set(document) != _RECEIPT_KEYS or document.get("schemaVersion") != 1:
        raise _ReceiptInvalidV1("receipt fields are invalid")
    source = document.get("source")
    updater = document.get("updater")
    if (
        type(source) is not dict
        or set(source) != {"lexicalPath", "resolvedPath", "sha256"}
        or type(updater) is not dict
        or set(updater) != {"activationId", "release", "sourceDigest"}
    ):
        raise _ReceiptInvalidV1("receipt identity is invalid")
    for value in (source["lexicalPath"], source["resolvedPath"]):
        if type(value) is not str or not value or not Path(value).is_absolute():
            raise _ReceiptInvalidV1("receipt path is invalid")
    if (
        type(source["sha256"]) is not str
        or _SHA256.fullmatch(source["sha256"]) is None
        or type(updater["activationId"]) is not str
        or not updater["activationId"].startswith("act2_")
        or type(updater["release"]) is not str
        or not updater["release"]
        or type(updater["sourceDigest"]) is not str
        or _SHA256.fullmatch(updater["sourceDigest"]) is None
    ):
        raise _ReceiptInvalidV1("receipt identity scalar is invalid")
    outcome = document.get("outcome")
    reason = document.get("reasonCode")
    retry_after = document.get("retryAfterEpochSeconds")
    accepted_id = document.get("acceptedActivationId")
    if (
        outcome not in {"ACCEPTED", "INCOMPATIBLE", "RETRY_AFTER"}
        or type(reason) is not str
        or _REASON_CODE.fullmatch(reason) is None
        or (outcome == "ACCEPTED" and (
            type(accepted_id) is not str
            or _ACTIVATION_ID.fullmatch(accepted_id) is None
            or retry_after is not None
        ))
        or (outcome == "INCOMPATIBLE" and (
            accepted_id is not None or retry_after is not None
        ))
        or (outcome == "RETRY_AFTER" and (
            accepted_id is not None
            or type(retry_after) is not int
            or retry_after < 0
        ))
    ):
        raise _ReceiptInvalidV1("receipt outcome is invalid")
    projection = {
        name: document[name]
        for name in (
            "schemaVersion",
            "source",
            "updater",
            "outcome",
            "reasonCode",
            "retryAfterEpochSeconds",
            "acceptedActivationId",
        )
    }
    if document.get("receiptFingerprint") != domain_fingerprint(
        _RECEIPT_DOMAIN, projection
    ):
        raise _ReceiptInvalidV1("receipt fingerprint is invalid")


def _receipt_matches_request(
    document: Mapping[str, object], request: SourceReconciliationRequestV1
) -> bool:
    source = document["source"]
    updater = document["updater"]
    assert isinstance(source, dict) and isinstance(updater, dict)
    return source == {
        "lexicalPath": str(request.drift.lexical_path),
        "resolvedPath": str(request.drift.resolved_path),
        "sha256": request.drift.observed_sha256,
    } and updater == {
        "activationId": request.updater_activation_id,
        "release": request.updater_release,
        "sourceDigest": request.updater_source_digest,
    }


def _open_private_state_directory(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    information = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise OSError("state_home is not a private owned directory")
    return descriptor


def _open_private_lock(directory_descriptor: int) -> int:
    base_flags = (
        os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(
            _LOCK_NAME,
            base_flags,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        try:
            descriptor = os.open(
                _LOCK_NAME,
                base_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            descriptor = os.open(
                _LOCK_NAME,
                base_flags,
                dir_fd=directory_descriptor,
            )
    information = os.fstat(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or information.st_nlink != 1
        or stat.S_IMODE(information.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise OSError("reconciliation lock is not private")
    return descriptor


def _atomic_write_receipt(
    directory_descriptor: int, document: Mapping[str, object]
) -> None:
    raw = canonical_json_bytes(dict(document))
    temporary_name = f".{_RECEIPT_NAME}.{secrets.token_hex(16)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short receipt write")
            view = view[written:]
        os.fsync(descriptor)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o600
        ):
            raise OSError("staged reconciliation receipt is unsafe")
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            _RECEIPT_NAME,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
        observed = _read_receipt(directory_descriptor)
        if observed != dict(document):
            raise OSError("published reconciliation receipt differs")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass


def _absolute_path(value: object, name: str) -> None:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ValueError(f"{name} must be an absolute Path")


def _epoch_second(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ValueError("now_epoch_seconds returned an invalid value")
    return int(value)


def _retry_after(now_epoch_seconds: Callable[[], int | float]) -> int:
    return _epoch_second(now_epoch_seconds()) + _RETRY_SECONDS


__all__ = [
    "RunProcessV1",
    "SourceReconciliationAcceptanceV1",
    "SourceReconciliationRequestV1",
    "SourceReconciliationResultV1",
    "reconcile_source_drift_v1",
]
