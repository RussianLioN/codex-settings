#!/usr/bin/env python3
"""Reconcile the narrow, user-owned default Codex entrypoint transactionally."""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


SCHEMA_VERSION = 1
MAX_FILE_SIZE = 256 * 1024
JSON_MODE = 0o600
HIGHFD_MODE = 0o755
LEGACY_ALIASES_MODE = 0o644
TARGET_ALIASES_MODE = 0o600
TARGET_ORDER = ("highfd", "aliases")
RECEIPT_DOCUMENT_TYPE = "codex-entrypoint-receipt-v1"
JOURNAL_DOCUMENT_TYPE = "codex-entrypoint-journal-v1"
RECEIPT_FINGERPRINT_DOMAIN = b"codex-entrypoint-receipt-v1\x00"
JOURNAL_FINGERPRINT_DOMAIN = b"codex-entrypoint-journal-v1\x00"
LEGACY_ALIASES = (
    b"# Codex autonomous workflow profile aliases.\n"
    b"alias codex='$HOME/.local/bin/codex-highfd'\n"
    b"alias codexs='$HOME/.local/bin/codex-highfd --profile standard'\n"
    b"alias codexro='$HOME/.local/bin/codex-highfd --profile safe-readonly'\n"
    b"alias codexwide='$HOME/.local/bin/codex-highfd --profile wide-readers'\n"
    b"alias codexfa='$HOME/.local/bin/codex-highfd --profile full-access'\n"
    b"alias codexfd='$HOME/.local/bin/codex-highfd --fd-doctor'\n"
)
TARGET_ALIASES = (
    b"alias codex='CODEX_SMART_ENABLED=1 "
    b"$HOME/.local/bin/codex-highfd'\n"
    b"alias codex-native='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd'\n"
    b"alias codexs='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile standard'\n"
    b"alias codexro='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile safe-readonly'\n"
    b"alias codexwide='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile wide-readers'\n"
    b"alias codexfa='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --profile full-access'\n"
    b"alias codexfd='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 "
    b"$HOME/.local/bin/codex-highfd --fd-doctor'\n"
)


class ReconcileConflict(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class InjectedFailure(Exception):
    pass


@dataclass(frozen=True)
class Layout:
    home: Path
    source_root: Path
    highfd: Path
    aliases: Path
    receipt: Path
    journal: Path
    lock: Path
    source_highfd: Path
    legacy_highfd: Path
    allow_test_failpoints: bool

    @classmethod
    def create(
        cls,
        home: Path,
        source_root: Path,
        *,
        allow_test_failpoints: bool,
    ) -> "Layout":
        codex_home = home / ".codex"
        manifests = codex_home / "install-manifests"
        return cls(
            home=home,
            source_root=source_root,
            highfd=home / ".local" / "bin" / "codex-highfd",
            aliases=codex_home / "codex-autonomous-aliases.zsh",
            receipt=manifests / "codex-entrypoint-v1.json",
            journal=manifests / "codex-entrypoint-v1.journal.json",
            lock=manifests / "codex-entrypoint-v1.lock",
            source_highfd=source_root / "scripts" / "codex-highfd",
            legacy_highfd=(
                source_root
                / "tests"
                / "smart_subagents"
                / "fixtures"
                / "codex-highfd-legacy"
            ),
            allow_test_failpoints=allow_test_failpoints,
        )

    def targets(self) -> dict[str, Path]:
        return {"highfd": self.highfd, "aliases": self.aliases}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


ManagedVersionIdentity = tuple[str, int, int, str, int, int]


def _managed_version_identity(
    desired: dict[str, dict[str, object]],
) -> ManagedVersionIdentity:
    highfd = desired["highfd"]
    aliases = desired["aliases"]
    highfd_digest = highfd.get("sha256")
    highfd_size = highfd.get("size")
    highfd_mode = highfd.get("mode")
    aliases_digest = aliases.get("sha256")
    aliases_size = aliases.get("size")
    aliases_mode = aliases.get("mode")
    if (
        not isinstance(highfd_digest, str)
        or type(highfd_size) is not int
        or type(highfd_mode) is not int
        or not isinstance(aliases_digest, str)
        or type(aliases_size) is not int
        or type(aliases_mode) is not int
    ):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "managed version identity is incomplete",
        )
    return (
        highfd_digest,
        highfd_size,
        highfd_mode,
        aliases_digest,
        aliases_size,
        aliases_mode,
    )


# Keep every field literal: deriving historical identities from current byte
# constants would silently rewrite the registry when those constants change.
# Before changing either managed file, add the departing exact pair here.
REGISTERED_MANAGED_VERSIONS: frozenset[ManagedVersionIdentity] = frozenset(
    {
        (
            "a04efa493f60cc4a31cfe443aecfc8d02"
            "e804422aeb976cfc3cc7aa4602a8e57",
            2169,
            0o755,
            "c8a87dac327ac4552660f4bbefac3eefa"
            "799a99a11f0b6e01ea3af6437d80aac",
            718,
            0o600,
        ),
        (
            "a04efa493f60cc4a31cfe443aecfc8d02"
            "e804422aeb976cfc3cc7aa4602a8e57",
            2169,
            0o755,
            "f3cc0056eec087ea40fe34ce5dccd044"
            "c1bad32964fc9649651f1eb59813a330",
            741,
            0o600,
        ),
        (
            "a04efa493f60cc4a31cfe443aecfc8d02"
            "e804422aeb976cfc3cc7aa4602a8e57",
            2169,
            0o755,
            "7e12c02b07fb90a072cc04742ef63d060"
            "70b8beb1a4270e5d61c079ac655185e",
            420,
            0o600,
        ),
    }
)


def _file_projection(data: bytes, mode: int) -> dict[str, object]:
    return {
        "dataBase64": base64.b64encode(data).decode("ascii"),
        "mode": mode,
        "sha256": _sha256(data),
        "size": len(data),
        "type": "file",
    }


def _absent_projection() -> dict[str, object]:
    return {"type": "absent"}


def _projection_bytes(projection: dict[str, object]) -> bytes | None:
    if projection.get("type") == "absent":
        return None
    encoded = projection.get("dataBase64")
    if not isinstance(encoded, str):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "file projection has no dataBase64",
        )
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "file projection contains invalid base64",
        ) from exc


def _validate_projection(
    value: object,
    *,
    label: str,
    allowed_modes: set[int],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection is not an object",
        )
    projection = dict(value)
    projection_type = projection.get("type")
    if projection_type == "absent":
        if projection != {"type": "absent"}:
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                f"{label} absent projection has extra fields",
            )
        return projection
    if projection_type != "file":
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection type is unsupported",
        )
    if set(projection) != {
        "dataBase64",
        "mode",
        "sha256",
        "size",
        "type",
    }:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} file projection fields are invalid",
        )
    mode = projection.get("mode")
    size = projection.get("size")
    digest = projection.get("sha256")
    if type(mode) is not int or mode not in allowed_modes:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection mode is invalid",
        )
    if type(size) is not int or size < 0 or size > MAX_FILE_SIZE:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection size is invalid",
        )
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection digest is invalid",
        )
    data = _projection_bytes(projection)
    if data is None or len(data) != size or _sha256(data) != digest:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} projection bytes do not match metadata",
        )
    return projection


def _target_code(label: str, reason: str) -> str:
    return f"ENTRYPOINT_{label.upper()}_{reason}_CONFLICT"


def _read_projection(
    path: Path,
    *,
    label: str,
    allowed_modes: set[int],
) -> dict[str, object]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return _absent_projection()
    if not stat.S_ISREG(before.st_mode):
        raise ReconcileConflict(
            _target_code(label, "TYPE"),
            f"{path} is not a regular file",
        )
    if before.st_uid != os.getuid():
        raise ReconcileConflict(
            _target_code(label, "OWNER"),
            f"{path} is not owned by the current user",
        )
    if before.st_nlink != 1:
        raise ReconcileConflict(
            _target_code(label, "LINK_COUNT"),
            f"{path} has an unsupported link count",
        )
    mode = stat.S_IMODE(before.st_mode)
    if mode not in allowed_modes:
        raise ReconcileConflict(
            _target_code(label, "MODE"),
            f"{path} has unsupported mode {mode:o}",
        )
    if before.st_size > MAX_FILE_SIZE:
        raise ReconcileConflict(
            _target_code(label, "SIZE"),
            f"{path} exceeds the read limit",
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.getuid()
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != mode
            or after.st_size != before.st_size
        ):
            raise ReconcileConflict(
                _target_code(label, "RACE"),
                f"{path} changed during inspection",
            )
        chunks: list[bytes] = []
        remaining = MAX_FILE_SIZE + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_FILE_SIZE or len(data) != after.st_size:
            raise ReconcileConflict(
                _target_code(label, "SIZE"),
                f"{path} exceeds the read limit",
            )
        return _file_projection(data, mode)
    finally:
        os.close(descriptor)


def _read_source(path: Path, *, label: str, mode: int) -> bytes:
    projection = _read_projection(
        path,
        label=label,
        allowed_modes={mode},
    )
    data = _projection_bytes(projection)
    if data is None:
        raise ReconcileConflict(
            "ENTRYPOINT_SOURCE_MISSING",
            f"missing source file: {path}",
        )
    return data


def _json_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _fingerprint(
    value: dict[str, object],
    *,
    domain: bytes,
) -> str:
    unsigned = dict(value)
    unsigned.pop("fingerprint", None)
    canonical = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(domain + canonical)


def _seal_document(
    value: dict[str, object],
    *,
    domain: bytes,
) -> dict[str, object]:
    sealed = dict(value)
    sealed["fingerprint"] = _fingerprint(sealed, domain=domain)
    return sealed


def _validate_fingerprint(
    value: dict[str, object],
    *,
    domain: bytes,
    label: str,
) -> None:
    fingerprint = value.get("fingerprint")
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
        or fingerprint != _fingerprint(value, domain=domain)
    ):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} fingerprint is invalid",
        )


def _parse_json_projection(
    projection: dict[str, object],
    *,
    label: str,
) -> dict[str, object]:
    data = _projection_bytes(projection)
    if data is None:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} is absent",
        )
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} is not valid JSON",
        ) from exc
    if not isinstance(value, dict):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} is not a JSON object",
        )
    if data != _json_bytes(value):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} is not canonical JSON",
        )
    return value


def _desired_projections(
    layout: Layout,
) -> tuple[dict[str, dict[str, object]], bytes]:
    highfd = _read_source(
        layout.source_highfd,
        label="source_highfd",
        mode=HIGHFD_MODE,
    )
    return {
        "highfd": _file_projection(highfd, HIGHFD_MODE),
        "aliases": _file_projection(TARGET_ALIASES, TARGET_ALIASES_MODE),
    }, highfd


def _legacy_highfd_bytes(layout: Layout) -> bytes:
    return _read_source(
        layout.legacy_highfd,
        label="legacy_highfd",
        mode=LEGACY_ALIASES_MODE,
    )


def _inventory_targets(
    layout: Layout,
) -> dict[str, dict[str, object]]:
    return {
        "highfd": _read_projection(
            layout.highfd,
            label="highfd",
            allowed_modes={HIGHFD_MODE},
        ),
        "aliases": _read_projection(
            layout.aliases,
            label="aliases",
            allowed_modes={LEGACY_ALIASES_MODE, TARGET_ALIASES_MODE},
        ),
    }


def _classify_known_targets(
    layout: Layout,
    observed: dict[str, dict[str, object]],
    desired: dict[str, dict[str, object]],
    legacy_highfd: bytes,
) -> None:
    highfd = observed["highfd"]
    highfd_data = _projection_bytes(highfd)
    known_highfd = (
        highfd.get("type") == "absent"
        or highfd == desired["highfd"]
        or (
            highfd_data == legacy_highfd
            and highfd.get("mode") == HIGHFD_MODE
        )
    )
    if not known_highfd:
        raise ReconcileConflict(
            "ENTRYPOINT_HIGHFD_CONTENT_CONFLICT",
            f"{layout.highfd} has unknown contents",
        )

    aliases = observed["aliases"]
    aliases_data = _projection_bytes(aliases)
    known_aliases = (
        aliases.get("type") == "absent"
        or aliases == desired["aliases"]
        or (
            aliases_data == LEGACY_ALIASES
            and aliases.get("mode") == LEGACY_ALIASES_MODE
        )
    )
    if not known_aliases:
        raise ReconcileConflict(
            "ENTRYPOINT_ALIASES_CONTENT_CONFLICT",
            f"{layout.aliases} has unknown contents",
        )


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise ReconcileConflict(
                    "ENTRYPOINT_DIRECTORY_INVALID",
                    f"cannot locate an existing ancestor for {path}",
                )
            cursor = parent
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ReconcileConflict(
                "ENTRYPOINT_DIRECTORY_INVALID",
                f"{cursor} is not a directory",
            )
        if info.st_uid != os.getuid():
            raise ReconcileConflict(
                "ENTRYPOINT_DIRECTORY_INVALID",
                f"{cursor} is not owned by the current user",
            )
        break
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ReconcileConflict(
                    "ENTRYPOINT_DIRECTORY_INVALID",
                    f"{directory} cannot be used safely",
                )
        _fsync_directory(directory.parent)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"refusing to write oversized state to {path}",
        )
    _ensure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _durable_remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _write_projection(path: Path, projection: dict[str, object]) -> None:
    data = _projection_bytes(projection)
    if data is None:
        _durable_remove(path)
        return
    mode = projection.get("mode")
    if type(mode) is not int:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"projection for {path} has invalid mode",
        )
    _atomic_write(path, data, mode)


def _acquire_lock(layout: Layout) -> int:
    _ensure_directory(layout.lock.parent)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(layout.lock, flags, JSON_MODE)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != JSON_MODE
            or info.st_size != 0
        ):
            raise ReconcileConflict(
                "ENTRYPOINT_LOCK_CONFLICT",
                f"{layout.lock} is not a safe 0600 lock file",
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_optional_json(
    path: Path,
    *,
    label: str,
) -> tuple[dict[str, object], dict[str, object]] | None:
    projection = _read_projection(
        path,
        label=label,
        allowed_modes={JSON_MODE},
    )
    if projection.get("type") == "absent":
        return None
    return projection, _parse_json_projection(projection, label=label)


def _validate_projection_set(
    value: object,
    *,
    field: str,
    aliases_modes: set[int] | None = None,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != set(TARGET_ORDER):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{field} must contain exactly the managed targets",
        )
    if aliases_modes is None:
        aliases_modes = {LEGACY_ALIASES_MODE, TARGET_ALIASES_MODE}
    return {
        "highfd": _validate_projection(
            value["highfd"],
            label=f"{field}.highfd",
            allowed_modes={HIGHFD_MODE},
        ),
        "aliases": _validate_projection(
            value["aliases"],
            label=f"{field}.aliases",
            allowed_modes=aliases_modes,
        ),
    }


def _expected_targets(layout: Layout) -> dict[str, str]:
    return {
        "aliases": str(layout.aliases),
        "highfd": str(layout.highfd),
    }


def _validate_initial_before(
    before: dict[str, dict[str, object]],
    *,
    layout: Layout,
) -> None:
    legacy = {
        "highfd": _file_projection(
            _legacy_highfd_bytes(layout),
            HIGHFD_MODE,
        ),
        "aliases": _file_projection(
            LEGACY_ALIASES,
            LEGACY_ALIASES_MODE,
        ),
    }
    for name in TARGET_ORDER:
        if before[name] not in (_absent_projection(), legacy[name]):
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                f"receipt before.{name} is outside the initial-state domain",
            )


def _validate_receipt(
    value: dict[str, object],
    *,
    layout: Layout,
    tracked_desired: dict[str, dict[str, object]],
) -> tuple[
    str,
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
]:
    if set(value) != {
        "before",
        "desired",
        "documentType",
        "fingerprint",
        "schemaVersion",
        "state",
        "targets",
    }:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt fields are invalid",
        )
    if value.get("documentType") != RECEIPT_DOCUMENT_TYPE:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt document type is unsupported",
        )
    _validate_fingerprint(
        value,
        domain=RECEIPT_FINGERPRINT_DOMAIN,
        label="receipt",
    )
    if value.get("schemaVersion") != SCHEMA_VERSION:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt schema version is unsupported",
        )
    state = value.get("state")
    if state not in {"active", "rolled_back"}:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt state is unsupported",
        )
    targets = value.get("targets")
    if targets != _expected_targets(layout):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt target set is invalid",
        )
    before = _validate_projection_set(value.get("before"), field="before")
    _validate_initial_before(before, layout=layout)
    desired = _validate_projection_set(
        value.get("desired"),
        field="desired",
        aliases_modes={TARGET_ALIASES_MODE},
    )
    if desired["highfd"].get("type") != "file":
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt desired.highfd must be a file",
        )
    if desired["aliases"].get("type") != "file":
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt desired.aliases must be a file",
        )
    if (
        desired != tracked_desired
        and _managed_version_identity(desired)
        not in REGISTERED_MANAGED_VERSIONS
    ):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "receipt desired pair is outside the managed-version registry",
        )
    return state, before, desired


def _receipt_document(
    *,
    layout: Layout,
    state: str,
    before: dict[str, dict[str, object]],
    desired: dict[str, dict[str, object]],
) -> dict[str, object]:
    return _seal_document(
        {
            "before": before,
            "desired": desired,
            "documentType": RECEIPT_DOCUMENT_TYPE,
            "schemaVersion": SCHEMA_VERSION,
            "state": state,
            "targets": _expected_targets(layout),
        },
        domain=RECEIPT_FINGERPRINT_DOMAIN,
    )


def _parse_receipt_projection(
    projection: dict[str, object],
    *,
    layout: Layout,
    tracked_desired: dict[str, dict[str, object]],
    label: str,
    allow_absent: bool,
) -> tuple[
    dict[str, object],
    str,
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
] | None:
    if projection.get("type") == "absent":
        if allow_absent:
            return None
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            f"{label} cannot be absent",
        )
    value = _parse_json_projection(projection, label=label)
    state, before, desired = _validate_receipt(
        value,
        layout=layout,
        tracked_desired=tracked_desired,
    )
    return value, state, before, desired


def _journal_document(
    *,
    layout: Layout,
    operation: str,
    phase: str,
    before: dict[str, dict[str, object]],
    desired: dict[str, dict[str, object]],
    receipt_before: dict[str, object],
    receipt_desired: dict[str, object],
) -> dict[str, object]:
    return _seal_document(
        {
            "before": before,
            "desired": desired,
            "documentType": JOURNAL_DOCUMENT_TYPE,
            "operation": operation,
            "phase": phase,
            "receiptBefore": receipt_before,
            "receiptDesired": receipt_desired,
            "schemaVersion": SCHEMA_VERSION,
            "targets": _expected_targets(layout),
        },
        domain=JOURNAL_FINGERPRINT_DOMAIN,
    )


def _validate_journal(
    value: dict[str, object],
    *,
    layout: Layout,
    tracked_desired: dict[str, dict[str, object]],
) -> tuple[
    str,
    str,
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, object],
    dict[str, object],
]:
    if set(value) != {
        "before",
        "desired",
        "documentType",
        "fingerprint",
        "operation",
        "phase",
        "receiptBefore",
        "receiptDesired",
        "schemaVersion",
        "targets",
    }:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal fields are invalid",
        )
    if value.get("documentType") != JOURNAL_DOCUMENT_TYPE:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal document type is unsupported",
        )
    _validate_fingerprint(
        value,
        domain=JOURNAL_FINGERPRINT_DOMAIN,
        label="journal",
    )
    if value.get("schemaVersion") != SCHEMA_VERSION:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal schema version is unsupported",
        )
    operation = value.get("operation")
    if operation not in {"apply", "rollback"}:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal operation is unsupported",
        )
    phase = value.get("phase")
    if phase not in {"prepared", "highfd", "aliases", "receipt"}:
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal phase is unsupported",
        )
    if value.get("targets") != _expected_targets(layout):
        raise ReconcileConflict(
            "ENTRYPOINT_STATE_INVALID",
            "journal target set is invalid",
        )
    before = _validate_projection_set(value.get("before"), field="before")
    desired = _validate_projection_set(value.get("desired"), field="desired")
    receipt_before = _validate_projection(
        value.get("receiptBefore"),
        label="receiptBefore",
        allowed_modes={JSON_MODE},
    )
    receipt_desired = _validate_projection(
        value.get("receiptDesired"),
        label="receiptDesired",
        allowed_modes={JSON_MODE},
    )
    parsed_before = _parse_receipt_projection(
        receipt_before,
        layout=layout,
        tracked_desired=tracked_desired,
        label="receiptBefore",
        allow_absent=operation == "apply",
    )
    parsed_desired = _parse_receipt_projection(
        receipt_desired,
        layout=layout,
        tracked_desired=tracked_desired,
        label="receiptDesired",
        allow_absent=False,
    )
    if parsed_desired is None:
        raise AssertionError("receiptDesired parser accepted absence")
    (
        _desired_document,
        desired_state,
        desired_initial,
        desired_installed,
    ) = parsed_desired
    if operation == "apply":
        if (
            desired_installed != desired
            or (
                desired != tracked_desired
                and _managed_version_identity(desired)
                not in REGISTERED_MANAGED_VERSIONS
            )
        ):
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                "apply journal is outside the managed-version registry",
            )
        if desired_state != "active":
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                "apply journal receiptDesired is not active",
            )
        if parsed_before is None:
            expected_before = desired_initial
        else:
            (
                _before_document,
                before_state,
                before_initial,
                before_installed,
            ) = parsed_before
            if desired_initial != before_initial:
                raise ReconcileConflict(
                    "ENTRYPOINT_STATE_INVALID",
                    "apply journal changes the initial rollback state",
                )
            expected_before = (
                before_installed
                if before_state == "active"
                else before_initial
            )
        if before != expected_before:
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                "apply journal before state is inconsistent",
            )
    else:
        if parsed_before is None:
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                "rollback journal has no active receipt",
            )
        (
            _before_document,
            before_state,
            before_initial,
            before_installed,
        ) = parsed_before
        if (
            before_state != "active"
            or desired_state != "rolled_back"
            or before != before_installed
            or desired != before_initial
            or desired_initial != before_initial
            or desired_installed != before_installed
        ):
            raise ReconcileConflict(
                "ENTRYPOINT_STATE_INVALID",
                "rollback journal is outside the receipt state transition",
            )
    return (
        operation,
        phase,
        before,
        desired,
        receipt_before,
        receipt_desired,
    )


def _read_for_transaction(
    path: Path,
    *,
    label: str,
    before: dict[str, object],
    desired: dict[str, object],
) -> dict[str, object]:
    modes = {
        mode
        for projection in (before, desired)
        if (mode := projection.get("mode")) is not None and type(mode) is int
    }
    return _read_projection(
        path,
        label=label,
        allowed_modes=modes or {JSON_MODE},
    )


def _test_failpoints_permitted(argv: list[str], home: Path) -> bool:
    if "--home" not in argv:
        return False
    return home.resolve() != Path.home().resolve()


def _reach_failpoint(name: str, *, permitted: bool) -> None:
    if not permitted:
        return
    requested = os.environ.get("CODEX_ENTRYPOINT_TEST_FAILPOINT")
    if requested == name:
        raise InjectedFailure(name)
    if requested == f"oserror_{name}":
        raise OSError(errno.EIO, f"injected I/O failure at {name}")


def _write_journal(
    layout: Layout,
    journal: dict[str, object],
) -> None:
    sealed = _seal_document(
        journal,
        domain=JOURNAL_FINGERPRINT_DOMAIN,
    )
    journal.clear()
    journal.update(sealed)
    _atomic_write(layout.journal, _json_bytes(journal), JSON_MODE)


def _execute_transaction(
    layout: Layout,
    journal: dict[str, object],
    *,
    newly_prepared: bool,
) -> None:
    tracked_desired, _highfd = _desired_projections(layout)
    (
        operation,
        _phase,
        before,
        desired,
        receipt_before,
        receipt_desired,
    ) = _validate_journal(
        journal,
        layout=layout,
        tracked_desired=tracked_desired,
    )
    targets = layout.targets()

    observations: dict[str, dict[str, object]] = {}
    for name in TARGET_ORDER:
        observed = _read_for_transaction(
            targets[name],
            label=name,
            before=before[name],
            desired=desired[name],
        )
        if observed not in (before[name], desired[name]):
            raise ReconcileConflict(
                _target_code(name, "TRANSACTION_STATE"),
                f"{targets[name]} matches neither transaction projection",
            )
        observations[name] = observed

    receipt_observed = _read_for_transaction(
        layout.receipt,
        label="receipt",
        before=receipt_before,
        desired=receipt_desired,
    )
    if receipt_observed not in (receipt_before, receipt_desired):
        raise ReconcileConflict(
            "ENTRYPOINT_RECEIPT_TRANSACTION_STATE_CONFLICT",
            f"{layout.receipt} matches neither transaction projection",
        )

    for name in TARGET_ORDER:
        if observations[name] == before[name] and before[name] != desired[name]:
            _write_projection(targets[name], desired[name])
            if (
                newly_prepared
                and operation == "apply"
                and name == "highfd"
            ):
                _reach_failpoint(
                    "after_highfd_replace",
                    permitted=layout.allow_test_failpoints,
                )
            if (
                newly_prepared
                and operation == "rollback"
                and name == "highfd"
            ):
                _reach_failpoint(
                    "after_rollback_highfd_replace",
                    permitted=layout.allow_test_failpoints,
                )
        journal["phase"] = name
        _write_journal(layout, journal)

    if receipt_observed == receipt_before and receipt_before != receipt_desired:
        _write_projection(layout.receipt, receipt_desired)
    journal["phase"] = "receipt"
    _write_journal(layout, journal)
    if newly_prepared and operation == "apply":
        _reach_failpoint(
            "after_apply_receipt_replace",
            permitted=layout.allow_test_failpoints,
        )

    for name in TARGET_ORDER:
        verified = _read_for_transaction(
            targets[name],
            label=name,
            before=before[name],
            desired=desired[name],
        )
        if verified != desired[name]:
            raise ReconcileConflict(
                _target_code(name, "VERIFY"),
                f"{targets[name]} does not match the desired projection",
            )
    verified_receipt = _read_for_transaction(
        layout.receipt,
        label="receipt",
        before=receipt_before,
        desired=receipt_desired,
    )
    if verified_receipt != receipt_desired:
        raise ReconcileConflict(
            "ENTRYPOINT_RECEIPT_VERIFY_CONFLICT",
            f"{layout.receipt} does not match the desired projection",
        )
    _durable_remove(layout.journal)


def _new_transaction(
    *,
    layout: Layout,
    operation: str,
    before: dict[str, dict[str, object]],
    desired: dict[str, dict[str, object]],
    receipt_before: dict[str, object],
    receipt_document: dict[str, object],
) -> dict[str, object]:
    return _journal_document(
        layout=layout,
        operation=operation,
        phase="prepared",
        before=before,
        desired=desired,
        receipt_before=receipt_before,
        receipt_desired=_file_projection(
            _json_bytes(receipt_document),
            JSON_MODE,
        ),
    )


def _result(
    *,
    command: str,
    status: str,
    code: str,
    changed: bool | None,
    targets: tuple[Path, ...] = (),
) -> dict[str, object]:
    value: dict[str, object] = {
        "changed": changed,
        "code": code,
        "command": command,
        "schemaVersion": SCHEMA_VERSION,
        "status": status,
    }
    if targets:
        value["targets"] = [str(path) for path in targets]
    return value


def _inspect_apply(
    layout: Layout,
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    tuple[dict[str, object], dict[str, object]] | None,
    str | None,
    dict[str, dict[str, object]] | None,
    dict[str, dict[str, object]] | None,
]:
    desired, _highfd = _desired_projections(layout)
    observed = _inventory_targets(layout)
    existing_receipt = _read_optional_json(layout.receipt, label="receipt")
    if existing_receipt is None:
        _classify_known_targets(
            layout,
            observed,
            desired,
            _legacy_highfd_bytes(layout),
        )
        if observed == desired or any(
            observed[name] == desired[name] for name in TARGET_ORDER
        ):
            raise ReconcileConflict(
                "ENTRYPOINT_RECEIPT_MISSING",
                f"managed target files require a receipt: {layout.receipt}",
            )
        _validate_initial_before(observed, layout=layout)
        return desired, observed, None, None, None, None

    state, initial, installed = _validate_receipt(
        existing_receipt[1],
        layout=layout,
        tracked_desired=desired,
    )
    expected_observed = installed if state == "active" else initial
    if observed != expected_observed:
        raise ReconcileConflict(
            "ENTRYPOINT_RECEIPT_STATE_CONFLICT",
            f"{state} receipt does not exactly bind the current targets",
        )
    return (
        desired,
        observed,
        existing_receipt,
        state,
        initial,
        installed,
    )


def _preview(layout: Layout) -> tuple[int, dict[str, object]]:
    existing_journal = _read_optional_json(layout.journal, label="journal")
    if existing_journal is not None:
        tracked_desired, _highfd = _desired_projections(layout)
        _validate_journal(
            existing_journal[1],
            layout=layout,
            tracked_desired=tracked_desired,
        )
        return 1, _result(
            command="preview",
            status="RECOVERY_REQUIRED",
            code="ENTRYPOINT_RECOVERY_REQUIRED",
            changed=False,
        )
    desired, observed, _receipt, state, _initial, installed = _inspect_apply(
        layout
    )
    if state == "active" and installed == desired:
        return 0, _result(
            command="preview",
            status="unchanged",
            code="ENTRYPOINT_UNCHANGED",
            changed=False,
        )
    changed_targets = tuple(
        layout.targets()[name]
        for name in TARGET_ORDER
        if observed[name] != desired[name]
    )
    return 0, _result(
        command="preview",
        status="planned",
        code="ENTRYPOINT_CHANGES_REQUIRED",
        changed=True,
        targets=changed_targets,
    )


def _doctor(layout: Layout) -> tuple[int, dict[str, object]]:
    try:
        existing_journal = _read_optional_json(
            layout.journal,
            label="journal",
        )
        if existing_journal is not None:
            tracked_desired, _highfd = _desired_projections(layout)
            _validate_journal(
                existing_journal[1],
                layout=layout,
                tracked_desired=tracked_desired,
            )
            return 1, _result(
                command="doctor",
                status="RECOVERY_REQUIRED",
                code="ENTRYPOINT_RECOVERY_REQUIRED",
                changed=False,
            )

        desired, _highfd = _desired_projections(layout)
        observed = _inventory_targets(layout)
        receipt = _read_optional_json(layout.receipt, label="receipt")
        if receipt is None:
            _classify_known_targets(
                layout,
                observed,
                desired,
                _legacy_highfd_bytes(layout),
            )
            if observed == desired:
                raise ReconcileConflict(
                    "ENTRYPOINT_RECEIPT_MISSING",
                    f"managed desired files require a receipt: {layout.receipt}",
                )
            ready = False
        else:
            state, initial, installed = _validate_receipt(
                receipt[1],
                layout=layout,
                tracked_desired=desired,
            )
            expected_observed = installed if state == "active" else initial
            if observed != expected_observed:
                raise ReconcileConflict(
                    "ENTRYPOINT_RECEIPT_STATE_CONFLICT",
                    f"{state} receipt does not exactly bind the current targets",
                )
            ready = state == "active" and installed == desired
    except ReconcileConflict as exc:
        result = _result(
            command="doctor",
            status="DRIFT",
            code=exc.code,
            changed=False,
        )
        result["problem"] = exc.detail
        return 1, result
    if ready:
        return 0, _result(
            command="doctor",
            status="READY",
            code="ENTRYPOINT_READY",
            changed=False,
        )
    return 1, _result(
        command="doctor",
        status="DRIFT",
        code="ENTRYPOINT_DRIFT",
        changed=False,
    )


def _recover_existing(
    layout: Layout,
    *,
    requested_command: str,
) -> tuple[int, dict[str, object]] | None:
    existing = _read_optional_json(layout.journal, label="journal")
    if existing is None:
        return None
    journal = existing[1]
    tracked_desired, _highfd = _desired_projections(layout)
    operation, *_rest = _validate_journal(
        journal,
        layout=layout,
        tracked_desired=tracked_desired,
    )
    if operation != requested_command:
        raise ReconcileConflict(
            "ENTRYPOINT_RECOVERY_OPERATION_CONFLICT",
            f"pending {operation} must be resumed with --{operation}",
        )
    _execute_transaction(layout, journal, newly_prepared=False)
    status = "applied" if operation == "apply" else "rolled_back"
    return 0, _result(
        command=operation,
        status=status,
        code="ENTRYPOINT_RECOVERED",
        changed=True,
        targets=(layout.highfd, layout.aliases),
    )


def _inspect_rollback(
    layout: Layout,
) -> tuple[
    tuple[dict[str, object], dict[str, object]] | None,
    dict[str, dict[str, object]],
    str | None,
    dict[str, dict[str, object]] | None,
    dict[str, dict[str, object]] | None,
]:
    tracked_desired, _highfd = _desired_projections(layout)
    observed = _inventory_targets(layout)
    existing_receipt = _read_optional_json(layout.receipt, label="receipt")
    if existing_receipt is None:
        if any(
            observed[name].get("type") != "absent" for name in TARGET_ORDER
        ):
            raise ReconcileConflict(
                "ENTRYPOINT_RECEIPT_MISSING",
                f"rollback requires a receipt for existing targets: {layout.receipt}",
            )
        return None, observed, None, None, None
    state, initial, installed = _validate_receipt(
        existing_receipt[1],
        layout=layout,
        tracked_desired=tracked_desired,
    )
    expected_observed = installed if state == "active" else initial
    if observed != expected_observed:
        raise ReconcileConflict(
            "ENTRYPOINT_RECEIPT_STATE_CONFLICT",
            f"{state} receipt does not exactly bind the current targets",
        )
    return existing_receipt, observed, state, initial, installed


def _preflight_command(layout: Layout, *, operation: str) -> None:
    """Reject conflicts before creating or changing the persistent lock."""
    existing_journal = _read_optional_json(layout.journal, label="journal")
    if existing_journal is not None:
        tracked_desired, _highfd = _desired_projections(layout)
        pending_operation, *_rest = _validate_journal(
            existing_journal[1],
            layout=layout,
            tracked_desired=tracked_desired,
        )
        if pending_operation != operation:
            raise ReconcileConflict(
                "ENTRYPOINT_RECOVERY_OPERATION_CONFLICT",
                f"pending {pending_operation} must be resumed with "
                f"--{pending_operation}",
            )
        return
    if operation == "apply":
        _inspect_apply(layout)
    else:
        _inspect_rollback(layout)


def _apply(layout: Layout) -> tuple[int, dict[str, object]]:
    recovered = _recover_existing(layout, requested_command="apply")

    (
        desired,
        observed,
        existing_receipt,
        state,
        initial,
        installed,
    ) = _inspect_apply(layout)
    receipt_before = (
        _absent_projection() if existing_receipt is None else existing_receipt[0]
    )
    if state == "active" and installed == desired:
        if recovered is not None:
            return recovered
        return 0, _result(
            command="apply",
            status="unchanged",
            code="ENTRYPOINT_UNCHANGED",
            changed=False,
        )

    receipt_initial = observed if initial is None else initial
    receipt = _receipt_document(
        layout=layout,
        state="active",
        before=receipt_initial,
        desired=desired,
    )
    journal = _new_transaction(
        layout=layout,
        operation="apply",
        before=observed,
        desired=desired,
        receipt_before=receipt_before,
        receipt_document=receipt,
    )
    _write_journal(layout, journal)
    _execute_transaction(layout, journal, newly_prepared=True)
    return 0, _result(
        command="apply",
        status="applied",
        code="ENTRYPOINT_APPLIED",
        changed=True,
        targets=(layout.highfd, layout.aliases),
    )


def _rollback(layout: Layout) -> tuple[int, dict[str, object]]:
    recovered = _recover_existing(layout, requested_command="rollback")
    if recovered is not None:
        return recovered

    existing_receipt, observed, state, original, installed = _inspect_rollback(
        layout
    )
    if existing_receipt is None:
        return 0, _result(
            command="rollback",
            status="unchanged",
            code="ENTRYPOINT_UNCHANGED",
            changed=False,
        )
    if state == "rolled_back":
        return 0, _result(
            command="rollback",
            status="unchanged",
            code="ENTRYPOINT_UNCHANGED",
            changed=False,
        )
    if state != "active" or original is None or installed is None:
        raise AssertionError("rollback inspection returned an invalid state")
    receipt_projection = existing_receipt[0]

    rolled_back_receipt = _receipt_document(
        layout=layout,
        state="rolled_back",
        before=original,
        desired=installed,
    )
    journal = _new_transaction(
        layout=layout,
        operation="rollback",
        before=installed,
        desired=original,
        receipt_before=receipt_projection,
        receipt_document=rolled_back_receipt,
    )
    _write_journal(layout, journal)
    _execute_transaction(layout, journal, newly_prepared=True)
    return 0, _result(
        command="rollback",
        status="rolled_back",
        code="ENTRYPOINT_ROLLED_BACK",
        changed=True,
        targets=(layout.highfd, layout.aliases),
    )


def _parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconcile the narrow default Codex entrypoint.",
    )
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--preview", action="store_true")
    commands.add_argument("--apply", action="store_true")
    commands.add_argument("--doctor", action="store_true")
    commands.add_argument("--rollback", action="store_true")
    parser.add_argument("--json", action="store_true", required=True)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser.parse_args(argv)


def _absolute_path(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ReconcileConflict(
            "ENTRYPOINT_INVALID_INVOCATION",
            f"{label} must be an absolute path",
        )
    return path


def run(argv: list[str]) -> tuple[int, dict[str, object]]:
    arguments = _parse_arguments(argv)
    home = _absolute_path(arguments.home, label="--home")
    source_root = _absolute_path(
        arguments.source_root,
        label="--source-root",
    )
    layout = Layout.create(
        home,
        source_root,
        allow_test_failpoints=_test_failpoints_permitted(argv, home),
    )
    if arguments.preview:
        return _preview(layout)
    if arguments.doctor:
        return _doctor(layout)

    operation = "apply" if arguments.apply else "rollback"
    _preflight_command(layout, operation=operation)
    lock_descriptor = _acquire_lock(layout)
    try:
        if arguments.apply:
            return _apply(layout)
        return _rollback(layout)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def main(argv: list[str] | None = None) -> int:
    command = "unknown"
    arguments = sys.argv[1:] if argv is None else argv
    for candidate in ("preview", "apply", "doctor", "rollback"):
        if f"--{candidate}" in arguments:
            command = candidate
            break
    try:
        code, result = run(arguments)
    except ReconcileConflict as exc:
        code = 2
        result = _result(
            command=command,
            status="conflict",
            code=exc.code,
            changed=False,
        )
        result["problem"] = exc.detail
    except InjectedFailure:
        code = 70
        result = _result(
            command=command,
            status="failed",
            code="ENTRYPOINT_TEST_FAILPOINT",
            changed=True,
        )
    except OSError as exc:
        code = 74
        result = _result(
            command=command,
            status="failed",
            code="ENTRYPOINT_IO_ERROR",
            changed=None,
        )
        result["problem"] = os.strerror(exc.errno or errno.EIO)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
