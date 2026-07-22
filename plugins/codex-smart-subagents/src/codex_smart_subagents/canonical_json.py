"""Canonical JSON and domain-separated fingerprints for Codex contracts."""

from __future__ import annotations

import hashlib
from typing import Any


MAX_SAFE_INTEGER = 9_007_199_254_740_991


class CanonicalJsonError(ValueError):
    """Raised when a value is outside the canonical-json-v1 data model."""


def canonical_json_v1(value: Any) -> str:
    """Encode a value using the exact canonical-json-v1 contract."""

    return _encode(value, active=set())


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_v1(value).encode("utf-8")


def domain_fingerprint(domain: str, value: Any) -> str:
    if not isinstance(domain, str) or not domain or "\0" in domain:
        raise CanonicalJsonError("fingerprint domain must be a non-empty string")
    return hashlib.sha256(
        domain.encode("utf-8") + b"\0" + canonical_json_bytes(value)
    ).hexdigest()


def _encode(value: Any, *, active: set[int]) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalJsonError("integer is outside the safe range")
        return str(value)
    if type(value) is str:
        return _encode_string(value)
    if type(value) is list:
        marker = id(value)
        if marker in active:
            raise CanonicalJsonError("cyclic arrays are not supported")
        active.add(marker)
        try:
            return "[" + ",".join(_encode(item, active=active) for item in value) + "]"
        finally:
            active.remove(marker)
    if type(value) is dict:
        marker = id(value)
        if marker in active:
            raise CanonicalJsonError("cyclic objects are not supported")
        if not all(type(key) is str for key in value):
            raise CanonicalJsonError("object keys must be strings")
        active.add(marker)
        try:
            keys = sorted(value, key=lambda item: item.encode("utf-8"))
            return "{" + ",".join(
                _encode_string(key) + ":" + _encode(value[key], active=active)
                for key in keys
            ) + "}"
        except UnicodeEncodeError as exc:
            raise CanonicalJsonError("unpaired Unicode surrogate is forbidden") from exc
        finally:
            active.remove(marker)
    raise CanonicalJsonError(
        f"unsupported canonical-json-v1 value: {type(value).__name__}"
    )


def _encode_string(value: str) -> str:
    encoded: list[str] = ['"']
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalJsonError("unpaired Unicode surrogate is forbidden")
        if character == '"':
            encoded.append('\\"')
        elif character == "\\":
            encoded.append("\\\\")
        elif codepoint <= 0x1F:
            encoded.append(f"\\u00{codepoint:02x}")
        else:
            encoded.append(character)
    encoded.append('"')
    return "".join(encoded)
