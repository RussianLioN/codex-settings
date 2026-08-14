"""Canonical stable Codex version compatibility checks."""

from __future__ import annotations

import re


MINIMUM_STABLE_CODEX_VERSION = "0.144.4"
_STABLE_SEMANTIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


def parse_stable_codex_version(version: str) -> tuple[int, int, int]:
    """Parse one canonical stable semantic version."""

    if not isinstance(version, str):
        raise ValueError("Codex version must be a string")
    match = _STABLE_SEMANTIC_VERSION.fullmatch(version)
    if match is None:
        raise ValueError(
            "Codex version must be a canonical stable semantic version"
        )
    try:
        major, minor, patch = match.groups()
        return int(major), int(minor), int(patch)
    except ValueError as exc:
        raise ValueError(
            "Codex version is outside the supported numeric range"
        ) from exc


def codex_version_supported(
    version: str,
    *,
    minimum: str = MINIMUM_STABLE_CODEX_VERSION,
) -> bool:
    """Return whether a canonical stable version meets the effective minimum."""

    try:
        parsed = parse_stable_codex_version(version)
        minimum_parsed = parse_stable_codex_version(minimum)
        global_minimum = parse_stable_codex_version(
            MINIMUM_STABLE_CODEX_VERSION
        )
    except ValueError:
        return False
    return parsed >= max(global_minimum, minimum_parsed)
